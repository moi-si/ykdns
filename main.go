package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/moi-si/addrtrie"
	"golang.org/x/sync/singleflight"
)

type cacheEntry struct {
	rcode             int
	answer, ns, extra []dns.RR
	expireAt          time.Time
}

func cacheKey(domain string, qtype uint16) string {
	return domain + ":" + dns.TypeToString[qtype]
}

var (
	listenAddr, cachePath *string
	domainMatcher         *addrtrie.DomainMatcher[bool]
	ipv4Trie              *addrtrie.BitTrie[bool]
	ipv6Trie              *addrtrie.BitTrie6[bool]
	typeCache             sync.Map
	cache                 sync.Map
	reqGroup              = new(singleflight.Group)
	cacheTTL              = 300 * time.Second
	isDomestic            func(string) (bool, error)
)

func handler(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}

	qname := req.Question[0].Name
	ck := cacheKey(qname, req.Question[0].Qtype)
	log.Println("Query:", ck)
	resp := new(dns.Msg)
	resp.SetReply(req)

	v, found := cache.Load(ck)
	if found {
		entry := v.(cacheEntry)
		log.Println("Cache hit:", ck)
		resp.Rcode = entry.rcode
		resp.Answer = entry.answer
		resp.Ns = entry.ns
		resp.Extra = entry.extra
		if time.Now().Before(entry.expireAt) {
			if err := w.WriteMsg(resp); err != nil {
				log.Println("ERROR writing message:", err)
			}
			return
		}
		cache.Delete(ck)
		log.Printf("Cache for %s expired and was deleted", ck)
	}

	isDom, err := isDomestic(qname)
	if err != nil {
		log.Printf("%s: %s", qname, err)
		return
	}
	if isDom {
		log.Println(qname, "is a domestic domain")
		v, err, _ = reqGroup.Do(ck, func() (any, error) {
			return dmsExchange(req)
		})
	} else {
		log.Println(qname, "is a foreign domain")
		v, err, _ = reqGroup.Do(ck, func() (any, error) {
			return dftExchange(req)
		})
	}

	if err != nil {
		log.Println("ERROR querying upsteam:", err)
		resp.SetRcode(req, dns.RcodeServerFailure)
		if err = w.WriteMsg(resp); err != nil {
			log.Println("ERROR writing message:", err)
		}
		return
	}
	in := v.(*dns.Msg)
	ce := cacheEntry{
		rcode:    in.Rcode,
		answer:   in.Answer,
		expireAt: time.Now().Add(cacheTTL),
	}
	cache.Store(ck, ce)
	resp.Rcode = in.Rcode
	resp.Answer = in.Answer
	resp.Ns = in.Ns
	resp.Extra = in.Extra

	if err = w.WriteMsg(resp); err != nil {
		log.Println("ERROR writing message:", err)
	} else {
		log.Println("Successfully sent response")
	}
}

func init() {
	listenAddr = flag.String("addr", "127.0.0.1:8053", "Listen address")
	dftDoH := flag.String("dftdoh", "https://cloudflare-dns.com/dns-query", "Default DoH")
	dmsDNS := flag.String("dmsdns", "udp://223.5.5.5:53", "Domestic DNS over UDP/TLS/HTTPS")
	proxyAddr := flag.String("proxy", "", "Address of SOCKS5 Proxy server for default DoH")
	confPath := flag.String("conf", "sites.conf", "Sites config file path")
	bySOA := flag.Bool("soa", false, "Diversion through the existence of SOA records")
	ipListPath := flag.String("ips", "ips.txt", "Domestic IP/CIDR list file path")
	cachePath = flag.String("cache", "type_cache.conf", "Type cache file path")
	ttl := flag.Int("ttl", 0, "DNS cache TTL (second)")
	flag.Parse()

	if *ttl > 0 {
		cacheTTL = time.Duration(*ttl) * time.Second
	}

	domainMatcher = addrtrie.NewDomainMatcher[bool]()
	if err := loadConfig(*confPath, domainMatcher.Add); err != nil {
		fmt.Println("ERROR load config:", err)
		os.Exit(0)
	}
	fn := func(s string, b bool) error {
		typeCache.Store(s, b)
		return domainMatcher.Add(s, b)
	}
	if err := loadConfig("type_cache.conf", fn); err != nil {
		fmt.Println("ERROR load type cache:", err)
	}

	if *bySOA {
		isDomestic = func(domain string) (bool, error) {
			if v, ok := typeCache.Load(domain); ok {
				return v.(bool), nil
			}
			if domain[len(domain)-1] == '.' {
				domain = domain[:len(domain)-1]
			}
			isDom := domainMatcher.Find(domain)
			if isDom != nil {
				return *isDom, nil
			}
			msg := new(dns.Msg)
			msg.SetQuestion(domain, dns.TypeSOA)
			in, err := dmsExchange(msg)
			if err != nil {
				return false, fmt.Errorf("exchange: %s", err)
			}
			if in.Rcode != dns.RcodeSuccess {
				return false, fmt.Errorf("rcode: %s", dns.RcodeToString[in.Rcode])
			}
			for _, ans := range in.Answer {
				if _, ok := ans.(*dns.SOA); ok {
					typeCache.Store(domain, true)
					return true, nil
				}
			}
			typeCache.Store(domain, false)
			return false, nil
		}
	} else {
		if err := loadDmsIP(*ipListPath); err != nil {
			fmt.Println("ERROR load dms IP:", err)
			os.Exit(0)
		}
		isDomestic = func(domain string) (bool, error) {
			if v, ok := typeCache.Load(domain); ok {
				return v.(bool), nil
			}
			isDom := domainMatcher.Find(domain[:len(domain)-1])
			if isDom != nil {
				return *isDom, nil
			}
			msg := new(dns.Msg)
			msg.SetQuestion(domain, dns.TypeA)
			in, err := dmsExchange(msg)
			if err != nil {
				return false, fmt.Errorf("exchange: %s", err)
			}
			if in.Rcode != dns.RcodeSuccess {
				return false, fmt.Errorf("rcode: %s", dns.RcodeToString[in.Rcode])
			}
			var ip string
			for _, ans := range in.Answer {
				if record, ok := ans.(*dns.A); ok {
					ip = record.A.String()
					continue
				}
			}
			if ip == "" {
				return false, fmt.Errorf("exchange: A record not found")
			}
			if strings.Contains(ip, ":") {
				isDom, _ = ipv6Trie.Find(ip)
			} else {
				isDom = ipv4Trie.Find(ip)
			}
			if isDom == nil {
				typeCache.Store(domain, false)
				return false, nil
			}
			typeCache.Store(domain, *isDom)
			return *isDom, nil
		}
	}

	var httpCli *http.Client
	if *proxyAddr == "" {
		httpCli = new(http.Client)
		dftExchange = func(req *dns.Msg) (*dns.Msg, error) {
			return dohExchange(req, *dftDoH, httpCli)
		}
	} else {
		ssHttpCli, err := newSock5HttpClient(*proxyAddr)
		if err != nil {
			fmt.Println("Failed to create SOCKS5 HTTP client:", err)
			os.Exit(0)
		}
		dftExchange = func(req *dns.Msg) (*dns.Msg, error) {
			return dohExchange(req, *dftDoH, ssHttpCli)
		}
	}
	if strings.HasPrefix(*dmsDNS, "https://") {
		if httpCli == nil {
			httpCli = new(http.Client)
		}
		dmsExchange = func(req *dns.Msg) (*dns.Msg, error) {
			return dohExchange(req, *dmsDNS, httpCli)
		}
	} else {
		dnsCli := new(dns.Client)
		if strings.HasPrefix(*dmsDNS, "tls://") {
			dnsCli.Net = "tcp-tls"
		} else if strings.HasPrefix(*dmsDNS, "tcp://") {
			dnsCli.Net = "tcp"
		} else if !strings.HasPrefix(*dmsDNS, "udp://") {
			fmt.Println("Unknown domestic DNS protocol")
			os.Exit(0)
		}
		addr := (*dmsDNS)[6:]
		dmsExchange = func(req *dns.Msg) (*dns.Msg, error) {
			in, _, err := dnsCli.Exchange(req, addr)
			return in, err
		}
	}
}

func main() {
	fmt.Println("YukiDNS (Go Version) v0.2.1")

	server := &dns.Server{Addr: *listenAddr, Net: "udp"}
	dns.HandleFunc(".", handler)
	fmt.Println("Listen on", *listenAddr)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGALRM)
	go func() {
		<-sigChan
		if err := writeTypeCache(); err != nil {
			fmt.Println(err)
		}
		os.Exit(0)
	}()

	if err := server.ListenAndServe(); err != nil {
		log.Fatalln("Failed to start server:", err)
	}
}
