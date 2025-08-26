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
)

type cacheEntry struct {
	rcode    int
	answer   []dns.RR
	expireAt time.Time
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
	cacheTTL              = 300 * time.Second
)

func isDomestic(domain string) (bool, error) {
	isDom := domainMatcher.Find(domain[:len(domain)-1])
	if isDom != nil {
		return *isDom, nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)
	in, err := dmsExchange(msg)
	if err != nil {
		return false, fmt.Errorf("dmsExchange: %s", err)
	}
	if in.Rcode != dns.RcodeSuccess {
		return false, fmt.Errorf("dmsExchange: %s", dns.RcodeToString[in.Rcode])
	}
	var ip string
	for _, ans := range in.Answer {
		if record, ok := ans.(*dns.A); ok {
			ip = record.A.String()
			continue
		}
	}
	if ip == "" {
		return false, fmt.Errorf("dmsExchange: A record not found")
	}
	if strings.Contains(ip, ":") {
		isDom, _ = ipv6Trie.Find(ip)
	} else {
		isDom = ipv4Trie.Find(ip)
	}
	if isDom == nil {
		return false, nil
	}
	return *isDom, nil
}

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
		if time.Now().Before(entry.expireAt) {
			if err := w.WriteMsg(resp); err != nil {
				log.Println("Error writing message:", err)
			}
			return
		}
		cache.Delete(ck)
		log.Printf("Cache for %s expired and was deleted", ck)
	}

	var isDom bool
	var err error
	if v, ok := typeCache.Load(qname); ok {
		isDom = v.(bool)
	} else {
		isDom, err = isDomestic(qname)
		if err != nil {
			log.Printf("%s: %s", qname, err)
			return
		}
		typeCache.Store(qname, isDom)
	}
	var in *dns.Msg
	if isDom {
		log.Println(qname, "is domestic domain")
		in, err = dmsExchange(req)
	} else {
		log.Println(qname, "is foreign domain")
		in, err = dftExchange(req)
	}

	if err != nil {
		log.Println("Error querying upsteam:", err)
		resp.SetRcode(req, dns.RcodeServerFailure)
		if err = w.WriteMsg(resp); err != nil {
			log.Println("Error writing message:", err)
		}
		return
	}
	ce := cacheEntry{
		rcode:    in.Rcode,
		answer:   in.Answer,
		expireAt: time.Now().Add(cacheTTL),
	}
	cache.Store(ck, ce)
	resp.Rcode = in.Rcode
	resp.Answer = in.Answer

	if err = w.WriteMsg(resp); err != nil {
		log.Println("Error writing message:", err)
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
	ipListPath := flag.String("ips", "ips.txt", "Domestic IP/CIDR list file path")
	cachePath = flag.String("cache", "type_cache.conf", "Type cache file path")
	ttl := flag.Int("ttl", 0, "DNS cache TTL (second)")
	flag.Parse()

	if *ttl <= 0 {
		cacheTTL = 300 * time.Second
	} else {
		cacheTTL = time.Duration(*ttl) * time.Second
	}

	domainMatcher = addrtrie.NewDomainMatcher[bool]()
	if err := loadConfig(*confPath, domainMatcher.Add); err != nil {
		fmt.Println("Error load config:", err)
		os.Exit(0)
	}
	if err := loadConfig("type_cache.conf", domainMatcher.Add); err != nil {
		fmt.Println("Error load type cache:", err)
	}
	if err := loadDmsIP(*ipListPath); err != nil {
		fmt.Println("Error load dms IP:", err)
		os.Exit(0)
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
		dmsExchange = func(req *dns.Msg) (*dns.Msg, error) {
			in, _, err := dnsCli.Exchange(req, *dmsDNS)
			return in, err
		}
	}
}

func main() {
	fmt.Println("YukiDNS (Go Version) v0.1.0")

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
