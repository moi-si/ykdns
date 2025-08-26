package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

var dftExchange, dmsExchange func(*dns.Msg) (*dns.Msg, error)

func newSock5HttpClient(proxyAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("create socks5 dialer: %s", err)
	}
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}
	transport := &http.Transport{DialContext: dialContext}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}, nil
}

func dohExchange(req *dns.Msg, dohURL string, httpCli *http.Client) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns request: %s", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(wire)
	u := fmt.Sprintf("%s?dns=%s", dohURL, b64)
	httpReq, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build http request: %s", err)
	}
	httpReq.Header.Set("Accept", "application/dns-message")
	resp, err := httpCli.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http status: %s", resp.Status)
	}
	respWire, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read http body: %s", err)
	}
	ans := new(dns.Msg)
	if err := ans.Unpack(respWire); err != nil {
		return nil, fmt.Errorf("unpack dns response: %s", err)
	}
	return ans, nil
}
