package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyDNSDoesNotDependOnLocalResolution(t *testing.T) {
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, _ := net.SplitHostPort(r.Host)
		address, err := netip.ParseAddr(host)
		if r.Method != http.MethodConnect || port != "443" || err != nil || !PublicAddr(address) {
			t.Errorf("unexpected DNS bootstrap: %s %s", r.Method, r.Host)
		}
		connects.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	client := NewClient(Options{Proxy: u, DNS: []string{"127.0.0.1"}, Timeout: time.Second})
	defer client.CloseIdleConnections()
	if response, err := client.Get("https://no-local-dns.invalid/sub"); err == nil {
		response.Body.Close()
		t.Fatal("test proxy unexpectedly served a DNS response")
	}
	if connects.Load() == 0 {
		t.Fatal("proxy download attempted local DNS instead of proxied DoH")
	}
}

func TestDoHAnswersAreBoundedAndCheckedBeforeConnect(t *testing.T) {
	for i, response := range []string{
		`{"Status":0,"Answer":[{"type":1,"data":"1.1.1.1"},{"type":1,"data":"127.0.0.1"}]}`,
		`{"Status":2}`,
		`{"Status":0,"TC":true}`,
		`{"Status":0,"Answer":[{"type":1,"data":"not-an-address"}]}`,
		`{}`,
	} {
		t.Run(response, func(t *testing.T) {
			dns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept") != "application/dns-json" || r.URL.Query().Get("name") != "example.com" {
					t.Error("DoH request was not encoded correctly")
				}
				fmt.Fprint(w, response)
			}))
			defer dns.Close()
			client := newClient(Options{Timeout: time.Second}, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				return lookupDoH(ctx, dns.Client(), dns.URL, network, host)
			})
			defer client.CloseIdleConnections()
			res, err := client.Get("https://example.com")
			if err == nil {
				res.Body.Close()
				t.Fatal("invalid or mixed-private DNS response was accepted")
			}
			if i == 0 && !errors.Is(err, ErrNotPublic) {
				t.Fatalf("mixed public/private answers must be rejected by address policy: %v", err)
			}
		})
	}
}

func TestIPv4TunnelPrefixesAreNotPublic(t *testing.T) {
	for _, address := range []string{"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::", "2001::ffff:7fff:fffe"} {
		if PublicAddr(netip.MustParseAddr(address)) {
			t.Errorf("embedded-address tunnel was accepted: %s", address)
		}
	}
}

func TestProxyDNSRetriesBootstrapAcrossFamiliesAndProviders(t *testing.T) {
	var ipv4, ipv6, secondary atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		address, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || !PublicAddr(address) || r.Method != http.MethodConnect {
			t.Errorf("DNS bootstrap was not pinned to a public address: %s", r.Host)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if address.Is4() {
			ipv4.Add(1)
		} else {
			ipv6.Add(1)
		}
		if host == "8.8.8.8" || host == "8.8.4.4" || strings.HasPrefix(host, "2001:4860:4860::") {
			secondary.Add(1)
		}
		// A successful CONNECT followed by a broken TLS session must also
		// advance the bootstrap, not permanently pin it to the first IP.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		conn.Close()
	}))
	defer proxy.Close()
	address, _ := url.Parse(proxy.URL)
	client := NewClient(Options{Proxy: address, DNS: []string{"127.0.0.1"}, Timeout: 3 * time.Second})
	defer client.CloseIdleConnections()
	if response, err := client.Get("https://audit-dns.invalid"); err == nil {
		response.Body.Close()
		t.Fatal("broken TLS bootstrap unexpectedly succeeded")
	}
	if ipv4.Load() == 0 || ipv6.Load() == 0 || secondary.Load() == 0 {
		t.Fatalf("bootstrap fallback missing: IPv4=%d IPv6=%d secondary=%d", ipv4.Load(), ipv6.Load(), secondary.Load())
	}
}
