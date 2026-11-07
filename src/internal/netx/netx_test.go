package netx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"1.1.1.1", "223.5.5.5", "2606:4700::1111"} {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not public", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "100.64.0.1", "169.254.1.1", "::1", "fe80::1", "fc00::1", "198.18.0.1", "0.0.0.0", "::ffff:127.0.0.1", "224.0.0.1"} {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s public", s)
		}
	}
}

func TestCheckURL(t *testing.T) {
	if _, err := CheckURL("https://example.com/x", false, false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://example.com", "https://127.0.0.1/", "https://localhost/", "file:///etc/passwd", "https://[::1]/", "gopher://x"} {
		if _, err := CheckURL(bad, false, false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := CheckURL("http://192.168.1.1/sub", true, true); err != nil {
		t.Fatal(err)
	}
}

func TestDirectClientRefusesPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	c := NewClient(Options{AllowHTTP: true})
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("private destination reached")
	}
	c = NewClient(Options{AllowHTTP: true, AllowPrivate: true})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Redirects to private targets are refused even when the first hop is public-looking.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
	}))
	defer redir.Close()
	c = NewClient(Options{AllowHTTP: true, AllowPrivate: false})
	if _, err := c.Get(redir.URL); err == nil {
		t.Fatal("redirect followed")
	}
	if RootCAs() == nil {
		t.Fatal("no roots")
	}
}

func TestProxyPinsPublicAddress(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != "1.1.1.1:80" || request.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			t.Errorf("unexpected CONNECT request: method=%s host=%s", request.Method, request.Host)
			writer.WriteHeader(407)
			return
		}
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
		forwarded, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			t.Error(err)
			return
		}
		defer forwarded.Body.Close()
		if forwarded.Host != "review.example" {
			t.Error("original HTTP host was not preserved", forwarded.Host)
		}
		io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}))
	defer proxy.Close()
	address, _ := url.Parse(proxy.URL)
	address.User = url.UserPassword("user", "pass")
	client := newClient(Options{Proxy: address, AllowHTTP: true, Timeout: time.Second}, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	defer client.CloseIdleConnections()
	response, err := client.Get("http://review.example/resource")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	contents, _ := io.ReadAll(response.Body)
	if string(contents) != "ok" {
		t.Fatal("tunneled request failed")
	}
}

func TestProxyRejectsUnsafeResolution(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Error("unsafe target reached the proxy")
		writer.WriteHeader(502)
	}))
	defer proxy.Close()
	address, _ := url.Parse(proxy.URL)
	for _, mode := range []string{"private", "mixed", "unresolved", "empty"} {
		t.Run(mode, func(t *testing.T) {
			client := newClient(Options{Proxy: address, AllowHTTP: true, Timeout: time.Second}, func(context.Context, string, string) ([]netip.Addr, error) {
				switch mode {
				case "private":
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				case "mixed":
					return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, nil
				case "unresolved":
					return nil, errors.New("resolution failed")
				default:
					return nil, nil
				}
			})
			defer client.CloseIdleConnections()
			if response, err := client.Get("http://review.example/sub"); err == nil {
				response.Body.Close()
				t.Fatal("unsafe resolution accepted")
			}
		})
	}
	client := NewClient(Options{Proxy: address, AllowHTTP: true, Timeout: time.Second})
	if response, err := client.Get(proxy.URL); err == nil {
		response.Body.Close()
		t.Fatal("literal private address accepted")
	} else if !strings.Contains(err.Error(), ErrNotPublic.Error()) {
		t.Fatal("unexpected policy error", err)
	}
}
