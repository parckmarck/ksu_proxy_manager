package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/netx"
)

func TestAndroidAuditProxiedDNSIsolated(t *testing.T) {
	deviceOnly(t)
	for _, engineName := range []string{config.EngineMihomo, config.EngineSingBox} {
		t.Run(engineName, func(t *testing.T) {
			e := deviceCore(t, engineName)
			var mode, queries, downloads atomic.Int32
			mode.Store(4)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Host {
				case "cloudflare-dns.com", "dns.google":
					if r.Header.Get("Accept") != "application/dns-json" || r.URL.Query().Get("name") != "audit-download.example" {
						t.Error("incorrect DoH request through the core")
					}
					queries.Add(1)
					answers := []map[string]any{}
					if r.URL.Query().Get("type") == "A" && mode.Load() != 6 {
						answers = append(answers, map[string]any{"type": 1, "data": "93.184.215.14"})
						if mode.Load() < 0 {
							answers = append(answers, map[string]any{"type": 1, "data": "127.0.0.1"})
						}
					}
					if r.URL.Query().Get("type") == "AAAA" && mode.Load() == 6 {
						answers = append(answers, map[string]any{"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"})
					}
					w.Header().Set("Content-Type", "application/dns-json")
					_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": answers})
				case "audit-download.example":
					downloads.Add(1)
					fmt.Fprint(w, "audit download through the real core")
				default:
					t.Errorf("unexpected TLS host: %s", r.Host)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			origin.TLS = &tls.Config{Certificates: []tls.Certificate{auditDNSCertificate(t)}, MinVersion: tls.VersionTLS12}
			origin.StartTLS()
			defer origin.Close()

			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host, port, err := net.SplitHostPort(r.Host)
				address, parseErr := netip.ParseAddr(host)
				if r.Method != http.MethodConnect || err != nil || parseErr != nil || port != "443" || !netx.PublicAddr(address) {
					t.Errorf("core received an unpinned or private CONNECT destination: %s", r.Host)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				upstream, err := net.DialTimeout("tcp", origin.Listener.Addr().String(), 3*time.Second)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer upstream.Close()
				downstream, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer downstream.Close()
				fmt.Fprint(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, downstream)
					upstream.Close()
					close(done)
				}()
				_, _ = io.Copy(downstream, upstream)
				downstream.Close()
				<-done
			}))
			defer relay.Close()
			relayURL, _ := url.Parse(relay.URL)
			port, _ := strconv.Atoi(relayURL.Port())
			_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
				c.Nodes = []config.Node{{ID: "audit-doh-relay", Name: "Audit relay", Type: "http", Server: relayURL.Hostname(), Port: port}}
				c.Groups = []config.Group{{ID: "audit-doh", Name: "Audit DNS", Type: "select", Nodes: []string{"audit-doh-relay"}}}
				c.Routing.Final = "group:audit-doh"
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			e.mustOK("POST", "/api/v1/core/start", nil, nil)
			for _, family := range []int32{4, 6, -1} {
				mode.Store(family)
				before := downloads.Load()
				client := netx.NewClient(netx.Options{Proxy: e.d.engine.ProxyURL(), DNS: []string{"127.0.0.1"}, Timeout: 10 * time.Second})
				request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://audit-download.example/payload", nil)
				response, err := client.Do(request)
				if family < 0 {
					if response != nil {
						response.Body.Close()
					}
					client.CloseIdleConnections()
					if !errors.Is(err, netx.ErrNotPublic) || downloads.Load() != before {
						t.Fatalf("mixed private DNS answer crossed the real core: err=%v downloads=%d", err, downloads.Load()-before)
					}
					continue
				}
				if err != nil {
					client.CloseIdleConnections()
					t.Fatal("DoH/pinned download with broken local DNS failed", err)
				}
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				client.CloseIdleConnections()
				if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "audit download through the real core" {
					t.Fatal("real-core download payload mismatch", readErr)
				}
			}
			if queries.Load() != 6 || downloads.Load() != 2 {
				t.Fatalf("unexpected exchanges: DoH=%d downloads=%d", queries.Load(), downloads.Load())
			}
			t.Log("PASS: real core carried verified TLS DoH and IPv4/IPv6 pinned downloads with broken local DNS; mixed-private answers never reached the target")
		})
	}
}

func auditDNSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		DNSNames:     []string{"cloudflare-dns.com", "dns.google", "audit-download.example"},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// This root exists only in the isolated test process, never on the device.
	netx.RootCAs().AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
