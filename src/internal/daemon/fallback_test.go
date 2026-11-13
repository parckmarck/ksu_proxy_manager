package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ksu_proxy_manager/internal/clashapi"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/proc"
)

const (
	fallbackHealthURL = "http://198.51.100.77/health"
	fallbackProbeURL  = "http://198.51.100.77/probe"
	fallbackGroupID   = "failover"
)

// fallbackHTTPProxy terminates HTTP proxy requests locally, including the
// CONNECT tunnel used by both real cores' HTTP outbounds. It never dials the
// requested destination. TEST-NET-2 avoids the renderer's private-IP DIRECT
// rules without requiring a public server or even a working default route.
type fallbackHTTPProxy struct {
	server     *httptest.Server
	name       string
	delay      time.Duration
	alive      atomic.Bool
	health     atomic.Int64
	probes     atomic.Int64
	rejected   atomic.Int64
	unexpected atomic.Int64
}

func newFallbackHTTPProxy(t *testing.T, name string, delay time.Duration) *fallbackHTTPProxy {
	t.Helper()
	p := &fallbackHTTPProxy{name: name, delay: delay}
	p.alive.Store(true)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always hijack so an unavailable proxy closes the connection before
		// CONNECT succeeds, rather than returning an HTTP health-check error.
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if !p.alive.Load() {
			p.rejected.Add(1)
			return
		}
		if r.Method == http.MethodConnect {
			if r.Host != "198.51.100.77:80" {
				p.unexpected.Add(1)
				return
			}
			if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			if err := buffered.Flush(); err != nil {
				return
			}
			r, err = http.ReadRequest(buffered.Reader)
			if err != nil {
				return
			}
		}
		defer r.Body.Close()
		if r.Host != "198.51.100.77" && r.Host != "198.51.100.77:80" {
			p.unexpected.Add(1)
			return
		}
		status, body := http.StatusOK, p.name
		switch r.URL.Path {
		case "/health":
			p.health.Add(1)
			time.Sleep(p.delay)
			status, body = http.StatusNoContent, ""
		case "/probe":
			p.probes.Add(1)
		default:
			p.unexpected.Add(1)
			return
		}
		// An in-flight check must not revive first after the failure switch.
		if !p.alive.Load() {
			p.rejected.Add(1)
			return
		}
		response := &http.Response{
			StatusCode: status,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Connection":   {"close"},
				"Content-Type": {"text/plain"},
			},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Close:         true,
			Request:       r,
		}
		_ = response.Write(conn)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *fallbackHTTPProxy) node(t *testing.T) config.Node {
	t.Helper()
	u, err := url.Parse(p.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portString, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	return config.Node{ID: p.name, Name: p.name, Type: "http", Server: host, Port: port}
}

// TestFallbackCoreRouting runs only with explicit real-core fixtures. Android
// uses the same device reservation guard as the dedicated Android entry point;
// it must never fall through to Linux's user/network-namespace runner.
func TestFallbackCoreRouting(t *testing.T) {
	if proc.IsAndroid() {
		deviceOnly(t)
		runFallbackCoreRouting(t, true)
		return
	}
	if runtime.GOOS != "linux" || os.Getenv("KPM_TEST_CORES") == "" {
		t.Skip("requires Linux network namespaces and KPM_TEST_CORES")
	}
	if !inNetns(t) {
		return
	}
	runFallbackCoreRouting(t, false)
}

func TestAndroidFallbackCoreRouting(t *testing.T) {
	deviceOnly(t)
	runFallbackCoreRouting(t, true)
}

func fallbackCoreEnv(t *testing.T, engineName string, device bool) *testEnv {
	t.Helper()
	if device {
		return deviceCore(t, engineName)
	}
	e := newEnv(t, true, nil)
	bin := filepath.Join(os.Getenv("KPM_TEST_CORES"), engineName)
	info, err := e.d.installCandidate(context.Background(), bin, t.TempDir(), engineName, cores.Installation{Source: "fallback-test", Verification: "local-unverified"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.d.apps.PackagesList, []byte("com.test.root 0 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.Engine = engineName
		c.Settings.CoreVersions[engineName] = info.Version
		c.Apps = config.AppPolicy{Mode: "include", Packages: []string{"com.test.root"}, Users: []int{0}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func runFallbackCoreRouting(t *testing.T, device bool) {
	t.Helper()
	for _, engineName := range []string{config.EngineMihomo, config.EngineSingBox} {
		t.Run(engineName, func(t *testing.T) {
			firstDelay, secondDelay := 250*time.Millisecond, 20*time.Millisecond
			if engineName == config.EngineSingBox {
				// Start with first selected even after the compatibility URLTest
				// finishes, so disabling it proves an actual replacement.
				firstDelay, secondDelay = secondDelay, firstDelay
			}
			first := newFallbackHTTPProxy(t, "first", firstDelay)
			second := newFallbackHTTPProxy(t, "second", secondDelay)
			e := fallbackCoreEnv(t, engineName, device)
			t.Cleanup(func() {
				if t.Failed() {
					for _, path := range []string{e.layout.DaemonLog(), e.layout.CoreLog()} {
						data, _ := os.ReadFile(path)
						t.Logf("%s:\n%s", filepath.Base(path), data)
					}
				}
			})
			_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
				c.Settings.AutoStart = false
				c.Settings.AutoRestart = false
				c.Settings.RulesetAutoUpdate = false
				c.Nodes = []config.Node{first.node(t), second.node(t)}
				c.Groups = []config.Group{{ID: fallbackGroupID, Name: "故障转移测试", Type: "fallback", Nodes: []string{"first", "second"}, TestURL: fallbackHealthURL, IntervalSec: 30, ToleranceMs: 1}}
				c.Routing = config.Routing{Mode: "rule", Preset: "custom", Final: config.GroupRef(fallbackGroupID)}
				// All test destinations are numeric. Even an accidental DNS
				// lookup is confined to loopback rather than a public resolver.
				c.DNS.Mode = "realip"
				c.DNS.Direct = []string{"udp://127.0.0.1:9"}
				c.DNS.Proxy = []string{"udp://127.0.0.1:9"}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			e.mustOK(http.MethodPost, "/api/v1/core/start", nil, nil)
			status := e.waitState(engine.StateRunning, 30*time.Second)
			if engineName == config.EngineSingBox {
				warnings := strings.Join(status.Warnings, "\n")
				if !strings.Contains(warnings, "故障转移") || !strings.Contains(warnings, "urltest") {
					t.Fatalf("running status must expose the fallback downgrade warning: %q", warnings)
				}
			}
			api, output, err := e.d.engine.API()
			if err != nil {
				t.Fatal(err)
			}
			groupTag := output.TagOf[config.GroupRef(fallbackGroupID)]
			firstTag, secondTag := output.TagOf[config.NodeRef("first")], output.TagOf[config.NodeRef("second")]
			if groupTag == "" || firstTag == "" || secondTag == "" {
				t.Fatal("core outbound mappings missing")
			}
			if engineName == config.EngineMihomo {
				firstMS, err := api.Delay(context.Background(), firstTag, fallbackHealthURL, 3000)
				if err != nil {
					t.Fatal("first health check", err)
				}
				secondMS, err := api.Delay(context.Background(), secondTag, fallbackHealthURL, 3000)
				if err != nil || firstMS <= secondMS {
					t.Fatalf("fixture must measure first slower: first=%dms second=%dms error=%v", firstMS, secondMS, err)
				}
			} else {
				fallbackSingBoxHealth(t, api, groupTag)
			}
			fallbackWaitSelection(t, api, groupTag, firstTag, firstTag, secondTag, engineName)
			proxyURL := e.d.engine.ProxyURL()
			if proxyURL == nil {
				t.Fatal("running core has no authenticated mixed proxy")
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			if marker, err := fallbackRequest(client); err != nil || marker != "first" {
				t.Fatalf("initial request: marker=%q error=%v", marker, err)
			}
			first.alive.Store(false)
			if engineName == config.EngineMihomo {
				// Mihomo stores health per exact URL; the group's URL must be
				// used here, not the application's default delay-test URL.
				if _, err := api.Delay(context.Background(), firstTag, fallbackHealthURL, 3000); err == nil {
					t.Fatal("unavailable first proxy passed the core health check")
				}
				if _, err := api.Delay(context.Background(), secondTag, fallbackHealthURL, 3000); err != nil {
					t.Fatal("second proxy must remain healthy", err)
				}
			} else {
				// A failed real CONNECT invalidates sing-box's cached first
				// history. The group URLTest API then checks it immediately,
				// avoiding the 30-second cache window for successful checks.
				if marker, err := fallbackRequest(client); err == nil {
					t.Fatalf("failed first proxy unexpectedly served %q", marker)
				}
				fallbackSingBoxHealth(t, api, groupTag)
			}
			fallbackWaitSelection(t, api, groupTag, secondTag, firstTag, secondTag, engineName)
			for i := 0; i < 3; i++ {
				if marker, err := fallbackRequest(client); err != nil || marker != "second" {
					t.Fatalf("new connection %d after failure: marker=%q error=%v", i+1, marker, err)
				}
			}
			if first.health.Load() == 0 || second.health.Load() == 0 || first.rejected.Load() == 0 || second.probes.Load() < 3 {
				t.Fatalf("missing fixture evidence: health=%d/%d first failures=%d second probes=%d", first.health.Load(), second.health.Load(), first.rejected.Load(), second.probes.Load())
			}
			if first.unexpected.Load()+second.unexpected.Load() != 0 {
				t.Fatal("core attempted a destination outside the local fixture protocol")
			}
			t.Logf("PASS: %s routed first, then second after first failed; health requests=%d/%d", engineName, first.health.Load(), second.health.Load())
		})
	}
}

func fallbackRequest(client *http.Client) (string, error) {
	response, err := client.Get(fallbackProbeURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return string(body), nil
}

func fallbackWaitSelection(t *testing.T, api *clashapi.Client, group, want, first, second, engineName string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last clashapi.Proxy
	var lastErr error
	for time.Now().Before(deadline) {
		proxies, err := api.Proxies(context.Background())
		last, lastErr = proxies[group], err
		if err == nil && last.Now == want {
			wantType := "Fallback"
			if engineName == config.EngineSingBox {
				wantType = "URLTest"
			}
			if !strings.EqualFold(last.Type, wantType) || len(last.All) != 2 || last.All[0] != first || last.All[1] != second {
				t.Fatalf("unexpected live core group: %+v, want type=%s members=[%s %s]", last, wantType, first, second)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("core group did not select %q: last=%+v error=%v", want, last, lastErr)
}

func fallbackSingBoxHealth(t *testing.T, api *clashapi.Client, group string) {
	t.Helper()
	// sing-box's individual /proxies/{name}/delay discards HTTP URLs. Its
	// /group/{name}/delay instead invokes URLTestGroup.URLTest with the group's
	// configured URL, so the test remains entirely local and uses HTTP 204.
	// See experimental/clashapi/api_meta_group.go in sing-box v1.13.21.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, api.Base+"/group/"+url.PathEscape(group)+"/delay?timeout=3000", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+api.Secret)
	response, err := api.HTTP.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var results map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&results); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("sing-box group health API: HTTP %d results=%v error=%v", response.StatusCode, results, err)
	}
}
