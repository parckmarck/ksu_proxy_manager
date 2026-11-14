package daemon

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/proc"
)

// Both entry points use the real authenticated mixed inbound. Binding its
// client connections to two loopback source addresses exercises source matching
// without changing TUN capture or contacting a public destination or resolver.
func TestSourceIPCoreRouting(t *testing.T) {
	if proc.IsAndroid() {
		deviceOnly(t)
		runSourceIPCoreRouting(t, true)
		return
	}
	if runtime.GOOS != "linux" || os.Getenv("KPM_TEST_CORES") == "" {
		t.Skip("requires Linux network namespaces and KPM_TEST_CORES")
	}
	if !inNetns(t) {
		return
	}
	runSourceIPCoreRouting(t, false)
}

func TestAndroidSourceIPCoreRouting(t *testing.T) {
	deviceOnly(t)
	runSourceIPCoreRouting(t, true)
}

func runSourceIPCoreRouting(t *testing.T, device bool) {
	t.Helper()
	for _, engineName := range []string{config.EngineMihomo, config.EngineSingBox} {
		t.Run(engineName, func(t *testing.T) {
			first := newFallbackHTTPProxy(t, "first", 0)
			second := newFallbackHTTPProxy(t, "second", 0)
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
				c.Groups = []config.Group{
					{ID: "first-route", Name: "first", Type: "select", Nodes: []string{"first"}, Selected: config.NodeRef("first")},
					{ID: "second-route", Name: "second", Type: "select", Nodes: []string{"second"}, Selected: config.NodeRef("second")},
				}
				c.Routing = config.Routing{Mode: "rule", Preset: "custom", Final: config.GroupRef("second-route")}
				c.DNS.Mode = "realip"
				c.DNS.Direct = []string{"udp://127.0.0.1:9"}
				c.DNS.Proxy = []string{"udp://127.0.0.1:9"}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			source := config.Rule{ID: "source", Enabled: true, Type: "source_ip_cidr", Values: []string{"192.0.2.0/24", "127.0.0.0/31"}, Target: config.GroupRef("first-route")}
			later := config.Rule{ID: "later", Enabled: true, Type: "network", Values: []string{"tcp"}, Target: config.GroupRef("second-route")}
			bareIPs := source
			bareIPs.Values = []string{"127.0.0.1", "127.0.0.2"}
			disabled := source
			disabled.Enabled = false
			reject := source
			reject.Target = config.TargetReject
			for _, tc := range []struct {
				name  string
				rules []config.Rule
				want  [2]string // 127.0.0.1, 127.0.0.2; empty means rejected
			}{
				{"cidr-and-later-rule", []config.Rule{source, later}, [2]string{"first", "second"}},
				{"bare-ip-values-are-or", []config.Rule{bareIPs, later}, [2]string{"first", "first"}},
				{"earlier-rule-wins", []config.Rule{later, source}, [2]string{"second", "second"}},
				{"disabled-source-rule", []config.Rule{disabled, later}, [2]string{"second", "second"}},
				{"source-reject", []config.Rule{reject, later}, [2]string{"", "second"}},
			} {
				t.Logf("applying %s", tc.name)
				// Routing must pass the public API's validation, and saving it
				// does not apply it. Start explicitly renders the saved revision.
				routing := config.Routing{Mode: "rule", Preset: "custom", Final: config.TargetReject, Rules: tc.rules}
				e.mustOK(http.MethodPut, "/api/v1/routing", routing, nil)
				e.mustOK(http.MethodPost, "/api/v1/core/start", nil, nil)
				status := e.waitState(engine.StateRunning, 30*time.Second)
				if status.Pending {
					t.Fatalf("%s routing revision was not applied", tc.name)
				}
				identity, err := proc.Capture(status.PID)
				if err != nil {
					t.Fatal(err)
				}
				before := [2]int64{first.probes.Load(), second.probes.Load()}
				wantProbes := before
				for i, sourceIP := range []string{"127.0.0.1", "127.0.0.2"} {
					client := sourceIPClient(t, e, sourceIP)
					marker, err := fallbackRequest(client)
					client.CloseIdleConnections()
					if tc.want[i] == "" {
						if err == nil {
							t.Fatalf("%s source=%s must reject, got marker=%q", tc.name, sourceIP, marker)
						}
					} else {
						if err != nil || marker != tc.want[i] {
							t.Fatalf("%s source=%s: marker=%q error=%v, want %q", tc.name, sourceIP, marker, err, tc.want[i])
						}
						if marker == "first" {
							wantProbes[0]++
						} else {
							wantProbes[1]++
						}
					}
				}
				if got := [2]int64{first.probes.Load(), second.probes.Load()}; got != wantProbes {
					t.Fatalf("%s local outbound probes=%v, want %v (before=%v)", tc.name, got, wantProbes, before)
				}
				if first.unexpected.Load()+second.unexpected.Load() != 0 {
					t.Fatal("core attempted a destination outside the local fixture protocol")
				}
				e.mustOK(http.MethodPost, "/api/v1/core/stop", nil, nil)
				e.waitState(engine.StateStopped, 10*time.Second)
				assertFallbackStopped(t, identity)
				t.Logf("PASS: %s %s source markers=%v; stop cleanup verified", engineName, tc.name, tc.want)
			}
		})
	}
}

func sourceIPClient(t *testing.T, e *testEnv, source string) *http.Client {
	t.Helper()
	proxyURL := e.d.engine.ProxyURL()
	if proxyURL == nil {
		t.Fatal("running core has no authenticated mixed proxy")
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: dialer.DialContext, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func assertFallbackStopped(t *testing.T, identity proc.Identity) {
	t.Helper()
	if identity.Alive() {
		t.Fatal("source-IP core survived stop")
	}
	if rules := ownedRules(t); len(rules) != 0 {
		t.Fatalf("capture rules left after source-IP stop: %v", rules)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if routes := tableRoutes(t, family); len(routes) != 0 {
			t.Fatalf("capture routes left after source-IP stop: %v", routes)
		}
	}
}
