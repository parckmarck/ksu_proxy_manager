package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/proc"
)

const loadBalanceGroupID = "balance"

// TestLoadBalanceCoreRouting exercises rendered groups through the real Mihomo
// mixed inbound. Every destination is numeric TEST-NET and both HTTP/CONNECT
// outbounds terminate in the local fallback fixture; no public server is used.
func TestLoadBalanceCoreRouting(t *testing.T) {
	if proc.IsAndroid() {
		deviceOnly(t)
		runLoadBalanceCoreRouting(t, true)
		return
	}
	if runtime.GOOS != "linux" || os.Getenv("KPM_TEST_CORES") == "" {
		t.Skip("requires Linux network namespaces and KPM_TEST_CORES")
	}
	if !inNetns(t) {
		return
	}
	runLoadBalanceCoreRouting(t, false)
}

func TestAndroidLoadBalanceCoreRouting(t *testing.T) {
	deviceOnly(t)
	runLoadBalanceCoreRouting(t, true)
}

func runLoadBalanceCoreRouting(t *testing.T, device bool) {
	t.Helper()
	for _, tc := range []struct {
		name     string
		strategy string
	}{
		{"round-robin", "round-robin"},
		{"consistent-hashing", "consistent-hashing"},
		{"default-consistent-hashing", ""},
		{"sticky-sessions", "sticky-sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := newFallbackHTTPProxy(t, "first", 10*time.Millisecond)
			second := newFallbackHTTPProxy(t, "second", 10*time.Millisecond)
			e := fallbackCoreEnv(t, config.EngineMihomo, device)
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
				group := config.Group{ID: loadBalanceGroupID, Name: "负载均衡测试", Type: "load-balance", Nodes: []string{"first", "second"}, TestURL: fallbackHealthURL, IntervalSec: 30}
				// Decode the public schema so this test reaches validation even
				// before the new strategy field exists (the intended RED case).
				patch, err := json.Marshal(map[string]string{"strategy": tc.strategy})
				if err != nil {
					return err
				}
				if err := json.Unmarshal(patch, &group); err != nil {
					return err
				}
				c.Groups = []config.Group{group}
				c.Routing = config.Routing{Mode: "rule", Preset: "custom", Final: config.GroupRef(loadBalanceGroupID)}
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
			identity, err := proc.Capture(status.PID)
			if err != nil {
				t.Fatal(err)
			}
			api, output, err := e.d.engine.API()
			if err != nil {
				t.Fatal(err)
			}
			groupTag := output.TagOf[config.GroupRef(loadBalanceGroupID)]
			firstTag, secondTag := output.TagOf[config.NodeRef("first")], output.TagOf[config.NodeRef("second")]
			if groupTag == "" || firstTag == "" || secondTag == "" {
				t.Fatal("core outbound mappings missing")
			}
			proxies, err := api.Proxies(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			group := proxies[groupTag]
			if !strings.EqualFold(group.Type, "LoadBalance") || len(group.All) != 2 || group.All[0] != firstTag || group.All[1] != secondTag {
				t.Fatalf("unexpected live core group: %+v, want LoadBalance members=[%s %s]", group, firstTag, secondTag)
			}
			for _, tag := range []string{firstTag, secondTag} {
				if _, err := api.Delay(context.Background(), tag, fallbackHealthURL, 3000); err != nil {
					t.Fatalf("local fixture health check %q: %v", tag, err)
				}
			}
			// Both the daemon and the live core must treat this as automatic.
			if err := api.Select(context.Background(), groupTag, firstTag); err == nil {
				t.Fatal("live LoadBalance group accepted manual selection")
			}
			var rejected json.RawMessage
			if code := e.call(http.MethodPost, "/api/v1/groups/"+loadBalanceGroupID+"/select", map[string]string{"member": config.NodeRef("first")}, &rejected); code != http.StatusBadRequest {
				t.Fatalf("automatic group selection: HTTP %d %s", code, rejected)
			}
			var view struct {
				Running bool             `json:"running"`
				Groups  []proxyGroupView `json:"groups"`
			}
			e.mustOK(http.MethodGet, "/api/v1/proxies", nil, &view)
			if !view.Running || len(view.Groups) != 1 || view.Groups[0].ID != loadBalanceGroupID || view.Groups[0].Type != "load-balance" || view.Groups[0].Selected != "" || view.Groups[0].Now != "" || len(view.Groups[0].Members) != 2 {
				t.Fatalf("automatic group API state: %+v", view)
			}
			proxyURL := e.d.engine.ProxyURL()
			if proxyURL == nil {
				t.Fatal("running core has no authenticated mixed proxy")
			}
			// Keep-alive is disabled and the fixture closes every response,
			// so all six probes cause independent outbound selections.
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			markers := make([]string, 0, 6)
			counts := map[string]int{}
			for i := 0; i < 6; i++ {
				marker, err := fallbackRequest(client)
				if err != nil || (marker != "first" && marker != "second") {
					t.Fatalf("new connection %d: marker=%q error=%v", i+1, marker, err)
				}
				markers = append(markers, marker)
				counts[marker]++
			}
			if tc.strategy == "round-robin" {
				if counts["first"] != 3 || counts["second"] != 3 {
					t.Fatalf("round-robin must distribute six new connections equally: %v", markers)
				}
			} else if counts[markers[0]] != 6 {
				t.Fatalf("%s must keep the same target on one healthy outbound: %v", tc.name, markers)
			}
			if first.health.Load() == 0 || second.health.Load() == 0 || first.probes.Load() != int64(counts["first"]) || second.probes.Load() != int64(counts["second"]) {
				t.Fatalf("missing fixture evidence: health=%d/%d probes=%d/%d markers=%v", first.health.Load(), second.health.Load(), first.probes.Load(), second.probes.Load(), markers)
			}
			if first.unexpected.Load()+second.unexpected.Load() != 0 {
				t.Fatal("core attempted a destination outside the local fixture protocol")
			}
			if tc.strategy == "round-robin" {
				// A saved type change is pending until apply. The still-running
				// selector must not lend its fixed Now to the new balance view.
				_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
					c.Groups[0].Type, c.Groups[0].Selected = "select", config.NodeRef("first")
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				e.mustOK(http.MethodPost, "/api/v1/core/restart", nil, nil)
				e.waitState(engine.StateRunning, 30*time.Second)
				// Capture the replacement identity for the final stop check.
				identity, err = proc.Capture(e.d.engine.Status().PID)
				if err != nil {
					t.Fatal(err)
				}
				e.mustOK(http.MethodGet, "/api/v1/proxies", nil, &view)
				if view.Groups[0].Now != config.NodeRef("first") {
					t.Fatal("selector precondition missing", view)
				}
				_, err = e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
					c.Groups[0].Type = "load-balance"
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				e.mustOK(http.MethodGet, "/api/v1/proxies", nil, &view)
				if view.Groups[0].Now != "" || view.Groups[0].Selected != "" {
					t.Fatal("pending balance view inherited selector exit", view)
				}
			}
			e.mustOK(http.MethodPost, "/api/v1/core/stop", nil, nil)
			e.waitState(engine.StateStopped, 10*time.Second)
			if identity.Alive() {
				t.Fatal("load-balance core survived stop")
			}
			if rules := ownedRules(t); len(rules) != 0 {
				t.Fatalf("capture rules left after load-balance stop: %v", rules)
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				if routes := tableRoutes(t, family); len(routes) != 0 {
					t.Fatalf("capture routes left after load-balance stop: %v", routes)
				}
			}
			t.Logf("PASS: Mihomo %s routed six new connections %v; automatic selection and stop cleanup verified", tc.name, markers)
		})
	}
}
