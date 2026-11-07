package daemon

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/netx"
)

// These checks also compile against the preserved original source, so the
// same Android workload can demonstrate the before/after behavior.
func TestAndroidAuditRetryAfterFailedRestart(t *testing.T) {
	e := deviceCore(t, config.EngineMihomo)
	_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.AutoRestart = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	running := e.waitState(engine.StateRunning, 30*time.Second)
	cfg, _ := e.d.store.Snapshot()
	installation, err := e.d.cores.Resolve(config.EngineMihomo, cfg.Settings.CoreVersions[config.EngineMihomo], e.d.abi)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := e.d.cores.Verify(installation)
	if err != nil {
		t.Fatal(err)
	}
	hidden := binary + ".audit-hidden"
	if err := os.Rename(binary, hidden); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if fsutil.Exists(hidden) {
			_ = os.Rename(hidden, binary)
		}
	})
	if err := syscall.Kill(running.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		state := e.status()
		if state.Restarts >= 2 || state.Restarts == 1 && state.State == engine.StateFailed {
			t.Logf("first restart rejected missing core: state=%s attempts=%d", state.State, state.Restarts)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first restart failure was not observed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := os.Rename(hidden, binary); err != nil {
		t.Fatal(err)
	}
	recovered := e.waitState(engine.StateRunning, 12*time.Second)
	if recovered.PID == running.PID || recovered.Restarts < 2 {
		t.Fatalf("did not recover through a later retry: %+v", recovered)
	}
	t.Logf("PASS: failed first attempt recovered automatically, attempts=%d", recovered.Restarts)
	if err := syscall.Kill(recovered.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	e.waitState(engine.StateRestarting, 5*time.Second)
	e.mustOK("POST", "/api/v1/core/stop", nil, nil)
	time.Sleep(3 * time.Second)
	if status := e.status(); status.State != engine.StateStopped || status.PID != 0 {
		t.Fatalf("retry overrode explicit stop: %+v", status)
	}
	t.Log("PASS: user stop cancels a queued automatic retry")
}

func TestAndroidAuditAutoStartRetries(t *testing.T) {
	e := deviceCore(t, config.EngineMihomo)
	cfg, _ := e.d.store.Snapshot()
	installation, err := e.d.cores.Resolve(config.EngineMihomo, cfg.Settings.CoreVersions[config.EngineMihomo], e.d.abi)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := e.d.cores.Verify(installation)
	if err != nil {
		t.Fatal(err)
	}
	hidden := binary + ".audit-boot-hidden"
	if err := os.Rename(binary, hidden); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if fsutil.Exists(hidden) {
			_ = os.Rename(hidden, binary)
		}
	})
	if _, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.AutoStart = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.d.engine.AutoStart()
	e.waitState(engine.StateRestarting, 3*time.Second)
	if err := os.Rename(hidden, binary); err != nil {
		t.Fatal(err)
	}
	e.waitState(engine.StateRunning, 8*time.Second)
	t.Log("PASS: automatic startup recovered after the initially missing core became available")
}

func TestAndroidAuditForeignActionRuleSurvives(t *testing.T) {
	e := deviceCore(t, config.EngineMihomo)
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	rule := netlink.NewRule()
	rule.Family, rule.Priority, rule.Type = netlink.FAMILY_V4, 20265, unix.FR_ACT_UNREACHABLE
	rule.UIDRange = netlink.NewRuleUIDRange(65000, 65000)
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RuleDel(rule) })
	present := func() bool {
		t.Helper()
		rules, err := netlink.RuleList(netlink.FAMILY_V4)
		if err != nil {
			t.Fatal(err)
		}
		for _, got := range rules {
			// The vendored netlink RuleList does not populate Type.
			if got.Priority == rule.Priority && got.Table == 0 && got.UIDRange != nil && *got.UIDRange == *rule.UIDRange {
				return true
			}
		}
		return false
	}
	if !present() {
		t.Fatal("foreign action-only rule was not observable immediately after creation")
	}
	time.Sleep(2 * time.Second)
	if present() {
		t.Log("PASS: foreign unreachable rule at priority 20265 survived reconciliation")
		return
	}
	t.Fatal("module removed a foreign action-only policy rule")
}

func TestAndroidAuditRecoveryInstallsBlockingPlan(t *testing.T) {
	e := deviceCore(t, config.EngineMihomo)
	_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.AutoStart = true
		c.Settings.FailClosed = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.d.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		defaults := 0
		for _, route := range tableRoutes(t, family) {
			if route.Type == unix.RTN_UNREACHABLE && (route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0") {
				defaults++
			}
		}
		if defaults != 2 {
			t.Fatalf("family %d has %d blocking defaults during recovery, want 2", family, defaults)
		}
	}
	t.Log("PASS: recovery retains dual-stack blocking rules before core startup")
}

func TestAndroidAuditFakeIPv6OverridesLANBypass(t *testing.T) {
	e := deviceCore(t, config.EngineSingBox)
	_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.BypassLAN = true
		c.DNS.Mode = "fakeip"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	target := netip.MustParseAddr("fc00::1234")
	best := -1
	var selected netlink.Route
	for _, route := range tableRoutes(t, netlink.FAMILY_V6) {
		if route.Table != capture.Table || route.Dst == nil || !route.Dst.Contains(net.IP(target.AsSlice())) {
			continue
		}
		ones, _ := route.Dst.Mask.Size()
		if ones > best {
			best, selected = ones, route
		}
	}
	if best < 18 || selected.LinkIndex == 0 || selected.Type == unix.RTN_THROW {
		t.Fatalf("fake IPv6 followed LAN bypass: %v", selected)
	}
	t.Logf("PASS: fake-ip wins longest-prefix selection over ULA throw: %v", selected)
}

func TestAndroidAuditProtectedUIDs(t *testing.T) {
	e := deviceCore(t, config.EngineMihomo)
	contents := "com.android.settings 1000 0 /test\ncom.android.captiveportallogin 19990 0 /test\ncom.audit.normal 19991 0 /test\n"
	if err := os.WriteFile(e.d.apps.PackagesList, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Apps = config.AppPolicy{Mode: "include", Users: []int{0}, Packages: []string{"com.android.settings", "com.android.captiveportallogin", "com.audit.normal"}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	for _, rule := range ownedRules(t) {
		if rule.UIDRange == nil {
			continue
		}
		for _, uid := range []uint32{1000, 19990, 29990} {
			if uid >= rule.UIDRange.Start && uid <= rule.UIDRange.End {
				t.Fatalf("protected UID %d remained in an actual kernel rule: %v", uid, rule)
			}
		}
	}
	plan := e.d.engine.Status().Capture
	if plan.Rules == 0 {
		t.Fatal("normal test app was also excluded")
	}
	t.Log("PASS: synthetic system/portal/shared-sandbox UIDs excluded from actual Android UID and DNS rules")
}

func TestAndroidAuditUIReadDoesNotConsumeUIDChange(t *testing.T) {
	e := deviceCore(t, config.EngineMihomo)
	if err := os.WriteFile(e.d.apps.PackagesList, []byte("com.audit.reinstalled 19991 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Apps = config.AppPolicy{Mode: "include", Users: []int{0}, Packages: []string{"com.audit.reinstalled"}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	if err := os.WriteFile(e.d.apps.PackagesList, []byte("com.audit.reinstalled 19992 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustOK("GET", "/api/v1/apps", nil, nil)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		found, stale := false, false
		for _, rule := range ownedRules(t) {
			if rule.UIDRange != nil && rule.Table == capture.Table {
				found = found || rule.UIDRange.Start == 19992
				stale = stale || rule.UIDRange.Start == 19991
			}
		}
		if found && !stale {
			t.Log("PASS: UID rules updated after the applications UI consumed the list cache")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("UI list refresh hid the package UID change from the engine")
}

func TestAndroidAuditProxiedDNSWithBrokenLocalResolver(t *testing.T) {
	if os.Getenv("KPM_TEST_INTERNET") != "1" {
		t.Skip("set KPM_TEST_INTERNET=1 for the external DoH network check")
	}
	e := deviceCore(t, config.EngineMihomo)
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	client := netx.NewClient(netx.Options{Proxy: e.d.engine.ProxyURL(), DNS: []string{"127.0.0.1"}, Timeout: 25 * time.Second})
	defer client.CloseIdleConnections()
	response, err := client.Get("https://example.com")
	if err != nil {
		t.Fatal("proxied download with intentionally broken local DNS failed", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("external download status", response.StatusCode)
	}
	t.Log("PASS: authenticated core download succeeded without a working local DNS resolver")
}

func TestAndroidAuditSnapshotState(t *testing.T) {
	deviceOnly(t)
	e := newEnv(t, false, nil)
	path := filepath.Join(e.layout.DataDir, "audit-state")
	if err := os.WriteFile(path, []byte(strings.Repeat("audit", 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := apps.NewSource().List(context.Background())
	if err != nil || len(list) == 0 {
		t.Fatal("real Android package database is unavailable", err)
	}
	t.Logf("PASS: isolated data path, package database readable (%d entries)", len(list))
}
