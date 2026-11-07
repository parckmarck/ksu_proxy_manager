package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/netx"
	"ksu_proxy_manager/internal/proc"
)

func deviceOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("KPM_DEVICE_TESTS") != "1" || !proc.IsAndroid() || os.Geteuid() != 0 {
		t.Skip("requires an explicitly reserved, rooted Android test device")
	}
	if len(ownedRules(t)) != 0 {
		t.Fatal("stop the installed module before running device tests")
	}
}

func TestAndroidSharedStorage(t *testing.T) {
	deviceOnly(t)
	environment := newEnv(t, false, nil)
	environment.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": "trojan://device-dummy-password@example.com:443#Device"}, nil)
	var exported struct {
		Path string `json:"path"`
	}
	environment.mustOK("POST", "/api/v1/backup/export", map[string]bool{"secrets": true}, &exported)
	t.Cleanup(func() { _ = os.Remove(exported.Path) })
	info, err := os.Stat(exported.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("shared-storage export: bytes=%d mode=%o", info.Size(), info.Mode().Perm())
	environment.mustOK("POST", "/api/v1/backup/restore", map[string]string{"path": exported.Path}, nil)
	link := exported.Path + ".link"
	if err := os.Symlink(exported.Path, link); err != nil {
		t.Logf("shared-storage symlink unsupported: %v", err)
	} else {
		_ = os.Remove(link)
		t.Log("shared-storage symlinks are supported")
	}
}

func deviceCore(t *testing.T, engineName string) *testEnv {
	t.Helper()
	deviceOnly(t)
	bin := filepath.Join(os.Getenv("KPM_TEST_CORES"), engineName)
	if !fsutil.Exists(bin) {
		t.Fatalf("required core fixture missing: %s", bin)
	}
	realApps, err := apps.NewSource().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var app apps.App
	for _, candidate := range realApps {
		if candidate.UID >= apps.FirstAppID && candidate.UID <= apps.LastAppID {
			app = candidate
			break
		}
	}
	if app.Package == "" {
		t.Fatal("no installed application UID available")
	}
	previousTick := testEngineTick
	testEngineTick = 200 * time.Millisecond
	environment := newEnv(t, true, nil)
	testEngineTick = previousTick
	info, err := environment.d.installCandidate(context.Background(), bin, t.TempDir(), engineName, cores.Installation{Source: "device-test", Verification: "local-unverified"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(environment.d.apps.PackagesList, []byte(fmt.Sprintf("%s %d 0 /test\n", app.Package, app.UID)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = environment.d.store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Settings.AutoStart = false
		configuration.Settings.AutoRestart = false
		configuration.Settings.RulesetAutoUpdate = false
		configuration.Settings.Engine = engineName
		configuration.Settings.CoreVersions[engineName] = info.Version
		configuration.Settings.IPv6 = true
		configuration.Settings.FailClosed = true
		configuration.Routing.Preset = "custom"
		configuration.Routing.BlockAds = false
		configuration.Routing.Final = config.TargetDirect
		configuration.DNS.Mode = "realip"
		configuration.Apps = config.AppPolicy{Mode: "include", Packages: []string{app.Package}, Users: []int{0}}
		configuration.Groups = []config.Group{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("device core=%s version=%s test app UID=%d", engineName, info.Version, app.UID)
	return environment
}

func TestAndroidCoreLifecycle(t *testing.T) {
	deviceOnly(t)
	for _, engineName := range []string{config.EngineMihomo, config.EngineSingBox} {
		t.Run(engineName, func(t *testing.T) {
			environment := deviceCore(t, engineName)
			environment.mustOK("POST", "/api/v1/core/start", nil, nil)
			status := environment.waitState(engine.StateRunning, 30*time.Second)
			if status.Capture.DNSPriority != 15900 || !status.Capture.TunPresent {
				t.Fatalf("unexpected Android capture: %+v", status.Capture)
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				if len(tableRoutes(t, family)) == 0 {
					t.Fatal("missing capture routes", family)
				}
			}
			auxiliaryRules := 0
			for _, rule := range ownedRules(t) {
				if rule.Table == capture.CoreTable && rule.OifName == engine.TunName {
					auxiliaryRules++
				}
			}
			if auxiliaryRules != 1 {
				t.Fatal("core auxiliary IPv6 rule was not isolated in its reserved table", auxiliaryRules)
			}
			var identity struct {
				Identity proc.Identity `json:"identity"`
			}
			if err := fsutil.ReadJSON(environment.layout.CoreInfo(), &identity); err != nil {
				t.Fatal(err)
			}
			fixture := filepath.Join(os.Getenv("KPM_TEST_CORES"), engineName)
			if _, err := environment.d.installCandidate(context.Background(), fixture, t.TempDir(), engineName, cores.Installation{Source: "device-reinstall"}); err != nil {
				t.Fatal(err)
			}
			if !identity.Identity.Alive() {
				t.Fatal("same-version reinstall invalidated the running core identity")
			}
			var originRequests atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				originRequests.Add(1)
				fmt.Fprint(writer, "device-ok")
			}))
			defer origin.Close()
			proxyURL := environment.d.engine.ProxyURL()
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			contents, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(contents) != "device-ok" {
				t.Fatal("authenticated proxy request failed")
			}
			withoutCredentials := *proxyURL
			withoutCredentials.User = nil
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(&withoutCredentials)
			client.CloseIdleConnections()
			if response, err := client.Get(origin.URL); err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusProxyAuthRequired {
					t.Fatal("unauthenticated proxy request was not rejected with 407", response.StatusCode)
				}
			} else {
				t.Fatal("unauthenticated request did not reach the live proxy", err)
			}
			wrongCredentials := *proxyURL
			wrongCredentials.User = url.UserPassword("wrong", "wrong")
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(&wrongCredentials)
			client.CloseIdleConnections()
			response, err = client.Get(origin.URL)
			if err != nil {
				t.Fatal("incorrect-credential request did not reach the live proxy", err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusProxyAuthRequired && response.StatusCode != http.StatusForbidden {
				t.Fatal("incorrect proxy credentials were not rejected", response.StatusCode)
			}
			if originRequests.Load() != 1 {
				t.Fatal("an unauthenticated request reached the origin", originRequests.Load())
			}
			listener, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			origin6 := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { fmt.Fprint(writer, "ipv6-ok") }))
			origin6.Listener = listener
			origin6.Start()
			defer origin6.Close()
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
			client.CloseIdleConnections()
			response, err = client.Get(origin6.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("IPv6 proxy request failed", response.StatusCode)
			}
			if err := os.WriteFile(environment.layout.DisableFlag(), []byte("1"), 0o600); err != nil {
				t.Fatal(err)
			}
			environment.waitState(engine.StateDisabled, 10*time.Second)
			if len(ownedRules(t)) != 0 {
				t.Fatal("disable kept capture rules")
			}
			_ = os.Remove(environment.layout.DisableFlag())
			environment.waitState(engine.StateStopped, 10*time.Second)
			t.Log("PASS: UID/DNS routes, IPv4/IPv6 proxy, correct/missing/wrong credentials, reinstall identity, disable and cleanup")
		})
	}
}

func TestAndroidFailClosedEnabledBeforeFailedReapply(t *testing.T) {
	environment := deviceCore(t, config.EngineMihomo)
	_, err := environment.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.FailClosed = false
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	environment.mustOK("POST", "/api/v1/core/start", nil, nil)
	_, err = environment.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.FailClosed = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(environment.d.apps.PackagesList); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := environment.d.engine.Start(context.Background()); err == nil {
		t.Fatal("expected app resolution failure")
	}
	if environment.status().State != engine.StateFailed {
		t.Fatal("failed restart did not enter the failed state")
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		unreachable := 0
		for _, route := range tableRoutes(t, family) {
			if route.Type == syscall.RTN_UNREACHABLE && (route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0") {
				unreachable++
			}
		}
		if unreachable != 2 {
			t.Fatalf("family %d: expected two blocking fallbacks, got %d", family, unreachable)
		}
	}
	t.Log("PASS: enabling fail-closed before a failed restart retains dual-stack unreachable fallbacks")
}

func TestAndroidCoreIdentityWriteFailure(t *testing.T) {
	environment := deviceCore(t, config.EngineMihomo)
	if err := os.Mkdir(environment.layout.CoreInfo(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := environment.d.engine.Start(context.Background()); err == nil {
		t.Fatal("core started without a writable identity record")
	}
	if environment.status().PID != 0 {
		t.Fatal("unrecorded core was left running")
	}
}

func TestAndroidLargeBackupRoundTrip(t *testing.T) {
	deviceOnly(t)
	checkLargeBackupRoundTrip(t)
}

func TestAndroidFailedCaptureReconcile(t *testing.T) {
	deviceOnly(t)
	environment := deviceCore(t, config.EngineMihomo)
	environment.mustOK("POST", "/api/v1/core/start", nil, nil)
	status := environment.waitState(engine.StateRunning, 30*time.Second)
	if err := syscall.Kill(status.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	environment.waitState(engine.StateFailed, 10*time.Second)
	var removed netlink.Rule
	for _, rule := range ownedRules(t) {
		if rule.Table == capture.CoreTable {
			t.Fatal("crashed core left an auxiliary IPv6 rule")
		}
		if rule.Family == netlink.FAMILY_V4 && rule.Table == capture.Table && rule.UIDRange != nil {
			removed = rule
		}
	}
	if removed.UIDRange == nil {
		t.Fatal("no app rule remained after fail-closed crash")
	}
	if err := netlink.RuleDel(&removed); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, rule := range ownedRules(t) {
			if rule.Family == removed.Family && rule.Table == removed.Table && rule.UIDRange != nil && *rule.UIDRange == *removed.UIDRange {
				t.Log("PASS: fail-closed rule healed while the core remained failed")
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("fail-closed app rule did not heal after being removed")
}

func TestAndroidPrivateDNSDiagnostic(t *testing.T) {
	deviceOnly(t)
	previous, err := exec.Command("settings", "get", "global", "private_dns_mode").Output()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		value := strings.TrimSpace(string(previous))
		arguments := []string{"put", "global", "private_dns_mode", value}
		if value == "null" {
			arguments = []string{"delete", "global", "private_dns_mode"}
		}
		_ = exec.Command("settings", arguments...).Run()
	}()
	if err := exec.Command("settings", "put", "global", "private_dns_mode", "hostname").Run(); err != nil {
		t.Fatal(err)
	}
	environment := newEnv(t, false, nil)
	var diagnostic struct {
		Warning bool `json:"privateDnsWarning"`
	}
	environment.mustOK("GET", "/api/v1/diagnostics", nil, &diagnostic)
	if !diagnostic.Warning {
		t.Fatal("strict Private DNS warning missing")
	}
}

func TestAndroidMultiuserAndHotspot(t *testing.T) {
	deviceOnly(t)
	user, err := strconv.Atoi(os.Getenv("KPM_DEVICE_USER"))
	if err != nil || user <= 0 {
		t.Skip("KPM_DEVICE_USER must name a temporary Android profile")
	}
	available := false
	for _, identifier := range apps.NewSource().Users() {
		available = available || identifier == user
	}
	if !available {
		t.Fatal("test profile is not present in Android user directories")
	}
	link := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "kpmap0"}, Mode: netlink.TUNTAP_MODE_TUN, Flags: netlink.TUNTAP_DEFAULTS}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	environment := deviceCore(t, config.EngineMihomo)
	_, err = environment.d.store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Apps.Users = []int{0, user}
		configuration.Settings.Hotspot = config.Hotspot{Enabled: true, Interfaces: []string{"kpmap0"}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	foreign := netlink.NewRule()
	foreign.Family, foreign.Priority, foreign.Table = netlink.FAMILY_V4, 13000, 42317
	foreign.UIDRange = netlink.NewRuleUIDRange(uint32(user*apps.PerUserRange+10041), uint32(user*apps.PerUserRange+10041))
	if err := netlink.RuleAdd(foreign); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RuleDel(foreign) })
	environment.mustOK("POST", "/api/v1/core/start", nil, nil)
	status := environment.waitState(engine.StateRunning, 30*time.Second)
	if status.Capture.DNSPriority <= foreign.Priority {
		t.Fatal("DNS capture precedes the VPN priority band")
	}
	profileRules, hotspotRules := 0, 0
	for _, rule := range ownedRules(t) {
		if rule.UIDRange != nil && int(rule.UIDRange.Start)/apps.PerUserRange == user {
			profileRules++
		}
		if rule.IifName == "kpmap0" {
			hotspotRules++
		}
	}
	if profileRules == 0 || hotspotRules != 2 {
		t.Fatalf("profile rules=%d hotspot IPv4/IPv6 rules=%d", profileRules, hotspotRules)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		if err := exec.Command(binary, "-t", "filter", "-C", "FORWARD", "-j", capture.ForwardChain).Run(); err != nil {
			t.Fatal(binary, "forwarding chain missing", err)
		}
	}
	environment.mustOK("POST", "/api/v1/core/stop", nil, nil)
	for _, binary := range []string{"iptables", "ip6tables"} {
		if err := exec.Command(binary, "-t", "filter", "-L", capture.ForwardChain, "-n").Run(); err == nil {
			t.Fatal(binary, "forwarding chain was not removed")
		}
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Priority == foreign.Priority && rule.Table == foreign.Table {
			t.Logf("PASS: profile UID rules=%d, dual-stack hotspot chain lifecycle, foreign VPN-priority rule preserved", profileRules)
			return
		}
	}
	t.Fatal("foreign VPN-priority rule was removed")
}

func TestAndroidProxyAddressPolicy(t *testing.T) {
	deviceOnly(t)
	environment := deviceCore(t, config.EngineMihomo)
	environment.mustOK("POST", "/api/v1/core/start", nil, nil)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { fmt.Fprint(writer, "private-target") }))
	defer origin.Close()
	client := netx.NewClient(netx.Options{Proxy: environment.d.engine.ProxyURL(), AllowHTTP: true, AllowPrivate: false, Timeout: 5 * time.Second})
	defer client.CloseIdleConnections()
	response, err := client.Get(origin.URL)
	if err == nil {
		response.Body.Close()
		t.Fatalf("public-only proxy client reached a private target: HTTP %d", response.StatusCode)
	}
	t.Logf("PASS: public-only proxy client rejected the private target: %v", err)
	allowed := netx.NewClient(netx.Options{Proxy: environment.d.engine.ProxyURL(), AllowHTTP: true, AllowPrivate: true, Timeout: 5 * time.Second})
	defer allowed.CloseIdleConnections()
	response, err = allowed.Get(origin.URL)
	if err != nil {
		t.Fatal("authenticated CONNECT control request failed", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("explicit local-target control request failed", response.StatusCode)
	}
}
