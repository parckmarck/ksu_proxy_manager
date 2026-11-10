package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/proc"
)

// inNetns re-runs the calling test inside an unprivileged user+network
// namespace and reports whether the caller is already inside it.
func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv("KPM_IN_NETNS") == "1" {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			t.Fatal(err)
		}
		return true
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1", "-test.timeout=10m")
	cmd.Env = append(os.Environ(), "KPM_IN_NETNS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "unshare failed") {
			t.Skipf("user namespaces unavailable: %s", out)
		}
		t.Fatalf("netns run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("netns run did not pass:\n%s", out)
	}
	t.Logf("netns output:\n%s", out)
	return false
}

func ownedRules(t *testing.T) []netlink.Rule {
	t.Helper()
	var out []netlink.Rule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if capture.Owned(r) {
				out = append(out, r)
			}
		}
	}
	return out
}

func tableRoutes(t *testing.T, fam int) []netlink.Route {
	t.Helper()
	var out []netlink.Route
	for _, table := range []int{capture.Table, capture.TunTable} {
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, routes...)
	}
	return out
}

// occupyTunName creates a non-TUN link with the core's TUN name so that the
// next core start cannot create its device.
func occupyTunName(t *testing.T) netlink.Link {
	t.Helper()
	attrs := netlink.LinkAttrs{Name: engine.TunName}
	var last error
	for _, l := range []netlink.Link{&netlink.Dummy{LinkAttrs: attrs}, &netlink.Bridge{LinkAttrs: attrs}} {
		err := netlink.LinkAdd(l)
		if err == nil {
			return l
		}
		if errors.Is(err, syscall.EEXIST) {
			t.Fatalf("TUN still present when the core is dead: %v", err)
		}
		last = err
	}
	t.Skipf("cannot create a blocking link in this namespace: %v", last)
	return nil
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return fsutil.CopyFile(p, target, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) status() engine.Status {
	e.t.Helper()
	var st struct {
		Core engine.Status `json:"core"`
	}
	e.mustOK("GET", "/api/v1/status", nil, &st)
	return st.Core
}

func (e *testEnv) waitState(want string, timeout time.Duration) engine.Status {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	var st engine.Status
	for time.Now().Before(deadline) {
		st = e.status()
		if st.State == want {
			return st
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.t.Fatalf("state %q not reached, last %+v", want, st)
	return st
}

func recoveryTestEnv(t *testing.T) *testEnv {
	t.Helper()
	directory := os.Getenv("KPM_TEST_CORES")
	if directory == "" {
		t.Skip("KPM_TEST_CORES not set")
	}
	environment := newEnv(t, true, nil)
	_, err := environment.d.installCandidate(context.Background(), filepath.Join(directory, "mihomo"), t.TempDir(), config.EngineMihomo, cores.Installation{Source: "test", Verification: "local-unverified"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(environment.d.apps.PackagesList, []byte("com.test.root 0 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = environment.d.store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Settings.AutoStart = false
		configuration.Settings.AutoRestart = false
		configuration.Routing.Preset = "custom"
		configuration.Apps = config.AppPolicy{Mode: "include", Packages: []string{"com.test.root"}, Users: []int{0}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return environment
}

func TestE2EFailClosedEnabledBeforeFailedReapply(t *testing.T) {
	if os.Getenv("KPM_TEST_CORES") == "" {
		t.Skip("KPM_TEST_CORES not set")
	}
	if !inNetns(t) {
		return
	}
	environment := recoveryTestEnv(t)
	environment.mustOK("POST", "/api/v1/core/start", nil, nil)
	_, err := environment.d.store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Settings.FailClosed = true
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
		t.Fatal("expected failed app resolution")
	}
	unreachable := 0
	for _, route := range tableRoutes(t, netlink.FAMILY_V4) {
		if route.Type == syscall.RTN_UNREACHABLE && (route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0") {
			unreachable++
		}
	}
	if environment.status().State != engine.StateFailed || unreachable != 2 {
		t.Fatal("failed reapply lost fail-closed protection", unreachable)
	}
}

func TestE2ECoreIdentityWriteFailure(t *testing.T) {
	if os.Getenv("KPM_TEST_CORES") == "" {
		t.Skip("KPM_TEST_CORES not set")
	}
	if !inNetns(t) {
		return
	}
	environment := recoveryTestEnv(t)
	if err := os.Mkdir(environment.layout.CoreInfo(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := environment.d.engine.Start(context.Background()); err == nil {
		t.Fatal("start succeeded without a recovery record")
	}
	if environment.status().PID != 0 {
		t.Fatal("unrecorded core was left running")
	}
}

func TestE2ELifecycle(t *testing.T) {
	coresDir := os.Getenv("KPM_TEST_CORES")
	if coresDir == "" {
		t.Skip("KPM_TEST_CORES not set")
	}
	if !inNetns(t) {
		return
	}
	cases := []struct{ name, file, engine string }{
		{"mihomo-archive", "mihomo-1.19.33.gz", "mihomo"},
		{"singbox-archive", "sing-box-1.14.4.tar.gz", "sing-box"},
		{"singbox-1.13-binary", "sing-box-1.13", "sing-box"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join(coresDir, tc.file)
			if !fsutil.Exists(src) {
				t.Skipf("%s missing", src)
			}
			runLifecycle(t, src, tc.engine)
		})
	}
}

func runLifecycle(t *testing.T, src, eng string) {
	importDir := t.TempDir()
	imported := filepath.Join(importDir, filepath.Base(src))
	if err := fsutil.CopyFile(src, imported, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KPM_IMPORT_ROOT", importDir)
	rulesetFixtures := os.Getenv("KPM_TEST_RULESETS")
	e := newEnv(t, true, func(l paths.Layout) {
		if rulesetFixtures != "" {
			copyTree(t, rulesetFixtures, l.RulesetDir())
		}
	})
	if os.Getenv("KPM_DEBUG_E2E") == "1" {
		t.Cleanup(func() {
			for _, p := range []string{e.layout.DaemonLog(), e.layout.CoreLog()} {
				b, _ := os.ReadFile(p)
				t.Logf("%s:\n%s", filepath.Base(p), b)
			}
		})
	}
	if err := os.WriteFile(e.d.apps.PackagesList, []byte("com.test.root 0 0 /data/user/0/com.test.root\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Import the core (archives are extracted, ELF and version probed).
	var task Task
	e.mustOK("POST", "/api/v1/cores/import", map[string]string{"path": imported}, &task)
	task = e.waitTask(task.ID)
	if task.State != TaskSucceeded {
		t.Fatalf("import failed: %+v", task)
	}
	var files struct {
		Installed []struct {
			Engine       string `json:"engine"`
			Version      string `json:"version"`
			Verification string `json:"verification"`
		} `json:"installed"`
	}
	e.mustOK("GET", "/api/v1/cores", nil, &files)
	if len(files.Installed) != 1 || files.Installed[0].Engine != eng || files.Installed[0].Verification != "local-unverified" {
		t.Fatalf("installed: %+v", files.Installed)
	}

	// Configure: engine, IPv6, app policy limited to uid 0 (the only uid
	// mapped in the test namespace), and an unreachable node.
	var s struct {
		Settings map[string]any `json:"settings"`
	}
	e.mustOK("GET", "/api/v1/settings", nil, &s)
	s.Settings["engine"] = eng
	s.Settings["ipv6"] = true
	s.Settings["autoStart"] = false
	e.mustOK("PUT", "/api/v1/settings", s.Settings, nil)
	e.mustOK("PUT", "/api/v1/apps/policy", map[string]any{"mode": "include", "packages": []string{"com.test.root", "com.missing.app"}, "users": []int{0}}, nil)
	var node struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/nodes", map[string]any{"node": map[string]any{"name": "socks", "type": "socks", "server": "127.0.0.1", "port": 9, "udp": true}}, &node)

	// Start.
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	st := e.waitState(engine.StateRunning, 30*time.Second)
	if st.Engine != eng || st.PID == 0 || !st.CaptureActive || st.Pending {
		t.Fatalf("status after start: %+v", st)
	}
	if len(st.UnknownPackages) != 1 || st.UnknownPackages[0] != "com.missing.app" {
		t.Fatalf("unknown packages: %+v", st.UnknownPackages)
	}
	if _, err := netlink.LinkByName(engine.TunName); err != nil {
		t.Fatalf("tun missing: %v", err)
	}
	rules := ownedRules(t)
	uidRules, dnsRules := 0, 0
	for _, r := range rules {
		if r.UIDRange != nil {
			if r.UIDRange.Start != 0 || r.UIDRange.End != 0 {
				t.Fatalf("unexpected uid range %+v", r.UIDRange)
			}
			if r.Table == capture.TunTable {
				dnsRules++
			} else {
				uidRules++
			}
		}
	}
	if uidRules != 2 || dnsRules != 2 {
		t.Fatalf("want uid and dns rules for v4+v6, got %d/%d: %v", uidRules, dnsRules, rules)
	}
	if len(tableRoutes(t, netlink.FAMILY_V4)) == 0 || len(tableRoutes(t, netlink.FAMILY_V6)) == 0 {
		t.Fatal("capture table empty")
	}

	// Runtime API: proxies, mode switch, proxied request, delay test.
	var proxies struct {
		Running bool `json:"running"`
		Groups  []struct {
			ID      string `json:"id"`
			Now     string `json:"now"`
			Members []struct {
				Ref string `json:"ref"`
			} `json:"members"`
		} `json:"groups"`
	}
	e.mustOK("GET", "/api/v1/proxies", nil, &proxies)
	if !proxies.Running || len(proxies.Groups) != 2 {
		t.Fatalf("proxies: %+v", proxies)
	}
	for _, g := range proxies.Groups {
		if len(g.Members) == 0 || g.Now == "" {
			t.Fatalf("group without live members: %+v", g)
		}
	}
	e.mustOK("POST", "/api/v1/groups/proxy/select", map[string]string{"member": "DIRECT"}, nil)
	e.mustOK("GET", "/api/v1/proxies", nil, &proxies)
	for _, g := range proxies.Groups {
		if g.ID == "proxy" && g.Now != "DIRECT" {
			t.Fatalf("select not applied: %+v", g)
		}
	}
	e.mustOK("PUT", "/api/v1/routing/mode", map[string]string{"mode": "global"}, nil)
	e.mustOK("PUT", "/api/v1/routing/mode", map[string]string{"mode": "rule"}, nil)
	if st := e.status(); st.Pending || st.Mode != "rule" {
		t.Fatalf("runtime changes must not be pending: %+v", st)
	}
	var settings struct {
		Settings config.Settings `json:"settings"`
	}
	e.mustOK("GET", "/api/v1/settings", nil, &settings)
	settings.Settings.Download.Mode = "proxy"
	settings.Settings.AutoStart = !settings.Settings.AutoStart
	e.mustOK("PUT", "/api/v1/settings", settings.Settings, nil)
	if st := e.status(); st.Pending {
		t.Fatalf("settings the core does not use must not be pending: %+v", st)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "pong") }))
	defer origin.Close()
	proxyURL := e.d.engine.ProxyURL()
	if proxyURL == nil {
		t.Fatal("no proxy url")
	}
	pc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	resp, err := pc.Get(origin.URL)
	if err != nil {
		t.Fatalf("request through core: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "pong" {
		t.Fatalf("proxied body %q", body)
	}
	noUser := *proxyURL
	noUser.User = nil
	unauth := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&noUser)}, Timeout: 5 * time.Second}
	if resp, err := unauth.Get(origin.URL); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("mixed inbound accepted an unauthenticated client")
		}
	}
	wrongUser := *proxyURL
	wrongUser.User = url.UserPassword("incorrect", "incorrect")
	wrongAuth := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&wrongUser)}, Timeout: 5 * time.Second}
	defer wrongAuth.CloseIdleConnections()
	if response, err := wrongAuth.Get(origin.URL); err == nil {
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("mixed inbound accepted incorrect credentials")
		}
	}
	var delay struct {
		Results map[string]delayResult `json:"results"`
	}
	e.mustOK("POST", "/api/v1/nodes/delay", map[string]any{"ids": []string{node.ID}, "timeout": 1000}, &delay)
	if r := delay.Results[node.ID]; r.Method != "core" || r.Error == "" {
		t.Fatalf("delay: %+v", delay)
	}
	var conns struct {
		Running bool `json:"running"`
	}
	e.mustOK("GET", "/api/v1/connections", nil, &conns)
	if !conns.Running {
		t.Fatal("connections not running")
	}
	// Live app policy change updates the rules without a restart.
	pid := st.PID
	var applied saved
	e.mustOK("PUT", "/api/v1/apps/policy", map[string]any{"mode": "include", "packages": []string{"com.missing.app"}, "users": []int{0}}, &applied)
	if applied.Pending {
		t.Fatal("successfully applied app policy reported pending")
	}
	for _, r := range ownedRules(t) {
		if r.UIDRange != nil {
			t.Fatalf("uid rule kept after policy change: %v", r)
		}
	}
	if st := e.status(); st.PID != pid || st.Pending {
		t.Fatalf("policy change restarted core or left pending: %+v", st)
	}
	e.mustOK("PUT", "/api/v1/apps/policy", map[string]any{"mode": "include", "packages": []string{"com.test.root"}, "users": []int{0}}, nil)

	// A pending configuration change is applied by restart.
	e.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": "trojan://pw@127.0.0.1:9#T"}, nil)
	if st := e.status(); !st.Pending {
		t.Fatal("node change not pending")
	}
	e.mustOK("POST", "/api/v1/core/restart", nil, nil)
	st = e.waitState(engine.StateRunning, 30*time.Second)
	if st.PID == pid || st.Pending {
		t.Fatalf("restart: %+v", st)
	}

	// Crash: the core is restarted automatically and capture comes back.
	pid = st.PID
	_ = syscall.Kill(pid, syscall.SIGKILL)
	deadline := time.Now().Add(30 * time.Second)
	for {
		st = e.status()
		if st.State == engine.StateRunning && st.PID != pid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no automatic restart: %+v", st)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st.Restarts != 1 || !st.CaptureActive {
		t.Fatalf("after crash: %+v", st)
	}

	// Fail-closed: without auto restart, capture stays and blocks.
	e.mustOK("GET", "/api/v1/settings", nil, &s)
	s.Settings["failClosed"] = true
	s.Settings["autoRestart"] = false
	e.mustOK("PUT", "/api/v1/settings", s.Settings, nil)
	e.mustOK("POST", "/api/v1/core/restart", nil, nil)
	st = e.waitState(engine.StateRunning, 30*time.Second)
	_ = syscall.Kill(st.PID, syscall.SIGKILL)
	e.waitState(engine.StateFailed, 15*time.Second)
	if len(ownedRules(t)) == 0 {
		t.Fatal("fail-closed removed capture rules")
	}
	for _, r := range tableRoutes(t, netlink.FAMILY_V4) {
		if r.LinkIndex != 0 && r.Type != syscall.RTN_UNREACHABLE {
			t.Fatalf("route through dead tun kept: %v", r)
		}
	}

	// Fail-closed must also hold when the automatic restart itself fails: a
	// foreign link squatting on the TUN name makes the restarted core unable
	// to come up.
	s.Settings["autoRestart"] = true
	e.mustOK("PUT", "/api/v1/settings", s.Settings, nil)
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	st = e.waitState(engine.StateRunning, 30*time.Second)
	_ = syscall.Kill(st.PID, syscall.SIGKILL)
	gone := time.Now().Add(5 * time.Second)
	for time.Now().Before(gone) {
		if _, err := netlink.LinkByName(engine.TunName); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	blocker := occupyTunName(t)
	t.Cleanup(func() { _ = netlink.LinkDel(blocker) })
	deadline = time.Now().Add(110 * time.Second)
	for {
		st = e.status()
		if st.State == engine.StateFailed && st.Restarts == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("automatic restart did not exhaust the full finite budget: %+v", st)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st.LastError == "" {
		t.Fatalf("failed restart did not retain its error: %+v", st)
	}
	if len(ownedRules(t)) == 0 {
		t.Fatal("fail-closed removed capture rules after a failed restart")
	}
	unreachable := false
	for _, r := range tableRoutes(t, netlink.FAMILY_V4) {
		if r.Type == syscall.RTN_UNREACHABLE {
			unreachable = true
		}
	}
	if !unreachable {
		t.Fatal("fail-closed fallback route missing after a failed restart")
	}
	if err := netlink.LinkDel(blocker); err != nil {
		t.Fatal(err)
	}
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	e.waitState(engine.StateRunning, 30*time.Second)

	// Stop removes everything.
	e.mustOK("POST", "/api/v1/core/stop", nil, nil)
	if st := e.status(); st.State != engine.StateStopped {
		t.Fatalf("stop: %+v", st)
	}
	if r := ownedRules(t); len(r) != 0 {
		t.Fatalf("rules left after stop: %v", r)
	}
	if len(tableRoutes(t, netlink.FAMILY_V4))+len(tableRoutes(t, netlink.FAMILY_V6)) != 0 {
		t.Fatal("routes left after stop")
	}
	if _, err := netlink.LinkByName(engine.TunName); err == nil {
		t.Fatal("tun left after stop")
	}

	// A selection made while the core is stopped must win over the core's
	// cached selection (sing-box restores cache.db otherwise), and the daemon
	// shutdown with a running core cleans up as well.
	e.mustOK("POST", "/api/v1/groups/proxy/select", map[string]string{"member": "node:" + node.ID}, nil)
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	st = e.waitState(engine.StateRunning, 30*time.Second)
	e.mustOK("GET", "/api/v1/proxies", nil, &proxies)
	for _, g := range proxies.Groups {
		if g.ID == "proxy" && g.Now != "node:"+node.ID {
			t.Fatalf("selection made while stopped not applied: %+v", g)
		}
	}
	id, err := proc.Capture(st.PID)
	if err != nil {
		t.Fatal(err)
	}
	e.d.Shutdown(30 * time.Second)
	if id.Alive() {
		t.Fatal("core survived daemon shutdown")
	}
	if r := ownedRules(t); len(r) != 0 {
		t.Fatalf("rules left after shutdown: %v", r)
	}
	b, _ := os.ReadFile(e.layout.ModuleProp())
	if !strings.Contains(string(b), "管理服务未运行") {
		t.Fatalf("description not updated: %s", b)
	}
	logs, _ := os.ReadFile(e.layout.CoreLog())
	if strings.Contains(string(logs), proxyURL.User.String()) {
		t.Fatal("core log contains proxy credentials")
	}
}

func TestE2EHangRestart(t *testing.T) {
	coresDir := os.Getenv("KPM_TEST_CORES")
	src := filepath.Join(coresDir, "sing-box-1.14.4.tar.gz")
	if coresDir == "" || !fsutil.Exists(src) {
		t.Skip("sing-box test core not available")
	}
	if !inNetns(t) {
		return
	}
	importDir := t.TempDir()
	imported := filepath.Join(importDir, filepath.Base(src))
	if err := fsutil.CopyFile(src, imported, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KPM_IMPORT_ROOT", importDir)
	testEngineTick = 200 * time.Millisecond
	defer func() { testEngineTick = 0 }()
	e := newEnv(t, true, nil)
	_ = os.WriteFile(e.d.apps.PackagesList, []byte("com.test.root 0 0 /x\n"), 0o644)
	var task Task
	e.mustOK("POST", "/api/v1/cores/import", map[string]string{"path": imported}, &task)
	if task = e.waitTask(task.ID); task.State != TaskSucceeded {
		t.Fatalf("import: %+v", task)
	}
	var s struct {
		Settings map[string]any `json:"settings"`
	}
	e.mustOK("GET", "/api/v1/settings", nil, &s)
	s.Settings["engine"] = "sing-box"
	e.mustOK("PUT", "/api/v1/settings", s.Settings, nil)
	e.mustOK("PUT", "/api/v1/apps/policy", map[string]any{"mode": "include", "packages": []string{"com.test.root"}, "users": []int{0}}, nil)
	e.mustOK("POST", "/api/v1/core/start", nil, nil)
	st := e.waitState(engine.StateRunning, 30*time.Second)
	// Freeze the core: its controller stops answering while the process lives.
	if err := syscall.Kill(st.PID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		cur := e.status()
		if cur.State == engine.StateRunning && cur.PID != st.PID {
			if !strings.Contains(cur.LastExit, "控制接口无响应") || cur.Restarts != 1 || !cur.CaptureActive {
				t.Fatalf("after hang restart: %+v", cur)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hung core not restarted: %+v", cur)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if fsutil.Exists(fmt.Sprintf("/proc/%d/stat", st.PID)) {
		if b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", st.PID)); !strings.Contains(string(b), ") Z ") {
			t.Fatal("hung core still alive")
		}
	}
	// A stop during the restart backoff wins over the pending restart.
	cur := e.status()
	_ = syscall.Kill(cur.PID, syscall.SIGKILL)
	e.waitState(engine.StateRestarting, 10*time.Second)
	e.mustOK("POST", "/api/v1/core/stop", nil, nil)
	time.Sleep(3 * time.Second)
	if st := e.status(); st.State != engine.StateStopped || st.PID != 0 {
		t.Fatalf("restart after user stop: %+v", st)
	}
	if r := ownedRules(t); len(r) != 0 {
		t.Fatalf("rules left: %v", r)
	}
}

func TestE2ERecoverOrphan(t *testing.T) {
	if !inNetns(t) {
		return
	}
	orphan := exec.Command("sleep", "600")
	orphan.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := orphan.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = orphan.Wait() }()
	defer func() { _ = orphan.Process.Kill() }()
	id, err := proc.Capture(orphan.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	stale := netlink.NewRule()
	stale.Family = netlink.FAMILY_V4
	stale.Priority = capture.DefaultBase + 10
	stale.Table = capture.Table
	stale.UIDRange = netlink.NewRuleUIDRange(0, 0)
	if err := netlink.RuleAdd(stale); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, true, func(l paths.Layout) {
		rec := map[string]any{"engine": "mihomo", "version": "1.19.33", "identity": id}
		if err := fsutil.WriteJSONAtomic(l.CoreInfo(), rec, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for id.Alive() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if id.Alive() {
		t.Fatal("orphan core not terminated")
	}
	if r := ownedRules(t); len(r) != 0 {
		t.Fatalf("stale rules not removed: %v", r)
	}
	if fsutil.Exists(e.layout.CoreInfo()) {
		t.Fatal("core.json kept")
	}
	// An unrelated process whose PID matches a stale record is never killed.
	other := exec.Command("sleep", "600")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Process.Kill(); _ = other.Wait() }()
	fake := proc.Identity{PID: other.Process.Pid, StartTicks: 1, BootID: id.BootID, Exe: id.Exe}
	if fake.Alive() {
		t.Fatal("identity check accepted a different process")
	}
}
