package engine

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/logx"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/render"
	"ksu_proxy_manager/internal/store"
	"ksu_proxy_manager/internal/supervisor"
)

type testNetlink struct {
	capture.Netlink
	routes []netlink.Route
}

func (backend *testNetlink) LinkByName(string) (netlink.Link, error) {
	return nil, netlink.LinkNotFoundError{}
}

func (backend *testNetlink) RuleList(int) ([]netlink.Rule, error)        { return nil, nil }
func (backend *testNetlink) RuleAdd(*netlink.Rule) error                 { return nil }
func (backend *testNetlink) RouteList(int, int) ([]netlink.Route, error) { return nil, nil }
func (backend *testNetlink) RouteAdd(route *netlink.Route) error {
	backend.routes = append(backend.routes, *route)
	return nil
}

func newTestEngine(t *testing.T) (*Engine, *testNetlink) {
	t.Helper()
	directory := t.TempDir()
	layout := paths.Layout{ModuleDir: filepath.Join(directory, "module"), DataDir: filepath.Join(directory, "data")}
	persistence, err := store.Open(layout)
	if err != nil {
		t.Fatal(err)
	}
	backend := &testNetlink{}
	manager := New(Deps{Layout: layout, Store: persistence, Cores: cores.NewRegistry(layout),
		Capture: capture.NewWith(backend, nil, directory), Log: logx.NewLogger(nil), CaptureEnabled: true})
	manager.cfg, _ = persistence.Snapshot()
	manager.runRev = manager.cfg.Revision
	manager.engine = manager.cfg.Settings.Engine
	t.Cleanup(manager.cancel)
	return manager, backend
}

func TestFailClosedUpgradesExistingPlan(t *testing.T) {
	manager, backend := newTestEngine(t)
	plan := &capture.Plan{TunName: TunName, IPv6: true, Ranges: []apps.UIDRange{{Start: 10001, End: 10001}}}
	if err := manager.d.Capture.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	manager.failCapture(context.Background(), true)
	if !manager.d.Capture.Plan().FailClosed || len(backend.routes) != 4 || plan.FailClosed {
		t.Fatal("failure protection must install a new fail-closed plan")
	}
}

func TestRuntimeSettingsKeepPendingFieldsSeparate(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.proc = &supervisor.Process{}
	manager.state = StateRunning
	originalMTU := manager.cfg.Settings.MTU
	_, err := manager.d.Store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Settings.MTU = 1500
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := manager.d.Store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Settings.AutoStart = !configuration.Settings.AutoStart
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.RuntimeSettings(next.Revision, next.Settings)
	if manager.cfg.Settings.MTU != originalMTU || manager.cfg.Settings.AutoStart != next.Settings.AutoStart {
		t.Fatal("core-independent settings polluted the running configuration")
	}
}

func TestMissingRulesetsRespectPendingRevision(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.proc = &supervisor.Process{}
	manager.state = StateRunning
	manager.d.Downloader = func(ctx context.Context, engineName string, identifiers []render.RulesetID) error { return nil }
	_, err := manager.d.Store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Settings.MTU = 1500
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.fetchMissing(manager.engine, []render.RulesetID{{Kind: "geosite", Name: "cn"}}, manager.runRev)
	if manager.lastErr != "" {
		t.Fatal("pending configuration entered restart preparation")
	}
}

func TestMaintenanceKeepsLatestAppPolicy(t *testing.T) {
	t.Run("current revision", func(t *testing.T) { checkMaintenanceAppPolicy(t, false) })
	t.Run("pending core settings", func(t *testing.T) { checkMaintenanceAppPolicy(t, true) })
}

func checkMaintenanceAppPolicy(t *testing.T, pending bool) {
	manager, _ := newTestEngine(t)
	manager.proc = &supervisor.Process{}
	manager.state = StateRunning
	if pending {
		if _, err := manager.d.Store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
			c.Settings.MTU = 1500
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	runningRevision := manager.runRev
	manager.d.Apps = apps.NewSource()
	manager.d.Apps.PackagesList = filepath.Join(t.TempDir(), "packages.list")
	if err := os.WriteFile(manager.d.Apps.PackagesList, []byte("com.test.present 10001 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.cfg.Apps = config.AppPolicy{Mode: "include", Packages: []string{"com.test.missing"}, Users: []int{0}}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	capacity, err := unix.FcntlInt(writer.Fd(), unix.F_SETPIPE_SZ, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), capacity)); err != nil {
		t.Fatal(err)
	}
	manager.d.Log.SetEcho(writer)
	finished := make(chan struct{})
	go func() { manager.refreshCaptureIfIdle(manager.proc); close(finished) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		manager.mu.Lock()
		computed := len(manager.unknownPkgs) == 1
		manager.mu.Unlock()
		if computed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("maintenance did not reach pre-apply barrier")
		}
		runtime.Gosched()
	}
	policy := config.AppPolicy{Mode: "include", Packages: []string{"com.test.present"}, Users: []int{0}}
	next, err := manager.d.Store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		configuration.Apps = policy
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateApps(next.Revision, policy); err != nil {
		t.Fatal(err)
	}
	if len(manager.d.Capture.Plan().Ranges) == 0 {
		t.Fatal("control: new policy did not apply")
	}
	if _, err := io.ReadFull(reader, make([]byte, capacity)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not finish")
	}
	if len(manager.d.Capture.Plan().Ranges) == 0 || !manager.appsDirty {
		t.Fatal("stale maintenance plan overwrote the new policy or was not scheduled for retry")
	}
	if pending && manager.runRev != runningRevision {
		t.Fatal("app update incorrectly marked pending core settings as applied")
	}
}

// Which apps are captured applies at once; per-app targets need a core restart.
func TestAppRouteChangeStaysPending(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.proc = &supervisor.Process{}
	manager.state = StateRunning
	manager.d.Apps = apps.NewSource()
	manager.d.Apps.PackagesList = filepath.Join(t.TempDir(), "packages.list")
	if err := os.WriteFile(manager.d.Apps.PackagesList, []byte("com.test.present 10001 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	save := func(policy config.AppPolicy) int64 {
		t.Helper()
		next, err := manager.d.Store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
			c.Apps = policy
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.UpdateApps(next.Revision, next.Apps); err != nil {
			t.Fatal(err)
		}
		return next.Revision
	}
	policy := config.AppPolicy{Mode: "include", Packages: []string{"com.test.present"}, Users: []int{0}}
	if revision := save(policy); manager.runRev != revision {
		t.Fatal("a capture-only change must not stay pending")
	}
	running := manager.runRev
	policy.Mode = "exclude"
	policy.Routes = []config.AppRoute{{Package: "com.test.present", Target: config.TargetDirect}}
	save(policy)
	if manager.runRev != running || len(manager.cfg.Apps.Routes) != 0 {
		t.Fatal("changed app routes were marked as applied without a core restart")
	}
	if manager.cfg.Apps.Mode != "exclude" {
		t.Fatal("the capture part of the policy was not applied")
	}
}

func TestRulesetsUpdatedRechecksRevisionAfterLock(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.proc = &supervisor.Process{}
	manager.state = StateRunning
	manager.out = &render.Output{Missing: []render.RulesetID{{Kind: "geosite", Name: "cn"}}}
	manager.opMu.Lock()
	manager.RulesetsUpdated()
	_, err := manager.d.Store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Settings.MTU = 1500
		return nil
	})
	manager.opMu.Unlock()
	manager.wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if manager.lastErr != "" || manager.state != StateRunning {
		t.Fatal("queued ruleset reload applied a newer pending revision")
	}
}

func TestRecoveryPreservesDamagedIdentityRecord(t *testing.T) {
	for _, contents := range []string{"{invalid", `{"identity":{}}`} {
		t.Run(contents, func(t *testing.T) {
			manager, _ := newTestEngine(t)
			path := manager.d.Layout.CoreInfo()
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := manager.Recover(context.Background()); err == nil {
				t.Fatal("unverifiable recovery was reported as successful")
			}
			if manager.state != StateFailed || manager.recoveryErr == nil {
				t.Fatal("recovery failure was not retained")
			}
			if err := manager.Start(context.Background()); err == nil {
				t.Fatal("new core start was permitted before recovery")
			}
			if err := manager.Stop(context.Background()); err == nil {
				t.Fatal("stop claimed success without verifying the old core")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != contents {
				t.Fatal("damaged identity record was discarded", err)
			}
		})
	}
}

func TestFailedStateReconcilesFailClosed(t *testing.T) {
	manager, backend := newTestEngine(t)
	manager.state = StateFailed
	plan := &capture.Plan{TunName: TunName, IPv6: true, FailClosed: true, Ranges: []apps.UIDRange{{Start: 10001, End: 10001}}}
	if err := manager.d.Capture.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	backend.routes = nil
	manager.maintain(1)
	if len(backend.routes) != 4 {
		t.Fatal("failed core protection was not reconciled")
	}
}
