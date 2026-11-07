package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/store"
	"ksu_proxy_manager/internal/supervisor"
)

func TestAutomaticRetryUsesFullBudget(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.d.CaptureEnabled = false
	previous := restartBackoff
	restartBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { restartBackoff = previous }()
	manager.retryStart(manager.intent, false)
	if len(manager.restarts) != 3 || manager.state != StateFailed {
		t.Fatalf("failed starts did not consume the full finite budget: attempts=%d state=%s", len(manager.restarts), manager.state)
	}
}

func TestAutoStartRetriesWithoutInstalledCore(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.d.CaptureEnabled = false
	logs, err := os.CreateTemp(t.TempDir(), "boot-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	manager.d.Log.SetEcho(logs)
	previous := startupBackoff
	startupBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { startupBackoff = previous }()
	manager.AutoStart()
	manager.wg.Wait()
	contents, err := os.ReadFile(logs.Name())
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(contents), "启动前校验失败"); count != 4 {
		t.Fatalf("startup attempts=%d, want initial attempt plus 3 retries", count)
	}
}

func TestUserStopCancelsRetry(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.d.CaptureEnabled = false
	previous := restartBackoff
	restartBackoff = []time.Duration{100 * time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { restartBackoff = previous }()
	manager.track(func() { manager.retryStart(0, false) })
	deadline := time.Now().Add(time.Second)
	for manager.Status().State != StateRestarting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.wg.Wait()
	if manager.Status().State != StateStopped || len(manager.restarts) != 1 {
		t.Fatal("automatic retry overrode a user stop")
	}
}

func TestAppPolicyRemainsDesiredAfterLookupFailure(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.proc = &supervisor.Process{}
	manager.state = StateRunning
	manager.d.Apps = newAppSource(t)
	policy := config.AppPolicy{Mode: "include", Packages: []string{"com.test.next"}, Users: []int{0}}
	next, err := manager.d.Store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Apps = policy
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := manager.UpdateApps(next.Revision, policy); err == nil {
		t.Fatal("expected missing package database error")
	}
	if !manager.appsDirty || manager.cfg.Apps.Packages[0] != "com.test.next" {
		t.Fatal("saved app policy was not retained for retry")
	}
	if err := os.WriteFile(manager.d.Apps.PackagesList, []byte("com.test.next 10042 0 /test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.refreshCaptureIfIdle(manager.proc)
	plan := manager.d.Capture.Plan()
	if plan == nil || len(plan.Ranges) == 0 || plan.Ranges[0].Start != 10042 {
		t.Fatal("retry did not apply the new policy")
	}
}

func newAppSource(t *testing.T) *apps.Source {
	t.Helper()
	source := apps.NewSource()
	source.PackagesList = filepath.Join(t.TempDir(), "packages.list")
	return source
}

func TestCorruptConfigDoesNotEnterAutomaticRetryLoop(t *testing.T) {
	manager, _ := newTestEngine(t)
	manager.d.CaptureEnabled = false
	if err := os.WriteFile(manager.d.Layout.ConfigFile(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	manager.d.Store, err = store.Open(manager.d.Layout)
	if err != nil {
		t.Fatal(err)
	}
	previous := startupBackoff
	startupBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { startupBackoff = previous }()
	logs, err := os.CreateTemp(t.TempDir(), "invalid-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	manager.d.Log.SetEcho(logs)
	manager.AutoStart()
	manager.wg.Wait()
	contents, err := os.ReadFile(logs.Name())
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(contents), "启动前校验失败"); count != 1 {
		t.Fatalf("permanent config error retried %d times, want one attempt", count)
	}
	if manager.Status().State != StateFailed {
		t.Fatal("permanent error was not reported as failed")
	}
}
