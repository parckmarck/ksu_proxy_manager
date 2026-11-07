package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/supervisor"
)

func TestOrphanChild(t *testing.T) {
	if os.Getenv("KPM_CLI_CHILD") != "1" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
}

func TestStopDoesNotClaimSuccessWithOrphan(t *testing.T) {
	directory := t.TempDir()
	layout := paths.Layout{ModuleDir: filepath.Join(directory, "module"), DataDir: filepath.Join(directory, "data")}
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	process, err := supervisor.Start(supervisor.Spec{Binary: os.Args[0], Args: []string{"-test.run=^TestOrphanChild$"}, Env: append(os.Environ(), "KPM_CLI_CHILD=1")})
	if err != nil {
		t.Fatal(err)
	}
	defer process.Stop(time.Second)
	if err := fsutil.WriteJSONAtomic(layout.CoreInfo(), map[string]any{"identity": process.Identity()}, 0o600); err != nil {
		t.Fatal(err)
	}
	exitCode := cmdCoreStop(newClient(layout), layout)
	if exitCode == 0 && process.Identity().Alive() {
		t.Fatal("stop reported success with a live orphan")
	}
}

func TestStopRespectsDaemonLock(t *testing.T) {
	directory := t.TempDir()
	layout := paths.Layout{ModuleDir: filepath.Join(directory, "module"), DataDir: filepath.Join(directory, "data")}
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	lock, err := fsutil.TryLock(layout.DaemonLock())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if code := cmdCoreStop(newClient(layout), layout); code == 0 {
		t.Fatal("unresponsive live daemon was treated as stopped")
	}
}

func TestStopPreservesDamagedCoreRecord(t *testing.T) {
	for _, contents := range []string{"{invalid", `{"identity":{}}`} {
		t.Run(contents, func(t *testing.T) {
			directory := t.TempDir()
			layout := paths.Layout{ModuleDir: filepath.Join(directory, "module"), DataDir: filepath.Join(directory, "data")}
			if err := layout.Ensure(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(layout.CoreInfo(), []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if code := cmdCoreStop(newClient(layout), layout); code == 0 {
				t.Fatal("stop claimed success with an unverifiable record")
			}
			got, err := os.ReadFile(layout.CoreInfo())
			if err != nil || string(got) != contents {
				t.Fatal("unverified core record was removed", err)
			}
		})
	}
}
