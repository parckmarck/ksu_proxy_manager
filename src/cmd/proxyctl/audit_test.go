package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
)

func TestAPIPathsKeepValidDottedIDsWithoutTraversal(t *testing.T) {
	for _, path := range []string{"/api/v1/nodes/hk..1", "/api/v1/nodes/hk%2e%2e1", "/api/v1/nodes?name=a..b"} {
		if !validAPIPath(path) {
			t.Errorf("valid object ID rejected: %s", path)
		}
	}
	for _, path := range []string{"/api/v1/../nodes", "/api/v1/%2e%2e/nodes", "/api/v1/x%2f..%2fnodes", "/api/v1/%5cetc", "/api/v1/%GG", "/api/v1/./nodes"} {
		if validAPIPath(path) {
			t.Errorf("unsafe path accepted: %s", path)
		}
	}
}

func TestBridgeDoesNotTreatUncertainWritesAsDaemonDown(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "TIMEOUT"},
		{&net.OpError{Op: "dial", Err: syscall.ENOENT}, "DAEMON_DOWN"},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "DAEMON_DOWN"},
		{&net.OpError{Op: "dial", Err: syscall.EACCES}, "CONNECTION_ERROR"},
		{errors.New("response truncated"), "RESPONSE_ERROR"},
	}
	for _, test := range tests {
		if got := bridgeTransportError(test.err)["code"]; got != test.code {
			t.Errorf("%v: got %v, want %s", test.err, got, test.code)
		}
	}
}

func TestCleanupPreservesActiveDaemonSocket(t *testing.T) {
	dir := t.TempDir()
	layout := paths.Layout{ModuleDir: filepath.Join(dir, "module"), DataDir: filepath.Join(dir, "data")}
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	lock, err := fsutil.TryLock(layout.DaemonLock())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	listener, err := net.Listen("unix", layout.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := cleanupWithLock(layout); err == nil {
		t.Fatal("cleanup entered an active daemon's state")
	}
	if _, err := os.Stat(layout.Socket()); err != nil {
		t.Fatal("active daemon socket was removed", err)
	}
}
