package supervisor

import (
	"bytes"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type buf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *buf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *buf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestStopKillsProcessGroup(t *testing.T) {
	out := &buf{}
	// The shell ignores TERM and spawns a child; Stop must escalate to KILL
	// and take the whole group down.
	p, err := Start(Spec{Binary: "/bin/sh", Args: []string{"-c", "trap '' TERM; sleep 300 & echo started; wait"}, Dir: "/", Env: BaseEnv("/tmp"), Output: out})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "started") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	pgid, _ := syscall.Getpgid(p.PID())
	if pgid != p.PID() {
		t.Fatalf("not a group leader: %d", pgid)
	}
	start := time.Now()
	_ = p.Stop(500 * time.Millisecond)
	if !p.Exited() || !p.Stopping() {
		t.Fatal("not stopped")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("stop took too long")
	}
	if err := syscall.Kill(-pgid, 0); err == nil {
		t.Fatal("group members survived")
	}
}

func TestExitReason(t *testing.T) {
	p, err := Start(Spec{Binary: "/bin/sh", Args: []string{"-c", "exit 3"}, Dir: "/", Env: BaseEnv("/tmp"), Output: &buf{}})
	if err != nil {
		t.Fatal(err)
	}
	<-p.Done()
	if r := p.ExitReason(); !strings.Contains(r, "3") {
		t.Fatalf("reason %q", r)
	}
	if p.Stopping() {
		t.Fatal("natural exit marked as stopping")
	}
	if _, err := Start(Spec{Binary: "/nonexistent", Dir: "/", Output: &buf{}}); err == nil {
		t.Fatal("missing binary started")
	}
}
