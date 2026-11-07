// Package supervisor runs one child process in its own process group and
// reports its exit.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"ksu_proxy_manager/internal/proc"
)

type Spec struct {
	Binary string
	Args   []string
	Dir    string
	Env    []string
	Output io.Writer
}

type Process struct {
	cmd         *exec.Cmd
	id          proc.Identity
	done        chan struct{}
	mu          sync.Mutex
	exit        string
	exitAt      time.Time
	stopping    bool
	abortReason string
}

// BaseEnv is the minimal environment handed to cores.
func BaseEnv(home string) []string {
	return []string{
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
		"HOME=" + home,
		"TMPDIR=" + home,
		"XDG_CONFIG_HOME=" + home,
		"XDG_CACHE_HOME=" + home,
		"ANDROID_ROOT=/system",
		"ANDROID_DATA=/data",
	}
}

func Start(spec Spec) (*Process, error) {
	cmd := exec.Command(spec.Binary, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.Stdin = nil
	if spec.Output != nil {
		cmd.Stdout = spec.Output
		cmd.Stderr = spec.Output
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// A helper that inherited the output pipe must not keep Wait blocked.
	cmd.WaitDelay = pipeGrace
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &Process{cmd: cmd, done: make(chan struct{})}
	if id, err := proc.Capture(cmd.Process.Pid); err == nil {
		p.id = id
	} else {
		p.id = proc.Identity{PID: cmd.Process.Pid}
	}
	go p.wait()
	return p, nil
}

// pipeGrace bounds how long Wait may block on output pipes after the process
// itself has exited.
const pipeGrace = 5 * time.Second

func (p *Process) wait() {
	err := p.cmd.Wait()
	// Reap helpers the leader may have left in its group.
	_ = syscall.Kill(-p.id.PID, syscall.SIGKILL)
	p.mu.Lock()
	p.exitAt = time.Now()
	p.exit = describeExit(err, p.cmd.ProcessState)
	if p.abortReason != "" {
		p.exit = p.abortReason + "，已强制结束（" + p.exit + "）"
	}
	p.mu.Unlock()
	close(p.done)
}

func describeExit(err error, st *os.ProcessState) string {
	if st != nil {
		if ws, ok := st.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return fmt.Sprintf("被信号 %s 终止", ws.Signal())
			}
			return fmt.Sprintf("退出码 %d", ws.ExitStatus())
		}
	}
	if err != nil {
		return err.Error()
	}
	return "已退出"
}

func (p *Process) Identity() proc.Identity { return p.id }
func (p *Process) PID() int                { return p.id.PID }
func (p *Process) Done() <-chan struct{}   { return p.done }

func (p *Process) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// ExitReason describes how the process ended ("" while running).
func (p *Process) ExitReason() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exit
}

// Stopping reports whether Stop was requested (an exit is then expected).
func (p *Process) Stopping() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopping
}

// limitedBuffer keeps at most max bytes of output.
type limitedBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - len(b.buf); room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
		} else {
			b.buf = append(b.buf, p...)
		}
	}
	return len(p), nil
}

// Run executes a short-lived command in its own process group, keeps at most
// limit bytes of combined output and kills the whole group when ctx ends.
func Run(ctx context.Context, bin string, args []string, dir string, env []string, limit int) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	out := &limitedBuffer{max: limit}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = pipeGrace
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(2 * pipeGrace):
		}
		err = ctx.Err()
	}
	// Reap anything the command left behind in its group.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	out.mu.Lock()
	defer out.mu.Unlock()
	return string(out.buf), err
}

// Stop terminates the process group gracefully, escalating to SIGKILL. The
// exit is then reported as expected (Stopping returns true).
func (p *Process) Stop(grace time.Duration) error {
	p.mu.Lock()
	p.stopping = true
	p.mu.Unlock()
	return p.terminate(grace)
}

// Abort kills a misbehaving process; its exit is reported as unexpected so
// that the restart policy applies.
func (p *Process) Abort(reason string, grace time.Duration) error {
	p.mu.Lock()
	p.abortReason = reason
	p.mu.Unlock()
	return p.terminate(grace)
}

func (p *Process) terminate(grace time.Duration) error {
	if p.Exited() {
		return nil
	}
	_ = syscall.Kill(-p.id.PID, syscall.SIGTERM)
	select {
	case <-p.done:
		return nil
	case <-time.After(grace):
	}
	_ = syscall.Kill(-p.id.PID, syscall.SIGKILL)
	select {
	case <-p.done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("核心进程未能在 SIGKILL 后退出")
	}
}
