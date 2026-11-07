// Package proc verifies process identity and adjusts process placement.
package proc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Identity pins a PID to one specific process incarnation.
type Identity struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"startTicks"`
	BootID     string `json:"bootId"`
	Exe        string `json:"exe"`
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// startTicks reads field 22 of /proc/<pid>/stat.
func startTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, errors.New("无法解析进程状态")
	}
	fields := strings.Fields(string(b[i+1:]))
	// fields[0] is the state (field 3); starttime is field 22.
	if len(fields) < 20 {
		return 0, errors.New("进程状态字段不足")
	}
	if fields[0] == "Z" {
		return 0, errors.New("进程已退出")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// Capture records the identity of a running process.
func Capture(pid int) (Identity, error) {
	t, err := startTicks(pid)
	if err != nil {
		return Identity{}, err
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return Identity{}, err
	}
	return Identity{PID: pid, StartTicks: t, BootID: bootID(), Exe: strings.TrimSuffix(exe, " (deleted)")}, nil
}

// Alive reports whether the exact recorded process still runs.
func (id Identity) Alive() bool {
	if !id.Valid() || id.BootID != bootID() {
		return false
	}
	cur, err := Capture(id.PID)
	if err != nil {
		return false
	}
	return cur.StartTicks == id.StartTicks && filepath.Clean(cur.Exe) == filepath.Clean(id.Exe)
}

// Valid distinguishes a complete identity from a missing or damaged record.
func (id Identity) Valid() bool {
	return id.PID > 1 && id.StartTicks > 0 && id.BootID != "" && filepath.IsAbs(id.Exe)
}

// SignalGroup sends sig to the process group led by id after re-verifying it.
func (id Identity) SignalGroup(sig syscall.Signal) error {
	if !id.Alive() {
		return os.ErrProcessDone
	}
	pgid, err := syscall.Getpgid(id.PID)
	if err != nil {
		return err
	}
	if pgid == id.PID {
		return syscall.Kill(-pgid, sig)
	}
	return syscall.Kill(id.PID, sig)
}

// Signal sends sig to exactly the recorded process after re-verifying it.
func (id Identity) Signal(sig syscall.Signal) error {
	if !id.Alive() {
		return os.ErrProcessDone
	}
	return syscall.Kill(id.PID, sig)
}

// cgroupRoots are the hierarchies Android uses for app process groups and
// freezing; moving into their roots detaches us from the launching app.
var cgroupRoots = []string{
	"/sys/fs/cgroup", "/acct", "/dev/cpuctl", "/dev/cpuset", "/dev/memcg",
	"/dev/blkio", "/dev/stune", "/dev/freezer",
}

// Detach moves pid into the root cgroups and protects it from the low memory
// killer, so that closing the manager app does not kill the daemon or core.
func Detach(pid int) []string {
	var done []string
	for _, root := range cgroupRoots {
		p := filepath.Join(root, "cgroup.procs")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := os.WriteFile(p, []byte(strconv.Itoa(pid)), 0o644); err == nil {
			done = append(done, root)
		}
	}
	_ = os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid), []byte("-1000"), 0o644)
	return done
}

// IsAndroid reports whether we run on an Android userspace.
func IsAndroid() bool {
	_, err := os.Stat("/system/build.prop")
	return err == nil
}
