// Package apps maps Android packages to UIDs and computes capture UID ranges.
package apps

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/proc"
)

const (
	PerUserRange    = 100000
	FirstAppID      = 10000
	LastAppID       = 19999
	SandboxOffset   = 10000
	FirstIsolatedID = 90000
	LastIsolatedID  = 99999
)

type App struct {
	Package         string `json:"package"`
	UID             int    `json:"uid"`
	System          *bool  `json:"system,omitempty"`
	ProtectedReason string `json:"protectedReason,omitempty"`
}

// Source reads the package database. Paths are overridable for tests.
type Source struct {
	PackagesList    string
	UserDir         string
	mu              sync.Mutex
	mtime           time.Time
	cache           []App
	system          map[string]bool
	systemMtime     time.Time
	generation      uint64
	generationMtime time.Time
	generationSize  int64
}

func NewSource() *Source {
	return &Source{PackagesList: "/data/system/packages.list", UserDir: "/data/user"}
}

// ParsePackagesList parses /data/system/packages.list ("pkg uid ...").
func ParsePackagesList(data []byte) []App {
	var out []App
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	seen := map[string]bool{}
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !config.ValidPackageName(f[0]) || seen[f[0]] {
			continue
		}
		uid, err := strconv.Atoi(f[1])
		if err != nil || uid < 0 {
			continue
		}
		seen[f[0]] = true
		out = append(out, App{Package: f[0], UID: uid % PerUserRange})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

// Changed reports whether packages.list changed since the last List call.
func (s *Source) Changed() bool {
	st, err := os.Stat(s.PackagesList)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !st.ModTime().Equal(s.mtime)
}

// Generation is independent of the UI's list cache. Each consumer remembers
// the generation it applied, so reading the list cannot consume a change.
func (s *Source) Generation() uint64 {
	st, err := os.Stat(s.PackagesList)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && (!st.ModTime().Equal(s.generationMtime) || st.Size() != s.generationSize) {
		s.generation++
		s.generationMtime, s.generationSize = st.ModTime(), st.Size()
	}
	return s.generation
}

// List returns installed packages, re-reading packages.list when it changed and
// falling back to the package manager when the file is unreadable.
func (s *Source) List(ctx context.Context) ([]App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.PackagesList)
	if err == nil && st.ModTime().Equal(s.mtime) && s.cache != nil {
		return s.decorate(s.cache), nil
	}
	if err == nil {
		data, rerr := os.ReadFile(s.PackagesList)
		if rerr == nil {
			apps := ParsePackagesList(data)
			if len(apps) > 0 {
				s.cache, s.mtime = apps, st.ModTime()
				return s.decorate(apps), nil
			}
		}
	}
	apps, perr := listViaPM(ctx, "")
	if perr != nil {
		if err != nil {
			return nil, errors.Join(err, perr)
		}
		return nil, perr
	}
	s.cache = apps
	return s.decorate(apps), nil
}

func (s *Source) decorate(apps []App) []App {
	out := make([]App, len(apps))
	copy(out, apps)
	protected := make(map[int]string)
	for _, app := range out {
		if reason := exclusionReason(app, proc.IsAndroid()); reason != "" {
			protected[app.UID] = reason
		}
	}
	for i := range out {
		out[i].ProtectedReason = protected[out[i].UID]
	}
	if s.system != nil {
		for i := range out {
			v := s.system[out[i].Package]
			out[i].System = &v
		}
	}
	return out
}

// RefreshSystemFlags queries the package manager for system packages. It is
// slow on some devices, so callers run it in the background.
func (s *Source) RefreshSystemFlags(ctx context.Context) error {
	s.mu.Lock()
	if s.system != nil && s.systemMtime.Equal(s.mtime) {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	sys, err := listViaPM(ctx, "-s")
	if err != nil {
		return err
	}
	m := map[string]bool{}
	for _, a := range sys {
		m[a.Package] = true
	}
	s.mu.Lock()
	s.system, s.systemMtime = m, s.mtime
	s.mu.Unlock()
	return nil
}

func listViaPM(ctx context.Context, filter string) ([]App, error) {
	var lastErr error
	for _, argv := range [][]string{{"cmd", "package", "list", "packages", "-U"}, {"pm", "list", "packages", "-U"}} {
		if filter != "" {
			argv = append(argv, filter)
		}
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		out, err := exec.CommandContext(c, argv[0], argv[1:]...).Output()
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		var apps []App
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "package:"))
			name, rest, ok := strings.Cut(line, " uid:")
			if !ok || !config.ValidPackageName(name) {
				continue
			}
			uidStr := strings.Fields(rest)
			if len(uidStr) == 0 {
				continue
			}
			uid, err := strconv.Atoi(strings.Split(uidStr[0], ",")[0])
			if err != nil {
				continue
			}
			apps = append(apps, App{Package: name, UID: uid % PerUserRange})
		}
		if len(apps) > 0 {
			sort.Slice(apps, func(i, j int) bool { return apps[i].Package < apps[j].Package })
			return apps, nil
		}
		lastErr = errors.New("包管理器未返回任何应用")
	}
	if lastErr == nil {
		lastErr = errors.New("无法读取应用列表")
	}
	return nil, lastErr
}

// Users lists Android user IDs present on the device.
func (s *Source) Users() []int {
	entries, err := os.ReadDir(s.UserDir)
	if err != nil {
		return []int{0}
	}
	var out []int
	for _, e := range entries {
		if n, err := strconv.Atoi(e.Name()); err == nil && n >= 0 && n <= 999 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = []int{0}
	}
	sort.Ints(out)
	return out
}

// UIDRange is an inclusive range of Linux UIDs.
type UIDRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

// Ranges computes the UID ranges to capture for a policy. Unknown packages are
// returned separately; in include mode an empty result captures nothing.
func Ranges(policy config.AppPolicy, apps []App) (ranges []UIDRange, unknown []string) {
	return rangesForPlatform(policy, apps, proc.IsAndroid())
}

func exclusionReason(app App, android bool) string {
	if android && app.UID < FirstAppID {
		return "系统共享 UID"
	}
	switch app.Package {
	case "com.android.captiveportallogin", "com.google.android.captiveportallogin":
		return "网络认证应用"
	}
	return ""
}

func rangesForPlatform(policy config.AppPolicy, apps []App, android bool) (ranges []UIDRange, unknown []string) {
	appID := map[string]int{}
	protected := map[int]bool{}
	for _, a := range apps {
		appID[a.Package] = a.UID
		if exclusionReason(a, android) != "" {
			protected[a.UID] = true
		}
	}
	var listed []int
	for _, p := range policy.Packages {
		id, ok := appID[p]
		if !ok {
			unknown = append(unknown, p)
			continue
		}
		if protected[id] {
			continue
		}
		listed = append(listed, id)
	}
	var out []UIDRange
	for _, u := range policy.Users {
		base := uint32(u * PerUserRange)
		switch policy.Mode {
		case "include":
			for _, id := range listed {
				out = append(out, UIDRange{base + uint32(id), base + uint32(id)})
				if id >= FirstAppID && id <= LastAppID {
					sb := base + uint32(id+SandboxOffset)
					out = append(out, UIDRange{sb, sb})
				}
			}
		default:
			all := []UIDRange{
				{base + FirstAppID, base + LastAppID + SandboxOffset},
				{base + FirstIsolatedID, base + LastIsolatedID},
			}
			if policy.Mode == "exclude" {
				var holes []uint32
				for _, id := range listed {
					holes = append(holes, base+uint32(id))
					if id >= FirstAppID && id <= LastAppID {
						holes = append(holes, base+uint32(id+SandboxOffset))
					}
				}
				all = subtract(all, holes)
			}
			out = append(out, all...)
		}
	}
	var holes []uint32
	for _, user := range policy.Users {
		base := uint32(user * PerUserRange)
		for id := range protected {
			holes = append(holes, base+uint32(id))
			if id >= FirstAppID && id <= LastAppID {
				holes = append(holes, base+uint32(id+SandboxOffset))
			}
		}
	}
	out = subtract(out, holes)
	return Merge(out), unknown
}

// Merge sorts ranges and joins overlapping or adjacent ones.
func Merge(in []UIDRange) []UIDRange {
	if len(in) == 0 {
		return nil
	}
	r := append([]UIDRange(nil), in...)
	sort.Slice(r, func(i, j int) bool { return r[i].Start < r[j].Start })
	out := []UIDRange{r[0]}
	for _, x := range r[1:] {
		last := &out[len(out)-1]
		if x.Start <= last.End+1 {
			if x.End > last.End {
				last.End = x.End
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

func subtract(ranges []UIDRange, holes []uint32) []UIDRange {
	sort.Slice(holes, func(i, j int) bool { return holes[i] < holes[j] })
	out := ranges
	for _, h := range holes {
		var next []UIDRange
		for _, r := range out {
			if h < r.Start || h > r.End {
				next = append(next, r)
				continue
			}
			if h > r.Start {
				next = append(next, UIDRange{r.Start, h - 1})
			}
			if h < r.End {
				next = append(next, UIDRange{h + 1, r.End})
			}
		}
		out = next
	}
	return out
}
