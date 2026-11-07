// Package daemon hosts the management API and background schedulers.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/buildinfo"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/logx"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/proc"
	"ksu_proxy_manager/internal/render"
	"ksu_proxy_manager/internal/rulesets"
	"ksu_proxy_manager/internal/store"
	"ksu_proxy_manager/internal/subscription"
)

type Options struct {
	Layout         paths.Layout
	CaptureEnabled bool
	ABI            string
	Echo           bool
	// EngineTick shortens the engine maintenance interval (tests only).
	EngineTick time.Duration
}

type Daemon struct {
	layout   paths.Layout
	store    *store.Store
	cores    *cores.Registry
	rulesets *rulesets.Store
	apps     *apps.Source
	engine   *engine.Engine
	tasks    *TaskManager
	log      *logx.Logger
	daemonLg *logx.Sink
	coreLg   *logx.Sink
	abi      string
	limiter  authLimiter
	started  time.Time

	mu         sync.Mutex
	previews   map[string]*preview
	relCache   map[string]releaseCache
	subRetries map[string]subscriptionRetry

	refreshingApps atomic.Bool
	unixSrv        *http.Server
	tcpSrv         *http.Server
	tcpPort        int
	// webMu serializes listener changes; webKey mirrors the stored access key
	// so that authentication does not need a configuration snapshot.
	webMu     sync.Mutex
	webKey    atomic.Value
	descLast  string
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type preview struct {
	ID        string
	SubID     string
	Revision  int64
	Format    string
	Nodes     []subscription.Parsed
	Diff      subscription.Diff
	Issues    []subscription.Issue
	Usage     *config.Usage
	ExpiresAt time.Time
}

type subscriptionRetry struct {
	Failures int
	Next     time.Time
}

// ABI maps the running architecture to the Android ABI of the core binaries.
func ABI() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64-v8a"
	case "amd64":
		return "x86_64"
	case "arm":
		return "armeabi-v7a"
	case "386":
		return "x86"
	}
	return runtime.GOARCH
}

func New(opt Options) (*Daemon, error) {
	l := opt.Layout
	// Leftovers of interrupted downloads/imports and WebUI uploads.
	_ = os.RemoveAll(l.StagingDir())
	_ = os.RemoveAll(l.BridgeDir())
	if err := l.Ensure(); err != nil {
		return nil, err
	}
	dsink, err := logx.OpenSink(l.DaemonLog(), 1<<20, 2000)
	if err != nil {
		return nil, err
	}
	csink, err := logx.OpenSink(l.CoreLog(), 1<<20, 3000)
	if err != nil {
		return nil, err
	}
	lg := logx.NewLogger(dsink)
	if opt.Echo {
		lg.SetEcho(os.Stderr)
	}
	st, err := store.Open(l)
	if err != nil {
		return nil, err
	}
	for _, n := range st.Notices() {
		lg.Warn("store", n)
	}
	if err := st.LoadError(); err != nil {
		lg.Error("store", "配置文件无法加载，已使用默认配置（未覆盖原文件）", "error", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		layout: l, store: st, cores: cores.NewRegistry(l), rulesets: rulesets.New(l), apps: apps.NewSource(),
		tasks: NewTaskManager(), log: lg, daemonLg: dsink, coreLg: csink, abi: opt.ABI, started: time.Now(),
		previews: map[string]*preview{}, relCache: map[string]releaseCache{}, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		subRetries: map[string]subscriptionRetry{},
	}
	if d.abi == "" {
		d.abi = ABI()
	}
	// Development hosts have no Android package database.
	if p := os.Getenv("KPM_PACKAGES_LIST"); p != "" {
		d.apps.PackagesList = p
	}
	d.engine = engine.New(engine.Deps{
		Layout: l, Store: st, Cores: d.cores, Rulesets: d.rulesets, Apps: d.apps, Capture: capture.New(),
		Log: lg, CoreLog: csink, ABI: d.abi, CaptureEnabled: opt.CaptureEnabled,
		Downloader: d.downloadRulesets, OnChange: d.updateDescription, Tick: opt.EngineTick,
	})
	return d, nil
}

// Serve starts listeners, recovery and schedulers. It returns once listening.
func (d *Daemon) Serve() error {
	// Keep the API available for diagnostics if recovery needs user attention.
	_ = d.engine.Recover(d.ctx)
	l, err := listenUnix(d.layout.Socket())
	if err != nil {
		return fmt.Errorf("无法创建控制套接字: %w", err)
	}
	d.unixSrv = &http.Server{Handler: d.unixHandler(), ReadHeaderTimeout: 10 * time.Second}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if err := d.unixSrv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("api", "控制套接字服务退出", "error", err)
		}
	}()
	info := map[string]any{"pid": os.Getpid(), "version": buildinfo.Version, "build": buildinfo.ID, "startedAt": d.started.UTC().Format(time.RFC3339), "socket": d.layout.Socket()}
	if id, err := proc.Capture(os.Getpid()); err == nil {
		info["identity"] = id
	}
	if err := fsutil.WriteJSONAtomic(d.layout.DaemonInfo(), info, 0o600); err != nil {
		return err
	}
	d.syncWebAccess()
	d.engine.Run()
	d.engine.AutoStart()
	d.wg.Add(1)
	go d.scheduler()
	d.updateDescription()
	d.log.Info("daemon", "管理服务已启动", "version", buildinfo.Version, "build", buildinfo.ID, "pid", os.Getpid(), "abi", d.abi)
	return nil
}

// Done is closed when shutdown completes.
func (d *Daemon) Done() <-chan struct{} { return d.done }

// Shutdown stops the core, the listeners and background work.
func (d *Daemon) Shutdown(timeout time.Duration) {
	d.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		d.log.Info("daemon", "管理服务正在退出")
		// Cancel first so that in-flight lifecycle requests and schedulers
		// stop promptly instead of delaying the core shutdown.
		d.cancel()
		d.tasks.Shutdown(5 * time.Second)
		if err := d.engine.Shutdown(ctx); err != nil {
			d.log.Error("daemon", "停止核心时出错", "error", err)
		}
		d.webMu.Lock()
		tcp := d.tcpSrv
		d.tcpSrv = nil
		d.webMu.Unlock()
		if tcp != nil {
			_ = tcp.Shutdown(ctx)
		}
		if d.unixSrv != nil {
			_ = d.unixSrv.Shutdown(ctx)
		}
		d.wg.Wait()
		_ = os.Remove(d.layout.Socket())
		_ = os.Remove(d.layout.DaemonInfo())
		d.writeDescription("■ 管理服务未运行")
		_ = d.daemonLg.Close()
		_ = d.coreLg.Close()
		close(d.done)
	})
}

// syncWebAccess starts or stops the optional loopback TCP listener. It is
// serialized so that concurrent settings changes cannot leak a listener.
func (d *Daemon) syncWebAccess() {
	d.webMu.Lock()
	defer d.webMu.Unlock()
	cfg, sec := d.store.Snapshot()
	d.webKey.Store(sec.WebAccessKey)
	want := cfg.Settings.WebAccess.Enabled && sec.WebAccessKey != ""
	port := cfg.Settings.WebAccess.Port
	cur, curPort := d.tcpSrv, d.tcpPort
	if cur != nil && (!want || curPort != port) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = cur.Shutdown(ctx)
		cancel()
		d.tcpSrv, d.tcpPort = nil, 0
		cur = nil
	}
	if !want || cur != nil || d.ctx.Err() != nil {
		return
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		d.log.Error("api", "浏览器访问端口监听失败", "port", port, "error", err)
		return
	}
	srv := &http.Server{Handler: d.tcpGuard(d.apiMux(), port), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	d.tcpSrv, d.tcpPort = srv, port
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("api", "浏览器访问服务退出", "error", err)
		}
	}()
	d.log.Info("api", "浏览器访问已开启", "address", l.Addr().String())
}

// scheduler runs periodic subscription and rule-set updates.
func (d *Daemon) scheduler() {
	defer d.wg.Done()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	first := time.After(2 * time.Minute)
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-first:
		case <-t.C:
		}
		d.autoUpdateSubscriptions()
		d.autoUpdateRulesets()
		d.gcPreviews()
	}
}

func (d *Daemon) gcPreviews() {
	d.mu.Lock()
	for id, p := range d.previews {
		if time.Now().After(p.ExpiresAt) {
			delete(d.previews, id)
		}
	}
	d.mu.Unlock()
	// Abandoned WebUI uploads may contain credentials.
	if entries, err := os.ReadDir(d.layout.BridgeDir()); err == nil {
		for _, e := range entries {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > 10*time.Minute {
				_ = os.RemoveAll(filepath.Join(d.layout.BridgeDir(), e.Name()))
			}
		}
	}
}

func (d *Daemon) autoUpdateSubscriptions() {
	cfg, _ := d.store.Snapshot()
	for _, s := range cfg.Subscriptions {
		if s.AutoUpdateHours <= 0 {
			continue
		}
		last, _ := time.Parse(time.RFC3339, s.UpdatedAt)
		if time.Since(last) < time.Duration(s.AutoUpdateHours)*time.Hour {
			continue
		}
		d.mu.Lock()
		retry := d.subRetries[s.ID]
		d.mu.Unlock()
		if time.Now().Before(retry.Next) {
			continue
		}
		ctx, cancel := context.WithTimeout(d.ctx, 2*time.Minute)
		err := d.refreshAndCommit(ctx, s.ID)
		cancel()
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			d.mu.Lock()
			retry.Failures++
			retry.Next = time.Now().Add(subscriptionRetryDelay(retry.Failures))
			d.subRetries[s.ID] = retry
			d.mu.Unlock()
			d.log.Warn("subscription", "自动更新订阅失败", "name", s.Name, "error", err)
		} else {
			d.mu.Lock()
			delete(d.subRetries, s.ID)
			d.mu.Unlock()
			d.log.Info("subscription", "订阅已自动更新", "name", s.Name)
		}
	}
}

func subscriptionRetryDelay(failures int) time.Duration {
	return min(10*time.Minute<<min(max(failures-1, 0), 6), 6*time.Hour)
}

func (d *Daemon) autoUpdateRulesets() {
	cfg, _ := d.store.Snapshot()
	if !cfg.Settings.RulesetAutoUpdate {
		return
	}
	ids := neededRulesets(cfg)
	var stale []render.RulesetID
	for _, id := range ids {
		if age := d.rulesets.Age(cfg.Settings.Engine, id); age < 0 || age > 7*24*time.Hour {
			stale = append(stale, id)
		}
	}
	if len(stale) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Minute)
	defer cancel()
	if err := d.downloadRulesets(ctx, cfg.Settings.Engine, stale); err != nil {
		d.log.Warn("ruleset", "自动更新规则集失败", "error", err)
		return
	}
	d.reloadRulesets(ctx, stale)
}

// reloadRulesets asks a running Mihomo to re-read updated rule providers;
// sing-box watches local rule-set files itself.
func (d *Daemon) reloadRulesets(ctx context.Context, ids []render.RulesetID) {
	api, out, err := d.engine.API()
	if err != nil || out.Engine != config.EngineMihomo {
		return
	}
	for _, id := range ids {
		_ = api.UpdateRuleProvider(ctx, id.Tag())
	}
}

// neededRulesets lists every rule set the configuration references.
func neededRulesets(cfg config.Config) []render.RulesetID {
	seen := map[render.RulesetID]bool{}
	var out []render.RulesetID
	add := func(kind, name string) {
		id := render.RulesetID{Kind: kind, Name: name}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, r := range cfg.Routing.Rules {
		if !r.Enabled || (r.Type != "geosite" && r.Type != "geoip") {
			continue
		}
		for _, v := range r.Values {
			add(r.Type, v)
		}
	}
	if cfg.Routing.BlockAds {
		add("geosite", "category-ads-all")
	}
	if cfg.Routing.Preset == "cn" {
		add("geosite", "cn")
		add("geoip", "cn")
	}
	return out
}

// updateDescription mirrors the engine state into module.prop.
func (d *Daemon) updateDescription() {
	st := d.engine.Status()
	cfg, _ := d.store.Snapshot()
	var text string
	switch st.State {
	case engine.StateRunning:
		mode := map[string]string{"rule": "规则", "global": "全局", "direct": "直连"}[cfg.Routing.Mode]
		text = fmt.Sprintf("▶ 运行中 · %s %s · %s模式", st.Engine, st.Version, mode)
		if len(st.MissingRulesets) > 0 {
			text += " · 规则集下载中"
		}
	case engine.StateStarting, engine.StateRestarting:
		text = "… 正在启动"
	case engine.StateFailed:
		msg := st.LastError
		if r := []rune(msg); len(r) > 40 {
			msg = string(r[:40]) + "…"
		}
		text = "⚠ 异常：" + msg
		if cfg.Settings.FailClosed && st.CaptureActive {
			text += "（防泄漏已阻断代理应用）"
		}
	case engine.StateDisabled:
		text = "已在管理器中禁用"
	default:
		text = "■ 已停止"
	}
	d.writeDescription(text)
}

const baseDescription = "KernelSU 双核心代理管理：Mihomo / sing-box、TUN 透明代理、应用分流、订阅与 WebUI。"

func (d *Daemon) writeDescription(status string) {
	d.mu.Lock()
	if d.descLast == status {
		d.mu.Unlock()
		return
	}
	d.descLast = status
	d.mu.Unlock()
	path := d.layout.ModuleProp()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), "\nid="+paths.ModuleID+"\n") && !strings.HasPrefix(string(b), "id="+paths.ModuleID+"\n") {
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	found := false
	for i, ln := range lines {
		if strings.HasPrefix(ln, "description=") {
			lines[i] = "description=[" + strings.ReplaceAll(status, "\n", " ") + "] " + baseDescription
			found = true
		}
	}
	if !found {
		lines = append(lines, "description=["+status+"] "+baseDescription)
	}
	_ = fsutil.WriteFileAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// CaptureAllowed reports whether routing changes may be applied on this host.
func CaptureAllowed() bool {
	if os.Geteuid() != 0 {
		return false
	}
	return proc.IsAndroid() || os.Getenv("KPM_ALLOW_CAPTURE") == "1"
}
