// Package engine orchestrates the proxy core lifecycle: rendering, validation,
// process supervision, traffic capture, restart policy and runtime control.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/clashapi"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/logx"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/proc"
	"ksu_proxy_manager/internal/render"
	"ksu_proxy_manager/internal/rulesets"
	"ksu_proxy_manager/internal/store"
	"ksu_proxy_manager/internal/supervisor"
)

const (
	StateStopped    = "stopped"
	StateStarting   = "starting"
	StateRunning    = "running"
	StateStopping   = "stopping"
	StateRestarting = "restarting"
	StateFailed     = "failed"
	StateDisabled   = "disabled"

	TunName = "ksu-proxy0"
	TunIPv4 = "172.19.0.1/30"
	TunIPv6 = "fdfe:dcba:9877::1/126"

	// Every policy rule is evaluated per packet; keep the list bounded.
	maxUIDRanges = 1024
)

var (
	restartBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}
	startupBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 60 * time.Second}
	restartWindow  = 10 * time.Minute
	readyTimeout   = 20 * time.Second
	checkTimeout   = 45 * time.Second
	stopGrace      = 5 * time.Second
	tickInterval   = 5 * time.Second
)

type Deps struct {
	Layout   paths.Layout
	Store    *store.Store
	Cores    *cores.Registry
	Rulesets *rulesets.Store
	Apps     *apps.Source
	Capture  *capture.Manager
	Log      *logx.Logger
	CoreLog  *logx.Sink
	ABI      string
	// CaptureEnabled is false on development hosts where touching the host
	// routing table would be harmful; the core still runs.
	CaptureEnabled bool
	// Downloader fetches missing rule sets; nil disables automatic fetching.
	Downloader func(ctx context.Context, engine string, ids []render.RulesetID) error
	OnChange   func()
	// Tick overrides the maintenance interval (tests); zero means 5 seconds.
	Tick time.Duration
}

type Status struct {
	State           string             `json:"state"`
	Engine          string             `json:"engine,omitempty"`
	Version         string             `json:"version,omitempty"`
	PID             int                `json:"pid,omitempty"`
	StartedAt       string             `json:"startedAt,omitempty"`
	Revision        int64              `json:"revision"`
	Pending         bool               `json:"pending"`
	Mode            string             `json:"mode,omitempty"`
	LastError       string             `json:"lastError,omitempty"`
	LastExit        string             `json:"lastExit,omitempty"`
	Restarts        int                `json:"restarts"`
	Warnings        []string           `json:"warnings,omitempty"`
	MissingRulesets []render.RulesetID `json:"missingRulesets,omitempty"`
	UnknownPackages []string           `json:"unknownPackages,omitempty"`
	CaptureActive   bool               `json:"captureActive"`
	Capture         capture.Status     `json:"capture"`
}

type record struct {
	Engine   string        `json:"engine"`
	Version  string        `json:"version"`
	Identity proc.Identity `json:"identity"`
	Started  string        `json:"started"`
}

type Engine struct {
	d     Deps
	opMu  sync.Mutex
	mu    sync.Mutex
	state string

	proc           *supervisor.Process
	out            *render.Output
	rt             render.Runtime
	api            *clashapi.Client
	cfg            config.Config
	cfgGeneration  uint64
	appsGeneration uint64
	intent         uint64
	runRev         int64
	engine         string
	version        string
	startedAt      time.Time

	lastErr     string
	recoveryErr error
	lastExit    string
	userStopped bool
	disabled    bool
	closing     bool
	restarts    []time.Time
	unknownPkgs []string
	apiFailures int
	tunMissing  int
	appsDirty   bool
	lastGood    *config.Document

	traffic *trafficSampler
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	fetchMu sync.Mutex
}

func New(d Deps) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{d: d, state: StateStopped, ctx: ctx, cancel: cancel, traffic: newTrafficSampler()}
}

func (e *Engine) logf(level, msg string, kv ...any) {
	switch level {
	case "error":
		e.d.Log.Error("engine", msg, kv...)
	case "warn":
		e.d.Log.Warn("engine", msg, kv...)
	default:
		e.d.Log.Info("engine", msg, kv...)
	}
}

func (e *Engine) setState(s string) {
	e.mu.Lock()
	changed := e.state != s
	e.state = s
	e.mu.Unlock()
	if changed && e.d.OnChange != nil {
		e.d.OnChange()
	}
}

func (e *Engine) setError(err error) {
	e.mu.Lock()
	if err == nil {
		e.lastErr = ""
	} else {
		e.lastErr = err.Error()
	}
	e.mu.Unlock()
}

// Recover cleans up after a previous daemon instance: it terminates an orphan
// core (verified by identity) and removes any owned routing state.
func (e *Engine) Recover(ctx context.Context) (err error) {
	defer func() {
		e.mu.Lock()
		e.recoveryErr = err
		e.mu.Unlock()
		if err != nil {
			e.setError(err)
			e.setState(StateFailed)
			e.logf("error", "无法确认遗留核心已停止，保留恢复记录和接管状态", "error", err)
		}
	}()
	cfg, _ := e.d.Store.Snapshot()
	e.mu.Lock()
	stopped := e.userStopped || e.closing
	e.mu.Unlock()
	protect := e.d.CaptureEnabled && e.d.Store.LoadError() == nil && cfg.Settings.FailClosed &&
		cfg.Settings.AutoStart && !stopped && !fsutil.Exists(e.d.Layout.DisableFlag()) && !fsutil.Exists(e.d.Layout.RemoveFlag())
	if protect {
		plan, planErr := e.buildCapturePlan(cfg)
		if planErr != nil {
			return planErr
		}
		plan.Blocked = true
		if err := e.d.Capture.Apply(ctx, plan); err != nil {
			return fmt.Errorf("恢复前安装防泄漏阻断失败: %w", err)
		}
	}
	var rec record
	if readErr := fsutil.ReadJSON(e.d.Layout.CoreInfo(), &rec); readErr == nil {
		if !rec.Identity.Valid() {
			return errors.New("核心恢复记录不完整，请检查 run/core.json")
		}
		if rec.Identity.Alive() {
			e.logf("warn", "发现上次遗留的核心进程，正在结束", "pid", rec.Identity.PID)
			_ = rec.Identity.SignalGroup(15)
			deadline := time.Now().Add(stopGrace)
			for rec.Identity.Alive() && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
			}
			if rec.Identity.Alive() {
				_ = rec.Identity.SignalGroup(9)
				deadline = time.Now().Add(3 * time.Second)
				for rec.Identity.Alive() && time.Now().Before(deadline) {
					time.Sleep(100 * time.Millisecond)
				}
			}
			if rec.Identity.Alive() {
				return fmt.Errorf("遗留核心进程 %d 未能结束", rec.Identity.PID)
			}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("无法读取核心恢复记录: %w", readErr)
	}
	if removeErr := os.Remove(e.d.Layout.CoreInfo()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("无法清理已停止核心的恢复记录: %w", removeErr)
	}
	if e.d.CaptureEnabled {
		if !protect {
			if err := e.d.Capture.Clear(ctx); err != nil {
				e.logf("warn", "清理遗留路由状态失败", "error", err)
			}
		}
		if err := e.d.Capture.ClearCore(ctx); err != nil {
			return fmt.Errorf("清理遗留核心辅助路由失败: %w", err)
		}
	}
	return nil
}

// Run starts the background maintenance loop.
func (e *Engine) Run() {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		interval := tickInterval
		if e.d.Tick > 0 {
			interval = e.d.Tick
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		tick := 0
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-t.C:
				tick++
				e.maintain(tick)
			}
		}
	}()
}

func (e *Engine) maintain(tick int) {
	e.checkModuleFlags()
	e.mu.Lock()
	running := e.state == StateRunning
	p := e.proc
	api := e.api
	e.mu.Unlock()
	if !running || p == nil {
		if e.d.CaptureEnabled && e.opMu.TryLock() {
			e.mu.Lock()
			coreGone := e.proc == nil && e.recoveryErr == nil
			e.mu.Unlock()
			if coreGone {
				if err := e.d.Capture.ClearCore(e.ctx); err != nil {
					e.logf("warn", "清理核心辅助路由未完成，将重试", "error", err)
				}
			}
			if e.d.Capture.Plan() != nil {
				if _, err := e.d.Capture.Reconcile(e.ctx); err != nil {
					e.logf("warn", "阻断规则对账未完成，将重试", "error", err)
				}
			} else if e.d.Capture.CleanupPending() {
				e.clearCapture()
			}
			e.opMu.Unlock()
		}
		return
	}
	if e.d.CaptureEnabled {
		e.mu.Lock()
		dirty := e.appsDirty
		e.mu.Unlock()
		generation := e.d.Apps.Generation()
		e.mu.Lock()
		changed := generation != e.appsGeneration
		e.mu.Unlock()
		if dirty || changed {
			e.refreshCaptureIfIdle(p)
		}
		if _, err := e.d.Capture.Reconcile(e.ctx); err != nil {
			e.logf("warn", "路由对账未完成，将在下个周期重试", "error", err)
		}
		// A core that lost its TUN while staying alive blackholes (fail-closed)
		// or leaks (fail-open) traffic without ever exiting; treat it as hung.
		cs := e.d.Capture.Status()
		e.mu.Lock()
		if cs.Active && !cs.TunPresent {
			e.tunMissing++
		} else {
			e.tunMissing = 0
		}
		gone := e.tunMissing >= 3 && e.proc == p
		if gone {
			e.tunMissing = 0
		}
		e.mu.Unlock()
		if gone {
			e.logf("error", "TUN 网卡已消失但核心仍在运行，判定为异常并重启")
			e.track(func() { _ = p.Abort("TUN 网卡消失", stopGrace) })
			return
		}
	}
	if tick%3 == 0 && api != nil {
		ctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
		_, err := api.Version(ctx)
		cancel()
		e.mu.Lock()
		if err != nil {
			e.apiFailures++
		} else {
			e.apiFailures = 0
		}
		hung := e.apiFailures >= 4 && e.proc == p
		if hung {
			e.apiFailures = 0
		}
		e.mu.Unlock()
		if hung {
			e.logf("error", "核心控制接口连续无响应，判定为挂起并重启")
			// Abort (not Stop) so that watch applies the restart policy.
			e.track(func() { _ = p.Abort("控制接口无响应", stopGrace) })
		}
	}
}

// checkModuleFlags follows KernelSU's disable/remove markers.
func (e *Engine) checkModuleFlags() {
	disabled := fsutil.Exists(e.d.Layout.DisableFlag()) || fsutil.Exists(e.d.Layout.RemoveFlag())
	e.mu.Lock()
	was := e.disabled
	e.disabled = disabled
	if disabled != was {
		e.intent++
	}
	state := e.state
	e.mu.Unlock()
	if disabled && !was {
		e.logf("info", "模块已被禁用或标记卸载，停止核心")
		_ = e.stop(context.Background(), false)
		e.setState(StateDisabled)
	} else if !disabled && was {
		if state == StateDisabled {
			e.setState(StateStopped)
		}
		cfg, _ := e.d.Store.Snapshot()
		if cfg.Settings.AutoStart {
			e.mu.Lock()
			e.userStopped = false
			e.mu.Unlock()
			e.AutoStart()
		}
	}
}

// Disabled reports whether the module is disabled in the root manager.
func (e *Engine) Disabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.disabled
}

// AutoStart starts the core at boot when configured.
func (e *Engine) AutoStart() {
	e.checkModuleFlags()
	cfg, _ := e.d.Store.Snapshot()
	if !cfg.Settings.AutoStart || e.Disabled() {
		return
	}
	e.mu.Lock()
	generation := e.intent
	e.mu.Unlock()
	e.track(func() {
		e.opMu.Lock()
		if !e.autoAllowed(generation, true) {
			e.opMu.Unlock()
			return
		}
		e.mu.Lock()
		recoveryErr := e.recoveryErr
		e.mu.Unlock()
		var err error
		if recoveryErr != nil {
			err = e.Recover(e.ctx)
		}
		if err == nil {
			err = e.applyLocked(e.ctx)
		}
		e.opMu.Unlock()
		if err != nil {
			e.logf("error", "开机自动启动失败", "error", err)
			e.retryStart(generation, true)
		}
	})
}

// Start launches the core, or restarts it with the current configuration.
func (e *Engine) Start(ctx context.Context) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.Disabled() {
		return errors.New("模块已在管理器中禁用")
	}
	e.mu.Lock()
	closing := e.closing
	recoveryErr := e.recoveryErr
	if !closing {
		e.userStopped = false
		e.restarts = nil
		e.intent++
	}
	e.mu.Unlock()
	if closing || e.ctx.Err() != nil {
		return errors.New("管理服务正在退出")
	}
	if recoveryErr != nil {
		if err := e.Recover(ctx); err != nil {
			return err
		}
	}
	return e.applyLocked(ctx)
}

// reloadable reports, with opMu held, whether the core started from rev may
// be reloaded in place: a user stop, disable or shutdown since the caller's
// earlier check wins.
func (e *Engine) reloadable(engineName string, rev int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.proc != nil && e.state == StateRunning && !e.userStopped && !e.disabled && !e.closing &&
		e.ctx.Err() == nil && e.runRev == rev && e.engine == engineName
}

// Stop stops the core and removes traffic capture.
func (e *Engine) Stop(ctx context.Context) error {
	// Record the intent first so that a pending automatic restart yields.
	e.mu.Lock()
	e.userStopped = true
	e.intent++
	e.mu.Unlock()
	e.opMu.Lock()
	defer e.opMu.Unlock()
	return e.stopLocked(ctx, true)
}

func (e *Engine) stop(ctx context.Context, user bool) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	return e.stopLocked(ctx, user)
}

func (e *Engine) stopLocked(ctx context.Context, user bool) error {
	e.mu.Lock()
	if user {
		e.userStopped = true
	}
	p := e.proc
	recoveryErr := e.recoveryErr
	e.mu.Unlock()
	if p == nil {
		if recoveryErr != nil {
			if err := e.Recover(ctx); err != nil {
				return err
			}
		}
		if e.d.CaptureEnabled {
			if err := e.d.Capture.Clear(ctx); err != nil {
				e.logf("warn", "清理路由规则未完成，将自动重试", "error", err)
			}
			if err := e.d.Capture.ClearCore(ctx); err != nil {
				return err
			}
		}
		e.setState(StateStopped)
		return nil
	}
	e.setState(StateStopping)
	var errs []error
	if e.d.CaptureEnabled {
		if err := e.d.Capture.Clear(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := p.Stop(stopGrace); err != nil {
		errs = append(errs, err)
	}
	if !p.Exited() {
		err := errors.Join(errs...)
		e.setError(err)
		e.setState(StateFailed)
		return err
	}
	e.waitTunGone()
	if e.d.CaptureEnabled {
		if err := e.d.Capture.ClearCore(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	e.mu.Lock()
	e.proc, e.api = nil, nil
	e.mu.Unlock()
	e.traffic.reset()
	_ = os.Remove(e.d.Layout.CoreInfo())
	e.setState(StateStopped)
	err := errors.Join(errs...)
	e.setError(err)
	if err == nil {
		e.logf("info", "核心已停止")
	}
	return err
}

func (e *Engine) waitTunGone() {
	if !e.d.CaptureEnabled {
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := netlink.LinkByName(TunName); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Shutdown stops everything for daemon exit. Pending restarts and in-flight
// starts are cancelled first so that the stop cannot be delayed by them.
func (e *Engine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	e.closing = true
	e.userStopped = true
	e.intent++
	e.mu.Unlock()
	e.cancel()
	err := e.stop(ctx, false)
	e.wg.Wait()
	return err
}

// prepared is a rendered and validated configuration ready to launch.
type prepared struct {
	cfg     config.Config
	sec     config.Secrets
	inst    cores.Installation
	bin     string
	rt      render.Runtime
	out     *render.Output
	cfgPath string
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (e *Engine) prepare(ctx context.Context, cfg config.Config, sec config.Secrets) (*prepared, error) {
	if err := e.d.Store.LoadError(); err != nil {
		return nil, fmt.Errorf("配置文件无法使用，请在设置中恢复备份: %w", err)
	}
	engineName := cfg.Settings.Engine
	inst, err := e.d.Cores.Resolve(engineName, cfg.Settings.CoreVersions[engineName], e.d.ABI)
	if err != nil {
		return nil, err
	}
	bin, err := e.d.Cores.Verify(inst)
	if err != nil {
		return nil, err
	}
	ctlPort, err := freePort()
	if err != nil {
		return nil, err
	}
	mixPort, err := freePort()
	if err != nil {
		return nil, err
	}
	if mixPort == ctlPort {
		if mixPort, err = freePort(); err != nil {
			return nil, err
		}
	}
	work := e.d.Layout.CoreWorkDir()
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, err
	}
	rt := render.Runtime{
		TunName: TunName, TunIPv4: TunIPv4, TunIPv6: TunIPv6,
		ControllerPort: ctlPort, ControllerSecret: fsutil.RandomHex(16),
		MixedPort: mixPort, MixedUser: "kpm", MixedPass: fsutil.RandomHex(12),
		WorkDir: work, RulesetDir: e.d.Layout.RulesetDir(),
	}
	out, err := render.Render(render.Input{Config: cfg, Secrets: sec, Engine: engineName, Version: inst.Version, Runtime: rt, Rulesets: e.d.Rulesets.Lookup(engineName)})
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(work, "candidate-"+out.FileName)
	if err := fsutil.WriteFileAtomic(cfgPath, out.Content, 0o600); err != nil {
		return nil, err
	}
	pr := &prepared{cfg: cfg, sec: sec, inst: inst, bin: bin, rt: rt, out: out, cfgPath: cfgPath}
	if err := e.check(ctx, pr); err != nil {
		_ = os.Remove(cfgPath)
		return nil, err
	}
	return pr, nil
}

// secrets lists the literals of a prepared configuration that must never
// appear in logs or error messages.
func (pr *prepared) secrets() []string {
	out := []string{pr.rt.ControllerSecret, pr.rt.MixedPass}
	for _, fields := range pr.sec.Nodes {
		for _, v := range fields {
			out = append(out, v)
		}
	}
	for _, u := range pr.sec.Subscriptions {
		out = append(out, u)
	}
	return out
}

func (e *Engine) coreEnv(pr *prepared) []string {
	return append(supervisor.BaseEnv(pr.rt.WorkDir), pr.out.Env...)
}

func coreArgs(engine, dir, cfgPath string, check bool) []string {
	if engine == config.EngineMihomo {
		if check {
			return []string{"-t", "-d", dir, "-f", cfgPath}
		}
		return []string{"-d", dir, "-f", cfgPath}
	}
	if check {
		return []string{"check", "-D", dir, "-c", cfgPath}
	}
	return []string{"run", "-D", dir, "-c", cfgPath, "--disable-color"}
}

// check runs the core's own configuration test before anything is stopped.
func (e *Engine) check(ctx context.Context, pr *prepared) error {
	c, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	out, err := supervisor.Run(c, pr.bin, coreArgs(pr.inst.Engine, pr.rt.WorkDir, pr.cfgPath, true), pr.rt.WorkDir, e.coreEnv(pr), 64<<10)
	if c.Err() != nil {
		return errors.New("核心配置校验超时")
	}
	if err != nil {
		text := logx.ScrubWith(strings.TrimSpace(out), pr.secrets())
		lines := strings.Split(text, "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		return fmt.Errorf("核心拒绝了生成的配置: %s", strings.Join(lines, " | "))
	}
	return nil
}

// applyLocked validates the current configuration, then (re)starts the core.
// On failure of a restart it rolls back to the last good configuration.
func (e *Engine) applyLocked(ctx context.Context) error {
	cfg, sec := e.d.Store.Snapshot()
	return e.applyConfigLocked(ctx, cfg, sec)
}

func (e *Engine) applyConfigLocked(ctx context.Context, cfg config.Config, sec config.Secrets) error {
	e.mu.Lock()
	wasRunning := e.proc != nil
	e.mu.Unlock()
	if !wasRunning {
		e.setState(StateStarting)
	}
	pr, err := e.prepare(ctx, cfg, sec)
	if err != nil {
		e.setError(err)
		e.logf("error", "启动前校验失败", "error", err)
		if !wasRunning {
			e.setState(StateFailed)
		}
		return err
	}
	if wasRunning {
		e.setState(StateStarting)
		if err := e.stopProcessOnly(); err != nil {
			e.setError(err)
			e.setState(StateFailed)
			return err
		}
	}
	if err := e.launch(ctx, pr); err != nil {
		e.logf("error", "核心启动失败", "error", err)
		e.mu.Lock()
		good := e.lastGood
		coreStillAlive := e.proc != nil && !e.proc.Exited()
		e.mu.Unlock()
		if !coreStillAlive && wasRunning && good != nil && good.Revision != cfg.Revision {
			e.logf("warn", "尝试回滚到上次成功的配置", "revision", good.Revision)
			if prev, perr := e.prepare(ctx, good.Config, good.Secrets); perr == nil {
				if lerr := e.launch(ctx, prev); lerr == nil {
					e.setError(fmt.Errorf("新配置启动失败，已回滚到修订 %d: %v", good.Revision, err))
					return fmt.Errorf("新配置启动失败，已回滚: %w", err)
				}
			}
		}
		if e.d.CaptureEnabled {
			e.failCapture(ctx, cfg.Settings.FailClosed)
		}
		e.setError(err)
		e.setState(StateFailed)
		return err
	}
	e.setError(nil)
	return nil
}

// failCapture handles the routing state after a start/restart could not
// produce a running core. With fail-closed enabled the rules stay: without a
// TUN only the unreachable fallback remains, so captured apps are blocked
// instead of silently falling back to direct connections.
func (e *Engine) failCapture(ctx context.Context, failClosed bool) {
	plan := e.d.Capture.Plan()
	if failClosed && plan != nil {
		protected := *plan
		protected.FailClosed = true
		protected.Blocked = true
		e.logf("warn", "防泄漏已启用，核心未运行期间保留接管规则以阻断被接管应用")
		if err := e.d.Capture.Apply(ctx, &protected); err != nil {
			e.logf("warn", "路由对账未完成", "error", err)
		}
		return
	}
	_ = e.d.Capture.Clear(ctx)
}

// stopProcessOnly ends the current core but keeps capture rules in place.
func (e *Engine) stopProcessOnly() error {
	e.mu.Lock()
	p := e.proc
	e.mu.Unlock()
	if p != nil {
		if err := p.Stop(stopGrace); err != nil {
			return err
		}
		e.waitTunGone()
	}
	e.mu.Lock()
	e.proc, e.api = nil, nil
	e.mu.Unlock()
	e.traffic.reset()
	return nil
}

func (e *Engine) launch(ctx context.Context, pr *prepared) error {
	if e.d.CaptureEnabled {
		if err := e.d.Capture.ClearCore(ctx); err != nil {
			return fmt.Errorf("清理上次核心辅助路由失败: %w", err)
		}
	}
	final := filepath.Join(pr.rt.WorkDir, pr.out.FileName)
	for _, name := range []string{"config.yaml", "config.json"} {
		if name != pr.out.FileName {
			_ = os.Remove(filepath.Join(pr.rt.WorkDir, name))
		}
	}
	if err := os.Rename(pr.cfgPath, final); err != nil {
		return err
	}
	secrets := pr.secrets()
	e.d.CoreLog.SetSecrets(secrets)
	e.d.Log.Sink().SetSecrets(secrets)
	p, err := supervisor.Start(supervisor.Spec{
		Binary: pr.bin,
		Args:   coreArgs(pr.inst.Engine, pr.rt.WorkDir, final, false),
		Dir:    pr.rt.WorkDir,
		Env:    e.coreEnv(pr),
		Output: e.d.CoreLog.LineWriter(),
	})
	if err != nil {
		return err
	}
	rec := record{Engine: pr.inst.Engine, Version: pr.inst.Version, Identity: p.Identity(), Started: time.Now().UTC().Format(time.RFC3339)}
	if !rec.Identity.Valid() {
		stopErr := p.Stop(stopGrace)
		if !p.Exited() {
			e.retainStopping(p)
		}
		return errors.Join(errors.New("无法确认新核心进程的身份"), stopErr)
	}
	if err := fsutil.WriteJSONAtomic(e.d.Layout.CoreInfo(), rec, 0o600); err != nil {
		stopErr := p.Stop(stopGrace)
		if !p.Exited() {
			e.retainStopping(p)
		}
		return errors.Join(fmt.Errorf("无法保存核心恢复记录: %w", err), stopErr)
	}
	api := clashapi.New(fmt.Sprintf("127.0.0.1:%d", pr.rt.ControllerPort), pr.rt.ControllerSecret)
	if err := e.waitReady(ctx, p, api); err != nil {
		stopErr := p.Stop(stopGrace)
		if p.Exited() {
			_ = os.Remove(e.d.Layout.CoreInfo())
		} else {
			e.retainStopping(p)
		}
		return errors.Join(err, stopErr)
	}
	e.mu.Lock()
	e.proc, e.api, e.out, e.rt, e.cfg = p, api, pr.out, pr.rt, pr.cfg
	e.cfgGeneration++
	e.runRev, e.engine, e.version = pr.cfg.Revision, pr.inst.Engine, pr.inst.Version
	e.startedAt = time.Now()
	e.apiFailures, e.tunMissing = 0, 0
	e.mu.Unlock()
	abandon := func(err error) error {
		stopErr := p.Stop(stopGrace)
		e.mu.Lock()
		if p.Exited() {
			e.proc, e.api = nil, nil
		}
		e.mu.Unlock()
		if p.Exited() {
			_ = os.Remove(e.d.Layout.CoreInfo())
		}
		return errors.Join(err, stopErr)
	}
	// Register the exit watcher before anything else can fail: a core that
	// nobody supervises must never be left behind (shutdown refuses new work).
	if !e.track(func() { e.watch(p) }) {
		return abandon(errors.New("管理服务正在退出"))
	}
	if e.d.CaptureEnabled {
		if err := e.refreshCapturePlan(); err != nil {
			if !errors.Is(err, capture.ErrUnavailable) && !errors.Is(err, capture.ErrFirewall) {
				return abandon(fmt.Errorf("建立流量接管失败: %w", err))
			}
			e.mu.Lock()
			e.appsDirty = true
			e.mu.Unlock()
			e.logf("warn", "核心已就绪，接管规则将在后台重试", "error", err)
		}
	}
	// Both cores may restore an earlier selection from their cache file; the
	// saved configuration is authoritative.
	for gtag, mtag := range pr.out.Selected {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		if err := api.Select(c, gtag, mtag); err != nil {
			e.logf("warn", "同步代理组选择失败", "group", gtag, "error", err)
		}
		cancel()
	}
	e.mu.Lock()
	doc := config.Clone(config.Document{Config: pr.cfg, Secrets: pr.sec})
	e.lastGood = &doc
	e.mu.Unlock()
	e.traffic.start(e.ctx, api)
	e.setState(StateRunning)
	e.logf("info", "核心已启动", "engine", pr.inst.Engine, "version", pr.inst.Version, "pid", p.PID(), "revision", pr.cfg.Revision)
	for _, w := range pr.out.Warnings {
		e.logf("warn", w)
	}
	if len(pr.out.Missing) > 0 && e.d.Downloader != nil {
		engineName, missing, rev := pr.inst.Engine, pr.out.Missing, pr.cfg.Revision
		e.track(func() { e.fetchMissing(engineName, missing, rev) })
	}
	return nil
}

func (e *Engine) retainStopping(p *supervisor.Process) {
	e.mu.Lock()
	e.proc, e.api = p, nil
	e.mu.Unlock()
	e.track(func() { e.watch(p) })
}

func (e *Engine) waitReady(ctx context.Context, p *supervisor.Process, api *clashapi.Client) error {
	deadline := time.Now().Add(readyTimeout)
	for {
		if p.Exited() {
			lines, _ := e.d.CoreLog.Tail(0, 400)
			var tail []string
			for i := len(lines) - 1; i >= 0 && len(tail) < 4; i-- {
				if lines[i].Level == "error" || lines[i].Level == "warn" {
					tail = append([]string{lines[i].Text}, tail...)
				}
			}
			return fmt.Errorf("核心启动后立即退出（%s）%s", p.ExitReason(), strings.Join(tail, " | "))
		}
		tunOK := true
		if e.d.CaptureEnabled {
			// Only a real TUN counts; a foreign link squatting on the name
			// means the core could not create its device.
			l, err := netlink.LinkByName(TunName)
			tunOK = err == nil && l.Type() == (&netlink.Tuntap{}).Type()
		}
		if tunOK {
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := api.Version(c)
			cancel()
			if err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("核心在 20 秒内未就绪（TUN 网卡或控制接口不可用）")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// watch handles an unexpected core exit according to the restart policy. The
// operation lock is not held while waiting, so Stop/Start/Shutdown stay
// responsive during the backoff.
func (e *Engine) watch(p *supervisor.Process) {
	select {
	case <-p.Done():
	case <-e.ctx.Done():
		return
	}
	stopping := p.Stopping()
	reason := p.ExitReason()
	e.opMu.Lock()
	e.mu.Lock()
	if e.proc != p {
		e.mu.Unlock()
		e.opMu.Unlock()
		return
	}
	e.proc, e.api = nil, nil
	generation := e.intent
	if !stopping {
		e.lastExit = reason
	}
	failClosed := e.cfg.Settings.FailClosed
	e.mu.Unlock()
	e.traffic.reset()
	_ = os.Remove(e.d.Layout.CoreInfo())
	if e.d.CaptureEnabled {
		if err := e.d.Capture.ClearCore(e.ctx); err != nil {
			e.logf("warn", "清理核心辅助路由未完成，将重试", "error", err)
		}
	}
	if stopping {
		e.opMu.Unlock()
		return
	}
	e.logf("error", "核心意外退出", "reason", reason)
	e.setError(fmt.Errorf("核心意外退出（%s）", reason))
	e.setState(StateFailed)
	if e.d.CaptureEnabled {
		e.failCapture(e.ctx, failClosed)
	}
	e.opMu.Unlock()
	e.retryStart(generation, false)
}

// The operation lock is held by callers. Recheck user intent and policy after
// every wait, including failed starts that never registered an exit watcher.
func (e *Engine) autoAllowed(generation uint64, boot bool) bool {
	cfg, _ := e.d.Store.Snapshot()
	e.mu.Lock()
	defer e.mu.Unlock()
	policy := cfg.Settings.AutoRestart
	if boot {
		policy = cfg.Settings.AutoStart
	}
	return policy && e.intent == generation && !e.userStopped && !e.disabled &&
		!e.closing && e.proc == nil && e.ctx.Err() == nil
}

func (e *Engine) retryStart(generation uint64, boot bool) {
	backoff := restartBackoff
	if boot {
		backoff = startupBackoff
	}
	for bootAttempt := 0; ; bootAttempt++ {
		e.opMu.Lock()
		if !e.autoAllowed(generation, boot) {
			e.opMu.Unlock()
			return
		}
		if err := e.d.Store.LoadError(); err != nil {
			e.setError(fmt.Errorf("配置文件无法使用，请在设置中恢复备份: %w", err))
			e.setState(StateFailed)
			e.opMu.Unlock()
			return
		}
		e.mu.Lock()
		now := time.Now()
		recent := e.restarts[:0]
		for _, started := range e.restarts {
			if now.Sub(started) < restartWindow {
				recent = append(recent, started)
			}
		}
		e.restarts = recent
		attempt := len(recent)
		if boot {
			attempt = bootAttempt
		}
		exhausted := attempt >= len(backoff)
		if !exhausted && !boot {
			e.restarts = append(e.restarts, now)
		}
		e.mu.Unlock()
		if exhausted {
			e.setState(StateFailed)
			e.opMu.Unlock()
			e.logf("error", "自动启动重试次数已用尽")
			return
		}
		e.setState(StateRestarting)
		e.opMu.Unlock()
		delay := backoff[attempt]
		e.logf("warn", "将自动重试启动核心", "attempt", attempt+1, "delay", delay)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-e.ctx.Done():
			timer.Stop()
			return
		}
		e.opMu.Lock()
		if !e.autoAllowed(generation, boot) {
			e.mu.Lock()
			same := e.intent == generation && e.proc == nil && e.state == StateRestarting
			e.mu.Unlock()
			if same {
				e.setState(StateFailed)
			}
			e.opMu.Unlock()
			return
		}
		e.mu.Lock()
		recoveryErr := e.recoveryErr
		e.mu.Unlock()
		var err error
		if recoveryErr != nil {
			err = e.Recover(e.ctx)
		}
		if err == nil {
			err = e.applyLocked(e.ctx)
		}
		e.opMu.Unlock()
		if err == nil {
			return
		}
		e.logf("error", "自动启动失败，将按剩余预算重试", "error", err)
	}
}

// clearCapture removes all routing state; failures are retried by maintain.
func (e *Engine) clearCapture() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := e.d.Capture.Clear(ctx); err != nil {
		e.logf("warn", "清理路由规则未完成，将自动重试", "error", err)
	}
}

// track starts fn as a goroutine that Shutdown waits for; it refuses new work
// once shutdown has begun.
func (e *Engine) track(fn func()) bool {
	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return false
	}
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		fn()
	}()
	return true
}

// refreshCapturePlan recomputes UID ranges from the running configuration
// and applies the routing plan. Callers hold opMu.
func (e *Engine) refreshCapturePlan() error {
	e.mu.Lock()
	cfg := config.Clone(e.cfg)
	e.mu.Unlock()
	generation := e.d.Apps.Generation()
	plan, err := e.buildCapturePlan(cfg)
	if err != nil {
		return err
	}
	if err := e.d.Capture.Apply(e.ctx, plan); err != nil {
		return err
	}
	e.mu.Lock()
	e.appsGeneration, e.appsDirty = generation, false
	e.mu.Unlock()
	return nil
}

// refreshCaptureIfIdle is the maintenance-loop variant: the (possibly slow)
// package lookup runs without the operation lock, and the plan is only
// applied when no start/stop is in progress and the core is unchanged, so a
// stale plan can never be written after Stop cleared everything.
func (e *Engine) refreshCaptureIfIdle(p *supervisor.Process) {
	e.mu.Lock()
	cfg := config.Clone(e.cfg)
	generation := e.cfgGeneration
	e.mu.Unlock()
	appsGeneration := e.d.Apps.Generation()
	plan, err := e.buildCapturePlan(cfg)
	if err != nil {
		e.logf("warn", "更新应用规则失败", "error", err)
		return
	}
	if !e.opMu.TryLock() {
		// The lock holder recomputes the plan itself; retry next tick anyway.
		e.mu.Lock()
		e.appsDirty = true
		e.mu.Unlock()
		return
	}
	defer e.opMu.Unlock()
	e.mu.Lock()
	e.appsDirty = false
	current := e.proc == p && e.state == StateRunning && e.cfgGeneration == generation
	if !current && e.proc == p && e.state == StateRunning {
		e.appsDirty = true
	}
	e.mu.Unlock()
	if !current {
		return
	}
	if err := e.d.Capture.Apply(e.ctx, plan); err != nil {
		e.logf("warn", "更新应用规则失败", "error", err)
		e.mu.Lock()
		e.appsDirty = true
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.appsGeneration = appsGeneration
	e.mu.Unlock()
}

// buildCapturePlan resolves the app policy of cfg into a routing plan.
func (e *Engine) buildCapturePlan(cfg config.Config) (*capture.Plan, error) {
	list, err := e.d.Apps.List(e.ctx)
	if err != nil && cfg.Apps.Mode != "all" {
		return nil, fmt.Errorf("无法读取应用列表: %w", err)
	}
	ranges, unknown := apps.Ranges(cfg.Apps, list)
	if len(ranges) > maxUIDRanges {
		return nil, fmt.Errorf("应用名单产生 %d 条 UID 规则，超过上限 %d，请精简名单或用户", len(ranges), maxUIDRanges)
	}
	plan := &capture.Plan{
		TunName:    TunName,
		Ranges:     ranges,
		IPv6:       cfg.Settings.IPv6,
		FailClosed: cfg.Settings.FailClosed,
		Bypass:     append([]netip.Prefix(nil), capture.DefaultBypass...),
		KeepInTun: []netip.Prefix{
			netip.MustParsePrefix(TunIPv4).Masked(),
			netip.MustParsePrefix(TunIPv6).Masked(),
		},
	}
	if cfg.DNS.Mode == "fakeip" {
		plan.KeepInTun = append(plan.KeepInTun, netip.MustParsePrefix(render.FakeIPv4Range), netip.MustParsePrefix(render.FakeIPv6Range))
	}
	if cfg.Settings.BypassLAN {
		plan.Bypass = append(plan.Bypass, capture.LANBypass...)
	}
	for _, c := range cfg.Settings.BypassCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			plan.Bypass = append(plan.Bypass, p.Masked())
		}
	}
	if cfg.Settings.Hotspot.Enabled {
		plan.Hotspot = cfg.Settings.Hotspot.Interfaces
	}
	sort.Strings(unknown)
	e.mu.Lock()
	e.unknownPkgs = unknown
	e.mu.Unlock()
	if cfg.Apps.Mode == "include" && len(ranges) == 0 {
		e.logf("warn", "白名单中没有已安装的应用，当前不接管任何应用流量")
	}
	return plan, nil
}

// fetchMissing downloads rule sets that were absent at start and restarts the
// core when they become available and nothing else changed meanwhile.
func (e *Engine) fetchMissing(engine string, ids []render.RulesetID, rev int64) {
	e.fetchMu.Lock()
	defer e.fetchMu.Unlock()
	if e.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, 3*time.Minute)
	defer cancel()
	if err := e.d.Downloader(ctx, engine, ids); err != nil {
		e.logf("warn", "自动下载缺失规则集失败", "error", err)
		return
	}
	e.mu.Lock()
	same := e.state == StateRunning && e.runRev == rev && e.engine == engine
	e.mu.Unlock()
	if !same {
		return
	}
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if !e.reloadable(engine, rev) {
		return
	}
	cfg, sec := e.d.Store.Snapshot()
	if cfg.Revision != rev {
		return
	}
	e.logf("info", "缺失的规则集已下载，重新加载核心")
	_ = e.applyConfigLocked(e.ctx, cfg, sec)
}

// Status returns a snapshot for the API and module description.
func (e *Engine) Status() Status {
	e.mu.Lock()
	s := Status{State: e.state, Engine: e.engine, Version: e.version, Revision: e.runRev, LastError: e.lastErr, LastExit: e.lastExit,
		Restarts: len(e.restarts), UnknownPackages: append([]string(nil), e.unknownPkgs...)}
	if e.proc != nil {
		s.PID = e.proc.PID()
		s.StartedAt = e.startedAt.UTC().Format(time.RFC3339)
		s.Mode = e.cfg.Routing.Mode
		if e.out != nil {
			s.Warnings = append([]string(nil), e.out.Warnings...)
			s.MissingRulesets = append([]render.RulesetID(nil), e.out.Missing...)
		}
	}
	running := e.proc != nil
	e.mu.Unlock()
	if running {
		s.Pending = e.d.Store.Revision() != s.Revision
	}
	if e.d.CaptureEnabled {
		s.Capture = e.d.Capture.Status()
		s.CaptureActive = s.Capture.Active
	}
	return s
}

// API returns the controller client of the running core.
func (e *Engine) API() (*clashapi.Client, *render.Output, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.api == nil || e.out == nil {
		return nil, nil, errors.New("核心未运行")
	}
	return e.api, e.out, nil
}

// ProxyURL returns the authenticated local proxy of the running core.
func (e *Engine) ProxyURL() *url.URL {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proc == nil || e.state != StateRunning {
		return nil
	}
	return &url.URL{Scheme: "http", User: url.UserPassword(e.rt.MixedUser, e.rt.MixedPass), Host: fmt.Sprintf("127.0.0.1:%d", e.rt.MixedPort)}
}

// Traffic returns recent throughput samples.
func (e *Engine) Traffic() TrafficSnapshot { return e.traffic.snapshot() }

// runtimeChange marks a change that the running core already applied through
// its API, so that it does not show up as a pending restart.
func (e *Engine) runtimeChange(newRev int64, fn func(c *config.Config)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proc == nil {
		return
	}
	fn(&e.cfg)
	e.cfgGeneration++
	if e.runRev == newRev-1 {
		e.runRev = newRev
	}
}

// RuntimeSettings records saved settings that the running core does not use
// (start/restart policy, downloads, web access), so they are not pending.
func (e *Engine) RuntimeSettings(newRev int64, s config.Settings) {
	e.runtimeChange(newRev, func(c *config.Config) {
		c.Settings.AutoStart = s.AutoStart
		c.Settings.AutoRestart = s.AutoRestart
		c.Settings.WebAccess = s.WebAccess
		c.Settings.Download = s.Download
		c.Settings.RulesetAutoUpdate = s.RulesetAutoUpdate
	})
}

// UpdateApps applies a saved app policy to the running capture plan. Which
// apps are captured does not depend on the core configuration, so that part
// takes effect without a restart. Per-app targets are rendered into the core
// configuration; when they change, the revision stays pending until the core
// restarts. The desired policy is retained even when reconciliation needs
// another attempt.
func (e *Engine) UpdateApps(newRev int64, p config.AppPolicy) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.mu.Lock()
	running := e.proc != nil && e.state == StateRunning
	cfg := config.Clone(e.cfg)
	e.mu.Unlock()
	if cfg.Apps.SameRoutes(p) {
		e.runtimeChange(newRev, func(c *config.Config) { c.Apps = config.Clone(p) })
	} else {
		// Keep the routes the core was started with and leave runRev alone.
		applied := config.Clone(p)
		e.mu.Lock()
		if e.proc != nil {
			e.cfg.Apps.Mode, e.cfg.Apps.Packages, e.cfg.Apps.Users = applied.Mode, applied.Packages, applied.Users
			e.cfgGeneration++
		}
		e.mu.Unlock()
	}
	if running && e.d.CaptureEnabled {
		e.mu.Lock()
		e.appsDirty = true
		e.mu.Unlock()
		cfg.Apps = config.Clone(p)
		generation := e.d.Apps.Generation()
		plan, err := e.buildCapturePlan(cfg)
		if err != nil {
			return err
		}
		if err := e.d.Capture.Apply(e.ctx, plan); err != nil {
			return err
		}
		e.mu.Lock()
		e.appsGeneration, e.appsDirty = generation, false
		e.mu.Unlock()
	}
	return nil
}

// RulesetsUpdated reloads a core that started without some rule sets, unless
// other configuration changes are pending.
func (e *Engine) RulesetsUpdated() {
	rev := e.d.Store.Revision()
	e.mu.Lock()
	reload := e.proc != nil && e.state == StateRunning && e.out != nil && len(e.out.Missing) > 0 && e.runRev == rev
	engineName := e.engine
	e.mu.Unlock()
	if !reload {
		return
	}
	e.track(func() {
		e.opMu.Lock()
		defer e.opMu.Unlock()
		if !e.reloadable(engineName, rev) {
			return
		}
		cfg, sec := e.d.Store.Snapshot()
		if cfg.Revision != rev {
			return
		}
		e.logf("info", "规则集已就绪，重新加载核心")
		_ = e.applyConfigLocked(e.ctx, cfg, sec)
	})
}

// SetMode switches the routing mode at runtime and persists it. The running
// core is only marked up to date once it accepted the change.
func (e *Engine) SetMode(ctx context.Context, mode string) error {
	if mode != "rule" && mode != "global" && mode != "direct" {
		return errors.New("模式必须为 rule/global/direct")
	}
	next, err := e.d.Store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.Routing.Mode = mode
		return nil
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	api, eng := e.api, e.engine
	e.mu.Unlock()
	if api != nil {
		m := mode
		if eng == config.EngineSingBox {
			m = map[string]string{"rule": "Rule", "global": "Global", "direct": "Direct"}[mode]
		}
		if err := api.SetMode(ctx, m); err != nil {
			return fmt.Errorf("模式已保存，但核心未接受切换（重启后生效）: %w", err)
		}
	}
	e.runtimeChange(next.Revision, func(c *config.Config) { c.Routing.Mode = mode })
	return nil
}

// SelectMember changes a select group's member at runtime and persists it.
func (e *Engine) SelectMember(ctx context.Context, groupID, member string) error {
	next, err := e.d.Store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		g := c.GroupByID(groupID)
		if g == nil {
			return fmt.Errorf("代理组 %s 不存在", groupID)
		}
		if g.Type != "select" {
			return errors.New("只有手动选择组可以切换节点")
		}
		g.Selected = member
		return nil
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	api, out := e.api, e.out
	e.mu.Unlock()
	if api != nil && out != nil {
		gtag, ok := out.TagOf[config.GroupRef(groupID)]
		mtag, ok2 := out.TagOf[member]
		if !ok || !ok2 {
			return errors.New("该节点不在当前运行的配置中，应用配置后生效")
		}
		if err := api.Select(ctx, gtag, mtag); err != nil {
			return fmt.Errorf("选择已保存，但核心未接受切换（重启后生效）: %w", err)
		}
	}
	e.runtimeChange(next.Revision, func(c *config.Config) {
		if g := c.GroupByID(groupID); g != nil {
			g.Selected = member
		}
	})
	return nil
}
