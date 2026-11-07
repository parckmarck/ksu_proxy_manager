// Command proxyctl controls the daemon from shells, module scripts and the
// KernelSU WebUI bridge.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/buildinfo"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/proc"
)

const usage = `用法: proxyctl <命令>
  status [--json]              查看运行状态
  start | stop | restart       启动 / 停止 / 重启代理核心（必要时自动启动管理服务）
  toggle                       核心运行时停止，否则启动
  mode rule|global|direct      切换路由模式
  logs [daemon|core] [-n 行数]  查看日志
  doctor                       输出诊断信息
  cleanup                      紧急清理：停止服务与核心并移除本模块的路由规则
  daemon start|stop|restart|status
  version
  api METHOD PATH [--body-b64 B64 | --chunks ID N]   WebUI 桥接
  chunk ID INDEX B64                                  WebUI 桥接`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	syscall.Umask(0o077)
	l := paths.FromEnv()
	c := newClient(l)
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println(buildinfo.String())
		return 0
	case "help", "-h", "--help":
		fmt.Println(usage)
		return 0
	case "api":
		return cmdAPI(c, l, args[1:])
	case "chunk":
		return cmdChunk(l, args[1:])
	case "daemon":
		return cmdDaemon(c, l, args[1:])
	case "status":
		return cmdStatus(c, l, args[1:])
	case "start", "restart":
		return cmdCoreStart(c, l)
	case "stop":
		return cmdCoreStop(c, l)
	case "toggle":
		return cmdToggle(c, l)
	case "mode":
		return cmdMode(c, args[1:])
	case "logs":
		return cmdLogs(c, l, args[1:])
	case "doctor":
		return cmdDoctor(c, l)
	case "cleanup":
		return cmdCleanup(c, l)
	}
	fmt.Fprintln(os.Stderr, "未知命令:", args[0])
	fmt.Fprintln(os.Stderr, usage)
	return 2
}

type client struct {
	layout paths.Layout
	http   *http.Client
}

func newClient(l paths.Layout) *client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", l.Socket())
		},
		DisableKeepAlives: true,
	}
	return &client{layout: l, http: &http.Client{Transport: tr}}
}

func (c *client) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://kpm"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, b, err
}

// call performs a JSON request and turns API errors into Go errors.
func (c *client) call(timeout time.Duration, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	status, resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return fmt.Errorf("无法连接管理服务: %w", err)
	}
	if status < 200 || status > 299 {
		var e struct {
			Error struct {
				Message string `json:"message"`
				Field   string `json:"field"`
			} `json:"error"`
		}
		if json.Unmarshal(resp, &e) == nil && e.Error.Message != "" {
			if e.Error.Field != "" {
				return fmt.Errorf("%s（%s）", e.Error.Message, e.Error.Field)
			}
			return errors.New(e.Error.Message)
		}
		return fmt.Errorf("HTTP %d", status)
	}
	if out != nil {
		return json.Unmarshal(resp, out)
	}
	return nil
}

func (c *client) alive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status, _, err := c.do(ctx, http.MethodGet, "/api/v1/status", nil)
	return err == nil && status == http.StatusOK
}

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

var (
	apiPathRE = regexp.MustCompile(`^/api/v1/[A-Za-z0-9._~/%?&=:,+-]*$`)
	bridgeRE  = regexp.MustCompile(`^[a-f0-9]{8,32}$`)
	b64RE     = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)
)

const maxChunks = 4096

// bridgeError is the JSON failure shape of the WebUI bridge; code lets the
// UI tell a stopped daemon from a malformed request.
func bridgeError(code, msg string) map[string]any {
	return map[string]any{"status": 0, "code": code, "error": msg}
}

func validAPIPath(path string) bool {
	if len(path) > 4096 || !apiPathRE.MatchString(path) {
		return false
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || strings.Contains(u.Path, "\\") {
		return false
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func bridgeTransportError(err error) map[string]any {
	var network *net.OpError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return bridgeError("TIMEOUT", "请求超时，操作可能已执行，请先刷新状态，勿重复提交")
	case errors.As(err, &network) && network.Op == "dial":
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return bridgeError("DAEMON_DOWN", "管理服务未运行或无法连接")
		}
		return bridgeError("CONNECTION_ERROR", "无法连接管理服务，请检查权限与套接字")
	default:
		return bridgeError("RESPONSE_ERROR", "未能完整读取响应，操作结果未知，请先刷新状态")
	}
}

func cmdAPI(c *client, l paths.Layout, args []string) int {
	if len(args) < 2 {
		emit(bridgeError("BAD_REQUEST", "用法: api METHOD PATH [--body-b64 B64 | --chunks ID N]"))
		return 2
	}
	method, path := strings.ToUpper(args[0]), args[1]
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
	default:
		emit(bridgeError("BAD_REQUEST", "不支持的方法"))
		return 2
	}
	if !validAPIPath(path) {
		emit(bridgeError("BAD_REQUEST", "路径无效"))
		return 2
	}
	var body []byte
	var err error
	rest := args[2:]
	switch {
	case len(rest) == 0:
	case len(rest) == 2 && rest[0] == "--body-b64":
		body, err = base64.StdEncoding.DecodeString(rest[1])
	case len(rest) == 3 && rest[0] == "--chunks":
		body, err = readChunks(l, rest[1], rest[2])
	default:
		err = errors.New("参数无效")
	}
	if err != nil {
		emit(bridgeError("BODY_INVALID", "请求体无效: "+err.Error()))
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	status, resp, err := c.do(ctx, method, path, body)
	if err != nil {
		emit(bridgeTransportError(err))
		return 1
	}
	out := map[string]any{"status": status}
	if json.Valid(resp) {
		out["body"] = json.RawMessage(resp)
	} else {
		out["body"] = string(resp)
	}
	emit(out)
	return 0
}

func cleanupBridge(l paths.Layout) {
	entries, err := os.ReadDir(l.BridgeDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && time.Since(info.ModTime()) > 10*time.Minute {
			_ = os.RemoveAll(filepath.Join(l.BridgeDir(), e.Name()))
		}
	}
}

func cmdChunk(l paths.Layout, args []string) int {
	if len(args) != 3 {
		emit(map[string]any{"ok": false, "code": "BAD_REQUEST", "error": "用法: chunk ID INDEX B64"})
		return 2
	}
	id, data := args[0], args[2]
	idx, err := strconv.Atoi(args[1])
	if !bridgeRE.MatchString(id) || err != nil || idx < 0 || idx >= maxChunks || len(data) > 1<<20 || !b64RE.MatchString(data) {
		emit(map[string]any{"ok": false, "error": "分片参数无效"})
		return 2
	}
	cleanupBridge(l)
	dir := filepath.Join(l.BridgeDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		emit(map[string]any{"ok": false, "error": err.Error()})
		return 1
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, fmt.Sprintf("%04d", idx)), []byte(data), 0o600); err != nil {
		emit(map[string]any{"ok": false, "error": err.Error()})
		return 1
	}
	emit(map[string]any{"ok": true})
	return 0
}

func readChunks(l paths.Layout, id, count string) ([]byte, error) {
	n, err := strconv.Atoi(count)
	if !bridgeRE.MatchString(id) || err != nil || n <= 0 || n > maxChunks {
		return nil, errors.New("分片参数无效")
	}
	dir := filepath.Join(l.BridgeDir(), id)
	defer os.RemoveAll(dir)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		b, err := fsutil.ReadFileLimited(filepath.Join(dir, fmt.Sprintf("%04d", i)), 1<<20)
		if err != nil {
			return nil, fmt.Errorf("缺少分片 %d", i)
		}
		if sb.Len()+len(b) > 48<<20 {
			return nil, errors.New("请求体过大")
		}
		sb.Write(b)
	}
	return base64.StdEncoding.DecodeString(sb.String())
}

// daemonEnv builds a clean environment for the daemon; app-specific variables
// of the caller (for example the root manager's) are not inherited. On
// Android the search path is fixed; development hosts keep the caller's PATH
// so that test tooling stays reachable.
func daemonEnv(l paths.Layout) []string {
	pathVar := "/system/bin:/system/xbin:/vendor/bin:/product/bin:/apex/com.android.runtime/bin"
	if p := os.Getenv("PATH"); p != "" && !proc.IsAndroid() {
		pathVar += ":" + p
	}
	env := []string{"PATH=" + pathVar, "HOME=" + l.DataDir, "TMPDIR=" + l.StagingDir(), "LANG=C.UTF-8"}
	for _, k := range []string{
		"KPM_MODULE_DIR", "KPM_DATA_DIR", "KPM_ALLOW_CAPTURE", "KPM_ECHO", "KPM_IMPORT_ROOT", "KPM_PACKAGES_LIST",
		"ANDROID_ROOT", "ANDROID_DATA", "ANDROID_STORAGE", "EXTERNAL_STORAGE", "ANDROID_ART_ROOT",
		"ANDROID_I18N_ROOT", "ANDROID_TZDATA_ROOT", "BOOTCLASSPATH", "DEX2OATBOOTCLASSPATH", "SYSTEMSERVERCLASSPATH",
	} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func tailFile(path string, n int) string {
	b, err := fsutil.ReadFileLimited(path, 1<<20)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func startDaemon(c *client, l paths.Layout) error {
	if c.alive() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bin := filepath.Join(filepath.Dir(exe), "proxy-managerd")
	if st, err := os.Stat(bin); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("找不到管理服务程序 %s", bin)
	}
	if err := l.Ensure(); err != nil {
		return err
	}
	logPath := filepath.Join(l.LogDir(), "daemon-start.log")
	if st, err := os.Stat(logPath); err == nil && st.Size() > 256<<10 {
		_ = os.Rename(logPath, logPath+".1")
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "=== %s 启动 %s\n", time.Now().Format(time.RFC3339), buildinfo.String())
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()
	cmd := exec.Command(bin, "run")
	cmd.Dir = "/"
	cmd.Env = daemonEnv(l)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("无法启动管理服务: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(25 * time.Second)
	for {
		if c.alive() {
			return nil
		}
		select {
		case err := <-exited:
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 3 {
				// Another instance holds the lock; give it time to come up.
				for time.Now().Before(deadline) {
					if c.alive() {
						return nil
					}
					time.Sleep(300 * time.Millisecond)
				}
				return errors.New("已有管理服务实例持有运行锁但未响应，可执行 proxyctl cleanup 后重试")
			}
			return fmt.Errorf("管理服务启动失败（%v）:\n%s", err, tailFile(logPath, 8))
		case <-time.After(250 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("管理服务在 25 秒内未就绪，详见 logs/daemon-start.log")
		}
	}
}

type daemonInfo struct {
	PID      int            `json:"pid"`
	Identity *proc.Identity `json:"identity"`
}

func readDaemonInfo(l paths.Layout) daemonInfo {
	var info daemonInfo
	_ = fsutil.ReadJSON(l.DaemonInfo(), &info)
	return info
}

func waitGone(id *proc.Identity, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if id == nil || !id.Alive() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return id == nil || !id.Alive()
}

// stopDaemon asks the daemon to exit and falls back to verified signals. It
// only reports success once the daemon is confirmed gone.
func stopDaemon(c *client, l paths.Layout) error {
	info := readDaemonInfo(l)
	if c.alive() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _, _ = c.do(ctx, http.MethodPost, "/api/v1/daemon/shutdown", nil)
		cancel()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if !c.alive() && waitGone(info.Identity, 0) {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if info.Identity == nil {
		if c.alive() {
			return errors.New("管理服务仍在响应但无法确认其进程（run/daemon.json 缺失）")
		}
		return nil
	}
	if !info.Identity.Alive() {
		return nil
	}
	_ = info.Identity.Signal(syscall.SIGTERM)
	if waitGone(info.Identity, 30*time.Second) {
		return nil
	}
	_ = info.Identity.Signal(syscall.SIGKILL)
	if !waitGone(info.Identity, 3*time.Second) {
		return fmt.Errorf("管理服务进程 %d 未能结束", info.Identity.PID)
	}
	return cleanupWithLock(l)
}

func cleanupWithLock(l paths.Layout) error {
	if err := l.Ensure(); err != nil {
		return err
	}
	lock, err := fsutil.TryLock(l.DaemonLock())
	if err != nil {
		return fmt.Errorf("管理服务运行锁仍被持有，未清理活动实例: %w", err)
	}
	defer lock.Release()
	return cleanupOrphans(l)
}

// cleanupOrphans removes what a dead daemon may have left behind. The core
// record is kept while the core itself could not be ended, so that the next
// daemon start can still recover it.
func cleanupOrphans(l paths.Layout) error {
	if os.Geteuid() != 0 {
		return errors.New("清理路由与进程需要 root 权限")
	}
	var rec struct {
		Identity proc.Identity `json:"identity"`
	}
	err := fsutil.ReadJSON(l.CoreInfo(), &rec)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("无法读取核心恢复记录，未执行清理: %w", err)
	}
	if err == nil && !rec.Identity.Valid() {
		return errors.New("核心恢复记录不完整，无法确认停止状态，已保留 run/core.json")
	}
	if err == nil && rec.Identity.Alive() {
		_ = rec.Identity.SignalGroup(syscall.SIGTERM)
		if !waitGone(&rec.Identity, 5*time.Second) {
			_ = rec.Identity.SignalGroup(syscall.SIGKILL)
			if !waitGone(&rec.Identity, 2*time.Second) {
				return fmt.Errorf("核心进程 %d 未能结束，已保留 run/core.json", rec.Identity.PID)
			}
		}
	}
	_ = os.Remove(l.CoreInfo())
	_ = os.Remove(l.Socket())
	_ = os.Remove(l.DaemonInfo())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := capture.New()
	return errors.Join(manager.Clear(ctx), manager.ClearCore(ctx))
}

func cmdDaemon(c *client, l paths.Layout, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "用法: proxyctl daemon start|stop|restart|status")
		return 2
	}
	switch args[0] {
	case "start":
		if err := startDaemon(c, l); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("管理服务运行中")
	case "stop":
		if err := stopDaemon(c, l); err != nil {
			fmt.Fprintln(os.Stderr, "停止时出现问题:", err)
			return 1
		}
		fmt.Println("管理服务已停止")
	case "restart":
		if err := stopDaemon(c, l); err != nil {
			fmt.Fprintln(os.Stderr, "停止失败，未重启:", err)
			return 1
		}
		if err := startDaemon(c, l); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("管理服务已重启")
	case "status":
		if !c.alive() {
			fmt.Println("管理服务未运行")
			return 3
		}
		info := readDaemonInfo(l)
		fmt.Printf("管理服务运行中（PID %d）\n", info.PID)
	default:
		fmt.Fprintln(os.Stderr, "用法: proxyctl daemon start|stop|restart|status")
		return 2
	}
	return 0
}

type statusResp struct {
	Daemon struct {
		Version     string   `json:"version"`
		PID         int      `json:"pid"`
		ConfigError string   `json:"configError"`
		Notices     []string `json:"notices"`
	} `json:"daemon"`
	Core struct {
		State           string   `json:"state"`
		Engine          string   `json:"engine"`
		Version         string   `json:"version"`
		PID             int      `json:"pid"`
		Pending         bool     `json:"pending"`
		LastError       string   `json:"lastError"`
		CaptureActive   bool     `json:"captureActive"`
		UnknownPackages []string `json:"unknownPackages"`
	} `json:"core"`
	Engine string `json:"engine"`
	Mode   string `json:"mode"`
}

var stateNames = map[string]string{
	"stopped": "已停止", "starting": "启动中", "running": "运行中", "stopping": "停止中",
	"restarting": "重启中", "failed": "异常", "disabled": "已禁用",
}

var modeNames = map[string]string{"rule": "规则", "global": "全局", "direct": "直连"}

func printStatus(s statusResp) {
	fmt.Printf("管理服务：运行中（%s，PID %d）\n", s.Daemon.Version, s.Daemon.PID)
	line := "核心：" + stateNames[s.Core.State]
	if s.Core.Engine != "" {
		line += fmt.Sprintf(" · %s %s", s.Core.Engine, s.Core.Version)
	} else {
		line += " · 已选 " + s.Engine
	}
	line += " · " + modeNames[s.Mode] + "模式"
	fmt.Println(line)
	if s.Core.State == "running" {
		if s.Core.CaptureActive {
			fmt.Println("流量接管：已生效")
		} else {
			fmt.Println("流量接管：未生效")
		}
	}
	if s.Core.Pending {
		fmt.Println("提示：有尚未应用的配置修改，执行 proxyctl restart 生效")
	}
	if s.Core.LastError != "" {
		fmt.Println("最近错误：" + s.Core.LastError)
	}
	if s.Daemon.ConfigError != "" {
		fmt.Println("配置文件错误：" + s.Daemon.ConfigError)
	}
}

func cmdStatus(c *client, l paths.Layout, args []string) int {
	asJSON := len(args) > 0 && args[0] == "--json"
	if !c.alive() {
		if asJSON {
			emit(map[string]any{"daemon": nil})
		} else {
			fmt.Println("管理服务：未运行")
			var rec struct {
				Identity proc.Identity `json:"identity"`
			}
			if fsutil.ReadJSON(l.CoreInfo(), &rec) == nil && rec.Identity.Alive() {
				fmt.Println("警告：发现无人管理的核心进程，可执行 proxyctl cleanup")
			}
		}
		return 3
	}
	if asJSON {
		var raw json.RawMessage
		if err := c.call(10*time.Second, http.MethodGet, "/api/v1/status", nil, &raw); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		emit(raw)
		return 0
	}
	var s statusResp
	if err := c.call(10*time.Second, http.MethodGet, "/api/v1/status", nil, &s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	printStatus(s)
	return 0
}

func cmdCoreStart(c *client, l paths.Layout) int {
	if err := startDaemon(c, l); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := c.call(4*time.Minute, http.MethodPost, "/api/v1/core/start", nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		return 1
	}
	var s statusResp
	if err := c.call(10*time.Second, http.MethodGet, "/api/v1/status", nil, &s); err == nil {
		printStatus(s)
	}
	return 0
}

func cmdCoreStop(c *client, l paths.Layout) int {
	if !c.alive() {
		if err := l.Ensure(); err != nil {
			fmt.Fprintln(os.Stderr, "无法确认停止状态:", err)
			return 1
		}
		lock, err := fsutil.TryLock(l.DaemonLock())
		if err != nil {
			fmt.Fprintln(os.Stderr, "管理服务未响应但仍持有实例锁，请执行 proxyctl cleanup")
			return 1
		}
		defer lock.Release()
		if err := cleanupOrphans(l); err != nil {
			fmt.Fprintln(os.Stderr, "停止或清理未完成:", err)
			return 1
		}
		fmt.Println("已停止遗留核心并清理接管规则")
		return 0
	}
	if err := c.call(time.Minute, http.MethodPost, "/api/v1/core/stop", nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "停止失败:", err)
		return 1
	}
	fmt.Println("核心已停止")
	return 0
}

// cmdToggle is used by the module action button.
func cmdToggle(c *client, l paths.Layout) int {
	if c.alive() {
		var s statusResp
		if err := c.call(10*time.Second, http.MethodGet, "/api/v1/status", nil, &s); err == nil {
			switch s.Core.State {
			case "running", "starting", "restarting":
				return cmdCoreStop(c, l)
			}
		}
	}
	return cmdCoreStart(c, l)
}

func cmdMode(c *client, args []string) int {
	if len(args) != 1 || modeNames[args[0]] == "" {
		fmt.Fprintln(os.Stderr, "用法: proxyctl mode rule|global|direct")
		return 2
	}
	if err := c.call(30*time.Second, http.MethodPut, "/api/v1/routing/mode", map[string]string{"mode": args[0]}, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("已切换为" + modeNames[args[0]] + "模式")
	return 0
}

func cmdLogs(c *client, l paths.Layout, args []string) int {
	source, n := "daemon", 200
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "daemon", "core":
			source = args[i]
		case "-n":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 && v <= 2000 {
					n = v
				}
				i++
			}
		}
	}
	if c.alive() {
		var resp struct {
			Lines []struct {
				Time  string `json:"time"`
				Level string `json:"level"`
				Text  string `json:"text"`
			} `json:"lines"`
		}
		q := url.Values{"source": {source}, "limit": {strconv.Itoa(n)}}
		if err := c.call(10*time.Second, http.MethodGet, "/api/v1/logs?"+q.Encode(), nil, &resp); err == nil {
			w := bufio.NewWriter(os.Stdout)
			for _, ln := range resp.Lines {
				fmt.Fprintf(w, "%s %-5s %s\n", ln.Time, ln.Level, ln.Text)
			}
			_ = w.Flush()
			return 0
		}
	}
	path := l.DaemonLog()
	if source == "core" {
		path = l.CoreLog()
	}
	fmt.Println(tailFile(path, n))
	return 0
}

func cmdDoctor(c *client, l paths.Layout) int {
	fmt.Println("版本：" + buildinfo.String())
	if c.alive() {
		var raw map[string]any
		if err := c.call(20*time.Second, http.MethodGet, "/api/v1/diagnostics", nil, &raw); err == nil {
			b, _ := json.MarshalIndent(raw, "", "  ")
			fmt.Println(string(b))
			return 0
		}
	}
	fmt.Println("管理服务：未运行")
	fmt.Println("TUN 设备：", fsutil.Exists("/dev/net/tun") || fsutil.Exists("/dev/tun"))
	var owned []string
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(fam)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if capture.Owned(r) {
				owned = append(owned, capture.DescribeRule(r))
			}
		}
	}
	if len(owned) > 0 {
		fmt.Println("残留的本模块路由规则（可执行 proxyctl cleanup 清除）：")
		for _, r := range owned {
			fmt.Println("  " + r)
		}
	} else {
		fmt.Println("没有残留的路由规则")
	}
	fmt.Println("最近的启动日志：")
	fmt.Println(tailFile(filepath.Join(l.LogDir(), "daemon-start.log"), 10))
	if s := tailFile(filepath.Join(l.LogDir(), "service.log"), 10); s != "" {
		fmt.Println("开机启动记录（service.sh）：")
		fmt.Println(s)
	}
	return 0
}

func cmdCleanup(c *client, l paths.Layout) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "cleanup 需要 root 权限")
		return 1
	}
	if err := stopDaemon(c, l); err != nil {
		fmt.Fprintln(os.Stderr, "停止管理服务时出现问题:", err)
		return 1
	}
	if err := cleanupWithLock(l); err != nil {
		fmt.Fprintln(os.Stderr, "清理未完成:", err)
		return 1
	}
	fmt.Println("已停止服务并清理本模块的路由规则，网络已恢复为系统默认")
	return 0
}
