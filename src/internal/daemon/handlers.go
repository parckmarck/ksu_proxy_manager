package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"ksu_proxy_manager/internal/apps"
	"ksu_proxy_manager/internal/buildinfo"
	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/logx"
)

func (d *Daemon) hStatus(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	st := d.engine.Status()
	var loadErr string
	if err := d.store.LoadError(); err != nil {
		loadErr = err.Error()
	}
	t := d.engine.Traffic()
	t.History = nil
	return map[string]any{
		"daemon": map[string]any{
			"version": buildinfo.Version, "versionCode": buildinfo.VersionCode, "build": buildinfo.ID,
			"pid": os.Getpid(), "startedAt": d.started.UTC().Format(time.RFC3339), "abi": d.abi,
			"configError": loadErr, "notices": d.store.Notices(),
		},
		"core":     st,
		"revision": cfg.Revision,
		"engine":   cfg.Settings.Engine,
		"mode":     cfg.Routing.Mode,
		"counts": map[string]int{
			"nodes": len(cfg.Nodes), "groups": len(cfg.Groups), "subscriptions": len(cfg.Subscriptions), "rules": len(cfg.Routing.Rules),
		},
		"webAccess": map[string]any{"enabled": cfg.Settings.WebAccess.Enabled, "port": cfg.Settings.WebAccess.Port, "hasKey": sec.WebAccessKey != ""},
		"traffic":   t,
	}, nil
}

// lifecycleCtx is used for start/stop: a client that disconnects must not
// abort a transition half-way.
func (d *Daemon) lifecycleCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(d.ctx, 3*time.Minute)
}

func (d *Daemon) hCoreStart(_ http.ResponseWriter, _ *http.Request) (any, error) {
	ctx, cancel := d.lifecycleCtx()
	defer cancel()
	if err := d.engine.Start(ctx); err != nil {
		return nil, &APIError{Status: http.StatusUnprocessableEntity, Code: "START_FAILED", Message: err.Error()}
	}
	return d.engine.Status(), nil
}

func (d *Daemon) hCoreStop(_ http.ResponseWriter, _ *http.Request) (any, error) {
	ctx, cancel := d.lifecycleCtx()
	defer cancel()
	if err := d.engine.Stop(ctx); err != nil {
		return nil, err
	}
	return d.engine.Status(), nil
}

func (d *Daemon) hTraffic(_ http.ResponseWriter, _ *http.Request) (any, error) {
	return d.engine.Traffic(), nil
}

func (d *Daemon) hConnections(_ http.ResponseWriter, r *http.Request) (any, error) {
	api, _, err := d.engine.API()
	if err != nil {
		return map[string]any{"connections": []any{}, "running": false}, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	c, err := api.Connections(ctx)
	if err != nil {
		return nil, unavailable("读取连接失败: " + err.Error())
	}
	type conn struct {
		ID       string   `json:"id"`
		Host     string   `json:"host"`
		Dest     string   `json:"dest"`
		Network  string   `json:"network"`
		Process  string   `json:"process,omitempty"`
		Chains   []string `json:"chains"`
		Rule     string   `json:"rule"`
		Upload   int64    `json:"upload"`
		Download int64    `json:"download"`
		Start    string   `json:"start"`
	}
	list := make([]conn, 0, len(c.Connections))
	for _, x := range c.Connections {
		md := x.Metadata
		s := func(k string) string {
			if v, ok := md[k]; ok && v != nil {
				return fmt.Sprint(v)
			}
			return ""
		}
		dest := s("destinationIP")
		if p := s("destinationPort"); p != "" {
			dest += ":" + p
		}
		list = append(list, conn{ID: x.ID, Host: s("host"), Dest: dest, Network: s("network"), Process: firstNonEmpty(s("process"), s("processPath")),
			Chains: x.Chains, Rule: strings.TrimSpace(x.Rule + " " + x.Payload), Upload: x.Upload, Download: x.Download, Start: x.Start})
	}
	return map[string]any{"connections": list, "running": true, "uploadTotal": c.UploadTotal, "downloadTotal": c.DownloadTotal}, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (d *Daemon) hCloseConnection(_ http.ResponseWriter, r *http.Request) (any, error) {
	api, _, err := d.engine.API()
	if err != nil {
		return nil, unavailable("核心未运行")
	}
	if err := api.CloseConnection(r.Context(), r.PathValue("id")); err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

func (d *Daemon) hConfig(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	return map[string]any{"config": cfg, "nodes": nodeViews(cfg, sec), "subscriptions": subViews(cfg, sec)}, nil
}

func (d *Daemon) hSettings(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, _ := d.store.Snapshot()
	return map[string]any{"settings": cfg.Settings, "revision": cfg.Revision}, nil
}

type saved struct {
	Revision int64 `json:"revision"`
	Pending  bool  `json:"pending"`
}

func (d *Daemon) savedResult(cfg config.Config) saved {
	st := d.engine.Status()
	running := st.State == engine.StateRunning
	return saved{Revision: cfg.Revision, Pending: running && st.Revision != cfg.Revision}
}

func (d *Daemon) hPutSettings(_ http.ResponseWriter, r *http.Request) (any, error) {
	var s config.Settings
	if err := decode(r, 64<<10, &s); err != nil {
		return nil, err
	}
	prev, _ := d.store.Snapshot()
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		c.Settings = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	if coreIndependent(prev.Settings, next.Settings) {
		d.engine.RuntimeSettings(next.Revision, next.Settings)
	}
	d.syncWebAccess()
	return d.savedResult(next), nil
}

// coreIndependent reports whether two settings differ only in fields that the
// running core does not use.
func coreIndependent(a, b config.Settings) bool {
	a.AutoStart, a.AutoRestart, a.WebAccess, a.Download, a.RulesetAutoUpdate = b.AutoStart, b.AutoRestart, b.WebAccess, b.Download, b.RulesetAutoUpdate
	return reflect.DeepEqual(a, b)
}

func (d *Daemon) hRouting(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, _ := d.store.Snapshot()
	return map[string]any{"routing": cfg.Routing, "revision": cfg.Revision}, nil
}

func (d *Daemon) hPutRouting(_ http.ResponseWriter, r *http.Request) (any, error) {
	var rt config.Routing
	if err := decode(r, 2<<20, &rt); err != nil {
		return nil, err
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		c.Routing = rt
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.savedResult(next), nil
}

func (d *Daemon) hPutMode(_ http.ResponseWriter, r *http.Request) (any, error) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := decode(r, 1024, &body); err != nil {
		return nil, err
	}
	if err := d.engine.SetMode(r.Context(), body.Mode); err != nil {
		return nil, badRequest("%v", err)
	}
	d.updateDescription()
	return map[string]string{"mode": body.Mode}, nil
}

func (d *Daemon) hDNS(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, _ := d.store.Snapshot()
	return map[string]any{"dns": cfg.DNS, "revision": cfg.Revision, "defaultFakeipFilter": config.DefaultFakeIPFilter}, nil
}

func (d *Daemon) hPutDNS(_ http.ResponseWriter, r *http.Request) (any, error) {
	var dns config.DNS
	if err := decode(r, 256<<10, &dns); err != nil {
		return nil, err
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		c.DNS = dns
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.savedResult(next), nil
}

func (d *Daemon) hApps(_ http.ResponseWriter, r *http.Request) (any, error) {
	cfg, _ := d.store.Snapshot()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	list, err := d.apps.List(ctx)
	if err != nil {
		return nil, unavailable("无法读取应用列表: " + err.Error())
	}
	if list == nil {
		list = []apps.App{}
	}
	if d.refreshingApps.CompareAndSwap(false, true) {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer d.refreshingApps.Store(false)
			c, cancel := context.WithTimeout(d.ctx, 60*time.Second)
			defer cancel()
			_ = d.apps.RefreshSystemFlags(c)
		}()
	}
	return map[string]any{"apps": list, "users": d.apps.Users(), "policy": cfg.Apps, "revision": cfg.Revision}, nil
}

func (d *Daemon) hPutAppPolicy(_ http.ResponseWriter, r *http.Request) (any, error) {
	var p config.AppPolicy
	if err := decode(r, 1<<20, &p); err != nil {
		return nil, err
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		c.Apps = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	applyErr := d.engine.UpdateApps(next.Revision, next.Apps)
	res := d.savedResult(next)
	out := map[string]any{"revision": res.Revision, "pending": res.Pending}
	if err := applyErr; err != nil {
		d.log.Warn("apps", "应用名单已保存，但即时更新路由失败", "error", err)
		out["pending"] = d.savedResult(next).Pending
		out["warning"] = "应用名单已保存，部分路由尚未生效，正在自动重试: " + err.Error()
	}
	return out, nil
}

func (d *Daemon) hLogs(_ http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()
	after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	sink := d.daemonLg
	if q.Get("source") == "core" {
		sink = d.coreLg
	}
	lines, last := sink.Tail(after, limit)
	if lines == nil {
		lines = []logx.Line{}
	}
	return map[string]any{"lines": lines, "last": last}, nil
}

func (d *Daemon) hClearLogs(_ http.ResponseWriter, r *http.Request) (any, error) {
	if r.URL.Query().Get("source") == "core" {
		d.coreLg.Clear()
	} else {
		d.daemonLg.Clear()
	}
	return map[string]bool{"ok": true}, nil
}

func (d *Daemon) hBackup(w http.ResponseWriter, r *http.Request) (any, error) {
	withSecrets := r.URL.Query().Get("secrets") == "1"
	if err := requireSecretExport(r, withSecrets); err != nil {
		return nil, err
	}
	return map[string]any{"document": d.exportDocument(withSecrets), "withSecrets": withSecrets, "exportedAt": time.Now().UTC().Format(time.RFC3339)}, nil
}

func (d *Daemon) exportDocument(withSecrets bool) config.Document {
	cfg, sec := d.store.Snapshot()
	doc := config.Document{Config: cfg}
	if withSecrets {
		doc.Secrets = sec
		doc.Secrets.WebAccessKey = ""
	} else {
		doc.Secrets = config.DefaultSecrets()
	}
	return doc
}

// downloadDirs are the shared-storage folders used for backup files.
func downloadDirs() []string {
	dirs := []string{"/sdcard/Download", "/storage/emulated/0/Download"}
	if extra := os.Getenv("KPM_IMPORT_ROOT"); extra != "" && filepath.IsAbs(extra) {
		dirs = append(dirs, extra)
	}
	return dirs
}

// hExportBackup writes a backup file into the Download folder, because the
// root manager's WebView cannot save files itself.
func (d *Daemon) hExportBackup(_ http.ResponseWriter, r *http.Request) (any, error) {
	var body struct {
		Secrets bool `json:"secrets"`
	}
	if err := decode(r, 1024, &body); err != nil {
		return nil, err
	}
	if err := requireSecretExport(r, body.Secrets); err != nil {
		return nil, err
	}
	dir := ""
	for _, c := range downloadDirs() {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			dir = c
			break
		}
	}
	if dir == "" {
		return nil, unavailable("找不到下载目录")
	}
	b, err := json.MarshalIndent(d.exportDocument(body.Secrets), "", "  ")
	if err != nil {
		return nil, err
	}
	name := "ksu_proxy_manager-" + time.Now().Format("20060102-150405") + ".json"
	path := filepath.Join(dir, name)
	// Shared storage is FUSE/sdcardfs: chmod and directory fsync may be
	// refused there, so fall back to a plain write.
	if err := fsutil.WriteFileAtomic(path, append(b, '\n'), 0o600); err != nil {
		if werr := os.WriteFile(path, append(b, '\n'), 0o600); werr != nil {
			return nil, err
		}
	}
	d.log.Info("backup", "已导出备份", "path", path, "secrets", body.Secrets)
	return map[string]string{"path": path}, nil
}

// hBackupFiles lists backup files in the Download folders.
func (d *Daemon) hBackupFiles(_ http.ResponseWriter, _ *http.Request) (any, error) {
	type file struct {
		Path    string `json:"path"`
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		ModTime string `json:"modTime"`
	}
	seen := map[string]bool{}
	out := []file{}
	for _, dir := range downloadDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !e.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(name), ".json") || !strings.Contains(strings.ToLower(name), "ksu_proxy_manager") {
				continue
			}
			real, st, err := importPath(filepath.Join(dir, name))
			if err != nil || seen[real] {
				continue
			}
			seen[real] = true
			out = append(out, file{Path: filepath.Join(dir, name), Name: name, Size: st.Size(), ModTime: st.ModTime().UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime > out[j].ModTime })
	return map[string]any{"files": out}, nil
}

func parseDocument(raw []byte) (config.Document, error) {
	var doc config.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, badRequest("备份内容无效: %v", err)
	}
	if doc.SchemaVersion != config.SchemaVersion {
		return doc, badRequest("备份版本 %d 不受支持", doc.SchemaVersion)
	}
	return doc, nil
}

func (d *Daemon) hBackups(_ http.ResponseWriter, _ *http.Request) (any, error) {
	list, err := d.store.Backups()
	if err != nil {
		return nil, err
	}
	return map[string]any{"backups": list}, nil
}

func (d *Daemon) hRestore(_ http.ResponseWriter, r *http.Request) (any, error) {
	var body struct {
		Document *json.RawMessage `json:"document"`
		Backup   string           `json:"backup"`
		Path     string           `json:"path"`
	}
	if err := decode(r, fsutil.MaxJSONSize+(64<<10), &body); err != nil {
		return nil, err
	}
	var doc config.Document
	switch {
	case body.Backup != "":
		b, err := d.store.ReadBackup(body.Backup)
		if err != nil {
			return nil, badRequest("备份不可用: %v", err)
		}
		doc = b
	case body.Path != "":
		if err := requireLocalImport(r); err != nil {
			return nil, err
		}
		file, err := openImport(body.Path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		raw, err := fsutil.ReadOpenFileLimited(file, fsutil.MaxJSONSize)
		if err != nil {
			return nil, badRequest("无法读取备份文件: %v", err)
		}
		if doc, err = parseDocument(raw); err != nil {
			return nil, err
		}
	case body.Document != nil:
		var err error
		if doc, err = parseDocument(*body.Document); err != nil {
			return nil, err
		}
	default:
		return nil, badRequest("缺少备份内容")
	}
	_, cur := d.store.Snapshot()
	doc.Secrets.Normalize()
	// Keep current credentials for nodes/subscriptions the import lacks.
	for id, fields := range cur.Nodes {
		if _, ok := doc.Secrets.Nodes[id]; !ok {
			doc.Secrets.Nodes[id] = fields
		}
	}
	for id, u := range cur.Subscriptions {
		if _, ok := doc.Secrets.Subscriptions[id]; !ok {
			doc.Secrets.Subscriptions[id] = u
		}
	}
	doc.Secrets.WebAccessKey = cur.WebAccessKey
	next, err := d.store.Replace(expectedRev(r), doc)
	if err != nil {
		return nil, err
	}
	d.syncWebAccess()
	return d.savedResult(next), nil
}

func (d *Daemon) hSystem(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	d.webMu.Lock()
	listening := d.tcpSrv != nil
	d.webMu.Unlock()
	return map[string]any{
		"deleteDataOnUninstall": fsutil.Exists(d.layout.DeleteMarker()),
		"webAccess":             cfg.Settings.WebAccess,
		"webAccessUrl":          fmt.Sprintf("http://127.0.0.1:%d/", cfg.Settings.WebAccess.Port),
		"webAccessActive":       listening,
		"hasWebKey":             sec.WebAccessKey != "",
		"dataDir":               d.layout.DataDir,
	}, nil
}

func (d *Daemon) hPutSystem(_ http.ResponseWriter, r *http.Request) (any, error) {
	var body struct {
		DeleteDataOnUninstall *bool `json:"deleteDataOnUninstall"`
	}
	if err := decode(r, 1024, &body); err != nil {
		return nil, err
	}
	if body.DeleteDataOnUninstall != nil {
		if *body.DeleteDataOnUninstall {
			if err := fsutil.WriteFileAtomic(d.layout.DeleteMarker(), []byte("1\n"), 0o600); err != nil {
				return nil, err
			}
		} else if err := os.Remove(d.layout.DeleteMarker()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return d.hSystem(nil, r)
}

func (d *Daemon) hWebKey(_ http.ResponseWriter, _ *http.Request) (any, error) {
	key := fsutil.RandomHex(24)
	if _, err := d.store.Update(-1, func(_ *config.Config, s *config.Secrets) error {
		s.WebAccessKey = key
		return nil
	}); err != nil {
		return nil, err
	}
	d.syncWebAccess()
	return map[string]string{"key": key}, nil
}

func getprop(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getprop", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (d *Daemon) hDiagnostics(_ http.ResponseWriter, r *http.Request) (any, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	uname, _ := os.ReadFile("/proc/version")
	out := map[string]any{
		"kernel":     strings.TrimSpace(string(uname)),
		"android":    getprop("ro.build.version.release"),
		"sdk":        getprop("ro.build.version.sdk"),
		"device":     getprop("ro.product.model"),
		"abi":        d.abi,
		"tunDevice":  fsutil.Exists("/dev/net/tun") || fsutil.Exists("/dev/tun"),
		"captureAll": CaptureAllowed(),
	}
	if c, err := exec.CommandContext(ctx, "settings", "get", "global", "private_dns_mode").Output(); err == nil {
		mode := strings.TrimSpace(string(c))
		out["privateDns"] = mode
		out["privateDnsWarning"] = mode == "hostname"
	}
	rules := []string{}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		list, err := netlink.RuleList(fam)
		if err != nil {
			continue
		}
		for _, rl := range list {
			if capture.Owned(rl) {
				rules = append(rules, famLabel(fam)+capture.DescribeRule(rl))
			}
		}
	}
	out["ownedRules"] = rules
	routes := []string{}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, table := range []int{capture.Table, capture.TunTable, capture.CoreTable} {
			list, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				continue
			}
			for _, rt := range list {
				routes = append(routes, famLabel(fam)+capture.DescribeRoute(rt))
			}
		}
	}
	out["ownedRoutes"] = routes
	out["core"] = d.engine.Status()
	return out, nil
}

func famLabel(fam int) string {
	if fam == netlink.FAMILY_V6 {
		return "IPv6 "
	}
	return "IPv4 "
}

// nodeView is the public representation of a node: secret values never leave.
type nodeView struct {
	config.Node
	Secrets          map[string]bool `json:"secrets"`
	SubscriptionName string          `json:"subscriptionName,omitempty"`
}

func nodeViews(cfg config.Config, sec config.Secrets) []nodeView {
	subs := map[string]string{}
	for _, s := range cfg.Subscriptions {
		subs[s.ID] = s.Name
	}
	out := make([]nodeView, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		v := nodeView{Node: n, Secrets: map[string]bool{}, SubscriptionName: subs[n.SubscriptionID]}
		for _, f := range config.SecretFields[n.Type] {
			v.Secrets[f] = sec.NodeSecret(n.ID, f) != ""
		}
		out = append(out, v)
	}
	return out
}

type subView struct {
	config.Subscription
	URLHost   string `json:"urlHost"`
	NodeCount int    `json:"nodeCount"`
}

func subViews(cfg config.Config, sec config.Secrets) []subView {
	out := make([]subView, 0, len(cfg.Subscriptions))
	for _, s := range cfg.Subscriptions {
		v := subView{Subscription: s}
		if u := sec.Subscriptions[s.ID]; u != "" {
			if i := strings.Index(u, "://"); i >= 0 {
				host := u[i+3:]
				if j := strings.IndexAny(host, "/?#"); j >= 0 {
					host = host[:j]
				}
				if k := strings.LastIndex(host, "@"); k >= 0 {
					host = host[k+1:]
				}
				v.URLHost = host
			}
		}
		for _, n := range cfg.Nodes {
			if n.SubscriptionID == s.ID {
				v.NodeCount++
			}
		}
		out = append(out, v)
	}
	return out
}
