package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/engine"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/render"
)

type releaseCache struct {
	at   time.Time
	list []cores.Release
}

func (d *Daemon) hCores(_ http.ResponseWriter, _ *http.Request) (any, error) {
	list, err := d.cores.List()
	if err != nil {
		return nil, err
	}
	cfg, _ := d.store.Snapshot()
	st := d.engine.Status()
	return map[string]any{"installed": list, "abi": d.abi, "engine": cfg.Settings.Engine, "selected": cfg.Settings.CoreVersions,
		"running": map[string]string{"engine": st.Engine, "version": st.Version}}, nil
}

func validEngine(e string) bool { return e == config.EngineMihomo || e == config.EngineSingBox }

func (d *Daemon) releases(ctx context.Context, eng string, pre bool) ([]cores.Release, error) {
	key := fmt.Sprintf("%s/%v", eng, pre)
	d.mu.Lock()
	if c, ok := d.relCache[key]; ok && time.Since(c.at) < 10*time.Minute {
		d.mu.Unlock()
		return c.list, nil
	}
	d.mu.Unlock()
	cfg, _ := d.store.Snapshot()
	clients, err := d.clients(cfg.Settings.Download.Mode, false, false, time.Minute)
	if err != nil {
		return nil, err
	}
	var list []cores.Release
	err = tryClients(ctx, clients, func(c *http.Client) error {
		var err error
		list, err = cores.ListReleases(ctx, c, eng, d.abi, pre)
		return err
	})
	if err != nil {
		return nil, unavailable("获取版本列表失败: " + err.Error())
	}
	d.mu.Lock()
	d.relCache[key] = releaseCache{at: time.Now(), list: list}
	d.mu.Unlock()
	return list, nil
}

func (d *Daemon) hReleases(_ http.ResponseWriter, r *http.Request) (any, error) {
	eng := r.URL.Query().Get("engine")
	if !validEngine(eng) {
		return nil, badRequest("未知核心")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	list, err := d.releases(ctx, eng, r.URL.Query().Get("pre") == "1")
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []cores.Release{}
	}
	return map[string]any{"releases": list, "minVersion": render.MinVersion[eng]}, nil
}

// stagingDir creates a private scratch directory for one download/import.
func (d *Daemon) stagingDir() (string, error) {
	if err := os.MkdirAll(d.layout.StagingDir(), 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(d.layout.StagingDir(), "core-")
}

// installCandidate extracts, checks and installs a core archive or binary.
func (d *Daemon) installCandidate(ctx context.Context, src, dir, wantEngine string, info cores.Installation) (cores.Installation, error) {
	bin, err := cores.Extract(src, filepath.Join(dir, "x"))
	if err != nil {
		return info, err
	}
	if err := cores.CheckELF(bin, d.abi); err != nil {
		return info, err
	}
	if err := os.Chmod(bin, 0o700); err != nil {
		return info, err
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	eng, ver, err := cores.Probe(pctx, bin)
	cancel()
	if err != nil {
		return info, fmt.Errorf("无法识别核心版本: %w", err)
	}
	if wantEngine != "" && eng != wantEngine {
		return info, fmt.Errorf("文件是 %s 而不是 %s", eng, wantEngine)
	}
	if !fsutil.SafeName(ver) {
		return info, fmt.Errorf("核心版本号 %q 无效", ver)
	}
	if render.VersionLess(ver, render.MinVersion[eng]) {
		return info, fmt.Errorf("%s %s 过旧，至少需要 %s", eng, ver, render.MinVersion[eng])
	}
	info.Engine, info.Version, info.ABI = eng, ver, d.abi
	return d.cores.Install(bin, info)
}

func (d *Daemon) hDownloadCore(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b struct {
		Engine string `json:"engine"`
		Tag    string `json:"tag"`
	}
	if err := decode(r, 1024, &b); err != nil {
		return nil, err
	}
	if !validEngine(b.Engine) {
		return nil, badRequest("未知核心")
	}
	if b.Tag != "" && !fsutil.SafeName(b.Tag) {
		return nil, badRequest("版本标签无效")
	}
	return d.tasks.Start(d.ctx, "core-download", func(ctx context.Context, t *TaskHandle) (any, error) {
		t.Progress("正在查询版本", 0, 0)
		list, err := d.releases(ctx, b.Engine, true)
		if err != nil {
			return nil, err
		}
		var rel *cores.Release
		for i := range list {
			if (b.Tag == "" && !list[i].Prerelease) || list[i].Tag == b.Tag {
				rel = &list[i]
				break
			}
		}
		if rel == nil || rel.Asset == nil {
			return nil, fmt.Errorf("没有找到适用于 %s 的 %s 版本 %s", d.abi, b.Engine, b.Tag)
		}
		if !fsutil.SafeName(rel.Asset.Name) {
			return nil, fmt.Errorf("发布资产名称异常: %q", rel.Asset.Name)
		}
		dir, err := d.stagingDir()
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		cfg, _ := d.store.Snapshot()
		clients, err := d.clients(cfg.Settings.Download.Mode, false, false, 0)
		if err != nil {
			return nil, err
		}
		urls := []string{rel.Asset.URL}
		if m := cfg.Settings.Download.GitHubMirror; m != "" {
			urls = append([]string{strings.TrimRight(m, "/") + "/" + rel.Asset.URL}, urls...)
		}
		dst := filepath.Join(dir, rel.Asset.Name)
		var errs []string
		ok := false
		for _, u := range urls {
			err := tryClients(ctx, clients, func(c *http.Client) error {
				return cores.Download(ctx, c, u, rel.Asset.Digest, rel.Asset.Size, dst, func(p cores.Progress) {
					t.Progress("正在下载 "+rel.Asset.Name, p.Done, p.Total)
				})
			})
			if err == nil {
				ok = true
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, err.Error())
		}
		if !ok {
			return nil, errors.New("下载失败: " + strings.Join(errs, "；"))
		}
		t.Progress("正在校验并安装", 0, 0)
		_, digest, _ := strings.Cut(rel.Asset.Digest, ":")
		info, err := d.installCandidate(ctx, dst, dir, b.Engine, cores.Installation{
			Source: "official", ReleaseAsset: rel.Asset.Name, AssetSHA256: strings.ToLower(digest), Verification: "github-digest",
		})
		if err != nil {
			return nil, err
		}
		d.log.Info("core", "核心已安装", "engine", info.Engine, "version", info.Version, "asset", rel.Asset.Name)
		return info, nil
	})
}

var coreFileRE = regexp.MustCompile(`(?i)(mihomo|clash|sing-box|singbox)`)

var importRoots = []string{"/sdcard", "/storage/emulated/0", "/data/local/tmp"}

func resolvedRoots() []string {
	var out []string
	for _, r := range importRoots {
		if p, err := filepath.EvalSymlinks(r); err == nil {
			out = append(out, p)
		}
	}
	if extra := os.Getenv("KPM_IMPORT_ROOT"); extra != "" && filepath.IsAbs(extra) {
		if p, err := filepath.EvalSymlinks(extra); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// importPath checks that p is a regular file below an allowed root.
func importPath(p string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(p) || len(p) > 1024 {
		return "", nil, badRequest("请提供绝对路径")
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(p))
	if err != nil {
		return "", nil, badRequest("文件不存在")
	}
	allowed := false
	for _, root := range resolvedRoots() {
		if strings.HasPrefix(real, root+string(filepath.Separator)) {
			allowed = true
		}
	}
	if !allowed {
		return "", nil, badRequest("只能从内部存储或 /data/local/tmp 导入")
	}
	st, err := os.Lstat(real)
	if err != nil || !st.Mode().IsRegular() {
		return "", nil, badRequest("不是普通文件")
	}
	if st.Size() > 256<<20 {
		return "", nil, badRequest("文件过大")
	}
	return real, st, nil
}

func openImport(path string) (*os.File, error) {
	real, _, err := importPath(path)
	if err != nil {
		return nil, err
	}
	file, err := fsutil.OpenWithin(real, resolvedRoots())
	if err != nil {
		return nil, badRequest("无法安全打开导入文件: %v", err)
	}
	info, err := file.Stat()
	if err != nil || info.Size() > 256<<20 {
		file.Close()
		return nil, badRequest("导入文件无效或过大")
	}
	return file, nil
}

func (d *Daemon) hCoreFiles(_ http.ResponseWriter, _ *http.Request) (any, error) {
	type file struct {
		Path    string `json:"path"`
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		ModTime string `json:"modTime"`
	}
	seen := map[string]bool{}
	var out []file
	for _, dir := range []string{"/sdcard/Download", "/storage/emulated/0/Download", "/data/local/tmp"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || !coreFileRE.MatchString(e.Name()) {
				continue
			}
			real, st, err := importPath(filepath.Join(dir, e.Name()))
			if err != nil || seen[real] {
				continue
			}
			seen[real] = true
			out = append(out, file{Path: filepath.Join(dir, e.Name()), Name: e.Name(), Size: st.Size(), ModTime: st.ModTime().UTC().Format(time.RFC3339)})
			if len(out) >= 100 {
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime > out[j].ModTime })
	if out == nil {
		out = []file{}
	}
	return map[string]any{"files": out}, nil
}

func (d *Daemon) hImportCore(_ http.ResponseWriter, r *http.Request) (any, error) {
	if err := requireLocalImport(r); err != nil {
		return nil, err
	}
	var b struct {
		Path string `json:"path"`
	}
	if err := decode(r, 4096, &b); err != nil {
		return nil, err
	}
	real, _, err := importPath(b.Path)
	if err != nil {
		return nil, err
	}
	return d.tasks.Start(d.ctx, "core-import", func(ctx context.Context, t *TaskHandle) (any, error) {
		file, err := openImport(real)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		t.Progress("正在复制文件", 0, 0)
		dir, err := d.stagingDir()
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		src := filepath.Join(dir, "import-"+filepath.Base(real))
		if err := fsutil.CopyOpenFile(file, src, 0o600, 256<<20); err != nil {
			return nil, err
		}
		sum, err := cores.FileSHA256(src)
		if err != nil {
			return nil, err
		}
		t.Progress("正在校验并安装", 0, 0)
		info, err := d.installCandidate(ctx, src, dir, "", cores.Installation{
			Source: "local", ReleaseAsset: filepath.Base(real), AssetSHA256: sum, Verification: "local-unverified",
		})
		if err != nil {
			return nil, err
		}
		d.log.Info("core", "已导入本地核心", "engine", info.Engine, "version", info.Version, "file", filepath.Base(real))
		return info, nil
	})
}

func (d *Daemon) hDeleteCore(_ http.ResponseWriter, r *http.Request) (any, error) {
	eng, ver := r.PathValue("engine"), r.PathValue("version")
	if !validEngine(eng) || !fsutil.SafeName(ver) {
		return nil, badRequest("参数无效")
	}
	// Cores of another ABI (e.g. left by a release that ran them through a
	// translator) are unusable here but must remain removable.
	abi := r.URL.Query().Get("abi")
	if abi == "" {
		abi = d.abi
	} else if _, ok := cores.ABIMachine[abi]; !ok {
		return nil, badRequest("ABI 无效")
	}
	st := d.engine.Status()
	if abi == d.abi && st.Engine == eng && st.Version == ver && st.State != engine.StateStopped && st.State != engine.StateFailed && st.State != engine.StateDisabled {
		return nil, badRequest("该核心正在使用，请先停止")
	}
	if err := d.cores.Delete(eng, ver, abi); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNotFound
		}
		return nil, err
	}
	if abi != d.abi {
		return map[string]bool{"ok": true}, nil
	}
	cfg, _ := d.store.Snapshot()
	if cfg.Settings.CoreVersions[eng] == ver {
		_, _ = d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
			delete(c.Settings.CoreVersions, eng)
			return nil
		})
	}
	return map[string]bool{"ok": true}, nil
}

func (d *Daemon) hRulesets(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, _ := d.store.Snapshot()
	needed := neededRulesets(cfg)
	var missing []render.RulesetID
	lookup := d.rulesets.Lookup(cfg.Settings.Engine)
	for _, id := range needed {
		if _, ok := lookup(id); !ok {
			missing = append(missing, id)
		}
	}
	if needed == nil {
		needed = []render.RulesetID{}
	}
	if missing == nil {
		missing = []render.RulesetID{}
	}
	return map[string]any{"installed": d.rulesets.List(), "needed": needed, "missing": missing, "engine": cfg.Settings.Engine,
		"autoUpdate": cfg.Settings.RulesetAutoUpdate}, nil
}

func (d *Daemon) hUpdateRulesets(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b struct {
		Engine  string `json:"engine"`
		Missing bool   `json:"missingOnly"`
	}
	if err := decode(r, 1024, &b); err != nil {
		return nil, err
	}
	cfg, _ := d.store.Snapshot()
	if b.Engine == "" {
		b.Engine = cfg.Settings.Engine
	}
	if !validEngine(b.Engine) {
		return nil, badRequest("未知核心")
	}
	ids := neededRulesets(cfg)
	if b.Missing {
		lookup := d.rulesets.Lookup(b.Engine)
		var only []render.RulesetID
		for _, id := range ids {
			if _, ok := lookup(id); !ok {
				only = append(only, id)
			}
		}
		ids = only
	}
	return d.tasks.Start(d.ctx, "rulesets", func(ctx context.Context, t *TaskHandle) (any, error) {
		if len(ids) == 0 {
			return map[string]int{"updated": 0}, nil
		}
		t.Progress("正在下载规则集", 0, int64(len(ids)))
		if err := d.downloadRulesets(ctx, b.Engine, ids); err != nil {
			return nil, err
		}
		d.reloadRulesets(ctx, ids)
		d.engine.RulesetsUpdated()
		return map[string]int{"updated": len(ids)}, nil
	})
}
