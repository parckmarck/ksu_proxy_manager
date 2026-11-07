package cores

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
)

var repos = map[string]string{
	config.EngineMihomo:  "MetaCubeX/mihomo",
	config.EngineSingBox: "SagerNet/sing-box",
}

type Asset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	URL    string `json:"url"`
}

type Release struct {
	Engine      string `json:"engine"`
	Tag         string `json:"tag"`
	Version     string `json:"version"`
	PublishedAt string `json:"publishedAt"`
	Prerelease  bool   `json:"prerelease"`
	Asset       *Asset `json:"asset,omitempty"`
}

// AssetName returns the official asset file name for engine/version/abi.
func AssetName(engine, tag, abi string) string {
	ver := strings.TrimPrefix(tag, "v")
	switch engine {
	case config.EngineMihomo:
		switch abi {
		case "arm64-v8a":
			return "mihomo-android-arm64-v8-" + tag + ".gz"
		case "x86_64":
			return "mihomo-android-amd64-" + tag + ".gz"
		}
	case config.EngineSingBox:
		switch abi {
		case "arm64-v8a":
			return "sing-box-" + ver + "-android-arm64.tar.gz"
		case "x86_64":
			return "sing-box-" + ver + "-android-amd64.tar.gz"
		}
	}
	return ""
}

type ghRelease struct {
	TagName     string `json:"tag_name"`
	Prerelease  bool   `json:"prerelease"`
	Draft       bool   `json:"draft"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		Digest string `json:"digest"`
		URL    string `json:"browser_download_url"`
	} `json:"assets"`
}

// ListReleases queries the GitHub API for the newest releases of engine.
func ListReleases(ctx context.Context, client *http.Client, engine, abi string, includePre bool) ([]Release, error) {
	repo, ok := repos[engine]
	if !ok {
		return nil, fmt.Errorf("未知核心 %s", engine)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repo+"/releases?per_page=20", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ksu_proxy_manager")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API 返回 %d", resp.StatusCode)
	}
	var raw []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("GitHub API 响应无效: %w", err)
	}
	var out []Release
	for _, r := range raw {
		if r.Draft || (r.Prerelease && !includePre) || !fsutil.SafeName(r.TagName) {
			continue
		}
		rel := Release{Engine: engine, Tag: r.TagName, Version: strings.TrimPrefix(r.TagName, "v"), PublishedAt: r.PublishedAt, Prerelease: r.Prerelease}
		want := AssetName(engine, r.TagName, abi)
		for _, a := range r.Assets {
			if a.Name == want {
				rel.Asset = &Asset{Name: a.Name, Size: a.Size, Digest: a.Digest, URL: a.URL}
			}
		}
		if rel.Asset != nil {
			out = append(out, rel)
		}
	}
	return out, nil
}

// Progress reports download state.
type Progress struct {
	Done  int64
	Total int64
}

// StallTimeout aborts a download that receives no data for this long. Large
// assets on slow links are not bounded by a total timeout.
var StallTimeout = 60 * time.Second

// Download fetches url into dst, verifying the GitHub digest ("sha256:<hex>").
func Download(ctx context.Context, client *http.Client, url, digest string, size int64, dst string, progress func(Progress)) error {
	algo, want, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" || len(want) != 64 {
		return errors.New("官方资产缺少可验证的 SHA-256 摘要，已拒绝下载")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	watchdog := time.AfterFunc(StallTimeout, func() { stalled.Store(true); cancel() })
	defer watchdog.Stop()
	fail := func(err error) error {
		if stalled.Load() {
			return fmt.Errorf("下载停滞：%s 内未收到数据", StallTimeout)
		}
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ksu_proxy_manager")
	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载返回 HTTP %d", resp.StatusCode)
	}
	total := resp.ContentLength
	if total <= 0 {
		total = size
	}
	if total > maxEntrySize {
		return errors.New("资产超过大小上限")
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 64<<10)
	last := time.Now()
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			watchdog.Reset(StallTimeout)
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return err
			}
			h.Write(buf[:n])
			done += int64(n)
			if done > maxEntrySize {
				f.Close()
				return errors.New("资产超过大小上限")
			}
			if progress != nil && time.Since(last) > 300*time.Millisecond {
				progress(Progress{Done: done, Total: total})
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fail(rerr)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if progress != nil {
		progress(Progress{Done: done, Total: total})
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA-256 不匹配（期望 %s…，实际 %s…）", want[:12], got[:12])
	}
	return nil
}
