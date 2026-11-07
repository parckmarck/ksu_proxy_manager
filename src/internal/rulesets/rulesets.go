// Package rulesets downloads and stores geosite/geoip rule sets in the binary
// formats of both cores (Mihomo .mrs and sing-box .srs).
package rulesets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/render"
)

const (
	baseURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
	maxSize = 32 << 20
)

type Entry struct {
	Engine    string `json:"engine"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	UpdatedAt string `json:"updatedAt"`
}

type Store struct {
	layout paths.Layout
	mu     sync.Mutex
}

func New(l paths.Layout) *Store { return &Store{layout: l} }

func ext(engine string) string {
	if engine == config.EngineSingBox {
		return ".srs"
	}
	return ".mrs"
}

// URL returns the upstream location of a rule set for engine.
func URL(engine string, id render.RulesetID) string {
	branch := "meta"
	if engine == config.EngineSingBox {
		branch = "sing"
	}
	return fmt.Sprintf("%s/%s/geo/%s/%s%s", baseURL, branch, id.Kind, url.PathEscape(id.Name), ext(engine))
}

// Path is the local file for a rule set.
func (s *Store) Path(engine string, id render.RulesetID) string {
	return filepath.Join(s.layout.RulesetDir(), engine, id.Tag()+ext(engine))
}

// Lookup returns a render.RulesetLookup for engine.
func (s *Store) Lookup(engine string) render.RulesetLookup {
	return func(id render.RulesetID) (string, bool) {
		if !validID(id) {
			return "", false
		}
		p := s.Path(engine, id)
		st, err := os.Stat(p)
		return p, err == nil && st.Size() > 0
	}
}

func validID(id render.RulesetID) bool {
	return (id.Kind == "geosite" || id.Kind == "geoip") && config.ValidGeoName(id.Name)
}

func validFormat(engine string, b []byte) bool {
	if engine == config.EngineSingBox {
		return bytes.HasPrefix(b, []byte("SRS"))
	}
	// Mihomo .mrs files are zstd frames.
	return bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd})
}

// Download fetches one rule set and atomically replaces the local copy.
func (s *Store) Download(ctx context.Context, client *http.Client, engine string, id render.RulesetID) error {
	if !validID(id) {
		return fmt.Errorf("规则集名称无效: %s", id.Tag())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL(engine, id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ksu_proxy_manager")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("规则集 %s 不存在", id.Tag())
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载规则集 %s 返回 HTTP %d", id.Tag(), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return err
	}
	if len(b) > maxSize {
		return errors.New("规则集超过大小上限")
	}
	if !validFormat(engine, b) {
		return fmt.Errorf("规则集 %s 内容格式无效", id.Tag())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.layout.RulesetDir(), engine)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.Path(engine, id), b, 0o600)
}

// List reports the rule sets present on disk.
func (s *Store) List() []Entry {
	out := []Entry{}
	for _, engine := range []string{config.EngineMihomo, config.EngineSingBox} {
		dir := filepath.Join(s.layout.RulesetDir(), engine)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if filepath.Ext(name) != ext(engine) {
				continue
			}
			base := name[:len(name)-len(ext(engine))]
			var kind, rn string
			for _, k := range []string{"geosite-", "geoip-"} {
				if len(base) > len(k) && base[:len(k)] == k {
					kind, rn = k[:len(k)-1], base[len(k):]
				}
			}
			if kind == "" {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, Entry{Engine: engine, Kind: kind, Name: rn, Size: info.Size(), UpdatedAt: info.ModTime().UTC().Format(time.RFC3339)})
		}
	}
	return out
}

// Age returns how long ago a rule set was written, or -1 when absent.
func (s *Store) Age(engine string, id render.RulesetID) time.Duration {
	st, err := os.Stat(s.Path(engine, id))
	if err != nil {
		return -1
	}
	return time.Since(st.ModTime())
}

// Prune deletes rule sets no longer referenced by the configuration.
func (s *Store) Prune(engine string, keep []render.RulesetID) {
	want := map[string]bool{}
	for _, id := range keep {
		want[filepath.Base(s.Path(engine, id))] = true
	}
	dir := filepath.Join(s.layout.RulesetDir(), engine)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !want[e.Name()] && filepath.Ext(e.Name()) == ext(engine) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
