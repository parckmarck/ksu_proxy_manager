// Package store persists the configuration document with revisions and backups.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
)

const maxBackups = 10

// ConflictError is returned when the caller's expected revision is stale.
type ConflictError struct{ Expected, Actual int64 }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("配置已被修改（期望修订 %d，当前 %d），请刷新后重试", e.Expected, e.Actual)
}

type Store struct {
	layout paths.Layout
	mu     sync.Mutex
	doc    config.Document
	// LoadError is set when the file on disk could not be used; defaults are
	// served until the user restores a backup or saves new settings.
	loadError error
	notices   []string
}

// Open loads config.json, migrating 1.x data when present.
func Open(layout paths.Layout) (*Store, error) {
	if err := layout.Ensure(); err != nil {
		return nil, err
	}
	s := &Store{layout: layout}
	path := layout.ConfigFile()
	if !fsutil.Exists(path) {
		if migrated, err := s.migrateLegacy(); err != nil {
			return nil, err
		} else if migrated {
			return s, nil
		}
		s.doc = config.Document{Config: config.Default(), Secrets: config.DefaultSecrets()}
		s.doc.Normalize()
		if err := s.recoverRevision(); err != nil {
			return nil, err
		}
		if err := s.writeLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	doc, err := readDocument(path)
	if err != nil {
		s.loadError = err
		s.doc = config.Document{Config: config.Default(), Secrets: config.DefaultSecrets()}
		s.doc.Normalize()
		if doc.Revision > 0 {
			s.doc.Revision = doc.Revision
		}
		if err := s.recoverRevision(); err != nil {
			return nil, err
		}
		return s, nil
	}
	s.doc = doc
	return s, nil
}

func (s *Store) recoverRevision() error {
	if s.doc.Revision == math.MaxInt64 {
		return errors.New("配置修订号已达到上限")
	}
	backups, err := s.listBackupsLocked()
	if err != nil {
		return err
	}
	for _, backup := range backups {
		if backup.Kind != "config" || backup.Revision < s.doc.Revision {
			continue
		}
		if backup.Revision == math.MaxInt64 {
			return errors.New("备份修订号已达到上限")
		}
		s.doc.Revision = backup.Revision + 1
	}
	return nil
}

func readDocument(path string) (config.Document, error) {
	var doc config.Document
	if err := fsutil.ReadJSON(path, &doc); err != nil {
		return doc, err
	}
	if doc.SchemaVersion > config.SchemaVersion {
		return doc, fmt.Errorf("配置版本 %d 高于本程序支持的 %d", doc.SchemaVersion, config.SchemaVersion)
	}
	doc.Config.Normalize()
	doc.Secrets.Normalize()
	if err := config.Validate(&doc.Config, &doc.Secrets); err != nil {
		return doc, fmt.Errorf("配置未通过校验: %w", err)
	}
	return doc, nil
}

func (s *Store) migrateLegacy() (bool, error) {
	legacyModel := filepath.Join(s.layout.ConfigDir(), "model.json")
	raw, err := os.ReadFile(legacyModel)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	secretsPath := filepath.Join(s.layout.ConfigDir(), "secrets.json")
	secRaw, err := os.ReadFile(secretsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if err := fsutil.WriteFileAtomic(filepath.Join(s.layout.BackupDir(), "legacy-model-"+stamp+".json"), raw, 0o600); err != nil {
		return false, err
	}
	if secRaw != nil {
		if err := fsutil.WriteFileAtomic(filepath.Join(s.layout.BackupDir(), "legacy-secrets-"+stamp+".json"), secRaw, 0o600); err != nil {
			return false, err
		}
	}
	cfg, sec, warnings, err := config.MigrateV2(raw, secRaw)
	if err != nil {
		// Keep the originals untouched and start from defaults; the backups
		// above remain available for manual recovery.
		s.notices = append(s.notices, "旧版配置迁移失败，已使用默认配置: "+err.Error())
		cfg, sec = config.Default(), config.DefaultSecrets()
		cfg.Normalize()
	}
	s.notices = append(s.notices, warnings...)
	s.doc = config.Document{Config: cfg, Secrets: sec}
	if err := s.writeLocked(); err != nil {
		return false, err
	}
	_ = os.Remove(legacyModel)
	_ = os.Remove(secretsPath)
	for _, d := range []string{"generated", "staging", "runtime", "subscriptions"} {
		_ = os.RemoveAll(filepath.Join(s.layout.DataDir, d))
	}
	if len(warnings) > 0 || err != nil {
		s.notices = append(s.notices, "旧版原始文件已备份到 config/backups/legacy-*-"+stamp+".json")
	}
	return true, nil
}

func (s *Store) writeLocked() error {
	b, err := json.MarshalIndent(&s.doc, "", "  ")
	if err != nil {
		return err
	}
	// What cannot be read back at the next start must not be written.
	if len(b) >= fsutil.MaxJSONSize {
		return fmt.Errorf("配置过大（%d 字节，上限 %d），请减少节点或订阅", len(b), fsutil.MaxJSONSize)
	}
	return fsutil.WriteFileAtomic(s.layout.ConfigFile(), append(b, '\n'), 0o600)
}

// LoadError reports why the on-disk configuration was rejected, if it was.
func (s *Store) LoadError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadError
}

// Notices returns one-time migration messages.
func (s *Store) Notices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.notices...)
}

// Snapshot returns deep copies of the current configuration and secrets.
func (s *Store) Snapshot() (config.Config, config.Secrets) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return config.Clone(s.doc.Config), config.Clone(s.doc.Secrets)
}

func (s *Store) Revision() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.Revision
}

// Update applies fn to a copy, validates it and persists it atomically.
// expected < 0 skips the optimistic concurrency check.
func (s *Store) Update(expected int64, fn func(*config.Config, *config.Secrets) error) (config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected >= 0 && expected != s.doc.Revision {
		return config.Clone(s.doc.Config), &ConflictError{Expected: expected, Actual: s.doc.Revision}
	}
	next := config.Clone(s.doc)
	if err := fn(&next.Config, &next.Secrets); err != nil {
		return config.Config{}, err
	}
	return s.commitLocked(next, false)
}

// Replace installs a complete document (restore/import).
func (s *Store) Replace(expected int64, doc config.Document) (config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected >= 0 && expected != s.doc.Revision {
		return config.Clone(s.doc.Config), &ConflictError{Expected: expected, Actual: s.doc.Revision}
	}
	return s.commitLocked(config.Clone(doc), true)
}

func (s *Store) commitLocked(next config.Document, replacement bool) (config.Config, error) {
	next.SchemaVersion = config.SchemaVersion
	next.Config.Normalize()
	next.Secrets.Normalize()
	pruneSecrets(&next)
	if err := config.Validate(&next.Config, &next.Secrets); err != nil {
		return config.Config{}, err
	}
	next.Revision = s.doc.Revision
	if !replacement && s.loadError == nil && reflect.DeepEqual(next, s.doc) {
		return config.Clone(s.doc.Config), nil
	}
	contentChanged := replacement || s.loadError != nil || !reflect.DeepEqual(configContent(next), configContent(s.doc))
	if s.loadError != nil {
		// Preserve the rejected file before replacing it.
		name := "rejected-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".json"
		if err := fsutil.CopyFile(s.layout.ConfigFile(), filepath.Join(s.layout.BackupDir(), name), 0o600); err != nil {
			return config.Config{}, fmt.Errorf("无法保留损坏的配置: %w", err)
		}
	} else if contentChanged {
		if err := s.backupLocked(); err != nil {
			return config.Config{}, err
		}
	}
	if contentChanged {
		if s.doc.Revision == math.MaxInt64 {
			return config.Config{}, errors.New("配置修订号已达到上限")
		}
		next.Revision++
	}
	prev := s.doc
	s.doc = next
	if err := s.writeLocked(); err != nil {
		s.doc = prev
		return config.Config{}, err
	}
	s.loadError = nil
	return config.Clone(s.doc.Config), nil
}

// Runtime subscription metadata is persisted, but is not a user edit and
// must not invalidate previews, optimistic locks, or recovery history.
func configContent(doc config.Document) config.Document {
	doc.Subscriptions = append([]config.Subscription(nil), doc.Subscriptions...)
	for i := range doc.Subscriptions {
		doc.Subscriptions[i].UpdatedAt = ""
		doc.Subscriptions[i].LastError = ""
		doc.Subscriptions[i].Usage = nil
	}
	return doc
}

// pruneSecrets drops credentials that no longer belong to any node/subscription
// or that the node type does not use.
func pruneSecrets(doc *config.Document) {
	nodes := map[string]config.Node{}
	for _, n := range doc.Nodes {
		nodes[n.ID] = n
	}
	for id, fields := range doc.Secrets.Nodes {
		n, ok := nodes[id]
		if !ok {
			delete(doc.Secrets.Nodes, id)
			continue
		}
		allowed := map[string]bool{}
		for _, f := range config.SecretFields[n.Type] {
			allowed[f] = true
		}
		for f := range fields {
			if !allowed[f] {
				delete(fields, f)
			}
		}
		if len(fields) == 0 {
			delete(doc.Secrets.Nodes, id)
		}
	}
	subs := map[string]bool{}
	for _, s := range doc.Subscriptions {
		subs[s.ID] = true
	}
	for id := range doc.Secrets.Subscriptions {
		if !subs[id] {
			delete(doc.Secrets.Subscriptions, id)
		}
	}
}

func (s *Store) backupLocked() error {
	src := s.layout.ConfigFile()
	raw, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	name := fmt.Sprintf("config-r%08d.json", s.doc.Revision)
	if err := fsutil.WriteFileAtomic(filepath.Join(s.layout.BackupDir(), name), raw, 0o600); err != nil {
		return err
	}
	all, err := s.listBackupsLocked()
	if err != nil {
		return err
	}
	var list []BackupInfo
	for _, backup := range all {
		if backup.Kind == "config" {
			list = append(list, backup)
		}
	}
	for len(list) > maxBackups {
		if err := os.Remove(filepath.Join(s.layout.BackupDir(), list[0].Name)); err != nil {
			return err
		}
		list = list[1:]
	}
	return nil
}

type BackupInfo struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Revision int64  `json:"revision"`
	Size     int64  `json:"size"`
	Time     string `json:"time"`
	modified time.Time
}

func (s *Store) listBackupsLocked() ([]BackupInfo, error) {
	entries, err := os.ReadDir(s.layout.BackupDir())
	if err != nil {
		return nil, err
	}
	out := []BackupInfo{}
	for _, e := range entries {
		name := e.Name()
		if !fsutil.SafeName(name) || !strings.HasSuffix(name, ".json") || !e.Type().IsRegular() {
			continue
		}
		var rev int64
		kind := ""
		switch {
		case strings.HasPrefix(name, "config-r"):
			var err error
			rev, err = strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(name, "config-r"), ".json"), 10, 64)
			if err != nil || rev < 0 {
				continue
			}
			kind = "config"
		case strings.HasPrefix(name, "rejected-"):
			kind = "rejected"
		case strings.HasPrefix(name, "legacy-model-"):
			kind = "legacy"
		default:
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{Name: name, Kind: kind, Revision: rev, Size: info.Size(), Time: info.ModTime().UTC().Format(time.RFC3339), modified: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].modified.Equal(out[j].modified) {
			return out[i].Name < out[j].Name
		}
		return out[i].modified.Before(out[j].modified)
	})
	return out, nil
}

func (s *Store) Backups() ([]BackupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listBackupsLocked()
}

// ReadBackup returns a validated document from the backup directory.
func (s *Store) ReadBackup(name string) (config.Document, error) {
	if !fsutil.SafeName(name) || !strings.HasSuffix(name, ".json") {
		return config.Document{}, errors.New("备份名称无效")
	}
	if strings.HasPrefix(name, "legacy-model-") {
		model, err := fsutil.ReadFileLimited(filepath.Join(s.layout.BackupDir(), name), fsutil.MaxJSONSize)
		if err != nil {
			return config.Document{}, err
		}
		secretName := "legacy-secrets-" + strings.TrimPrefix(name, "legacy-model-")
		secrets, err := fsutil.ReadFileLimited(filepath.Join(s.layout.BackupDir(), secretName), fsutil.MaxJSONSize)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return config.Document{}, err
		}
		cfg, sec, _, err := config.MigrateV2(model, secrets)
		return config.Document{Config: cfg, Secrets: sec}, err
	}
	if !strings.HasPrefix(name, "config-r") && !strings.HasPrefix(name, "rejected-") {
		return config.Document{}, errors.New("备份名称无效")
	}
	return readDocument(filepath.Join(s.layout.BackupDir(), name))
}
