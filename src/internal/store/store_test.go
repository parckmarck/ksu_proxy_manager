package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/paths"
)

func layout(t *testing.T) paths.Layout {
	dir := t.TempDir()
	return paths.Layout{ModuleDir: filepath.Join(dir, "m"), DataDir: filepath.Join(dir, "d")}
}

func TestOpenCreatesDefaults(t *testing.T) {
	l := layout(t)
	s, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(l.ConfigFile())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", st, err)
	}
	cfg, _ := s.Snapshot()
	if cfg.Settings.Engine != config.EngineMihomo {
		t.Fatal("not default")
	}
	info, _ := os.Stat(l.DataDir)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("data dir perm %v", info.Mode())
	}
}

func TestUpdateConflictBackupsAndPersistence(t *testing.T) {
	l := layout(t)
	s, _ := Open(l)
	rev := s.Revision()
	if _, err := s.Update(rev+1, func(*config.Config, *config.Secrets) error { return nil }); err == nil {
		t.Fatal("stale revision accepted")
	} else {
		var ce *ConflictError
		if !errors.As(err, &ce) {
			t.Fatalf("want conflict, got %v", err)
		}
	}
	// A failing validation leaves the stored document untouched.
	if _, err := s.Update(-1, func(c *config.Config, _ *config.Secrets) error { c.Settings.MTU = 1; return nil }); err == nil {
		t.Fatal("invalid update accepted")
	}
	if s.Revision() != rev {
		t.Fatal("revision changed on failure")
	}
	for i := 0; i < 15; i++ {
		if _, err := s.Update(-1, func(c *config.Config, _ *config.Secrets) error { c.Settings.MTU = 1400 + i; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.Backups()
	if len(list) != maxBackups {
		t.Fatalf("backups: %d", len(list))
	}
	doc, err := s.ReadBackup(list[len(list)-1].Name)
	if err != nil || doc.Settings.MTU != 1413 {
		t.Fatalf("backup content: %v %d", err, doc.Settings.MTU)
	}
	if _, err := s.ReadBackup("../config.json"); err == nil {
		t.Fatal("traversal accepted")
	}
	s2, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := s2.Snapshot()
	if cfg.Settings.MTU != 1414 || s2.Revision() != rev+15 {
		t.Fatalf("not persisted: %d rev %d", cfg.Settings.MTU, s2.Revision())
	}
}

func TestSecretsPruned(t *testing.T) {
	s, _ := Open(layout(t))
	_, err := s.Update(-1, func(c *config.Config, sec *config.Secrets) error {
		c.Nodes = append(c.Nodes, config.Node{ID: "n1", Name: "N", Type: "trojan", Server: "a.example.com", Port: 443, TLS: &config.TLS{Enabled: true}})
		sec.SetNodeSecrets("n1", map[string]string{"password": "p", "uuid": "stray"})
		sec.SetNodeSecrets("ghost", map[string]string{"password": "p"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, sec := s.Snapshot()
	if _, ok := sec.Nodes["ghost"]; ok || sec.Nodes["n1"]["uuid"] != "" {
		t.Fatalf("not pruned: %+v", sec.Nodes)
	}
}

func TestCorruptFileIsPreserved(t *testing.T) {
	l := layout(t)
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.ConfigFile(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	if s.LoadError() == nil {
		t.Fatal("no load error")
	}
	if b, _ := os.ReadFile(l.ConfigFile()); string(b) != "{broken" {
		t.Fatal("corrupt file overwritten on open")
	}
	if _, err := s.Update(-1, func(c *config.Config, _ *config.Secrets) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(l.BackupDir())
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rejected-") {
			found = true
		}
	}
	if !found || s.LoadError() != nil {
		t.Fatal("rejected file not kept or error not cleared")
	}
}

func TestLegacyMigration(t *testing.T) {
	l := layout(t)
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	model := `{"schemaVersion":2,"revision":3,"settings":{"autoStart":false,"selectedEngine":"mihomo"},"appPolicy":{"mode":"denylist","androidUserId":0,"packageNames":["com.a.b"]},
	"nodes":[{"id":"n1","name":"T","protocol":"trojan","server":"t.example.com","port":443,"credentials":{"password":"***"},"tls":{"enabled":true}}]}`
	secrets := `{"nodes":{"n1":{"password":"pw"}}}`
	_ = os.WriteFile(filepath.Join(l.ConfigDir(), "model.json"), []byte(model), 0o600)
	_ = os.WriteFile(filepath.Join(l.ConfigDir(), "secrets.json"), []byte(secrets), 0o600)
	_ = os.MkdirAll(filepath.Join(l.DataDir, "generated"), 0o700)
	s, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	cfg, sec := s.Snapshot()
	if len(cfg.Nodes) != 1 || sec.NodeSecret("n1", "password") != "pw" || cfg.Apps.Mode != "exclude" || cfg.Settings.AutoStart {
		t.Fatalf("migration: %+v", cfg)
	}
	if _, err := os.Stat(filepath.Join(l.ConfigDir(), "model.json")); !os.IsNotExist(err) {
		t.Fatal("legacy model kept")
	}
	if _, err := os.Stat(filepath.Join(l.DataDir, "generated")); !os.IsNotExist(err) {
		t.Fatal("legacy generated dir kept")
	}
	entries, _ := os.ReadDir(l.BackupDir())
	if len(entries) < 2 {
		t.Fatal("legacy originals not backed up")
	}
}
