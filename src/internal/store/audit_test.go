package store

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
)

func TestCorruptConfigKeepsMonotonicBackupRevisions(t *testing.T) {
	l := layout(t)
	s, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		_, err = s.Update(-1, func(c *config.Config, _ *config.Secrets) error {
			c.Settings.MTU = 1400 + i
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.Backups()
	maxRevision := before[len(before)-1].Revision
	if err := os.WriteFile(l.ConfigFile(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Revision() <= maxRevision {
		t.Fatalf("recovery revision=%d must exceed existing backup revision=%d", recovered.Revision(), maxRevision)
	}
	for i := 0; i < 3; i++ {
		_, err = recovered.Update(-1, func(c *config.Config, _ *config.Secrets) error {
			c.Settings.MTU = 1500 + i
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	after, _ := recovered.Backups()
	found := false
	for _, backup := range after {
		found = found || backup.Revision > maxRevision
	}
	if !found {
		t.Fatal("new recovery backups were immediately rotated away")
	}
}

func TestSubscriptionMetadataDoesNotConsumeBackupsOrRevision(t *testing.T) {
	s, err := Open(layout(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Update(-1, func(c *config.Config, sec *config.Secrets) error {
		c.Subscriptions = append(c.Subscriptions, config.Subscription{ID: "sub", Name: "Test"})
		sec.Subscriptions["sub"] = "https://example.com/sub"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rev := s.Revision()
	before, _ := s.Backups()
	for i := 0; i < 15; i++ {
		_, err = s.Update(-1, func(c *config.Config, _ *config.Secrets) error {
			sub := c.SubscriptionByID("sub")
			sub.LastError = "offline"
			sub.UpdatedAt = "2026-11-05T12:00:00Z"
			sub.Usage = &config.Usage{Download: int64(i)}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	after, _ := s.Backups()
	if s.Revision() != rev || !reflect.DeepEqual(before, after) {
		t.Fatalf("metadata consumed user history: revision %d -> %d; backups %d -> %d",
			rev, s.Revision(), len(before), len(after))
	}
	reopened, err := Open(s.layout)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := reopened.Snapshot()
	if cfg.SubscriptionByID("sub").Usage.Download != 14 {
		t.Fatal("metadata was not persisted")
	}
}

func TestIdenticalCommitDoesNotWrite(t *testing.T) {
	s, err := Open(layout(t))
	if err != nil {
		t.Fatal(err)
	}
	rev := s.Revision()
	info, _ := os.Stat(s.layout.ConfigFile())
	if _, err := s.Update(rev, func(*config.Config, *config.Secrets) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(s.layout.ConfigFile())
	backups, _ := s.Backups()
	if s.Revision() != rev || len(backups) != 0 || !info.ModTime().Equal(after.ModTime()) {
		t.Fatal("an unchanged document caused a disk write or revision change")
	}
}

func TestExplicitRestoreStillInvalidatesPreviews(t *testing.T) {
	s, err := Open(layout(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg, sec := s.Snapshot()
	before := s.Revision()
	if _, err := s.Replace(before, config.Document{Config: cfg, Secrets: sec}); err != nil {
		t.Fatal(err)
	}
	backups, err := s.Backups()
	if err != nil || s.Revision() != before+1 || len(backups) != 1 {
		t.Fatalf("explicit restore lost its revision/backup boundary: revision=%d backups=%d error=%v", s.Revision(), len(backups), err)
	}
}

func TestInvalidConfigRetainsKnownRevision(t *testing.T) {
	for _, backupRevision := range []int64{-1, 5, 50} {
		t.Run(fmtRevision(backupRevision), func(t *testing.T) {
			l := layout(t)
			s, err := Open(l)
			if err != nil {
				t.Fatal(err)
			}
			cfg, sec := s.Snapshot()
			doc := config.Document{Config: cfg, Secrets: sec}
			doc.Revision = 42
			if backupRevision >= 0 {
				backup := config.Clone(doc)
				backup.Revision = backupRevision
				if err := fsutil.WriteJSONAtomic(filepath.Join(l.BackupDir(), fmtRevision(backupRevision)), backup, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			doc.Settings.MTU = 1
			if err := fsutil.WriteJSONAtomic(l.ConfigFile(), doc, 0o600); err != nil {
				t.Fatal(err)
			}
			recovered, err := Open(l)
			if err != nil || recovered.LoadError() == nil {
				t.Fatal("invalid document was not retained for recovery", err)
			}
			if got := recovered.Revision(); got < 42 || got <= backupRevision {
				t.Fatalf("known revision rolled back: got %d, source 42, backup %d", got, backupRevision)
			}
			if _, err := recovered.Update(-1, func(c *config.Config, _ *config.Secrets) error {
				c.Settings.MTU = 1400
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if recovered.Revision() <= 42 {
				t.Fatal("first recovery save reused a historical revision")
			}
		})
	}
}

func fmtRevision(revision int64) string {
	return fmt.Sprintf("config-r%08d.json", revision)
}

func TestInvalidConfigRevisionCannotOverflow(t *testing.T) {
	l := layout(t)
	s, err := Open(l)
	if err != nil {
		t.Fatal(err)
	}
	cfg, sec := s.Snapshot()
	doc := config.Document{Config: cfg, Secrets: sec}
	doc.Revision, doc.Settings.MTU = math.MaxInt64, 1
	if err := fsutil.WriteJSONAtomic(l.ConfigFile(), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(l); err == nil {
		t.Fatal("exhausted revision was allowed to reset or overflow")
	}
}
