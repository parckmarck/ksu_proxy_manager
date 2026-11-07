package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeName(t *testing.T) {
	for _, s := range []string{"1.19.33", "v1.14.4", "alpha-abc", "sing-box", "a_b+c"} {
		if !SafeName(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", ".", "..", "../x", "a/b", ".hidden", "a b", "x\x00"} {
		if SafeName(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestWriteAtomicAndLimits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	if err := WriteJSONAtomic(p, map[string]int{"a": 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := ReadJSON(p, &v); err != nil || v["a"] == nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatal("perm")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left: %d", len(entries))
	}
	_ = os.WriteFile(p, make([]byte, 100), 0o600)
	if _, err := ReadFileLimited(p, 10); err == nil {
		t.Fatal("limit ignored")
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(p, link)
	if err := CopyFile(link, filepath.Join(dir, "copy"), 0o600); err == nil {
		t.Fatal("symlink source copied")
	}
}

func TestTryLockExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	l1, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(p); err == nil {
		t.Fatal("second lock acquired")
	}
	l1.Release()
	l2, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	l2.Release()
}
