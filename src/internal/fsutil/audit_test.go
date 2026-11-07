package fsutil

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestImportHandleRejectsSymlinksAndSurvivesPathReplacement(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(outside, []byte("private-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "nested")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "core")
	if err := os.WriteFile(path, []byte("original-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := OpenWithin(path, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenWithin(path, []string{root}); err == nil {
		f.Close()
		t.Fatal("leaf symlink was followed")
	}
	data, err := io.ReadAll(handle)
	if err != nil || string(data) != "original-data" {
		t.Fatal("opened handle was redirected by path replacement", err)
	}
	if err := os.Rename(dir, dir+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), dir); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenWithin(filepath.Join(dir, "private"), []string{root}); err == nil {
		f.Close()
		t.Fatal("intermediate symlink was followed")
	}
	if f, err := OpenWithin(outside, []string{root}); err == nil {
		f.Close()
		t.Fatal("file outside import roots was accepted")
	}
}

func TestImportRejectsFIFOAndBoundsCopiedContent(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegular(fifo); err == nil {
		f.Close()
		t.Fatal("FIFO was accepted as a regular import")
	}
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRegular(source)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dest := filepath.Join(root, "copy")
	if err := CopyOpenFile(f, dest, 0o600, 5); err == nil {
		t.Fatal("copy exceeded its bound")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("oversized partial import remained", err)
	}
}
