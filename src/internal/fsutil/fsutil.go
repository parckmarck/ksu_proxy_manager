// Package fsutil provides crash-safe file helpers shared by all components.
package fsutil

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// MaxJSONSize bounds every JSON document read from disk.
const MaxJSONSize = 32 << 20

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// SafeName reports whether s can be used as a single path segment.
func SafeName(s string) bool {
	return safeName.MatchString(s) && s != "." && s != ".."
}

// WriteFileAtomic writes data to a temporary sibling, syncs it and renames it
// over path so readers observe either the old or the new content.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func WriteJSONAtomic(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(b, '\n'), perm)
}

// ReadFileLimited reads at most limit bytes and fails if the file is larger.
func ReadFileLimited(path string, limit int64) ([]byte, error) {
	f, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadOpenFileLimited(f, limit)
}

func ReadOpenFileLimited(f *os.File, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s 超过大小上限 %d 字节", filepath.Base(f.Name()), limit)
	}
	return b, nil
}

func ReadJSON(path string, v any) error {
	b, err := ReadFileLimited(path, MaxJSONSize)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("解析 %s 失败: %w", filepath.Base(path), err)
	}
	return nil
}

func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func RandomHex(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// CopyFile copies a regular file without following a symlink at src.
func CopyFile(src, dst string, perm os.FileMode) error {
	in, err := OpenRegular(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return CopyOpenFile(in, dst, perm, 0)
}

func CopyOpenFile(in *os.File, dst string, perm os.FileMode, limit int64) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	var reader io.Reader = in
	if limit > 0 {
		reader = io.LimitReader(in, limit+1)
	}
	n, err := io.Copy(out, reader)
	if err == nil && limit > 0 && n > limit {
		err = errors.New("源文件超过大小上限")
	}
	if err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

func regularFile(fd int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("源文件不是普通文件")
	}
	return file, nil
}

// O_NONBLOCK also prevents a swapped FIFO from blocking before fstat.
func OpenRegular(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return regularFile(fd, path)
}

// OpenWithin anchors every directory component to an open directory handle.
// Replacing any component with a symlink cannot redirect the import outside
// the trusted roots between path validation and reading.
func OpenWithin(path string, roots []string) (*os.File, error) {
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			continue
		}
		fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(relative, string(filepath.Separator))
		for i, part := range parts {
			flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
			if i < len(parts)-1 {
				flags |= unix.O_DIRECTORY
			}
			next, openErr := unix.Openat(fd, part, flags, 0)
			unix.Close(fd)
			if openErr != nil {
				return nil, openErr
			}
			fd = next
		}
		return regularFile(fd, path)
	}
	return nil, errors.New("文件不在允许的导入目录内")
}

// Lock is an exclusive advisory lock held on an open file.
type Lock struct{ f *os.File }

// TryLock acquires an exclusive flock without blocking.
func TryLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
