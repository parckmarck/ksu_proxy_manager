// Package cores manages installed proxy core binaries: official releases,
// local imports, archive extraction, ELF/ABI checks and integrity records.
package cores

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/supervisor"
)

const (
	maxEntrySize = 256 << 20
	maxTotalSize = 512 << 20
	maxEntries   = 64
)

type Installation struct {
	Engine       string `json:"engine"`
	Version      string `json:"version"`
	ABI          string `json:"abi"`
	Source       string `json:"source"`
	ReleaseAsset string `json:"releaseAsset,omitempty"`
	SHA256       string `json:"sha256"`
	AssetSHA256  string `json:"assetSha256,omitempty"`
	Verification string `json:"verification"`
	RelativePath string `json:"relativePath"`
	InstalledAt  string `json:"installedAt"`
}

type index struct {
	SchemaVersion int            `json:"schemaVersion"`
	Items         []Installation `json:"items"`
}

type Registry struct {
	layout paths.Layout
	mu     sync.Mutex
}

func NewRegistry(l paths.Layout) *Registry { return &Registry{layout: l} }

func (r *Registry) load() (index, error) {
	var idx index
	err := fsutil.ReadJSON(r.layout.CoreIndex(), &idx)
	if errors.Is(err, os.ErrNotExist) {
		return index{SchemaVersion: 1, Items: []Installation{}}, nil
	}
	if err != nil {
		return idx, err
	}
	if idx.SchemaVersion != 1 {
		return idx, fmt.Errorf("不支持的核心索引版本 %d", idx.SchemaVersion)
	}
	if idx.Items == nil {
		idx.Items = []Installation{}
	}
	return idx, nil
}

func (r *Registry) save(idx index) error {
	sort.Slice(idx.Items, func(i, j int) bool {
		a, b := idx.Items[i], idx.Items[j]
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		return VersionLess(b.Version, a.Version)
	})
	return fsutil.WriteJSONAtomic(r.layout.CoreIndex(), idx, 0o600)
}

func relPath(engine, version, abi string) string {
	return filepath.Join("cores", engine, version, abi, "core")
}

func (r *Registry) List() ([]Installation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx, err := r.load()
	if err != nil {
		return nil, err
	}
	out := []Installation{}
	for _, it := range idx.Items {
		if fsutil.Exists(filepath.Join(r.layout.DataDir, relPath(it.Engine, it.Version, it.ABI))) {
			out = append(out, it)
		}
	}
	return out, nil
}

// Resolve finds an installation; an empty version selects the newest one.
func (r *Registry) Resolve(engine, version, abi string) (Installation, error) {
	items, err := r.List()
	if err != nil {
		return Installation{}, err
	}
	var best *Installation
	for i := range items {
		it := &items[i]
		if it.Engine != engine || (abi != "" && it.ABI != abi) {
			continue
		}
		if version != "" {
			if it.Version == version {
				return *it, nil
			}
			continue
		}
		if best == nil || VersionLess(best.Version, it.Version) {
			best = it
		}
	}
	if best == nil {
		if version != "" {
			return Installation{}, fmt.Errorf("%s %s 未安装", engine, version)
		}
		return Installation{}, fmt.Errorf("尚未安装 %s 核心，请先在“核心”页下载或导入", engine)
	}
	return *best, nil
}

// Verify re-hashes an installed binary and returns its absolute path.
func (r *Registry) Verify(it Installation) (string, error) {
	if !fsutil.SafeName(it.Engine) || !fsutil.SafeName(it.Version) || !fsutil.SafeName(it.ABI) {
		return "", errors.New("核心索引包含不安全的路径段")
	}
	p := filepath.Join(r.layout.DataDir, relPath(it.Engine, it.Version, it.ABI))
	st, err := os.Lstat(p)
	if err != nil {
		return "", fmt.Errorf("核心文件缺失: %w", err)
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("核心文件不是普通文件")
	}
	sum, err := FileSHA256(p)
	if err != nil {
		return "", err
	}
	if it.SHA256 != "" && !strings.EqualFold(sum, it.SHA256) {
		return "", fmt.Errorf("核心文件摘要与安装记录不一致（可能已被篡改或损坏），请重新安装")
	}
	_ = os.Chmod(p, 0o700)
	return p, nil
}

// Install copies a verified binary into the managed directory.
func (r *Registry) Install(binary string, info Installation) (Installation, error) {
	if !fsutil.SafeName(info.Engine) || !fsutil.SafeName(info.Version) || !fsutil.SafeName(info.ABI) {
		return info, errors.New("引擎、版本或 ABI 不能用作路径")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx, err := r.load()
	if err != nil {
		return info, err
	}
	sum, err := FileSHA256(binary)
	if err != nil {
		return info, err
	}
	info.SHA256 = sum
	info.RelativePath = relPath(info.Engine, info.Version, info.ABI)
	info.InstalledAt = time.Now().UTC().Format(time.RFC3339)
	dir := filepath.Join(r.layout.DataDir, filepath.Dir(info.RelativePath))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return info, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dir), ".install-")
	if err != nil {
		return info, err
	}
	defer os.RemoveAll(tmp)
	if err := fsutil.CopyFile(binary, filepath.Join(tmp, "core"), 0o700); err != nil {
		return info, err
	}
	if err := os.Rename(filepath.Join(tmp, "core"), filepath.Join(dir, "core")); err != nil {
		return info, err
	}
	items := idx.Items[:0]
	for _, it := range idx.Items {
		if !(it.Engine == info.Engine && it.Version == info.Version && it.ABI == info.ABI) {
			items = append(items, it)
		}
	}
	idx.Items = append(items, info)
	if err := r.save(idx); err != nil {
		return info, err
	}
	return info, nil
}

func (r *Registry) Delete(engine, version, abi string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx, err := r.load()
	if err != nil {
		return err
	}
	found := false
	items := idx.Items[:0]
	for _, it := range idx.Items {
		if it.Engine == engine && it.Version == version && it.ABI == abi {
			found = true
			continue
		}
		items = append(items, it)
	}
	if !found {
		return os.ErrNotExist
	}
	idx.Items = items
	if err := r.save(idx); err != nil {
		return err
	}
	if fsutil.SafeName(engine) && fsutil.SafeName(version) && fsutil.SafeName(abi) {
		_ = os.RemoveAll(filepath.Join(r.layout.CoresDir(), engine, version, abi))
		_ = os.Remove(filepath.Join(r.layout.CoresDir(), engine, version))
	}
	return nil
}

func FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ABIMachine maps Android ABIs to ELF machine types.
var ABIMachine = map[string]elf.Machine{
	"arm64-v8a":   elf.EM_AARCH64,
	"x86_64":      elf.EM_X86_64,
	"armeabi-v7a": elf.EM_ARM,
	"x86":         elf.EM_386,
}

// CheckELF verifies that p is an executable ELF for abi.
func CheckELF(p, abi string) error {
	f, err := elf.Open(p)
	if err != nil {
		return errors.New("文件不是 ELF 可执行文件")
	}
	defer f.Close()
	want, ok := ABIMachine[abi]
	if !ok {
		return fmt.Errorf("未知 ABI %s", abi)
	}
	if f.Machine != want {
		return fmt.Errorf("核心架构 %s 与设备 ABI %s 不匹配", f.Machine, abi)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return errors.New("ELF 文件不是可执行程序")
	}
	return nil
}

// Extract unpacks gz / tar.gz / zip archives or copies a bare ELF into dir and
// returns the path of the single candidate executable.
func Extract(src, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	head, _ := br.Peek(4)
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return "", fmt.Errorf("gzip 无效: %w", err)
		}
		defer gz.Close()
		gb := bufio.NewReaderSize(gz, 1024)
		hdr, _ := gb.Peek(512)
		if len(hdr) >= 262 && string(hdr[257:262]) == "ustar" {
			return extractTar(gb, dir)
		}
		return writeCandidate(gb, filepath.Join(dir, "core"))
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		_ = f.Close()
		return extractZip(src, dir)
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return writeCandidate(br, filepath.Join(dir, "core"))
	}
	return "", errors.New("不支持的文件格式（支持 .gz、.tar.gz、.zip 或 ELF）")
}

func writeCandidate(r io.Reader, dst string) (string, error) {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(out, io.LimitReader(r, maxEntrySize+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxEntrySize {
		return "", errors.New("解压后文件超过 256 MiB 上限")
	}
	return dst, nil
}

func safeEntry(name string) bool {
	clean := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	return clean != "." && !strings.HasPrefix(clean, "/") && !strings.HasPrefix(clean, "../") && clean != ".." && !strings.ContainsRune(name, 0)
}

var (
	coreNameRE  = regexp.MustCompile(`(?i)^(mihomo|sing-box|clash)([.-].*)?$`)
	sharedLibRE = regexp.MustCompile(`\.so(\.\d+)*$`)
)

// extracted is an archive member written to disk under a unique name.
type extracted struct {
	path string
	name string
}

func pickCandidate(files []extracted) (string, error) {
	var elfs []extracted
	for _, f := range files {
		if sharedLibRE.MatchString(f.name) {
			continue
		}
		if fh, err := os.Open(f.path); err == nil {
			magic := make([]byte, 4)
			_, _ = io.ReadFull(fh, magic)
			fh.Close()
			if bytes.Equal(magic, []byte("\x7fELF")) {
				elfs = append(elfs, f)
			}
		}
	}
	if len(elfs) == 1 {
		return elfs[0].path, nil
	}
	var named []string
	for _, f := range elfs {
		if coreNameRE.MatchString(f.name) {
			named = append(named, f.path)
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(elfs) == 0 {
		return "", errors.New("归档中没有可执行文件")
	}
	return "", errors.New("归档中包含多个可执行文件，无法确定核心")
}

func extractTar(r io.Reader, dir string) (string, error) {
	tr := tar.NewReader(r)
	var files []extracted
	var total int64
	for i := 0; ; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar 无效: %w", err)
		}
		if i >= maxEntries {
			return "", errors.New("归档条目过多")
		}
		if !safeEntry(h.Name) {
			return "", fmt.Errorf("归档包含不安全路径 %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return "", fmt.Errorf("归档包含不支持的条目类型 %q", h.Name)
		}
		if h.Size > maxEntrySize {
			return "", errors.New("归档条目超过 256 MiB")
		}
		total += h.Size
		if total > maxTotalSize {
			return "", errors.New("归档总大小超过上限")
		}
		dst := filepath.Join(dir, fmt.Sprintf("%02d-%s", i, filepath.Base(h.Name)))
		if _, err := writeCandidate(tr, dst); err != nil {
			return "", err
		}
		files = append(files, extracted{path: dst, name: path.Base(h.Name)})
	}
	return pickCandidate(files)
}

func extractZip(src, dir string) (string, error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return "", fmt.Errorf("zip 无效: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > maxEntries {
		return "", errors.New("归档条目过多")
	}
	var files []extracted
	var total uint64
	for i, zf := range zr.File {
		if !safeEntry(zf.Name) {
			return "", fmt.Errorf("归档包含不安全路径 %q", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			continue
		}
		if !zf.Mode().IsRegular() {
			return "", fmt.Errorf("归档包含不支持的条目类型 %q", zf.Name)
		}
		total += zf.UncompressedSize64
		if zf.UncompressedSize64 > maxEntrySize || total > maxTotalSize {
			return "", errors.New("归档内容超过大小上限")
		}
		rc, err := zf.Open()
		if err != nil {
			return "", err
		}
		dst := filepath.Join(dir, fmt.Sprintf("%02d-%s", i, filepath.Base(zf.Name)))
		_, err = writeCandidate(rc, dst)
		rc.Close()
		if err != nil {
			return "", err
		}
		files = append(files, extracted{path: dst, name: path.Base(strings.ReplaceAll(zf.Name, "\\", "/"))})
	}
	return pickCandidate(files)
}

var (
	mihomoVer  = regexp.MustCompile(`(?i)mihomo[^\n]*?\b(alpha-[0-9a-f]{4,40}|v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*)`)
	singboxVer = regexp.MustCompile(`(?i)sing-box version (\d+\.\d+\.\d+[0-9A-Za-z.+-]*)`)
)

// ParseVersion identifies the engine and version from version-command output.
func ParseVersion(out string) (engine, version string, err error) {
	if m := singboxVer.FindStringSubmatch(out); m != nil {
		return config.EngineSingBox, m[1], nil
	}
	if m := mihomoVer.FindStringSubmatch(out); m != nil {
		return config.EngineMihomo, strings.TrimPrefix(m[1], "v"), nil
	}
	return "", "", errors.New("无法从核心输出识别类型与版本")
}

// Probe runs the binary's version command in a scratch directory.
func Probe(ctx context.Context, bin string) (engine, version string, err error) {
	dir, err := os.MkdirTemp(filepath.Dir(bin), ".probe-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(bin, 0o700)
	var lastOut string
	// "-v" first: Mihomo ignores unknown positional arguments and would start
	// serving with "version", while sing-box rejects "-v" immediately.
	for _, args := range [][]string{{"-v"}, {"version"}} {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, _ := supervisor.Run(c, bin, args, dir, []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/system/bin:/usr/bin:/bin"}, 4096)
		cancel()
		lastOut = out
		if e, v, err := ParseVersion(lastOut); err == nil {
			if !fsutil.SafeName(v) {
				return "", "", fmt.Errorf("版本号 %q 不安全", v)
			}
			return e, v, nil
		}
	}
	return "", "", fmt.Errorf("无法识别核心版本: %s", strings.TrimSpace(firstLine(lastOut)))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// VersionLess compares dotted numeric versions.
func VersionLess(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return a < b
}

func parts(s string) [3]int {
	var out [3]int
	s = strings.TrimPrefix(s, "v")
	for i, p := range strings.SplitN(s, ".", 3) {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out[i] = n
	}
	return out
}
