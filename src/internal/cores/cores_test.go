package cores

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/supervisor"
)

// selfELF returns the running test binary, a valid ELF for the host ABI.
func selfELF(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Skip("no /proc/self/exe")
	}
	return b
}

func hostABI() string {
	if runtime.GOARCH == "arm64" {
		return "arm64-v8a"
	}
	return "x86_64"
}

func tarGz(t *testing.T, entries map[string][]byte, extra func(*tar.Writer)) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range entries {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	if extra != nil {
		extra(tw)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func write(t *testing.T, dir, name string, data []byte) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractFormats(t *testing.T) {
	elfBytes := selfELF(t)
	dir := t.TempDir()
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(elfBytes)
	_ = gw.Close()
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, _ := zw.Create("pkg/mihomo")
	_, _ = w.Write(elfBytes)
	w, _ = zw.Create("pkg/README.md")
	_, _ = w.Write([]byte("doc"))
	_ = zw.Close()
	ok := map[string][]byte{
		"bare":  elfBytes,
		"gz":    gzBuf.Bytes(),
		"targz": tarGz(t, map[string][]byte{"sing-box-1.0/sing-box": elfBytes, "sing-box-1.0/libcronet.so": elfBytes, "sing-box-1.0/LICENSE": []byte("x")}, nil),
		"zip":   zipBuf.Bytes(),
	}
	for name, data := range ok {
		src := write(t, dir, name+".in", data)
		out, err := Extract(src, filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := CheckELF(out, hostABI()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := map[string][]byte{
		"text":      []byte("hello"),
		"traversal": tarGz(t, map[string][]byte{"../evil": elfBytes}, nil),
		"absolute":  tarGz(t, map[string][]byte{"/etc/evil": elfBytes}, nil),
		"symlink": tarGz(t, map[string][]byte{"sing-box": elfBytes}, func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		}),
		"ambiguous": tarGz(t, map[string][]byte{"a": elfBytes, "b": elfBytes}, nil),
		"no-elf":    tarGz(t, map[string][]byte{"README": []byte("x")}, nil),
	}
	for name, data := range bad {
		src := write(t, dir, name+".in", data)
		if _, err := Extract(src, filepath.Join(dir, name)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := CheckELF(write(t, dir, "x.txt", []byte("no")), hostABI()); err == nil {
		t.Fatal("non-ELF accepted")
	}
	other := "arm64-v8a"
	if hostABI() == other {
		other = "x86_64"
	}
	if err := CheckELF(filepath.Join(dir, "bare", "core"), other); err == nil {
		t.Fatal("ABI mismatch accepted")
	}
}

func TestParseVersion(t *testing.T) {
	cases := map[string][2]string{
		"Mihomo Meta v1.19.33 linux amd64 with go1.25.1 Mon Oct 20 2026":        {"mihomo", "1.19.33"},
		"Mihomo Meta alpha-a1b2c3d android arm64 with go1.25.1":                 {"mihomo", "alpha-a1b2c3d"},
		"sing-box version 1.14.4\n\nEnvironment: go1.25.3 linux/amd64\nTags: x": {"sing-box", "1.14.4"},
		"sing-box version 1.15.0-alpha.3\n":                                     {"sing-box", "1.15.0-alpha.3"},
	}
	for in, want := range cases {
		e, v, err := ParseVersion(in)
		if err != nil || e != want[0] || v != want[1] {
			t.Errorf("%q: %s %s %v", in, e, v, err)
		}
	}
	if _, _, err := ParseVersion("Clash v1.0"); err == nil {
		t.Error("unknown accepted")
	}
}

func TestRegistry(t *testing.T) {
	dir := t.TempDir()
	l := paths.Layout{ModuleDir: filepath.Join(dir, "m"), DataDir: filepath.Join(dir, "d")}
	_ = l.Ensure()
	r := NewRegistry(l)
	bin := write(t, dir, "core", selfELF(t))
	for _, v := range []string{"1.19.2", "1.19.10"} {
		if _, err := r.Install(bin, Installation{Engine: "mihomo", Version: v, ABI: hostABI(), Source: "local"}); err != nil {
			t.Fatal(err)
		}
	}
	it, err := r.Resolve("mihomo", "", hostABI())
	if err != nil || it.Version != "1.19.10" {
		t.Fatalf("newest: %+v %v", it, err)
	}
	if _, err := r.Resolve("sing-box", "", hostABI()); err == nil {
		t.Fatal("missing engine resolved")
	}
	p, err := r.Verify(it)
	if err != nil {
		t.Fatal(err)
	}
	// Tampering is detected.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write([]byte("x"))
	f.Close()
	if _, err := r.Verify(it); err == nil {
		t.Fatal("tampered binary verified")
	}
	if _, err := r.Install(bin, Installation{Engine: "mihomo", Version: "../x", ABI: hostABI()}); err == nil {
		t.Fatal("unsafe version accepted")
	}
	if err := r.Delete("mihomo", "1.19.10", hostABI()); err != nil {
		t.Fatal(err)
	}
	list, _ := r.List()
	if len(list) != 1 || list[0].Version != "1.19.2" {
		t.Fatalf("after delete: %+v", list)
	}
}

func TestRegistryChild(t *testing.T) {
	if os.Getenv("KPM_REGISTRY_CHILD") != "1" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
}

func TestRegistryReinstallPreservesIdentity(t *testing.T) {
	directory := t.TempDir()
	layout := paths.Layout{ModuleDir: filepath.Join(directory, "module"), DataDir: filepath.Join(directory, "data")}
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(layout)
	info := Installation{Engine: "mihomo", Version: "1.19.33", ABI: hostABI(), Source: "test"}
	installed, err := registry.Install(os.Args[0], info)
	if err != nil {
		t.Fatal(err)
	}
	process, err := supervisor.Start(supervisor.Spec{Binary: filepath.Join(layout.DataDir, installed.RelativePath),
		Args: []string{"-test.run=^TestRegistryChild$"}, Env: append(os.Environ(), "KPM_REGISTRY_CHILD=1")})
	if err != nil {
		t.Fatal(err)
	}
	defer process.Stop(time.Second)
	identity := process.Identity()
	if !identity.Alive() {
		t.Fatal("control process not alive")
	}
	if _, err := registry.Install(os.Args[0], info); err != nil {
		t.Fatal(err)
	}
	if !identity.Alive() {
		t.Fatal("reinstallation invalidated a live process identity")
	}
}

func TestDownloadVerifiesDigest(t *testing.T) {
	payload := []byte("core-bytes")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "a")
	ctx := context.Background()
	if err := Download(ctx, srv.Client(), srv.URL, "sha256:"+hex.EncodeToString(sum[:]), 0, dst, nil); err != nil {
		t.Fatal(err)
	}
	if err := Download(ctx, srv.Client(), srv.URL, "sha256:"+fmt.Sprintf("%064d", 0), 0, dst, nil); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if err := Download(ctx, srv.Client(), srv.URL, "", 0, dst, nil); err == nil {
		t.Fatal("missing digest accepted")
	}
}

func TestDownloadStallAborts(t *testing.T) {
	old := StallTimeout
	StallTimeout = 300 * time.Millisecond
	defer func() { StallTimeout = old }()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		// Slow but steady data must not trip the watchdog.
		for i := 0; i < 5; i++ {
			_, _ = w.Write([]byte("0123456789"))
			w.(http.Flusher).Flush()
			time.Sleep(150 * time.Millisecond)
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	err := Download(context.Background(), srv.Client(), srv.URL, "sha256:"+fmt.Sprintf("%064d", 0), 0, filepath.Join(t.TempDir(), "a"), nil)
	if err == nil || !strings.Contains(err.Error(), "停滞") {
		t.Fatalf("err = %v", err)
	}
	if el := time.Since(start); el < 750*time.Millisecond || el > 5*time.Second {
		t.Fatalf("aborted after %v", el)
	}
}

func TestAssetName(t *testing.T) {
	if n := AssetName("mihomo", "v1.19.33", "arm64-v8a"); n != "mihomo-android-arm64-v8-v1.19.33.gz" {
		t.Fatal(n)
	}
	if n := AssetName("sing-box", "v1.14.4", "arm64-v8a"); n != "sing-box-1.14.4-android-arm64.tar.gz" {
		t.Fatal(n)
	}
	if n := AssetName("mihomo", "v1.19.33", "x86_64"); n != "mihomo-android-amd64-v1.19.33.gz" {
		t.Fatal(n)
	}
	if n := AssetName("sing-box", "v1.14.4", "x86_64"); n != "sing-box-1.14.4-android-amd64.tar.gz" {
		t.Fatal(n)
	}
	if AssetName("mihomo", "v1", "mips") != "" {
		t.Fatal("unknown abi")
	}
}
