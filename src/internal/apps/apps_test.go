package apps

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/proc"
)

func TestParsePackagesList(t *testing.T) {
	data := "com.a 10050 0 /data/user/0/com.a default:targetSdkVersion=34 3003 0 1\n" +
		"bad;name 10051 0 /x\ncom.b 1010123 0 /x\ncom.a 10099 0 /dup\nshort\n"
	apps := ParsePackagesList([]byte(data))
	want := []App{{Package: "com.a", UID: 10050}, {Package: "com.b", UID: 10123}}
	if !reflect.DeepEqual(apps, want) {
		t.Fatalf("%+v", apps)
	}
}

func TestRanges(t *testing.T) {
	apps := []App{{Package: "com.a", UID: 10050}, {Package: "com.sys", UID: 1000}}
	r, unknown := Ranges(config.AppPolicy{Mode: "include", Packages: []string{"com.a", "com.sys", "com.none"}, Users: []int{0, 10}}, apps)
	want := []UIDRange{{1000, 1000}, {10050, 10050}, {20050, 20050}, {1001000, 1001000}, {1010050, 1010050}, {1020050, 1020050}}
	if proc.IsAndroid() {
		want = []UIDRange{{10050, 10050}, {20050, 20050}, {1010050, 1010050}, {1020050, 1020050}}
	}
	if !reflect.DeepEqual(r, want) || len(unknown) != 1 {
		t.Fatalf("include: %+v %v", r, unknown)
	}
	r, _ = Ranges(config.AppPolicy{Mode: "all", Users: []int{0}}, apps)
	if !reflect.DeepEqual(r, []UIDRange{{10000, 29999}, {90000, 99999}}) {
		t.Fatalf("all: %+v", r)
	}
	r, _ = Ranges(config.AppPolicy{Mode: "exclude", Packages: []string{"com.a"}, Users: []int{0}}, apps)
	for _, x := range r {
		if (x.Start <= 10050 && 10050 <= x.End) || (x.Start <= 20050 && 20050 <= x.End) {
			t.Fatalf("excluded uid captured: %+v", r)
		}
	}
	if len(r) != 4 {
		t.Fatalf("exclude: %+v", r)
	}
	r, _ = Ranges(config.AppPolicy{Mode: "include", Packages: []string{"com.none"}, Users: []int{0}}, apps)
	if len(r) != 0 {
		t.Fatal("include with nothing installed must capture nothing")
	}
}

func TestSourceCacheAndUsers(t *testing.T) {
	dir := t.TempDir()
	s := NewSource()
	s.PackagesList = filepath.Join(dir, "packages.list")
	s.UserDir = filepath.Join(dir, "user")
	_ = os.WriteFile(s.PackagesList, []byte("com.a 10050 0 /x\n"), 0o644)
	ctx := context.Background()
	l, err := s.List(ctx)
	if err != nil || len(l) != 1 || s.Changed() {
		t.Fatalf("list: %v %v", l, err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(s.PackagesList, []byte("com.a 10050 0 /x\ncom.b 10051 0 /x\n"), 0o644)
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(s.PackagesList, future, future)
	if !s.Changed() {
		t.Fatal("change not detected")
	}
	if l, _ := s.List(ctx); len(l) != 2 {
		t.Fatal("not reloaded")
	}
	if u := s.Users(); !reflect.DeepEqual(u, []int{0}) {
		t.Fatalf("default users %v", u)
	}
	for _, d := range []string{"0", "10", "x"} {
		_ = os.MkdirAll(filepath.Join(s.UserDir, d), 0o755)
	}
	if u := s.Users(); !reflect.DeepEqual(u, []int{0, 10}) {
		t.Fatalf("users %v", u)
	}
}
