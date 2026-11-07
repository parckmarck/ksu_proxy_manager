package apps

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ksu_proxy_manager/internal/config"
)

func TestGenerationSurvivesUIReads(t *testing.T) {
	source := NewSource()
	source.PackagesList = filepath.Join(t.TempDir(), "packages.list")
	if err := os.WriteFile(source.PackagesList, []byte("com.test.app 10001 0 /x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := source.Generation()
	if _, err := source.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.PackagesList, []byte("com.test.app 10002 0 /x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(source.PackagesList, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := source.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.Generation() == before {
		t.Fatal("UI list read consumed the engine's change notification")
	}
}

func TestAndroidProtectedUIDsAreExcluded(t *testing.T) {
	list := []App{
		{Package: "com.android.settings", UID: 1000},
		{Package: "com.android.captiveportallogin", UID: 10041},
		{Package: "com.test.shared", UID: 10041},
		{Package: "com.test.normal", UID: 10042},
	}
	for _, mode := range []string{"all", "include", "exclude"} {
		policy := config.AppPolicy{Mode: mode, Users: []int{0, 10}}
		if mode == "include" {
			for _, app := range list {
				policy.Packages = append(policy.Packages, app.Package)
			}
		}
		ranges, _ := rangesForPlatform(policy, list, true)
		for _, user := range policy.Users {
			for _, uid := range []int{1000, 10041, 20041} {
				for _, r := range ranges {
					value := uint32(user*PerUserRange + uid)
					if value >= r.Start && value <= r.End {
						t.Fatalf("%s captured protected UID %d", mode, value)
					}
				}
			}
		}
	}
}
