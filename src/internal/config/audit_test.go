package config

import (
	"strings"
	"testing"
)

func TestReservedGroupNames(t *testing.T) {
	for _, name := range []string{"PASS", "REJECT-DROP", "COMPATIBLE"} {
		cfg, sec := Default(), DefaultSecrets()
		cfg.Groups[0].Name = name
		if err := Validate(&cfg, &sec); err == nil {
			t.Errorf("reserved group name %s was accepted", name)
		}
	}
}

func TestMigrationRepairsInvalidFieldsWithoutDiscardingNodes(t *testing.T) {
	model := `{"schemaVersion":2,"settings":{"autoStart":false,"selectedEngine":"mihomo","selectedCoreVersion":"../bad"},"appPolicy":{"mode":"allowlist","androidUserId":1000,"packageNames":["bad;name","com.test.valid"]},"nodes":[{"id":"one","name":"One","protocol":"trojan","server":"example.com","port":443,"upstreamId":"two","credentials":{"password":"secret"}},{"id":"two","name":"Two","protocol":"trojan","server":"example.net","port":443,"upstreamId":"one","credentials":{"password":"secret"}}],"proxyGroups":[{"id":"g","name":"PASS","nodeIds":["one","two"]}]}`
	cfg, sec, warnings, err := MigrateV2([]byte(model), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Nodes) != 2 || cfg.Settings.AutoStart || len(warnings) < 3 ||
		cfg.Apps.Users[0] != 0 || len(cfg.Apps.Packages) != 1 || !strings.HasPrefix(cfg.Groups[0].Name, "PASS (") {
		t.Fatalf("migration discarded valid data or did not report repairs: nodes=%d warnings=%v", len(cfg.Nodes), warnings)
	}
	if err := Validate(&cfg, &sec); err != nil {
		t.Fatal("repaired migration is invalid", err)
	}
}
