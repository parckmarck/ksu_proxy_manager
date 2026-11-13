package render

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"ksu_proxy_manager/internal/config"
)

func TestLoadBalanceGroupRendering(t *testing.T) {
	for _, strategy := range []string{"", "consistent-hashing", "round-robin", "sticky-sessions"} {
		for _, empty := range []bool{false, true} {
			t.Run(strategy+map[bool]string{false: "/members", true: "/empty"}[empty], func(t *testing.T) {
				c, s := fixture(false)
				var g config.Group
				if err := json.Unmarshal([]byte(`{"id":"balance","name":"均衡组","type":"load-balance","strategy":"`+strategy+`","nodes":["so1","ss1","so1"],"testUrl":"http://health.example.test/check","intervalSec":60,"toleranceMs":123}`), &g); err != nil {
					t.Fatal(err)
				}
				if empty {
					g.Nodes = nil
				}
				c.Groups = []config.Group{g}
				c.Routing = config.Routing{Mode: "rule", Preset: "custom", Final: config.GroupRef("balance")}
				out, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineMihomo, Runtime: testRuntime(t.TempDir())})
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := yaml.Unmarshal(out.Content, &doc); err != nil {
					t.Fatal(err)
				}
				group := doc["proxy-groups"].([]any)[0].(map[string]any)
				wantStrategy := strategy
				if strategy == "" {
					wantStrategy = "consistent-hashing"
				}
				if group["type"] != "load-balance" || group["strategy"] != wantStrategy {
					t.Fatal("wrong balance behavior", group)
				}
				want := []any{"SOCKS5", "HK SS obfs"}
				if empty {
					want = []any{"DIRECT"}
				}
				if !reflect.DeepEqual(group["proxies"], want) {
					t.Fatal("wrong members", group)
				}
				if group["url"] != "http://health.example.test/check" || group["interval"] != 60 {
					t.Fatal("health settings lost", group)
				}
				if _, ok := group["tolerance"]; ok {
					t.Fatal("load-balance has urltest tolerance")
				}
				if _, ok := out.Selected["均衡组"]; ok {
					t.Fatal("automatic group has manual selection")
				}
				if empty && !strings.Contains(strings.Join(out.Warnings, "\n"), "没有可用成员") {
					t.Fatal("missing empty group warning")
				}
				checkWithCore(t, config.EngineMihomo, out)
			})
		}
	}
}

func TestLoadBalanceRejectsEffectiveSingBoxEngine(t *testing.T) {
	c, s := fixture(false)
	c.Groups[1].Type = "load-balance"
	// Settings remains Mihomo: rendering a preview for another engine must
	// reject the group instead of silently turning it into a selector.
	out, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineSingBox, Runtime: testRuntime(t.TempDir())})
	if err == nil || out != nil || !strings.Contains(err.Error(), "sing-box") {
		t.Fatalf("out=%v err=%v", out, err)
	}
}
