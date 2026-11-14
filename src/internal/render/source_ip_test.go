package render

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"ksu_proxy_manager/internal/config"
)

func TestSourceIPRuleRendering(t *testing.T) {
	for _, engine := range []string{config.EngineMihomo, config.EngineSingBox} {
		t.Run(engine, func(t *testing.T) {
			c, s := config.Default(), config.DefaultSecrets()
			c.Apps.Routes = []config.AppRoute{{Package: "com.example.pinned", Target: config.TargetDirect}}
			c.Routing = config.Routing{Mode: "rule", Preset: "custom", Final: config.TargetDirect, Rules: []config.Rule{
				{ID: "disabled", Type: "source_ip_cidr", Values: []string{"198.51.100.0/24"}, Target: config.TargetReject},
				{ID: "sources", Enabled: true, Type: "source_ip_cidr", Values: []string{"192.168.43.2", "192.168.44.7/24", "2001:db8::2", "2001:db8:1::7/64"}, Target: config.TargetReject},
				{ID: "later", Enabled: true, Type: "domain", Values: []string{"example.com"}, Target: config.TargetDirect},
			}}
			out, err := Render(Input{Config: c, Secrets: s, Engine: engine, Runtime: testRuntime(t.TempDir())})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out.Content), "198.51.100.") {
				t.Fatal("disabled source rule was rendered")
			}
			if engine == config.EngineMihomo {
				var doc map[string]any
				if err := yaml.Unmarshal(out.Content, &doc); err != nil {
					t.Fatal(err)
				}
				rules := doc["rules"].([]any)
				start := -1
				for i, r := range rules {
					if r == "PROCESS-NAME,com.example.pinned,DIRECT" {
						start = i + 1
					}
				}
				want := []any{"SRC-IP-CIDR,192.168.43.2/32,REJECT", "SRC-IP-CIDR,192.168.44.0/24,REJECT", "SRC-IP-CIDR,2001:db8::2/128,REJECT", "SRC-IP-CIDR,2001:db8:1::/64,REJECT", "DOMAIN,example.com,DIRECT"}
				if start < 0 || len(rules) < start+len(want) || !reflect.DeepEqual(rules[start:start+len(want)], want) {
					t.Fatalf("source rules must follow pinned apps and precede later rules: %v", rules)
				}
			} else {
				var doc map[string]any
				if err := json.Unmarshal(out.Content, &doc); err != nil {
					t.Fatal(err)
				}
				rules := doc["route"].(map[string]any)["rules"].([]any)
				found := false
				for i, item := range rules {
					rule := item.(map[string]any)
					if values, ok := rule["source_ip_cidr"]; ok {
						want := []any{"192.168.43.2/32", "192.168.44.0/24", "2001:db8::2/128", "2001:db8:1::/64"}
						if !reflect.DeepEqual(values, want) || rule["action"] != "reject" || rule["ip_cidr"] != nil || i == 0 || i+1 >= len(rules) {
							t.Fatalf("source match/action: %v", rule)
						}
						before, after := rules[i-1].(map[string]any), rules[i+1].(map[string]any)
						if before["package_name"] == nil || after["domain"] == nil {
							t.Fatal("custom rule order changed", rules)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("missing source rule", rules)
				}
			}
			checkWithCore(t, engine, out)
		})
	}
}
