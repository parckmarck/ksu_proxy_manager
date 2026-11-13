package render

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"ksu_proxy_manager/internal/config"
)

func TestFallbackDowngradeWarningSurvivesNodeWarnings(t *testing.T) {
	c, s := fixture(false)
	xhttp := c.Nodes[6]
	c.Nodes = nil
	for i := 0; i < 110; i++ {
		n := xhttp
		n.ID, n.Name = fmt.Sprintf("x%d", i), fmt.Sprintf("XHTTP %d", i)
		c.Nodes = append(c.Nodes, n)
		s.SetNodeSecrets(n.ID, map[string]string{"uuid": testUUID})
	}
	c.Groups = []config.Group{{ID: "failover", Name: "故障转移", Type: "fallback", IncludeAll: true}}
	c.Routing = config.Routing{Mode: "rule", Preset: "custom", Final: config.GroupRef("failover")}
	out, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineSingBox, Runtime: testRuntime(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), "urltest") {
		t.Fatal("fallback downgrade was lost behind node warnings", out.Warnings)
	}
	if len(out.Warnings) > 100 {
		t.Fatal("warning bound exceeded", len(out.Warnings))
	}
}

func TestFallbackGroupRendering(t *testing.T) {
	for _, engineName := range []string{config.EngineMihomo, config.EngineSingBox} {
		for _, empty := range []bool{false, true} {
			t.Run(engineName+map[bool]string{false: "/ordered", true: "/empty"}[empty], func(t *testing.T) {
				c, s := fixture(false)
				c.Routing.Preset = "custom"
				c.Routing.BlockAds = false
				c.Routing.Rules = nil
				c.Groups = []config.Group{{ID: "failover", Name: "故障转移", Type: "fallback", Nodes: []string{"so1", "ss1", "so1"}, TestURL: "http://health.example.test/check", IntervalSec: 60, ToleranceMs: 123}}
				if empty {
					c.Groups[0].Nodes = nil
				}
				c.Routing.Final = config.GroupRef("failover")
				out, err := Render(Input{Config: c, Secrets: s, Engine: engineName, Runtime: testRuntime(t.TempDir())})
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				key, typeName, membersKey, intervalKey, interval := "proxy-groups", "fallback", "proxies", "interval", any(60)
				if engineName == config.EngineMihomo {
					err = yaml.Unmarshal(out.Content, &doc)
				} else {
					err = json.Unmarshal(out.Content, &doc)
					key, typeName, membersKey, intervalKey, interval = "outbounds", "urltest", "outbounds", "interval", "60s"
					if !strings.Contains(strings.Join(out.Warnings, "\n"), "故障转移") || !strings.Contains(strings.Join(out.Warnings, "\n"), "urltest") {
						t.Fatal("missing explicit downgrade warning", out.Warnings)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				var group map[string]any
				for _, item := range doc[key].([]any) {
					m := item.(map[string]any)
					if m["name"] == "故障转移" || m["tag"] == "故障转移" {
						group = m
						break
					}
				}
				if group == nil || group["type"] != typeName {
					t.Fatal("unexpected group", group)
				}
				want := []any{"SOCKS5", "HK SS obfs"}
				if empty {
					want = []any{"DIRECT"}
				}
				if !reflect.DeepEqual(group[membersKey], want) {
					t.Fatalf("member order: got %v, want %v", group[membersKey], want)
				}
				if group["url"] != c.Groups[0].TestURL || group[intervalKey] != interval {
					t.Fatal("health check settings lost", group)
				}
				if engineName == config.EngineMihomo {
					if _, ok := group["tolerance"]; ok {
						t.Fatal("fallback must not have urltest tolerance")
					}
				} else if group["tolerance"] != float64(123) {
					t.Fatal("urltest compatibility tolerance lost", group)
				}
				if _, ok := out.Selected["故障转移"]; ok {
					t.Fatal("automatic group got a manual selection")
				}
				if empty && !strings.Contains(strings.Join(out.Warnings, "\n"), "没有可用成员") {
					t.Fatal("empty group warning lost")
				}
				checkWithCore(t, engineName, out)
			})
		}
	}
}
