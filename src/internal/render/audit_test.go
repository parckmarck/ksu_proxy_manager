package render

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"ksu_proxy_manager/internal/config"
)

func TestQUICFingerprintDoesNotBecomeSingBoxUTLS(t *testing.T) {
	cfg, sec := fixture(true)
	cfg.NodeByID("hy1").TLS.Fingerprint = "chrome"
	cfg.NodeByID("tu1").TLS.Fingerprint = "firefox"
	out, err := Render(Input{Config: cfg, Secrets: sec, Engine: config.EngineSingBox, Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, config.EngineSingBox)})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []struct {
			Type string         `json:"type"`
			TLS  map[string]any `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out.Content, &doc); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, outbound := range doc.Outbounds {
		if outbound.Type == "hysteria2" || outbound.Type == "tuic" {
			count++
			if _, exists := outbound.TLS["utls"]; exists {
				t.Fatal("QUIC outbound retained unsupported uTLS")
			}
		}
	}
	if count != 2 || !strings.Contains(strings.Join(out.Warnings, "\n"), "QUIC") {
		t.Fatal("QUIC nodes or their compatibility warning are missing")
	}
	checkWithCore(t, config.EngineSingBox, out)
}

func TestMihomoKeepsManagementDestinationsPinned(t *testing.T) {
	cfg, sec := fixture(true)
	out, err := Render(Input{Config: cfg, Secrets: sec, Engine: config.EngineMihomo, Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, config.EngineMihomo)})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sniffer struct {
			Enabled bool     `yaml:"enable"`
			Skip    []string `yaml:"skip-src-address"`
		} `yaml:"sniffer"`
	}
	if err := yaml.Unmarshal(out.Content, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Sniffer.Enabled || strings.Join(doc.Sniffer.Skip, ",") != "127.0.0.0/8,::1/128" {
		t.Fatal("local pinned downloads were not excluded from destination sniffing")
	}
	checkWithCore(t, config.EngineMihomo, out)
}

func TestUnsupportedMihomoTransportsFailBeforeChangingGroups(t *testing.T) {
	for _, combination := range [][2]string{{"vm1", "xhttp"}, {"tr1", "http"}, {"tr1", "xhttp"}} {
		t.Run(strings.Join(combination[:], "-"), func(t *testing.T) {
			cfg, sec := fixture(false)
			cfg.NodeByID(combination[0]).Transport = &config.Transport{Type: combination[1], Path: "/test"}
			out, err := Render(Input{Config: cfg, Secrets: sec, Engine: config.EngineMihomo, Runtime: testRuntime(t.TempDir())})
			if err == nil || out != nil || !strings.Contains(err.Error(), "Mihomo") {
				t.Fatalf("unsupported transport silently changed group membership: %v", err)
			}
			if combination[1] == "http" {
				out, err := Render(Input{Config: cfg, Secrets: sec, Engine: config.EngineSingBox, Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, config.EngineSingBox)})
				if err != nil {
					t.Fatal("sing-box HTTP/2 support was incorrectly rejected", err)
				}
				checkWithCore(t, config.EngineSingBox, out)
			}
		})
	}
}

func BenchmarkBuildGroups10000Nodes(b *testing.B) {
	cfg := config.Config{Nodes: make([]config.Node, 10000), Groups: make([]config.Group, 200)}
	tags := make(map[string]string, len(cfg.Nodes))
	for i := range cfg.Nodes {
		id := fmt.Sprintf("node-%05d", i)
		cfg.Nodes[i] = config.Node{ID: id, Name: id}
		tags[id] = id
	}
	for i := range cfg.Groups {
		cfg.Groups[i] = config.Group{ID: fmt.Sprintf("group-%d", i), Type: "select", IncludeAll: true}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := &plan{in: &Input{Config: cfg}, nodeTag: tags, groupTag: map[string]string{}}
		p.buildGroups()
		if len(p.groups) != len(cfg.Groups) || len(p.groups[0].members) != len(cfg.Nodes) {
			b.Fatal("group membership changed")
		}
	}
}
