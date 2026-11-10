package config

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func validBase() (Config, Secrets) {
	c := Default()
	s := DefaultSecrets()
	c.Nodes = []Node{
		{ID: "a", Name: "A", Type: "trojan", Server: "a.example.com", Port: 443, TLS: &TLS{Enabled: true}},
		{ID: "b", Name: "B", Type: "shadowsocks", Server: "1.2.3.4", Port: 8388, Cipher: "aes-128-gcm"},
	}
	s.SetNodeSecrets("a", map[string]string{"password": "p"})
	s.SetNodeSecrets("b", map[string]string{"password": "p"})
	c.Normalize()
	s.Normalize()
	return c, s
}

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("want FieldError, got %v", err)
	}
	return fe.Field
}

func TestDefaultIsValid(t *testing.T) {
	c, s := Default(), DefaultSecrets()
	c.Normalize()
	if err := Validate(&c, &s); err != nil {
		t.Fatal(err)
	}
	if c.SchemaVersion != SchemaVersion || c.Settings.Engine != EngineMihomo {
		t.Fatalf("unexpected defaults %+v", c.Settings)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		mod   func(*Config, *Secrets)
		field string
	}{
		{"bad node id", func(c *Config, _ *Secrets) { c.Nodes[0].ID = "../x" }, "nodes[0].id"},
		{"dup node id", func(c *Config, _ *Secrets) { c.Nodes[1].ID = "a" }, "nodes[1].id"},
		{"bad port", func(c *Config, _ *Secrets) { c.Nodes[0].Port = 70000 }, "nodes[0].port"},
		{"missing secret", func(_ *Config, s *Secrets) { delete(s.Nodes, "a") }, "nodes[0]"},
		{"upstream missing", func(c *Config, _ *Secrets) { c.Nodes[0].Upstream = "zzz" }, "nodes[0].upstream"},
		{"upstream cycle", func(c *Config, _ *Secrets) { c.Nodes[0].Upstream = "b"; c.Nodes[1].Upstream = "a" }, "nodes"},
		{"reserved group name", func(c *Config, _ *Secrets) { c.Groups[0].Name = "DIRECT" }, "groups[0].name"},
		{"group cycle", func(c *Config, _ *Secrets) { c.Groups[1].Groups = []string{"proxy"} }, "groups"},
		{"bad filter regex", func(c *Config, _ *Secrets) { c.Groups[1].Filter = "(" }, "groups[1].filter"},
		{"bad final", func(c *Config, _ *Secrets) { c.Routing.Final = "group:none" }, "routing.final"},
		{"bad rule value", func(c *Config, _ *Secrets) {
			c.Routing.Rules = []Rule{{ID: "r1", Enabled: true, Type: "ip_cidr", Values: []string{"1.2.3.4/99"}, Target: TargetDirect}}
		}, "routing.rules[0].values"},
		{"bad dns", func(c *Config, _ *Secrets) { c.DNS.Direct = []string{"ftp://x"} }, "dns.direct[0]"},
		{"dns direct needs ip", func(c *Config, _ *Secrets) { c.DNS.Direct = []string{"https://dns.alidns.com/dns-query"} }, "dns.direct"},
		{"bad package", func(c *Config, _ *Secrets) { c.Apps.Mode = "include"; c.Apps.Packages = []string{"x;rm -rf"} }, "apps.packages"},
		{"bad app route package", func(c *Config, _ *Secrets) {
			c.Apps.Routes = []AppRoute{{Package: "x,DIRECT", Target: TargetDirect}}
		}, "apps.routes[0].package"},
		{"duplicate app route", func(c *Config, _ *Secrets) {
			c.Apps.Routes = []AppRoute{{Package: "com.example.app", Target: TargetDirect}, {Package: "com.example.app", Target: TargetReject}}
		}, "apps.routes[1].package"},
		{"app route to missing group", func(c *Config, _ *Secrets) {
			c.Apps.Routes = []AppRoute{{Package: "com.example.app", Target: "group:none"}}
		}, "apps.routes[0].target"},
		{"node as app route target", func(c *Config, _ *Secrets) {
			c.Apps.Routes = []AppRoute{{Package: "com.example.app", Target: "node:a"}}
		}, "apps.routes[0].target"},
		{"too many app routes", func(c *Config, _ *Secrets) {
			for i := 0; i <= MaxAppRoutes; i++ {
				c.Apps.Routes = append(c.Apps.Routes, AppRoute{Package: "com.example.app" + strconv.Itoa(i), Target: TargetDirect})
			}
		}, "apps.routes"},
		{"node as rule target", func(c *Config, _ *Secrets) {
			c.Routing.Rules = []Rule{{ID: "r1", Enabled: true, Type: "domain", Values: []string{"a.com"}, Target: "node:a"}}
		}, "routing.rules[0].target"},
		{"bad mtu", func(c *Config, _ *Secrets) { c.Settings.MTU = 100 }, "settings.mtu"},
		{"mirror with credentials", func(c *Config, _ *Secrets) { c.Settings.Download.GitHubMirror = "https://u:p@m.example/" }, "settings.download.githubMirror"},
		{"subscription without url", func(c *Config, _ *Secrets) {
			c.Subscriptions = []Subscription{{ID: "s1", Name: "S"}}
		}, "subscriptions[0].url"},
		{"trojan without tls block", func(c *Config, _ *Secrets) { c.Nodes[0].TLS = nil }, "nodes[0].tls.enabled"},
		{"control char in node name", func(c *Config, _ *Secrets) { c.Nodes[0].Name = "A\x1b[31m" }, "nodes[0].name"},
		{"newline in subscription name", func(c *Config, s *Secrets) {
			c.Subscriptions = []Subscription{{ID: "s1", Name: "S\n[error] fake"}}
			s.Subscriptions["s1"] = "https://sub.example.com/x"
		}, "subscriptions[0].name"},
		{"too many groups", func(c *Config, _ *Secrets) {
			for i := 0; i <= MaxGroups; i++ {
				c.Groups = append(c.Groups, Group{ID: "g" + strconv.Itoa(i), Name: "G" + strconv.Itoa(i), Type: "select"})
			}
		}, "groups"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, s := validBase()
			tc.mod(&c, &s)
			err := Validate(&c, &s)
			if err == nil {
				t.Fatal("accepted")
			}
			if f := fieldOf(t, err); !strings.HasPrefix(f, tc.field) {
				t.Fatalf("field %q, want prefix %q (%v)", f, tc.field, err)
			}
		})
	}
}

func TestValidateAcceptsChainsAndRules(t *testing.T) {
	c, s := validBase()
	c.Nodes[0].Upstream = "b"
	c.Routing.Rules = []Rule{
		{ID: "r1", Enabled: true, Type: "domain_suffix", Values: []string{"example.com", ".example.org"}, Target: "group:auto"},
		{ID: "r2", Enabled: true, Type: "geosite", Values: []string{"geolocation-!cn"}, Target: "group:proxy"},
		{ID: "r3", Enabled: true, Type: "port", Values: []string{"443", "8000-9000"}, Target: TargetReject},
		{ID: "r4", Enabled: false, Type: "package", Values: []string{"com.example.app"}, Target: TargetDirect},
	}
	if err := Validate(&c, &s); err != nil {
		t.Fatal(err)
	}
}

func TestAppRoutesNormalizeAndValidate(t *testing.T) {
	c, s := validBase()
	c.Apps.Routes = []AppRoute{
		{Package: " com.example.video ", Target: "group:auto"},
		{Package: "", Target: TargetDirect},
		{Package: "com.example.bank", Target: TargetDirect},
		{Package: "com.example.blocked", Target: TargetReject},
	}
	c.Normalize()
	if err := Validate(&c, &s); err != nil {
		t.Fatal(err)
	}
	if len(c.Apps.Routes) != 3 || c.Apps.Routes[0].Package != "com.example.bank" || c.Apps.Routes[2].Package != "com.example.video" {
		t.Fatalf("routes: %+v", c.Apps.Routes)
	}
	if clone := Clone(c); !c.Apps.SameRoutes(clone.Apps) || c.Apps.SameRoutes(Default().Apps) {
		t.Fatal("SameRoutes mismatch")
	}
	// Policies without per-app targets keep the schema 3 document shape.
	c.Apps.Routes = []AppRoute{}
	c.Normalize()
	b, err := json.Marshal(c.Apps)
	if err != nil {
		t.Fatal(err)
	}
	if c.Apps.Routes != nil || strings.Contains(string(b), "routes") {
		t.Fatalf("empty routes must be omitted: %s", b)
	}
}

func TestParseDNSServer(t *testing.T) {
	ok := map[string]DNSServer{
		"223.5.5.5":                    {Scheme: "udp", Host: "223.5.5.5", Port: 53},
		"[2400:3200::1]":               {Scheme: "udp", Host: "2400:3200::1", Port: 53},
		"tls://1.1.1.1":                {Scheme: "tls", Host: "1.1.1.1", Port: 853},
		"https://dns.google/dns-query": {Scheme: "https", Host: "dns.google", Port: 443, Path: "/dns-query"},
		"https://1.1.1.1":              {Scheme: "https", Host: "1.1.1.1", Port: 443, Path: "/dns-query"},
		"quic://dns.adguard.com:784":   {Scheme: "quic", Host: "dns.adguard.com", Port: 784},
		"tcp://8.8.8.8:5353":           {Scheme: "tcp", Host: "8.8.8.8", Port: 5353},
	}
	for in, want := range ok {
		got, err := ParseDNSServer(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "dns.google", "ftp://1.1.1.1", "https://u:p@dns.google", "tls://1.1.1.1/x", "https://1.1.1.1/q?x=1", "1.1.1.1,8.8.8.8"} {
		if _, err := ParseDNSServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFakeIPPatternRegex(t *testing.T) {
	cases := map[string][2][]string{
		"+.lan":                     {{"a.lan", "lan", "x.y.lan"}, {"alan", "lan.com"}},
		"*.example.com":             {{"a.example.com"}, {"example.com", "a.b.example.com"}},
		"time.*.com":                {{"time.apple.com"}, {"time.a.b.com"}},
		"localhost.ptlogin2.qq.com": {{"localhost.ptlogin2.qq.com"}, {"localhostxptlogin2.qq.com"}},
	}
	for p, c := range cases {
		re := FakeIPPatternRegex(p)
		for _, s := range c[0] {
			if !mustMatch(t, re, s) {
				t.Errorf("%s (%s) should match %s", p, re, s)
			}
		}
		for _, s := range c[1] {
			if mustMatch(t, re, s) {
				t.Errorf("%s (%s) should not match %s", p, re, s)
			}
		}
	}
}

func mustMatch(t *testing.T, expr, s string) bool {
	t.Helper()
	return regexp.MustCompile(expr).MatchString(s)
}

func TestSecretsNormalizeAndSet(t *testing.T) {
	var s Secrets
	s.Normalize()
	s.SetNodeSecrets("n", map[string]string{"password": "x", "uuid": ""})
	if s.NodeSecret("n", "password") != "x" || len(s.Nodes["n"]) != 1 {
		t.Fatalf("%+v", s.Nodes)
	}
	s.SetNodeSecrets("n", map[string]string{"password": ""})
	if _, ok := s.Nodes["n"]; ok {
		t.Fatal("empty secrets kept")
	}
}

func TestCloneIsDeep(t *testing.T) {
	c, _ := validBase()
	d := Clone(c)
	d.Nodes[0].Name = "changed"
	d.Groups[0].Nodes = append(d.Groups[0].Nodes, "x")
	if c.Nodes[0].Name == "changed" || len(c.Groups[0].Nodes) != 0 {
		t.Fatal("clone shares memory")
	}
}

func TestNormalizeTrimsBypassCIDRs(t *testing.T) {
	c := Default()
	c.Settings.BypassCIDRs = []string{" 10.1.0.0/16 ", "", "192.168.0.0/16"}
	c.Normalize()
	if strings.Join(c.Settings.BypassCIDRs, ",") != "10.1.0.0/16,192.168.0.0/16" {
		t.Fatalf("%v", c.Settings.BypassCIDRs)
	}
}

func TestMigrateV2KeepsCollidingIDsDistinct(t *testing.T) {
	model := map[string]any{
		"schemaVersion": 2,
		"proxyGroups":   []map[string]any{{"id": "a/b", "name": "甲"}, {"id": "a?b", "name": "乙"}},
		"subscriptions": []map[string]any{{"id": "s/1", "name": "S1"}, {"id": "s?1", "name": "S2"}},
	}
	secrets := map[string]any{"subscriptions": map[string]string{"s/1": "https://a.example.com/x", "s?1": "https://b.example.com/x"}}
	mb, _ := json.Marshal(model)
	sb, _ := json.Marshal(secrets)
	cfg, sec, _, err := MigrateV2(mb, sb)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Groups) != 2 || cfg.Groups[0].ID == cfg.Groups[1].ID {
		t.Fatalf("groups: %+v", cfg.Groups)
	}
	if len(cfg.Subscriptions) != 2 || cfg.Subscriptions[0].ID == cfg.Subscriptions[1].ID || len(sec.Subscriptions) != 2 {
		t.Fatalf("subs: %+v %v", cfg.Subscriptions, sec.Subscriptions)
	}
}

func TestMigrateV2(t *testing.T) {
	model := map[string]any{
		"schemaVersion": 2, "revision": 7,
		"settings":    map[string]any{"autoStart": true, "selectedEngine": "sing-box", "selectedCoreVersion": "1.12.3", "logLevel": "warning"},
		"appPolicy":   map[string]any{"mode": "allowlist", "androidUserId": 0, "packageNames": []string{"com.example.app"}},
		"proxyGroups": []map[string]any{{"id": "g1", "name": "主组", "nodeIds": []string{"n1", "n2"}, "selectedNodeId": "n2"}},
		"nodes": []map[string]any{
			{"id": "n1", "name": "SS", "protocol": "shadowsocks", "server": "1.2.3.4", "port": 8388, "credentials": map[string]any{"cipher": "aes-256-gcm", "password": "***"}, "udpEnabled": true},
			{"id": "n2", "name": "VL", "protocol": "vless", "server": "v.example.com", "port": 443, "credentials": map[string]any{"uuid": "***", "flow": "xtls-rprx-vision"},
				"tls": map[string]any{"enabled": true, "serverName": "v.example.com"}, "upstreamId": "n1"},
			{"id": "n3", "name": "Broken", "protocol": "unknown", "server": "x", "port": 1},
		},
		"subscriptions": []map[string]any{{"id": "s1", "name": "机场"}, {"id": "s2", "name": "坏订阅"}},
		"trafficRules":  []map[string]any{{"id": "r1", "network": "udp", "action": "block", "priority": 10}},
		"fallback":      map[string]any{"tcp": map[string]any{"action": "proxy", "proxyGroupId": "g1"}, "udp": map[string]any{"action": "direct"}},
	}
	secrets := map[string]any{
		"nodes":         map[string]any{"n1": map[string]string{"password": "pw"}, "n2": map[string]string{"uuid": "0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f"}},
		"subscriptions": map[string]string{"s1": "https://sub.example.com/x?token=1"},
	}
	mb, _ := json.Marshal(model)
	sb, _ := json.Marshal(secrets)
	cfg, sec, warnings, err := MigrateV2(mb, sb)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings: %v", warnings)
	}
	if cfg.Settings.Engine != EngineSingBox || cfg.Settings.CoreVersions[EngineSingBox] != "1.12.3" || cfg.Settings.LogLevel != "warn" {
		t.Fatalf("settings: %+v", cfg.Settings)
	}
	if len(cfg.Nodes) != 2 || cfg.NodeByID("n2").Upstream != "n1" || sec.NodeSecret("n1", "password") != "pw" {
		t.Fatalf("nodes: %+v", cfg.Nodes)
	}
	if g := cfg.GroupByID("g1"); g == nil || g.Selected != "node:n2" || len(g.Nodes) != 2 {
		t.Fatalf("group: %+v", g)
	}
	if cfg.Routing.Final != "group:g1" || cfg.Routing.Preset != "custom" || len(cfg.Routing.Rules) != 2 {
		t.Fatalf("routing: %+v", cfg.Routing)
	}
	if cfg.Apps.Mode != "include" || cfg.Apps.Packages[0] != "com.example.app" {
		t.Fatalf("apps: %+v", cfg.Apps)
	}
	if len(cfg.Subscriptions) != 1 || sec.Subscriptions["s1"] == "" {
		t.Fatalf("subs: %+v", cfg.Subscriptions)
	}
	if _, _, _, err := MigrateV2([]byte(`{"schemaVersion":9}`), nil); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestMigrateSubscriptionIDsAndGroupNames(t *testing.T) {
	model := []byte(`{"schemaVersion":2,"subscriptions":[{"id":"s1","name":"Legacy"}],"nodes":[{"id":"n1","name":"Legacy","protocol":"trojan","server":"example.com","port":443,"sourceSubscription":"s1"},{"id":"n2","name":"Legacy","protocol":"trojan","server":"example.com","port":443,"sourceSubscription":"s1"},{"id":"n3","name":"Manual","protocol":"trojan","server":"example.com","port":443,"upstreamId":"n1"}],"proxyGroups":[{"id":"g1","name":"Home, VPN","nodeIds":["n1","n2"],"selectedNodeId":"n2"},{"id":"g2","name":"Home, VPN","nodeIds":["n3"]}]}`)
	secretData := []byte(`{"nodes":{"n1":{"password":"one"},"n2":{"password":"two"},"n3":{"password":"three"}},"subscriptions":{"s1":"https://example.com/sub"}}`)
	configuration, secrets, warnings, err := MigrateV2(model, secretData)
	if err != nil {
		t.Fatal(err)
	}
	first := SubscriptionNodeID("s1", "Legacy")
	second := SubscriptionNodeID("s1", "Legacy (2)")
	group := configuration.GroupByID("g1")
	if len(configuration.Nodes) != 3 || configuration.NodeByID(first) == nil || configuration.NodeByID(second) == nil || configuration.NodeByID("n3").Upstream != first {
		t.Fatalf("node references not migrated: %+v", configuration.Nodes)
	}
	if group.Selected != NodeRef(second) || group.Nodes[0] != first || group.Name == configuration.GroupByID("g2").Name {
		t.Fatalf("group references/names not migrated: %+v", configuration.Groups)
	}
	if secrets.NodeSecret(first, "password") != "one" || secrets.NodeSecret(second, "password") != "two" || len(warnings) != 2 {
		t.Fatalf("credentials or warnings lost: %v", warnings)
	}
}
