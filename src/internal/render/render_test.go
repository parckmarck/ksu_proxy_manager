package render

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"ksu_proxy_manager/internal/config"
)

const (
	testUUID     = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testWGKey    = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	testReality  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
	testSS2022PW = "AAAAAAAAAAAAAAAAAAAAAA=="
)

// fixture builds a configuration exercising every node type and rule kind.
func fixture(ipv6 bool) (config.Config, config.Secrets) {
	c := config.Default()
	s := config.DefaultSecrets()
	c.Settings.IPv6 = ipv6
	tls := func(sni string) *config.TLS { return &config.TLS{Enabled: true, SNI: sni} }
	add := func(n config.Node, secrets map[string]string) {
		c.Nodes = append(c.Nodes, n)
		s.SetNodeSecrets(n.ID, secrets)
	}
	add(config.Node{ID: "ss1", Name: "HK SS obfs", Type: "shadowsocks", Server: "ss.example.com", Port: 8388, UDP: true, Cipher: "aes-256-gcm", Plugin: "obfs", PluginOpts: map[string]string{"mode": "http", "host": "bing.com"}}, map[string]string{"password": "pw1"})
	add(config.Node{ID: "ss2", Name: "JP SS2022 v2ray", Type: "shadowsocks", Server: "203.0.113.10", Port: 443, UDP: false, Cipher: "2022-blake3-aes-128-gcm", Plugin: "v2ray-plugin", PluginOpts: map[string]string{"mode": "websocket", "host": "cdn.example.com", "path": "/ws", "tls": "true"}}, map[string]string{"password": testSS2022PW})
	add(config.Node{ID: "vm1", Name: "US VMess WS", Type: "vmess", Server: "vm.example.com", Port: 443, UDP: true, Security: "auto", Transport: &config.Transport{Type: "ws", Path: "/v", Host: "vm.example.com", Headers: map[string]string{"User-Agent": "x"}}, TLS: &config.TLS{Enabled: true, SNI: "vm.example.com", ALPN: []string{"http/1.1"}, Fingerprint: "chrome"}}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "vm2", Name: "VMess gRPC", Type: "vmess", Server: "vm2.example.com", Port: 443, UDP: true, Security: "aes-128-gcm", AlterID: 0, Transport: &config.Transport{Type: "grpc", ServiceName: "svc"}, TLS: tls("vm2.example.com")}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "vl1", Name: "HK VLESS Reality", Type: "vless", Server: "198.51.100.7", Port: 443, UDP: true, Flow: "xtls-rprx-vision", TLS: &config.TLS{Enabled: true, SNI: "www.microsoft.com", Fingerprint: "chrome", RealityPublicKey: testReality, RealityShortID: "6ba85179e30d4fc2"}}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "vl2", Name: "VLESS WS chained", Type: "vless", Server: "vl.example.com", Port: 443, UDP: true, Upstream: "ss1", Transport: &config.Transport{Type: "ws", Path: "/x"}, TLS: tls("vl.example.com")}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "vl3", Name: "VLESS xhttp", Type: "vless", Server: "xh.example.com", Port: 443, UDP: true, Transport: &config.Transport{Type: "xhttp", Path: "/xh"}, TLS: tls("xh.example.com")}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "vl4", Name: "VLESS h2", Type: "vless", Server: "h2.example.com", Port: 443, UDP: true, Transport: &config.Transport{Type: "http", Path: "/h2", Host: "h2.example.com"}, TLS: tls("h2.example.com")}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "vm3", Name: "VMess HTTPUpgrade", Type: "vmess", Server: "hu.example.com", Port: 80, UDP: true, Security: "auto", Transport: &config.Transport{Type: "httpupgrade", Path: "/up", Host: "hu.example.com"}}, map[string]string{"uuid": testUUID})
	add(config.Node{ID: "tr1", Name: "Trojan gRPC", Type: "trojan", Server: "tr.example.com", Port: 443, UDP: true, Transport: &config.Transport{Type: "grpc", ServiceName: "tr"}, TLS: &config.TLS{Enabled: true, SNI: "tr.example.com", Insecure: true}}, map[string]string{"password": "trpw"})
	add(config.Node{ID: "hy1", Name: "SG Hysteria2", Type: "hysteria2", Server: "hy.example.com", Port: 443, UDP: true, UpMbps: 50, DownMbps: 200, Obfs: "salamander", Ports: "20000-30000,40000", TLS: tls("hy.example.com")}, map[string]string{"password": "hypw", "obfsPassword": "obfspw"})
	add(config.Node{ID: "tu1", Name: "TUIC v5", Type: "tuic", Server: "tu.example.com", Port: 443, UDP: true, CongestionControl: "bbr", UDPRelayMode: "native", TLS: tls("tu.example.com")}, map[string]string{"uuid": testUUID, "password": "tupw"})
	add(config.Node{ID: "at1", Name: "AnyTLS", Type: "anytls", Server: "at.example.com", Port: 443, UDP: true, TLS: tls("at.example.com")}, map[string]string{"password": "atpw"})
	add(config.Node{ID: "so1", Name: "SOCKS5", Type: "socks", Server: "192.0.2.5", Port: 1080, UDP: true}, map[string]string{"username": "u", "password": "p"})
	add(config.Node{ID: "ht1", Name: "HTTPS proxy", Type: "http", Server: "hp.example.com", Port: 443, TLS: tls("hp.example.com")}, map[string]string{"username": "u", "password": "p"})
	add(config.Node{ID: "wg1", Name: "WireGuard", Type: "wireguard", Server: "wg.example.com", Port: 51820, UDP: true, LocalAddress: []string{"10.0.0.2/32", "fd00::2/128"}, PeerPublicKey: testWGKey, Reserved: []int{1, 2, 3}, WGMTU: 1280}, map[string]string{"privateKey": testWGKey, "preSharedKey": testWGKey})
	c.Groups = append(c.Groups,
		config.Group{ID: "hk", Name: "香港节点", Type: "select", Nodes: []string{}, Groups: []string{}, Subscriptions: []string{}, IncludeAll: true, Filter: "HK|香港"},
		config.Group{ID: "media", Name: "流媒体", Type: "select", Nodes: []string{"vl1"}, Groups: []string{"proxy", "auto"}, Subscriptions: []string{}, IncludeDirect: true, Selected: config.NodeRef("vl1")},
	)
	c.Groups[0].Selected = config.GroupRef("auto")
	c.Routing.BlockAds = true
	c.Routing.BlockQUIC = true
	c.Routing.Final = config.GroupRef("proxy")
	c.Routing.Rules = []config.Rule{
		{ID: "r1", Enabled: true, Type: "domain_suffix", Values: []string{"google.com", ".youtube.com"}, Target: config.GroupRef("proxy")},
		{ID: "r2", Enabled: true, Type: "domain", Values: []string{"example.com"}, Target: config.TargetDirect},
		{ID: "r3", Enabled: true, Type: "domain_keyword", Values: []string{"adservice"}, Target: config.TargetReject},
		{ID: "r4", Enabled: true, Type: "ip_cidr", Values: []string{"8.8.8.8/32", "2001:4860::/32", "1.1.1.1"}, Target: config.GroupRef("proxy")},
		{ID: "r5", Enabled: true, Type: "geosite", Values: []string{"telegram", "not-downloaded"}, Target: config.GroupRef("media")},
		{ID: "r6", Enabled: true, Type: "geoip", Values: []string{"telegram"}, Target: config.GroupRef("media")},
		{ID: "r7", Enabled: true, Type: "package", Values: []string{"com.example.app"}, Target: config.TargetDirect},
		{ID: "r8", Enabled: true, Type: "port", Values: []string{"22", "6000-7000"}, Target: config.TargetDirect},
		{ID: "r9", Enabled: true, Type: "network", Values: []string{"udp"}, Target: config.GroupRef("hk")},
		{ID: "r10", Enabled: true, Type: "domain_regex", Values: []string{`^ad\d+\.example\.net$`}, Target: config.TargetReject},
		{ID: "r11", Enabled: false, Type: "domain", Values: []string{"disabled.example"}, Target: config.TargetReject},
	}
	c.DNS.Direct = []string{"223.5.5.5", "tls://dns.alidns.com"}
	c.DNS.Proxy = []string{"https://dns.google/dns-query", "https://1.1.1.1/dns-query"}
	c.Settings.LogLevel = "info"
	c.Normalize()
	s.Normalize()
	return c, s
}

func testRuntime(dir string) Runtime {
	return Runtime{TunName: "ksu-proxy0", TunIPv4: "172.19.0.1/30", TunIPv6: "fdfe:dcba:9877::1/126", ControllerPort: 19090, ControllerSecret: "secret-value-123",
		MixedPort: 17890, MixedUser: "kpm", MixedPass: "mixed-pass-123", WorkDir: dir, RulesetDir: dir}
}

func rulesetLookup(t *testing.T, engine string) RulesetLookup {
	base := os.Getenv("KPM_TEST_RULESETS")
	ext := ".mrs"
	if engine == config.EngineSingBox {
		ext = ".srs"
	}
	return func(id RulesetID) (string, bool) {
		if base == "" {
			return "/rulesets/" + id.Tag() + ext, id.Name != "not-downloaded"
		}
		p := filepath.Join(base, engine, id.Tag()+ext)
		_, err := os.Stat(p)
		return p, err == nil
	}
}

func TestConfigFixtureValid(t *testing.T) {
	c, s := fixture(false)
	if err := config.Validate(&c, &s); err != nil {
		t.Fatal(err)
	}
}

func TestRenderMihomoStructure(t *testing.T) {
	c, s := fixture(false)
	out, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineMihomo, Version: "1.19.33", Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, config.EngineMihomo)})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out.Content, &doc); err != nil {
		t.Fatal(err)
	}
	if got := len(doc["proxies"].([]any)); got != len(c.Nodes) {
		t.Fatalf("proxies = %d, want %d", got, len(c.Nodes))
	}
	tun := doc["tun"].(map[string]any)
	if tun["auto-route"] != false || tun["device"] != "ksu-proxy0" {
		t.Fatalf("unexpected tun: %v", tun)
	}
	if tun["iproute2-table-index"] != coreRouteTable {
		t.Fatal("Mihomo auxiliary routes are not isolated")
	}
	if _, ok := doc["mixed-port"]; ok {
		t.Fatal("must not expose a global unauthenticated mixed port")
	}
	if doc["external-controller"] != "127.0.0.1:19090" {
		t.Fatalf("controller = %v", doc["external-controller"])
	}
	rules := doc["rules"].([]any)
	last := rules[len(rules)-1].(string)
	if last != "MATCH,节点选择" {
		t.Fatalf("final rule = %q", last)
	}
	text := string(out.Content)
	for _, want := range []string{"RULE-SET,geosite-telegram,流媒体", "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", "PROCESS-NAME,com.example.app,DIRECT", "DST-PORT,6000-7000,DIRECT", "IP-CIDR6,2001:4860::/32,节点选择,no-resolve", "IP-CIDR,1.1.1.1/32,节点选择,no-resolve", "dialer-proxy: HK SS obfs", "rule-set:geosite-cn"} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config missing %q", want)
		}
	}
	if strings.Contains(text, "disabled.example") {
		t.Error("disabled rule rendered")
	}
	if len(out.Missing) != 1 || out.Missing[0].Name != "not-downloaded" {
		t.Errorf("missing = %v", out.Missing)
	}
	groups := doc["proxy-groups"].([]any)
	media := groups[3].(map[string]any)
	if media["name"] != "流媒体" || media["proxies"].([]any)[0] != "HK VLESS Reality" {
		t.Errorf("selected member must be first: %v", media)
	}
	hk := groups[2].(map[string]any)
	for _, m := range hk["proxies"].([]any) {
		if !strings.Contains(m.(string), "HK") {
			t.Errorf("filter leaked %v into 香港节点", m)
		}
	}
	if out.Selected["流媒体"] != "HK VLESS Reality" || out.Selected["节点选择"] != "自动选择" || len(out.Selected) != 3 {
		t.Errorf("selected = %v", out.Selected)
	}
	if strings.Contains(text, "IP-CIDR6,fdfe:dcba:9877::/126,REJECT") {
		t.Error("IPv6 TUN reject rendered while IPv6 is disabled")
	}
	c6, s6 := fixture(true)
	c6.Nodes[4].TLS.Fingerprint = ""
	out6, err := Render(Input{Config: c6, Secrets: s6, Engine: config.EngineMihomo, Version: "1.19.33", Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, config.EngineMihomo)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out6.Content), "IP-CIDR6,fdfe:dcba:9877::/126,REJECT,no-resolve") {
		t.Error("IPv6 TUN subnet must be rejected before the private DIRECT rules")
	}
	if !strings.Contains(string(out6.Content), "client-fingerprint: chrome") {
		t.Error("reality without an explicit fingerprint must default to chrome")
	}
}

func TestRenderSingBoxStructure(t *testing.T) {
	c, s := fixture(true)
	out, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineSingBox, Version: "1.14.4", Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, config.EngineSingBox)})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Content, &doc); err != nil {
		t.Fatal(err)
	}
	route := doc["route"].(map[string]any)
	if route["final"] != "节点选择" {
		t.Fatalf("final = %v", route["final"])
	}
	inb := doc["inbounds"].([]any)
	tun := inb[0].(map[string]any)
	if tun["auto_route"] != false || len(tun["address"].([]any)) != 2 {
		t.Fatalf("tun = %v", tun)
	}
	if tun["iproute2_table_index"] != float64(coreRouteTable) {
		t.Fatal("sing-box auxiliary routes are not isolated")
	}
	mixed := inb[1].(map[string]any)
	if mixed["listen"] != "127.0.0.1" || mixed["users"] == nil {
		t.Fatalf("mixed inbound must be loopback and authenticated: %v", mixed)
	}
	if len(doc["endpoints"].([]any)) != 1 {
		t.Fatal("wireguard must render as endpoint")
	}
	foundWarn := false
	dnsWarn := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "xhttp") {
			foundWarn = true
		}
		if strings.Contains(w, "代理 DNS") {
			dnsWarn = true
		}
	}
	if !foundWarn || !dnsWarn {
		t.Errorf("expected xhttp and ignored-DNS warnings, got %v", out.Warnings)
	}
	text := string(out.Content)
	for _, want := range []string{`"hijack-dns"`, `"clash_mode": "Global"`, `"package_name"`, `"port_range"`, `"server_ports"`, `"detour": "节点选择"`, `"domain_resolver": "dns-direct"`, `"inet6_range"`} {
		if !strings.Contains(text, want) {
			t.Errorf("sing-box config missing %s", want)
		}
	}
	// DNS follows the runtime mode, and the TUN subnet itself is rejected.
	dnsRules := doc["dns"].(map[string]any)["rules"].([]any)
	first, second := dnsRules[0].(map[string]any), dnsRules[1].(map[string]any)
	if first["clash_mode"] != "Direct" || first["server"] != "dns-direct" || second["clash_mode"] != "Global" || second["server"] != "dns-proxy" {
		t.Fatalf("dns mode rules: %v %v", first, second)
	}
	if last := dnsRules[len(dnsRules)-1].(map[string]any); last["server"] != "dns-fakeip" || last["rewrite_ttl"] != float64(1) {
		t.Fatalf("fake-ip answers must not be cached: %v", last)
	}
	rr := route["rules"].([]any)[2].(map[string]any)
	if rr["action"] != "reject" || len(rr["ip_cidr"].([]any)) != 2 || rr["ip_cidr"].([]any)[0] != "172.19.0.0/30" {
		t.Fatalf("tun subnet rule: %v", rr)
	}
}

func TestRenderMissingRulesetsDegrade(t *testing.T) {
	c, s := fixture(false)
	none := func(RulesetID) (string, bool) { return "", false }
	for _, eng := range []string{config.EngineMihomo, config.EngineSingBox} {
		out, err := Render(Input{Config: c, Secrets: s, Engine: eng, Version: "", Runtime: testRuntime(t.TempDir()), Rulesets: none})
		if err != nil {
			t.Fatal(eng, err)
		}
		if bytes.Contains(out.Content, []byte("geosite-cn")) || len(out.Missing) == 0 {
			t.Errorf("%s: missing rule sets must be omitted and reported", eng)
		}
	}
}

func TestRenderRejectsOldCore(t *testing.T) {
	c, s := fixture(false)
	if _, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineSingBox, Version: "1.11.9", Runtime: testRuntime(t.TempDir())}); err == nil {
		t.Fatal("sing-box 1.11 must be rejected")
	}
	if _, err := Render(Input{Config: c, Secrets: s, Engine: config.EngineMihomo, Version: "1.18.0", Runtime: testRuntime(t.TempDir())}); err == nil {
		t.Fatal("Mihomo without authenticated mixed listeners must be rejected")
	}
}

func TestRenderTransportHeaders(t *testing.T) {
	configuration, secrets := fixture(false)
	configuration.Nodes[2].Transport.Headers["Host"] = "ignored.example.com"
	configuration.Nodes[2].Transport.Headers["host"] = "also-ignored.example.com"
	configuration.Nodes[7].Transport.Headers = map[string]string{"X-Test": "required"}
	for _, engineName := range []string{config.EngineMihomo, config.EngineSingBox} {
		output, err := Render(Input{Config: configuration, Secrets: secrets, Engine: engineName, Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, engineName)})
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if engineName == config.EngineMihomo {
			if err := yaml.Unmarshal(output.Content, &document); err != nil {
				t.Fatal("duplicate YAML keys", err)
			}
		} else {
			if err := json.Unmarshal(output.Content, &document); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, outbound := range document["outbounds"].([]any) {
				object := outbound.(map[string]any)
				if object["tag"] == "VLESS h2" {
					headers := object["transport"].(map[string]any)["headers"].(map[string]any)
					found = headers["X-Test"] == "required"
				}
			}
			if !found {
				t.Fatal("HTTP transport headers lost")
			}
		}
		if bytes.Contains(output.Content, []byte("ignored.example.com")) {
			t.Fatal("ambiguous Host was not normalized")
		}
		checkWithCore(t, engineName, output)
	}
}

func TestRenderEmptyConfig(t *testing.T) {
	c := config.Default()
	c.Normalize()
	s := config.DefaultSecrets()
	for _, eng := range []string{config.EngineMihomo, config.EngineSingBox} {
		out, err := Render(Input{Config: c, Secrets: s, Engine: eng, Runtime: testRuntime(t.TempDir())})
		if err != nil {
			t.Fatal(eng, err)
		}
		if len(out.Warnings) == 0 {
			t.Errorf("%s: expected warnings for empty groups", eng)
		}
		checkWithCore(t, eng, out)
	}
}

// TestRenderWithRealCores validates generated files with the official binaries
// when KPM_TEST_CORES points at a directory containing them.
func TestRenderWithRealCores(t *testing.T) {
	if os.Getenv("KPM_TEST_CORES") == "" {
		t.Skip("KPM_TEST_CORES not set")
	}
	for _, ipv6 := range []bool{false, true} {
		for _, mode := range []string{"fakeip", "realip"} {
			for _, eng := range []string{config.EngineMihomo, config.EngineSingBox} {
				c, s := fixture(ipv6)
				c.DNS.Mode = mode
				out, err := Render(Input{Config: c, Secrets: s, Engine: eng, Runtime: testRuntime(t.TempDir()), Rulesets: rulesetLookup(t, eng)})
				if err != nil {
					t.Fatal(err)
				}
				checkWithCore(t, eng, out)
			}
		}
	}
}

func checkWithCore(t *testing.T, engine string, out *Output) {
	t.Helper()
	dir := os.Getenv("KPM_TEST_CORES")
	if dir == "" {
		return
	}
	work := t.TempDir()
	path := filepath.Join(work, out.FileName)
	if err := os.WriteFile(path, out.Content, 0o600); err != nil {
		t.Fatal(err)
	}
	type check struct {
		bin  string
		args []string
	}
	var checks []check
	if engine == config.EngineMihomo {
		checks = append(checks, check{filepath.Join(dir, "mihomo"), []string{"-t", "-d", work, "-f", path}})
	} else {
		for _, b := range []string{"sing-box", "sing-box-1.13"} {
			checks = append(checks, check{filepath.Join(dir, b), []string{"check", "-D", work, "-c", path}})
		}
	}
	for _, ck := range checks {
		if _, err := os.Stat(ck.bin); err != nil {
			t.Logf("skip %s: %v", ck.bin, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, ck.bin, ck.args...)
		cmd.Env = append(os.Environ(), out.Env...)
		cmd.Env = append(cmd.Env, "SAFE_PATHS="+os.Getenv("KPM_TEST_RULESETS"))
		res, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Errorf("%s rejected config: %v\n%s\n--- config ---\n%s", filepath.Base(ck.bin), err, res, out.Content)
		} else {
			t.Logf("%s accepted %s: %s", filepath.Base(ck.bin), out.FileName, lastLine(res))
		}
	}
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}
