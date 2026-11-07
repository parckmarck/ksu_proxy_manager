package subscription

import (
	"encoding/base64"
	"strings"
	"testing"

	"ksu_proxy_manager/internal/config"
)

func one(t *testing.T, link string) Parsed {
	t.Helper()
	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("%s: %v", link, err)
	}
	return p
}

func TestShareLinks(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"VM 节点","add":"vm.example.com","port":"443","id":"0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ray","tls":"tls","sni":"vm.example.com"}`
	cases := []struct {
		link   string
		typ    string
		server string
		port   int
		secret map[string]string
		check  func(t *testing.T, n config.Node)
	}{
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss")) + "@1.2.3.4:8388#SS%20%E8%8A%82%E7%82%B9", "shadowsocks", "1.2.3.4", 8388,
			map[string]string{"password": "pa:ss"}, func(t *testing.T, n config.Node) {
				if n.Cipher != "aes-256-gcm" || n.Name != "SS 节点" {
					t.Fatalf("%+v", n)
				}
			}},
		{"ss://2022-blake3-aes-128-gcm:YmFzZTY0a2V5@[2001:db8::1]:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#v6", "shadowsocks", "2001:db8::1", 443,
			map[string]string{"password": "YmFzZTY0a2V5"}, func(t *testing.T, n config.Node) {
				if n.Plugin != "obfs" || n.PluginOpts["host"] != "example.com" {
					t.Fatalf("plugin %+v %+v", n.Plugin, n.PluginOpts)
				}
			}},
		{"vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)), "vmess", "vm.example.com", 443,
			map[string]string{"uuid": "0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f"}, func(t *testing.T, n config.Node) {
				if n.Transport == nil || n.Transport.Type != "ws" || n.Transport.Path != "/ray" || n.Transport.Host != "cdn.example.com" || n.TLS == nil || !n.TLS.Enabled {
					t.Fatalf("%+v %+v %+v", n, n.Transport, n.TLS)
				}
			}},
		{"vless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@r.example.com:443?security=reality&sni=www.microsoft.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&fp=chrome&flow=xtls-rprx-vision&type=tcp#R", "vless", "r.example.com", 443,
			map[string]string{"uuid": "0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f"}, func(t *testing.T, n config.Node) {
				if n.Flow != "xtls-rprx-vision" || n.TLS == nil || n.TLS.RealityPublicKey == "" || n.TLS.RealityShortID != "6ba85179e30d4fc2" || n.TLS.Fingerprint != "chrome" {
					t.Fatalf("%+v %+v", n, n.TLS)
				}
			}},
		{"vless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@g.example.com:443?security=tls&type=grpc&serviceName=svc#G", "vless", "g.example.com", 443,
			nil, func(t *testing.T, n config.Node) {
				if n.Transport == nil || n.Transport.Type != "grpc" || n.Transport.ServiceName != "svc" {
					t.Fatalf("%+v", n.Transport)
				}
			}},
		{"trojan://p%40ss@t.example.com:443?sni=t.example.com&allowInsecure=1#T", "trojan", "t.example.com", 443,
			map[string]string{"password": "p@ss"}, func(t *testing.T, n config.Node) {
				if n.TLS == nil || !n.TLS.Insecure || n.TLS.SNI != "t.example.com" {
					t.Fatalf("%+v", n.TLS)
				}
			}},
		{"hysteria2://pw@h.example.com:443?obfs=salamander&obfs-password=op&sni=h.example.com&mport=20000-30000&upmbps=50&downmbps=200#H", "hysteria2", "h.example.com", 443,
			map[string]string{"password": "pw", "obfsPassword": "op"}, func(t *testing.T, n config.Node) {
				if n.Obfs != "salamander" || n.UpMbps != 50 || n.DownMbps != 200 || n.Ports != "20000-30000" {
					t.Fatalf("%+v", n)
				}
			}},
		{"hy2://pw@h2.example.com:8443#H2", "hysteria2", "h2.example.com", 8443, map[string]string{"password": "pw"}, nil},
		{"tuic://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f:pw@tu.example.com:443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=tu.example.com#TU", "tuic", "tu.example.com", 443,
			map[string]string{"uuid": "0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f", "password": "pw"}, func(t *testing.T, n config.Node) {
				if n.CongestionControl != "bbr" || n.UDPRelayMode != "quic" {
					t.Fatalf("%+v", n)
				}
			}},
		{"anytls://pw@a.example.com:443?sni=a.example.com#A", "anytls", "a.example.com", 443, map[string]string{"password": "pw"}, nil},
		{"socks5://user:pass@9.9.9.9:1080#S5", "socks", "9.9.9.9", 1080, map[string]string{"username": "user", "password": "pass"}, nil},
		{"https://user:pass@p.example.com:8443#HP", "http", "p.example.com", 8443, map[string]string{"username": "user", "password": "pass"}, func(t *testing.T, n config.Node) {
			if n.TLS == nil || !n.TLS.Enabled {
				t.Fatal("https proxy without TLS")
			}
		}},
		{"wireguard://cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5cHI%3D@w.example.com:51820?publickey=cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHVibGk%3D&address=10.0.0.2%2F32&mtu=1280&reserved=1,2,3#WG", "wireguard", "w.example.com", 51820,
			map[string]string{"privateKey": "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5cHI="}, func(t *testing.T, n config.Node) {
				if n.PeerPublicKey == "" || len(n.LocalAddress) != 1 || n.WGMTU != 1280 || len(n.Reserved) != 3 {
					t.Fatalf("%+v", n)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.typ+"/"+tc.server, func(t *testing.T) {
			p := one(t, tc.link)
			if p.Node.Type != tc.typ || p.Node.Server != tc.server || p.Node.Port != tc.port {
				t.Fatalf("got %s %s:%d", p.Node.Type, p.Node.Server, p.Node.Port)
			}
			for k, v := range tc.secret {
				if p.Secrets[k] != v {
					t.Fatalf("secret %s = %q, want %q", k, p.Secrets[k], v)
				}
			}
			p.Node.ID = "x"
			if err := config.ValidateNode(&p.Node, "node"); err != nil {
				t.Fatalf("parsed node invalid: %v", err)
			}
			if tc.check != nil {
				tc.check(t, p.Node)
			}
		})
	}
}

func TestBadLinks(t *testing.T) {
	for _, l := range []string{
		"ss://", "vmess://notbase64!!", "vless://@host:443", "trojan://pw@host:0", "trojan://pw@host:99999",
		"hysteria2://pw@:443", "ftp://x@y:1", "vless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@host:443?type=ws&path=" + strings.Repeat("a", 3000),
		"hysteria2://pw@h.example.com:443?mport=1-2-3",
		"vless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@r.example.com:443?security=reality&sni=www.microsoft.com&fp=chrome#NoKey",
	} {
		if r := Parse([]byte(l)); len(r.Nodes) != 0 || len(r.Issues) == 0 {
			t.Errorf("%.80q accepted", l)
		}
	}
}

func TestParseFormats(t *testing.T) {
	links := "trojan://pw@a.example.com:443#A\nvless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@b.example.com:443?security=tls#B\n"
	if r := Parse([]byte(links)); r.Format != "links" || len(r.Nodes) != 2 {
		t.Fatalf("links: %+v", r)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(links))
	if r := Parse([]byte(b64[:len(b64)-1] + "\n")); len(r.Nodes) != 2 && r.Format != "base64" {
		t.Logf("truncated base64 tolerated: %+v", r.Format)
	}
	if r := Parse([]byte(b64)); r.Format != "base64" || len(r.Nodes) != 2 {
		t.Fatalf("base64: %+v", r)
	}
	// Base64-wrapped Clash documents usually contain URLs; they must still be
	// recognised as Clash rather than as a list of share links.
	b64Clash := base64.StdEncoding.EncodeToString([]byte("proxy-providers:\n  p: {type: http, url: 'https://x.example.com/p', path: ./p.yaml}\nproxies:\n  - {name: BC, type: trojan, server: a.example.com, port: 443, password: pw}\n"))
	if r := Parse([]byte(b64Clash)); r.Format != "clash" || len(r.Nodes) != 1 {
		t.Fatalf("base64 clash: %+v", r)
	}
	clash := `
proxies:
  - {name: "C1", type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: "pw", udp: true}
  - name: C2
    type: vmess
    server: v.example.com
    port: 443
    uuid: 0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts: {path: /p, headers: {Host: cdn.example.com}}
  - {name: C3, type: hysteria2, server: h.example.com, port: 443, password: pw, ports: "2000-3000", up: "30 Mbps", down: 100}
  - {name: C4, type: unknown-type, server: x, port: 1}
proxy-groups:
  - {name: G, type: select, proxies: [C1, C2]}
`
	r := Parse([]byte(clash))
	if r.Format != "clash" || len(r.Nodes) != 3 || len(r.Issues) != 1 {
		t.Fatalf("clash: %+v", r)
	}
	if n := r.Nodes[1].Node; n.Transport == nil || n.Transport.Host != "cdn.example.com" || n.TLS == nil || !n.TLS.Enabled {
		t.Fatalf("clash vmess: %+v", n)
	}
	if n := r.Nodes[2].Node; n.UpMbps != 30 || n.DownMbps != 100 || n.Ports != "2000-3000" {
		t.Fatalf("clash hy2: %+v", n)
	}
	sb := `{"outbounds":[
		{"type":"shadowsocks","tag":"S1","server":"1.2.3.4","server_port":8388,"method":"aes-128-gcm","password":"pw"},
		{"type":"vless","tag":"S2","server":"v.example.com","server_port":443,"uuid":"0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f","tls":{"enabled":true,"server_name":"v.example.com","utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"http","path":"/h","host":["a.example.com"]}},
		{"type":"selector","tag":"sel","outbounds":["S1"]},
		{"type":"direct","tag":"direct"}],
	 "endpoints":[{"type":"wireguard","tag":"W","address":["10.0.0.2/32"],"private_key":"cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5cHI=","peers":[{"address":"w.example.com","port":51820,"public_key":"cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHVibGk=","allowed_ips":["0.0.0.0/0"]}]}]}`
	r = Parse([]byte(sb))
	if r.Format != "sing-box" || len(r.Nodes) != 3 {
		t.Fatalf("sing-box: %+v", r)
	}
	for _, bad := range []string{"", "   ", "random text", "{\"outbounds\": 5}"} {
		if r := Parse([]byte(bad)); len(r.Nodes) != 0 || len(r.Issues) == 0 {
			t.Errorf("%q: %+v", bad, r)
		}
	}
}

func TestClashYAMLBombsRejected(t *testing.T) {
	bomb := "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n" +
		"b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n" +
		"c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n" +
		"d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n" +
		"e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n" +
		"f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n" +
		"proxies: [*f]\n"
	if r := Parse([]byte(bomb)); len(r.Nodes) != 0 || len(r.Issues) == 0 {
		t.Fatalf("bomb parsed: %d nodes", len(r.Nodes))
	}
	deep := "proxies:\n" + strings.Repeat("- ", 500) + "x\n"
	if r := Parse([]byte(deep)); len(r.Nodes) != 0 {
		t.Fatal("deep nesting parsed")
	}
}

func TestFiltersIDsAndDiff(t *testing.T) {
	r := Parse([]byte("trojan://pw@a.example.com:443#香港 01\ntrojan://pw@b.example.com:443#香港 01\ntrojan://pw@c.example.com:443#日本 01\ntrojan://pw@d.example.com:443#官网 剩余流量\n"))
	nodes, err := ApplyFilters(r.Nodes, "香港|日本", "剩余")
	if err != nil || len(nodes) != 3 {
		t.Fatalf("filters: %d %v", len(nodes), err)
	}
	if _, err := ApplyFilters(r.Nodes, "(", ""); err == nil {
		t.Fatal("bad regex accepted")
	}
	AssignSubscriptionIDs("s1", nodes)
	if nodes[0].Node.Name == nodes[1].Node.Name || nodes[0].Node.ID == nodes[1].Node.ID {
		t.Fatal("duplicate names not disambiguated")
	}
	if nodes[0].Node.ID != NodeIDFor("s1", nodes[0].Node.Name) || NodeIDFor("s1", "x") == NodeIDFor("s2", "x") {
		t.Fatal("IDs not stable per subscription")
	}
	for _, n := range nodes {
		if !config.ValidID(n.Node.ID) || n.Node.SubscriptionID != "s1" {
			t.Fatalf("bad id %+v", n.Node)
		}
	}
	// A provider that already ships "(2)" suffixes must not collide.
	pre := Parse([]byte("trojan://pw@a.example.com:443#X\ntrojan://pw@b.example.com:443#X (2)\ntrojan://pw@c.example.com:443#X\n")).Nodes
	AssignSubscriptionIDs("s1", pre)
	seen := map[string]bool{}
	for _, p := range pre {
		if seen[p.Node.ID] {
			t.Fatalf("duplicate id after renaming: %+v", pre)
		}
		seen[p.Node.ID] = true
	}
	var current []config.Node
	sec := config.DefaultSecrets()
	for _, p := range nodes[:2] {
		current = append(current, p.Node)
		sec.SetNodeSecrets(p.Node.ID, p.Secrets)
	}
	next := []Parsed{nodes[0], nodes[2]}
	next[0].Secrets = map[string]string{"password": "changed"}
	d := Compare(current, sec, next)
	if len(d.Added) != 1 || len(d.Removed) != 1 || len(d.Changed) != 1 || d.Unchanged != 0 {
		t.Fatalf("diff: %+v", d)
	}
}

func TestNodeLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxNodes+5; i++ {
		b.WriteString("trojan://pw@a.example.com:443#n")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString("\n")
	}
	r := Parse([]byte(b.String()))
	if len(r.Nodes) != MaxNodes {
		t.Fatalf("got %d nodes", len(r.Nodes))
	}
}
