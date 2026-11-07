package subscription

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestDenseYAMLIsRejectedBeforeTreeAllocation(t *testing.T) {
	data := append([]byte("proxies: ["), bytes.Repeat([]byte("0,"), maxYAMLNodes)...)
	data = append(data, ']')
	result := Parse(data)
	if len(result.Nodes) != 0 || len(result.Issues) == 0 || !strings.Contains(result.Issues[0].Message, "复杂度") {
		t.Fatalf("dense YAML was not rejected by the pre-parser budget: %+v", result.Issues)
	}
}

func TestShareLinkEscapes(t *testing.T) {
	user := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p"))
	link := "ss://" + url.PathEscape(user) + "@example.com:443/?plugin=obfs-local;obfs=http;obfs-host=example.net#SS"
	link = strings.ReplaceAll(link, "=", "%3D")
	link = strings.ReplaceAll(link, "plugin%3D", "plugin=")
	link = strings.ReplaceAll(link, "obfs%3D", "obfs=")
	link = strings.ReplaceAll(link, "obfs-host%3D", "obfs-host=")
	p, err := ParseLink(link)
	if err != nil || p.Node.Plugin != "obfs" || p.Node.PluginOpts["host"] != "example.net" {
		t.Fatalf("SIP003 plugin or escaped Base64 padding was lost: %+v %v", p.Node, err)
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
	wg, err := ParseLink("wireguard://" + url.PathEscape(key) + "@example.com:51820?publickey=" + key + "&presharedkey=" + key + "&address=10.0.0.2")
	if err != nil || wg.Node.PeerPublicKey != key || wg.Secrets["preSharedKey"] != key {
		t.Fatal("WireGuard Base64 plus signs were interpreted as spaces", err)
	}
}

func TestUnsupportedSubscriptionSemanticsAreVisible(t *testing.T) {
	for _, text := range []string{
		"proxies:\n- {name: chained, type: trojan, server: example.com, port: 443, password: secret, dialer-proxy: upstream}",
		`{"outbounds":[{"type":"trojan","tag":"chained","server":"example.com","server_port":443,"password":"secret","detour":"upstream"}]}`,
	} {
		result := Parse([]byte(text))
		if len(result.Nodes) != 0 || len(result.Issues) == 0 {
			t.Fatal("a chained outbound was silently converted to an unchained node")
		}
	}
}

func TestSingBoxListableStrings(t *testing.T) {
	result := Parse([]byte(`{"outbounds":[{"type":"hysteria2","tag":"hy","server":"example.com","server_ports":"20000:30000","password":"secret","tls":{"enabled":true,"alpn":"h3"}}]}`))
	if len(result.Nodes) != 1 || result.Nodes[0].Node.Ports != "20000-30000" || result.Nodes[0].Node.TLS.ALPN[0] != "h3" {
		t.Fatalf("valid sing-box scalar lists were rejected: %+v", result)
	}
}

func TestSingBoxListableStringsRejectInvalidTypes(t *testing.T) {
	for _, value := range []string{`42`, `{}`, `["h3",42]`} {
		text := `{"outbounds":[{"type":"hysteria2","tag":"invalid","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true,"alpn":` + value + `}}]}`
		result := Parse([]byte(text))
		if len(result.Nodes) != 0 || len(result.Issues) == 0 {
			t.Fatalf("invalid ALPN list was silently ignored: %s", value)
		}
	}
	for _, value := range []string{`["h3"]`, `null`} {
		text := `{"outbounds":[{"type":"hysteria2","tag":"valid","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true,"alpn":` + value + `}}]}`
		if result := Parse([]byte(text)); len(result.Nodes) != 1 {
			t.Fatalf("valid ALPN array/null regressed: %s: %+v", value, result.Issues)
		}
	}
}

func BenchmarkDenseYAMLRejection(b *testing.B) {
	data := append([]byte("proxies: ["), bytes.Repeat([]byte("0,"), 500000)...)
	data = append(data, ']')
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if result := Parse(data); len(result.Nodes) != 0 || len(result.Issues) == 0 {
			b.Fatal("dense YAML was not rejected")
		}
	}
}
