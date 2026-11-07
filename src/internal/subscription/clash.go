package subscription

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"ksu_proxy_manager/internal/config"
)

const (
	maxYAMLDepth = 32
	maxYAMLNodes = 400000
	maxYAMLSize  = 4 << 20
)

// A conservative raw-input budget precedes yaml.v3's whole-document parser.
// Counting delimiters even inside scalars bounds allocations without trying
// to implement a second YAML parser; semantic/alias limits still apply below.
func preflightYAML(data []byte) error {
	if len(data) > maxYAMLSize {
		return errors.New("YAML 内容超过 4 MiB 上限")
	}
	budget := maxYAMLNodes / 2
	for _, b := range data {
		switch b {
		case '\n', ':', ',', '[', ']', '{', '}', '-', '?', '&', '*':
			budget--
			if budget < 0 {
				return errors.New("YAML 结构复杂度超过上限")
			}
		}
	}
	return nil
}

// checkYAML bounds document depth and size before decoding into Go values.
// Aliases are followed so that their expansion counts toward the limits.
func checkYAML(n *yaml.Node, depth int, count *int) error {
	*count++
	if *count > maxYAMLNodes {
		return errors.New("YAML 节点数量超过上限")
	}
	if depth > maxYAMLDepth {
		return errors.New("YAML 嵌套层级过深")
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		return checkYAML(n.Alias, depth+1, count)
	}
	for _, c := range n.Content {
		if err := checkYAML(c, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func parseClash(data []byte) Result {
	r := Result{Format: "clash"}
	if err := preflightYAML(data); err != nil {
		r.issue("", "%v", err)
		return r
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		r.issue("", "YAML 解析失败: %v", err)
		return r
	}
	count := 0
	if err := checkYAML(&root, 0, &count); err != nil {
		r.issue("", "%v", err)
		return r
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
		Legacy  []map[string]any `yaml:"Proxy"`
	}
	if err := root.Decode(&doc); err != nil {
		r.issue("", "YAML 结构无效: %v", err)
		return r
	}
	proxies := doc.Proxies
	if len(proxies) == 0 {
		proxies = doc.Legacy
	}
	if len(proxies) == 0 {
		r.issue("", "YAML 中没有 proxies 节点（不支持仅含 proxy-providers 的配置）")
		return r
	}
	for _, m := range proxies {
		if str(m, "dialer-proxy") != "" {
			r.issue(str(m, "name"), "dialer-proxy 前置路由无法完整导入，已跳过该节点")
			continue
		}
		for _, field := range []string{"smux", "multiplex"} {
			if value, ok := m[field]; ok && value != nil && value != false {
				r.issue(str(m, "name"), "%s 多路复用参数未导入", field)
			}
		}
		p, err := clashNode(m)
		if err != nil {
			r.issue(str(m, "name"), "%v", err)
			continue
		}
		r.add(p)
	}
	return r
}

func str(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func num(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}
	return 0
}

func boolean(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return truthy(v)
	case int:
		return v != 0
	}
	return false
}

func sub(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func strList(v any) []string {
	switch x := v.(type) {
	case string:
		return splitList(x)
	case []any:
		var out []string
		for _, i := range x {
			if s, ok := i.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func clashTLS(n *config.Node, m map[string]any, enabled bool) {
	if !enabled {
		return
	}
	t := &config.TLS{
		Enabled:     true,
		SNI:         firstNonEmpty(str(m, "servername"), str(m, "sni")),
		ALPN:        strList(m["alpn"]),
		Insecure:    boolean(m, "skip-cert-verify"),
		Fingerprint: strings.ToLower(str(m, "client-fingerprint")),
	}
	if ro := sub(m, "reality-opts"); ro != nil {
		t.RealityPublicKey = str(ro, "public-key")
		t.RealityShortID = str(ro, "short-id")
	}
	n.TLS = t
}

func clashTransport(n *config.Node, m map[string]any) error {
	network := str(m, "network")
	switch network {
	case "", "tcp":
		return nil
	case "ws":
		t := &config.Transport{Type: "ws"}
		if o := sub(m, "ws-opts"); o != nil {
			t.Path = str(o, "path")
			if boolean(o, "v2ray-http-upgrade") {
				t.Type = "httpupgrade"
			}
			if h := sub(o, "headers"); h != nil {
				for k, v := range h {
					s := fmt.Sprint(v)
					if strings.EqualFold(k, "host") {
						t.Host = s
					} else {
						if t.Headers == nil {
							t.Headers = map[string]string{}
						}
						t.Headers[k] = s
					}
				}
			}
		}
		n.Transport = t
	case "grpc":
		t := &config.Transport{Type: "grpc"}
		if o := sub(m, "grpc-opts"); o != nil {
			t.ServiceName = str(o, "grpc-service-name")
		}
		n.Transport = t
	case "h2":
		t := &config.Transport{Type: "http"}
		if o := sub(m, "h2-opts"); o != nil {
			t.Path = str(o, "path")
			if hosts := strList(o["host"]); len(hosts) > 0 {
				t.Host = hosts[0]
			}
		}
		n.Transport = t
	case "xhttp":
		t := &config.Transport{Type: "xhttp"}
		if o := sub(m, "xhttp-opts"); o != nil {
			t.Path = str(o, "path")
			t.Host = str(o, "host")
		}
		n.Transport = t
	case "http":
		return errors.New("不支持 TCP HTTP 伪装传输")
	default:
		return fmt.Errorf("不支持的传输方式 %s", network)
	}
	return nil
}

func clashNode(m map[string]any) (Parsed, error) {
	typ := str(m, "type")
	name := str(m, "name")
	server := str(m, "server")
	port := num(m, "port")
	var p Parsed
	switch typ {
	case "ss":
		p = newParsed("shadowsocks", name, server, port)
		p.Node.Cipher = strings.ToLower(str(m, "cipher"))
		p.Secrets["password"] = str(m, "password")
		if plugin := str(m, "plugin"); plugin != "" {
			opts := sub(m, "plugin-opts")
			switch plugin {
			case "obfs":
				p.Node.Plugin = "obfs"
				p.Node.PluginOpts = map[string]string{"mode": str(opts, "mode")}
				if h := str(opts, "host"); h != "" {
					p.Node.PluginOpts["host"] = h
				}
			case "v2ray-plugin":
				p.Node.Plugin = "v2ray-plugin"
				p.Node.PluginOpts = map[string]string{"mode": "websocket"}
				if mode := str(opts, "mode"); mode != "" && mode != "websocket" {
					return Parsed{}, fmt.Errorf("v2ray-plugin 模式 %s 不受支持", mode)
				}
				for _, k := range []string{"host", "path"} {
					if v := str(opts, k); v != "" {
						p.Node.PluginOpts[k] = v
					}
				}
				if boolean(opts, "tls") {
					p.Node.PluginOpts["tls"] = "true"
				}
				if boolean(opts, "mux") {
					p.Node.PluginOpts["mux"] = "true"
				}
			default:
				return Parsed{}, fmt.Errorf("不支持的 SS 插件 %s", plugin)
			}
		}
	case "vmess":
		p = newParsed("vmess", name, server, port)
		p.Secrets["uuid"] = str(m, "uuid")
		p.Node.AlterID = num(m, "alterId")
		p.Node.Security = strings.ToLower(firstNonEmpty(str(m, "cipher"), "auto"))
		if err := clashTransport(&p.Node, m); err != nil {
			return Parsed{}, err
		}
		clashTLS(&p.Node, m, boolean(m, "tls"))
	case "vless":
		p = newParsed("vless", name, server, port)
		p.Secrets["uuid"] = str(m, "uuid")
		p.Node.Flow = str(m, "flow")
		if enc := str(m, "encryption"); enc != "" && enc != "none" {
			return Parsed{}, fmt.Errorf("VLESS encryption=%s 不受支持", enc)
		}
		if err := clashTransport(&p.Node, m); err != nil {
			return Parsed{}, err
		}
		clashTLS(&p.Node, m, boolean(m, "tls") || sub(m, "reality-opts") != nil)
		if ro := sub(m, "reality-opts"); ro != nil && p.Node.TLS.RealityPublicKey == "" {
			return Parsed{}, errors.New("reality-opts 缺少 public-key")
		}
	case "trojan":
		p = newParsed("trojan", name, server, port)
		p.Secrets["password"] = str(m, "password")
		if err := clashTransport(&p.Node, m); err != nil {
			return Parsed{}, err
		}
		clashTLS(&p.Node, m, true)
	case "hysteria2":
		p = newParsed("hysteria2", name, server, port)
		p.Secrets["password"] = firstNonEmpty(str(m, "password"), str(m, "auth"))
		p.Node.Ports = strings.ReplaceAll(str(m, "ports"), " ", "")
		if o := str(m, "obfs"); o != "" {
			if o != "salamander" {
				return Parsed{}, fmt.Errorf("不支持的 Hysteria2 混淆 %s", o)
			}
			p.Node.Obfs = o
			p.Secrets["obfsPassword"] = str(m, "obfs-password")
		}
		p.Node.UpMbps = parseMbps(str(m, "up"))
		p.Node.DownMbps = parseMbps(str(m, "down"))
		clashTLS(&p.Node, m, true)
	case "tuic":
		p = newParsed("tuic", name, server, port)
		if str(m, "token") != "" && str(m, "uuid") == "" {
			return Parsed{}, errors.New("不支持 TUIC v4")
		}
		p.Secrets["uuid"] = str(m, "uuid")
		p.Secrets["password"] = str(m, "password")
		p.Node.CongestionControl = str(m, "congestion-controller")
		p.Node.UDPRelayMode = str(m, "udp-relay-mode")
		clashTLS(&p.Node, m, true)
	case "anytls":
		p = newParsed("anytls", name, server, port)
		p.Secrets["password"] = str(m, "password")
		clashTLS(&p.Node, m, true)
	case "socks5":
		p = newParsed("socks", name, server, port)
		p.Secrets["username"] = str(m, "username")
		p.Secrets["password"] = str(m, "password")
		if boolean(m, "tls") {
			return Parsed{}, errors.New("不支持 SOCKS over TLS")
		}
	case "http":
		p = newParsed("http", name, server, port)
		p.Secrets["username"] = str(m, "username")
		p.Secrets["password"] = str(m, "password")
		clashTLS(&p.Node, m, boolean(m, "tls"))
	case "wireguard":
		p = newParsed("wireguard", name, server, port)
		if _, ok := m["peers"]; ok {
			return Parsed{}, errors.New("不支持多 peer WireGuard")
		}
		p.Secrets["privateKey"] = str(m, "private-key")
		p.Secrets["preSharedKey"] = str(m, "pre-shared-key")
		p.Node.PeerPublicKey = str(m, "public-key")
		for _, k := range []string{"ip", "ipv6"} {
			if a := str(m, k); a != "" {
				if !strings.Contains(a, "/") {
					if strings.Contains(a, ":") {
						a += "/128"
					} else {
						a += "/32"
					}
				}
				p.Node.LocalAddress = append(p.Node.LocalAddress, a)
			}
		}
		if res, ok := m["reserved"].([]any); ok {
			for _, v := range res {
				switch b := v.(type) {
				case int:
					p.Node.Reserved = append(p.Node.Reserved, b)
				case float64:
					p.Node.Reserved = append(p.Node.Reserved, int(b))
				}
			}
		}
		p.Node.WGMTU = num(m, "mtu")
	default:
		return Parsed{}, fmt.Errorf("不支持的节点类型 %q", typ)
	}
	if _, ok := m["udp"]; ok {
		p.Node.UDP = boolean(m, "udp")
	} else {
		p.Node.UDP = typ == "hysteria2" || typ == "tuic" || typ == "wireguard"
	}
	if p.Node.Type == "hysteria2" || p.Node.Type == "tuic" || p.Node.Type == "wireguard" {
		p.Node.UDP = true
	}
	if p.Node.Type == "http" {
		p.Node.UDP = false
	}
	return p, nil
}
