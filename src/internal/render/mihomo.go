package render

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"ksu_proxy_manager/internal/config"
)

type kv struct {
	k string
	v any
}

// omap is an insertion-ordered YAML mapping.
type omap []kv

func (m omap) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.MappingNode}
	for _, e := range m {
		var vn yaml.Node
		if err := vn.Encode(e.v); err != nil {
			return nil, err
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e.k}, &vn)
	}
	return n, nil
}

func mihomoDNS(s config.DNSServer) string {
	host := s.Host
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		host = "[" + host + "]"
	}
	switch s.Scheme {
	case "udp":
		if s.Port == 53 {
			return host
		}
		return host + ":" + strconv.Itoa(s.Port)
	case "https":
		if s.Port == 443 {
			return "https://" + host + s.Path
		}
		return "https://" + host + ":" + strconv.Itoa(s.Port) + s.Path
	default:
		return s.Scheme + "://" + host + ":" + strconv.Itoa(s.Port)
	}
}

func mihomoLogLevel(l string) string {
	if l == "warn" {
		return "warning"
	}
	return l
}

func renderMihomo(p *plan) ([]byte, error) {
	in := p.in
	cfg := &in.Config
	rt := in.Runtime
	var proxies []any
	for _, pn := range p.nodes {
		m, err := mihomoProxy(pn)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, m)
	}
	var groups []any
	for _, g := range p.groups {
		m := omap{{"name", g.tag}}
		if g.group.Type == "urltest" || g.group.Type == "fallback" || g.group.Type == "load-balance" {
			typ := "url-test"
			if g.group.Type != "urltest" {
				typ = g.group.Type
			}
			m = append(m, kv{"type", typ}, kv{"proxies", g.members},
				kv{"url", orDefault(g.group.TestURL, defaultTestURL)},
				kv{"interval", orDefaultInt(g.group.IntervalSec, defaultInterval)})
			if g.group.Type == "urltest" {
				m = append(m, kv{"tolerance", orDefaultInt(g.group.ToleranceMs, defaultTolerate)})
			}
			if g.group.Type == "load-balance" {
				m = append(m, kv{"strategy", orDefault(g.group.Strategy, "consistent-hashing")})
			}
		} else {
			m = append(m, kv{"type", "select"}, kv{"proxies", g.members})
		}
		groups = append(groups, m)
	}
	globalMembers := []string{p.targetTag(p.global)}
	for _, g := range p.groups {
		if g.tag != globalMembers[0] {
			globalMembers = append(globalMembers, g.tag)
		}
	}
	if globalMembers[0] != "DIRECT" {
		globalMembers = append(globalMembers, "DIRECT")
	}
	groups = append(groups, omap{{"name", "GLOBAL"}, {"type", "select"}, {"proxies", globalMembers}})

	providers := omap{}
	for _, id := range sortedRulesets(p.rulesets) {
		behavior := "domain"
		if id.Kind == "geoip" {
			behavior = "ipcidr"
		}
		providers = append(providers, kv{id.Tag(), omap{{"type", "file"}, {"behavior", behavior}, {"format", "mrs"}, {"path", p.rulesets[id]}}})
	}

	var rules []string
	// Traffic addressed to the TUN's own IPv6 subnet would otherwise match
	// the private-range DIRECT rule; the IPv4 subnet adjoins the fake-ip pool
	// and is left to the core.
	if cfg.Settings.IPv6 && rt.TunIPv6 != "" {
		if pfx, err := netip.ParsePrefix(rt.TunIPv6); err == nil {
			rules = append(rules, "IP-CIDR6,"+pfx.Masked().String()+",REJECT,no-resolve")
		}
	}
	for _, c := range PrivateCIDRs {
		kind := "IP-CIDR"
		if strings.Contains(c, ":") {
			kind = "IP-CIDR6"
		}
		rules = append(rules, kind+","+c+",DIRECT,no-resolve")
	}
	for _, r := range p.rules {
		rules = append(rules, mihomoRules(p, r)...)
	}
	rules = append(rules, "MATCH,"+p.targetTag(p.final))

	var direct, proxyDNS, bootstrap []string
	for _, s := range p.directDNS {
		direct = append(direct, mihomoDNS(s))
		if s.IsIP() {
			bootstrap = append(bootstrap, mihomoDNS(s))
		}
	}
	for _, s := range p.proxyDNS {
		proxyDNS = append(proxyDNS, mihomoDNS(s))
	}
	dns := omap{
		{"enable", true},
		{"ipv6", cfg.Settings.IPv6},
		{"respect-rules", true},
		{"default-nameserver", bootstrap},
		{"proxy-server-nameserver", direct},
		{"direct-nameserver", direct},
		{"nameserver", proxyDNS},
	}
	if p.cnDNS {
		dns = append(dns, kv{"nameserver-policy", omap{{"rule-set:geosite-cn", direct}}})
	}
	if cfg.DNS.Mode == "fakeip" {
		filter := append([]string{}, cfg.DNS.FakeIPFilter...)
		if p.cnDNS {
			filter = append(filter, "rule-set:geosite-cn")
		}
		dns = append(dns, kv{"enhanced-mode", "fake-ip"}, kv{"fake-ip-range", "198.18.0.1/16"},
			kv{"fake-ip-filter-mode", "blacklist"}, kv{"fake-ip-filter", filter})
	} else {
		dns = append(dns, kv{"enhanced-mode", "redir-host"})
	}

	tun := omap{
		{"enable", true},
		{"device", rt.TunName},
	}
	if s := cfg.Settings.TunStack; s != "" {
		tun = append(tun, kv{"stack", s})
	}
	tun = append(tun,
		kv{"auto-route", false},
		kv{"iproute2-table-index", coreRouteTable},
		kv{"auto-redirect", false},
		kv{"auto-detect-interface", true},
		kv{"strict-route", false},
		kv{"dns-hijack", []string{"any:53", "tcp://any:53"}},
		kv{"mtu", cfg.Settings.MTU},
	)
	if cfg.Settings.IPv6 && rt.TunIPv6 != "" {
		tun = append(tun, kv{"inet6-address", []string{rt.TunIPv6}})
	}
	findProcess := "off"
	if p.hasPkg {
		findProcess = "strict"
	}
	doc := omap{
		{"mode", cfg.Routing.Mode},
		{"log-level", mihomoLogLevel(cfg.Settings.LogLevel)},
		{"ipv6", cfg.Settings.IPv6},
		{"allow-lan", false},
		{"unified-delay", true},
		{"tcp-concurrent", true},
		{"find-process-mode", findProcess},
		{"geo-auto-update", false},
		{"external-controller", fmt.Sprintf("127.0.0.1:%d", rt.ControllerPort)},
		{"secret", rt.ControllerSecret},
		{"profile", omap{{"store-selected", false}, {"store-fake-ip", true}}},
		{"listeners", []any{omap{
			{"name", "kpm-mixed"}, {"type", "mixed"}, {"listen", "127.0.0.1"}, {"port", rt.MixedPort}, {"udp", true},
			{"users", []any{omap{{"username", rt.MixedUser}, {"password", rt.MixedPass}}}},
		}}},
		{"tun", tun},
		{"sniffer", omap{
			{"enable", true},
			// The authenticated local client already validated and pinned its IP.
			{"skip-src-address", []string{"127.0.0.0/8", "::1/128"}},
			{"force-dns-mapping", true},
			{"parse-pure-ip", true},
			{"sniff", omap{
				{"HTTP", omap{{"ports", []any{80, "8080-8880"}}, {"override-destination", true}}},
				{"TLS", omap{{"ports", []int{443, 8443}}}},
				{"QUIC", omap{{"ports", []int{443, 8443}}}},
			}},
			{"skip-domain", []string{"+.push.apple.com", "Mijia Cloud"}},
		}},
		{"dns", dns},
		{"proxies", nonNil(proxies)},
		{"proxy-groups", groups},
	}
	if len(providers) > 0 {
		doc = append(doc, kv{"rule-providers", providers})
	}
	doc = append(doc, kv{"rules", rules})
	return yaml.Marshal(doc)
}

func nonNil(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func orDefaultInt(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

func mihomoRules(p *plan, r planRule) []string {
	target := p.targetTag(r.target)
	var out []string
	for _, v := range r.values {
		switch r.typ {
		case "domain":
			out = append(out, "DOMAIN,"+v+","+target)
		case "domain_suffix":
			out = append(out, "DOMAIN-SUFFIX,"+strings.TrimPrefix(v, ".")+","+target)
		case "domain_keyword":
			out = append(out, "DOMAIN-KEYWORD,"+v+","+target)
		case "domain_regex":
			out = append(out, "DOMAIN-REGEX,"+v+","+target)
		case "ip_cidr":
			pfx, _ := config.ParseCIDROrIP(v)
			kind := "IP-CIDR"
			if pfx.Addr().Is6() {
				kind = "IP-CIDR6"
			}
			out = append(out, kind+","+pfx.String()+","+target+",no-resolve")
		case "geosite":
			out = append(out, "RULE-SET,geosite-"+v+","+target)
		case "geoip":
			out = append(out, "RULE-SET,geoip-"+v+","+target+",no-resolve")
		case "package":
			out = append(out, "PROCESS-NAME,"+v+","+target)
		case "port":
			out = append(out, "DST-PORT,"+v+","+target)
		case "network":
			out = append(out, "NETWORK,"+strings.ToUpper(v)+","+target)
		}
	}
	if r.typ == "quic" {
		out = append(out, "AND,((NETWORK,UDP),(DST-PORT,443)),"+target)
	}
	return out
}

func mihomoTLS(m omap, n config.Node, sniKey string) omap {
	t := n.TLS
	if t == nil || !t.Enabled {
		return m
	}
	if n.Type == "vmess" || n.Type == "vless" || n.Type == "http" {
		m = append(m, kv{"tls", true})
	}
	if t.SNI != "" {
		m = append(m, kv{sniKey, t.SNI})
	}
	if t.Insecure {
		m = append(m, kv{"skip-cert-verify", true})
	}
	if len(t.ALPN) > 0 {
		m = append(m, kv{"alpn", t.ALPN})
	}
	fp := t.Fingerprint
	if fp == "" && t.RealityPublicKey != "" {
		// Reality needs a uTLS fingerprint; match the sing-box renderer.
		fp = "chrome"
	}
	if fp != "" {
		m = append(m, kv{"client-fingerprint", fp})
	}
	if t.RealityPublicKey != "" {
		ro := omap{{"public-key", t.RealityPublicKey}}
		if t.RealityShortID != "" {
			ro = append(ro, kv{"short-id", t.RealityShortID})
		}
		m = append(m, kv{"reality-opts", ro})
	}
	return m
}

func mihomoTransport(m omap, n config.Node) omap {
	t := n.Transport
	if t == nil || t.Type == "tcp" {
		return m
	}
	headers := omap{}
	if t.Host != "" {
		headers = append(headers, kv{"Host", t.Host})
	}
	customHeaders := transportHeaders(t)
	for _, k := range sortedKeys(customHeaders) {
		headers = append(headers, kv{k, customHeaders[k]})
	}
	switch t.Type {
	case "ws", "httpupgrade":
		o := omap{{"path", orDefault(t.Path, "/")}}
		if len(headers) > 0 {
			o = append(o, kv{"headers", headers})
		}
		if t.Type == "httpupgrade" {
			o = append(o, kv{"v2ray-http-upgrade", true})
		}
		m = append(m, kv{"network", "ws"}, kv{"ws-opts", o})
	case "grpc":
		m = append(m, kv{"network", "grpc"}, kv{"grpc-opts", omap{{"grpc-service-name", t.ServiceName}}})
	case "http":
		o := omap{{"path", orDefault(t.Path, "/")}}
		if t.Host != "" {
			o = append(o, kv{"host", []string{t.Host}})
		}
		m = append(m, kv{"network", "h2"}, kv{"h2-opts", o})
	case "xhttp":
		o := omap{{"path", orDefault(t.Path, "/")}}
		if t.Host != "" {
			o = append(o, kv{"host", t.Host})
		}
		m = append(m, kv{"network", "xhttp"}, kv{"xhttp-opts", o})
	}
	return m
}

func mihomoProxy(pn planNode) (omap, error) {
	n := pn.node
	s := pn.secrets
	m := omap{{"name", pn.tag}}
	switch n.Type {
	case "shadowsocks":
		m = append(m, kv{"type", "ss"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"cipher", n.Cipher}, kv{"password", s["password"]})
		switch n.Plugin {
		case "obfs":
			o := omap{{"mode", n.PluginOpts["mode"]}}
			if h := n.PluginOpts["host"]; h != "" {
				o = append(o, kv{"host", h})
			}
			m = append(m, kv{"plugin", "obfs"}, kv{"plugin-opts", o})
		case "v2ray-plugin":
			o := omap{{"mode", "websocket"}}
			if h := n.PluginOpts["host"]; h != "" {
				o = append(o, kv{"host", h})
			}
			if v := n.PluginOpts["path"]; v != "" {
				o = append(o, kv{"path", v})
			}
			if n.PluginOpts["tls"] == "true" {
				o = append(o, kv{"tls", true})
			}
			if n.PluginOpts["mux"] == "true" {
				o = append(o, kv{"mux", true})
			}
			m = append(m, kv{"plugin", "v2ray-plugin"}, kv{"plugin-opts", o})
		}
	case "vmess":
		m = append(m, kv{"type", "vmess"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"uuid", s["uuid"]},
			kv{"alterId", n.AlterID}, kv{"cipher", orDefault(n.Security, "auto")})
		m = mihomoTLS(m, n, "servername")
		m = mihomoTransport(m, n)
	case "vless":
		m = append(m, kv{"type", "vless"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"uuid", s["uuid"]})
		if n.Flow != "" {
			m = append(m, kv{"flow", n.Flow})
		}
		m = mihomoTLS(m, n, "servername")
		m = mihomoTransport(m, n)
	case "trojan":
		m = append(m, kv{"type", "trojan"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"password", s["password"]})
		m = mihomoTLS(m, n, "sni")
		m = mihomoTransport(m, n)
	case "hysteria2":
		m = append(m, kv{"type", "hysteria2"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"password", s["password"]})
		if n.Ports != "" {
			m = append(m, kv{"ports", n.Ports})
		}
		if n.UpMbps > 0 {
			m = append(m, kv{"up", fmt.Sprintf("%d Mbps", n.UpMbps)})
		}
		if n.DownMbps > 0 {
			m = append(m, kv{"down", fmt.Sprintf("%d Mbps", n.DownMbps)})
		}
		if n.Obfs != "" {
			m = append(m, kv{"obfs", n.Obfs}, kv{"obfs-password", s["obfsPassword"]})
		}
		m = mihomoTLS(m, n, "sni")
	case "tuic":
		m = append(m, kv{"type", "tuic"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"uuid", s["uuid"]}, kv{"password", s["password"]})
		if n.CongestionControl != "" {
			m = append(m, kv{"congestion-controller", n.CongestionControl})
		}
		if n.UDPRelayMode != "" {
			m = append(m, kv{"udp-relay-mode", n.UDPRelayMode})
		}
		if n.TLS == nil || len(n.TLS.ALPN) == 0 {
			m = append(m, kv{"alpn", []string{"h3"}})
		}
		m = mihomoTLS(m, n, "sni")
	case "anytls":
		m = append(m, kv{"type", "anytls"}, kv{"server", n.Server}, kv{"port", n.Port}, kv{"password", s["password"]})
		m = mihomoTLS(m, n, "sni")
	case "socks":
		m = append(m, kv{"type", "socks5"}, kv{"server", n.Server}, kv{"port", n.Port})
		if s["username"] != "" || s["password"] != "" {
			m = append(m, kv{"username", s["username"]}, kv{"password", s["password"]})
		}
	case "http":
		m = append(m, kv{"type", "http"}, kv{"server", n.Server}, kv{"port", n.Port})
		if s["username"] != "" || s["password"] != "" {
			m = append(m, kv{"username", s["username"]}, kv{"password", s["password"]})
		}
		m = mihomoTLS(m, n, "sni")
	case "wireguard":
		m = append(m, kv{"type", "wireguard"}, kv{"server", n.Server}, kv{"port", n.Port},
			kv{"private-key", s["privateKey"]}, kv{"public-key", n.PeerPublicKey})
		var have4, have6 bool
		for _, a := range n.LocalAddress {
			pfx, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, err
			}
			// Mihomo takes one address per family.
			if pfx.Addr().Is4() && !have4 {
				m = append(m, kv{"ip", pfx.Addr().String()})
				have4 = true
			} else if pfx.Addr().Is6() && !have6 {
				m = append(m, kv{"ipv6", pfx.Addr().String()})
				have6 = true
			}
		}
		if psk := s["preSharedKey"]; psk != "" {
			m = append(m, kv{"pre-shared-key", psk})
		}
		if len(n.Reserved) == 3 {
			m = append(m, kv{"reserved", n.Reserved})
		}
		if n.WGMTU > 0 {
			m = append(m, kv{"mtu", n.WGMTU})
		}
	default:
		return nil, fmt.Errorf("Mihomo 不支持节点类型 %s", n.Type)
	}
	m = append(m, kv{"udp", n.UDP})
	if pn.upstream != "" {
		m = append(m, kv{"dialer-proxy", pn.upstream})
	}
	return m, nil
}
