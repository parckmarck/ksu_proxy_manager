package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"ksu_proxy_manager/internal/config"
)

// jmap is an insertion-ordered JSON object.
type jmap []kv

func (m jmap) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range m {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(e.k)
		b.Write(k)
		b.WriteByte(':')
		v, err := json.Marshal(e.v)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func sortedRulesets(m map[RulesetID]string) []RulesetID {
	ids := make([]RulesetID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sortIDs(ids)
	return ids
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func singBoxDNSServer(tag string, s config.DNSServer, detour, resolver string) jmap {
	m := jmap{{"type", s.Scheme}, {"tag", tag}, {"server", s.Host}}
	defPort := map[string]int{"udp": 53, "tcp": 53, "tls": 853, "https": 443, "quic": 853}
	if s.Port != defPort[s.Scheme] {
		m = append(m, kv{"server_port", s.Port})
	}
	if s.Scheme == "https" && s.Path != "/dns-query" {
		m = append(m, kv{"path", s.Path})
	}
	if !s.IsIP() && resolver != "" {
		m = append(m, kv{"domain_resolver", resolver})
	}
	if detour != "" {
		m = append(m, kv{"detour", detour})
	}
	return m
}

func renderSingBox(p *plan) ([]byte, error) {
	in := p.in
	cfg := &in.Config
	rt := in.Runtime

	logm := jmap{{"timestamp", true}}
	if cfg.Settings.LogLevel == "silent" {
		logm = jmap{{"disabled", true}}
	} else {
		logm = append(logm, kv{"level", cfg.Settings.LogLevel})
	}

	var directIP config.DNSServer
	for _, s := range p.directDNS {
		if s.IsIP() {
			directIP = s
			break
		}
	}
	if len(p.directDNS) > 1 {
		p.warn("sing-box 仅使用第一个 IP 形式的直连 DNS（%s），其余 %d 个未生效", directIP.Host, len(p.directDNS)-1)
	}
	if len(p.proxyDNS) > 1 {
		p.warn("sing-box 仅使用第一个代理 DNS（%s），其余 %d 个未生效", p.proxyDNS[0].Host, len(p.proxyDNS)-1)
	}
	globalTag := p.targetTag(p.global)
	proxyDetour := ""
	if globalTag != "DIRECT" && globalTag != "REJECT" {
		proxyDetour = globalTag
	}
	servers := []any{
		singBoxDNSServer("dns-direct", directIP, "", ""),
		singBoxDNSServer("dns-proxy", p.proxyDNS[0], proxyDetour, "dns-direct"),
	}
	var dnsRules []any
	// DNS follows the runtime mode: direct mode never queries through a
	// proxy, global mode always does.
	dnsRules = append(dnsRules,
		jmap{{"clash_mode", "Direct"}, {"server", "dns-direct"}},
		jmap{{"clash_mode", "Global"}, {"server", "dns-proxy"}})
	if p.cnDNS {
		dnsRules = append(dnsRules, jmap{{"rule_set", []string{"geosite-cn"}}, {"server", "dns-direct"}})
	}
	if cfg.DNS.Mode == "fakeip" {
		inet := jmap{{"type", "fakeip"}, {"tag", "dns-fakeip"}, {"inet4_range", FakeIPv4Range}}
		if cfg.Settings.IPv6 {
			inet = append(inet, kv{"inet6_range", FakeIPv6Range})
		}
		servers = append(servers, inet)
		if re := p.fakeIPRegexes(); len(re) > 0 {
			dnsRules = append(dnsRules, jmap{{"domain_regex", re}, {"server", "dns-direct"}})
		}
		// The system resolver caches answers per network; a long TTL would
		// keep handing out fake IPs after the core restarts or is switched.
		dnsRules = append(dnsRules, jmap{{"query_type", []string{"A", "AAAA"}}, {"server", "dns-fakeip"}, {"rewrite_ttl", 1}})
	}
	strategy := "ipv4_only"
	if cfg.Settings.IPv6 {
		strategy = "prefer_ipv4"
	}
	dns := jmap{{"servers", servers}}
	if len(dnsRules) > 0 {
		dns = append(dns, kv{"rules", dnsRules})
	}
	dns = append(dns, kv{"final", "dns-proxy"}, kv{"strategy", strategy})

	addrs := []string{rt.TunIPv4}
	if cfg.Settings.IPv6 && rt.TunIPv6 != "" {
		addrs = append(addrs, rt.TunIPv6)
	}
	tun := jmap{{"type", "tun"}, {"tag", "tun-in"}, {"interface_name", rt.TunName}, {"address", addrs}, {"mtu", cfg.Settings.MTU},
		{"auto_route", false}, {"iproute2_table_index", coreRouteTable}}
	if s := cfg.Settings.TunStack; s != "" && s != "mips" && VersionLess(in.Version, "1.15.0") {
		tun = append(tun, kv{"stack", s})
	} else if s == "mips" {
		p.warn("sing-box 不支持 mips 协议栈，已使用默认协议栈")
	}
	inbounds := []any{
		tun,
		jmap{{"type", "mixed"}, {"tag", "mixed-in"}, {"listen", "127.0.0.1"}, {"listen_port", rt.MixedPort},
			{"users", []any{jmap{{"username", rt.MixedUser}, {"password", rt.MixedPass}}}}},
	}

	outbounds := []any{jmap{{"type", "direct"}, {"tag", "DIRECT"}}}
	var endpoints []any
	for _, pn := range p.nodes {
		ob, isEndpoint, err := singBoxOutbound(pn)
		if err != nil {
			return nil, err
		}
		if isEndpoint {
			endpoints = append(endpoints, ob)
		} else {
			outbounds = append(outbounds, ob)
		}
	}
	for _, g := range p.groups {
		if g.group.Type == "urltest" || g.group.Type == "fallback" {
			outbounds = append(outbounds, jmap{{"type", "urltest"}, {"tag", g.tag}, {"outbounds", g.members},
				{"url", orDefault(g.group.TestURL, defaultTestURL)},
				{"interval", fmt.Sprintf("%ds", orDefaultInt(g.group.IntervalSec, defaultInterval))},
				{"tolerance", orDefaultInt(g.group.ToleranceMs, defaultTolerate)}})
		} else {
			outbounds = append(outbounds, jmap{{"type", "selector"}, {"tag", g.tag}, {"outbounds", g.members}, {"default", g.selected}})
		}
	}

	// Traffic addressed to the TUN subnet itself would loop back into it.
	var tunNets []string
	for _, a := range addrs {
		if pfx, err := netip.ParsePrefix(a); err == nil {
			tunNets = append(tunNets, pfx.Masked().String())
		}
	}
	rules := []any{
		jmap{{"action", "sniff"}},
		jmap{{"type", "logical"}, {"mode", "or"}, {"rules", []any{jmap{{"protocol", "dns"}}, jmap{{"port", 53}}}}, {"action", "hijack-dns"}},
		jmap{{"ip_cidr", tunNets}, {"action", "reject"}},
		jmap{{"ip_cidr", PrivateCIDRs}, {"outbound", "DIRECT"}},
		jmap{{"clash_mode", "Direct"}, {"outbound", "DIRECT"}},
	}
	if globalTag == "REJECT" {
		rules = append(rules, jmap{{"clash_mode", "Global"}, {"action", "reject"}})
	} else {
		rules = append(rules, jmap{{"clash_mode", "Global"}, {"outbound", globalTag}})
	}
	for _, r := range p.rules {
		rules = append(rules, singBoxRule(p, r))
	}
	finalTag := p.targetTag(p.final)
	if finalTag == "REJECT" {
		rules = append(rules, jmap{{"action", "reject"}})
		finalTag = "DIRECT"
	}
	var ruleSets []any
	for _, id := range sortedRulesets(p.rulesets) {
		ruleSets = append(ruleSets, jmap{{"type", "local"}, {"tag", id.Tag()}, {"format", "binary"}, {"path", p.rulesets[id]}})
	}
	route := jmap{{"rules", rules}}
	if len(ruleSets) > 0 {
		route = append(route, kv{"rule_set", ruleSets})
	}
	route = append(route, kv{"final", finalTag}, kv{"auto_detect_interface", true}, kv{"default_domain_resolver", "dns-direct"})
	if p.hasPkg {
		route = append(route, kv{"find_process", true})
	}
	mode := map[string]string{"rule": "Rule", "global": "Global", "direct": "Direct"}[cfg.Routing.Mode]
	doc := jmap{
		{"log", logm},
		{"dns", dns},
		{"inbounds", inbounds},
		{"outbounds", outbounds},
	}
	if len(endpoints) > 0 {
		doc = append(doc, kv{"endpoints", endpoints})
	}
	doc = append(doc,
		kv{"route", route},
		kv{"experimental", jmap{
			{"clash_api", jmap{{"external_controller", fmt.Sprintf("127.0.0.1:%d", rt.ControllerPort)}, {"secret", rt.ControllerSecret}, {"default_mode", mode}}},
			{"cache_file", jmap{{"enabled", true}, {"path", "cache.db"}, {"store_fakeip", cfg.DNS.Mode == "fakeip"}}},
		}},
	)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func singBoxRule(p *plan, r planRule) jmap {
	var m jmap
	switch r.typ {
	case "domain", "domain_keyword", "domain_regex", "ip_cidr":
		m = jmap{{r.typ, r.values}}
	case "source_ip_cidr":
		vals := make([]string, len(r.values))
		for i, v := range r.values {
			pfx, _ := config.ParseCIDROrIP(v)
			vals[i] = pfx.String()
		}
		m = jmap{{"source_ip_cidr", vals}}
	case "domain_suffix":
		vals := make([]string, len(r.values))
		for i, v := range r.values {
			vals[i] = strings.TrimPrefix(v, ".")
		}
		m = jmap{{"domain_suffix", vals}}
	case "geosite", "geoip":
		tags := make([]string, len(r.values))
		for i, v := range r.values {
			tags[i] = r.typ + "-" + v
		}
		m = jmap{{"rule_set", tags}}
	case "package":
		m = jmap{{"package_name", r.values}}
	case "port":
		var ports []int
		var ranges []string
		for _, v := range r.values {
			if lo, hi, ok := strings.Cut(v, "-"); ok {
				ranges = append(ranges, lo+":"+hi)
			} else {
				var n int
				fmt.Sscanf(v, "%d", &n)
				ports = append(ports, n)
			}
		}
		if len(ports) > 0 {
			m = append(m, kv{"port", ports})
		}
		if len(ranges) > 0 {
			m = append(m, kv{"port_range", ranges})
		}
	case "network":
		m = jmap{{"network", r.values}}
	case "quic":
		m = jmap{{"network", []string{"udp"}}, {"port", []int{443}}}
	}
	if r.target == config.TargetReject {
		return append(m, kv{"action", "reject"})
	}
	return append(m, kv{"outbound", p.targetTag(r.target)})
}

func singBoxTLS(n config.Node) jmap {
	t := n.TLS
	if t == nil || !t.Enabled {
		return nil
	}
	m := jmap{{"enabled", true}}
	if t.SNI != "" {
		m = append(m, kv{"server_name", t.SNI})
	}
	if t.Insecure {
		m = append(m, kv{"insecure", true})
	}
	alpn := t.ALPN
	if len(alpn) == 0 && n.Type == "tuic" {
		alpn = []string{"h3"}
	}
	if len(alpn) > 0 {
		m = append(m, kv{"alpn", alpn})
	}
	fp := t.Fingerprint
	if fp == "" && t.RealityPublicKey != "" {
		fp = "chrome"
	}
	if fp != "" && n.Type != "hysteria2" && n.Type != "tuic" {
		m = append(m, kv{"utls", jmap{{"enabled", true}, {"fingerprint", fp}}})
	}
	if t.RealityPublicKey != "" {
		m = append(m, kv{"reality", jmap{{"enabled", true}, {"public_key", t.RealityPublicKey}, {"short_id", t.RealityShortID}}})
	}
	return m
}

func singBoxTransport(n config.Node) jmap {
	t := n.Transport
	if t == nil || t.Type == "tcp" {
		return nil
	}
	headers := jmap{}
	customHeaders := transportHeaders(t)
	for _, k := range sortedKeys(customHeaders) {
		headers = append(headers, kv{k, customHeaders[k]})
	}
	switch t.Type {
	case "ws":
		m := jmap{{"type", "ws"}, {"path", orDefault(t.Path, "/")}}
		if t.Host != "" {
			headers = append(jmap{{"Host", t.Host}}, headers...)
		}
		if len(headers) > 0 {
			m = append(m, kv{"headers", headers})
		}
		return m
	case "httpupgrade":
		m := jmap{{"type", "httpupgrade"}, {"path", orDefault(t.Path, "/")}}
		if t.Host != "" {
			m = append(m, kv{"host", t.Host})
		}
		if len(headers) > 0 {
			m = append(m, kv{"headers", headers})
		}
		return m
	case "grpc":
		return jmap{{"type", "grpc"}, {"service_name", t.ServiceName}}
	case "http":
		m := jmap{{"type", "http"}, {"path", orDefault(t.Path, "/")}}
		if t.Host != "" {
			m = append(m, kv{"host", []string{t.Host}})
		}
		if len(headers) > 0 {
			m = append(m, kv{"headers", headers})
		}
		return m
	}
	return nil
}

func singBoxPorts(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			hi = lo
		}
		out = append(out, lo+":"+hi)
	}
	return out
}

func singBoxOutbound(pn planNode) (jmap, bool, error) {
	n := pn.node
	s := pn.secrets
	m := jmap{{"type", n.Type}, {"tag", pn.tag}, {"server", n.Server}}
	if !(n.Type == "hysteria2" && n.Ports != "") {
		m = append(m, kv{"server_port", n.Port})
	}
	switch n.Type {
	case "shadowsocks":
		m = append(m, kv{"method", n.Cipher}, kv{"password", s["password"]})
		switch n.Plugin {
		case "obfs":
			opts := "obfs=" + n.PluginOpts["mode"]
			if h := n.PluginOpts["host"]; h != "" {
				opts += ";obfs-host=" + h
			}
			m = append(m, kv{"plugin", "obfs-local"}, kv{"plugin_opts", opts})
		case "v2ray-plugin":
			opts := []string{"mode=websocket"}
			if n.PluginOpts["tls"] == "true" {
				opts = append(opts, "tls")
			}
			if h := n.PluginOpts["host"]; h != "" {
				opts = append(opts, "host="+h)
			}
			if v := n.PluginOpts["path"]; v != "" {
				opts = append(opts, "path="+v)
			}
			m = append(m, kv{"plugin", "v2ray-plugin"}, kv{"plugin_opts", strings.Join(opts, ";")})
		}
	case "vmess":
		m = append(m, kv{"uuid", s["uuid"]}, kv{"security", orDefault(n.Security, "auto")})
		if n.AlterID > 0 {
			m = append(m, kv{"alter_id", n.AlterID})
		}
	case "vless":
		m = append(m, kv{"uuid", s["uuid"]})
		if n.Flow != "" {
			m = append(m, kv{"flow", n.Flow})
		}
	case "trojan", "anytls":
		m = append(m, kv{"password", s["password"]})
	case "hysteria2":
		if n.Ports != "" {
			m = append(m, kv{"server_ports", singBoxPorts(n.Ports)})
		}
		m = append(m, kv{"password", s["password"]})
		if n.UpMbps > 0 {
			m = append(m, kv{"up_mbps", n.UpMbps})
		}
		if n.DownMbps > 0 {
			m = append(m, kv{"down_mbps", n.DownMbps})
		}
		if n.Obfs != "" {
			m = append(m, kv{"obfs", jmap{{"type", n.Obfs}, {"password", s["obfsPassword"]}}})
		}
	case "tuic":
		m = append(m, kv{"uuid", s["uuid"]}, kv{"password", s["password"]})
		if n.CongestionControl != "" {
			m = append(m, kv{"congestion_control", n.CongestionControl})
		}
		if n.UDPRelayMode != "" {
			m = append(m, kv{"udp_relay_mode", n.UDPRelayMode})
		}
	case "socks":
		m[0] = kv{"type", "socks"}
		m = append(m, kv{"version", "5"})
		if s["username"] != "" || s["password"] != "" {
			m = append(m, kv{"username", s["username"]}, kv{"password", s["password"]})
		}
	case "http":
		if s["username"] != "" || s["password"] != "" {
			m = append(m, kv{"username", s["username"]}, kv{"password", s["password"]})
		}
	case "wireguard":
		peer := jmap{{"address", n.Server}, {"port", n.Port}, {"public_key", n.PeerPublicKey}, {"allowed_ips", []string{"0.0.0.0/0", "::/0"}}}
		if psk := s["preSharedKey"]; psk != "" {
			peer = append(peer, kv{"pre_shared_key", psk})
		}
		if len(n.Reserved) == 3 {
			peer = append(peer, kv{"reserved", n.Reserved})
		}
		ep := jmap{{"type", "wireguard"}, {"tag", pn.tag}, {"address", n.LocalAddress}, {"private_key", s["privateKey"]}, {"peers", []any{peer}}}
		if n.WGMTU > 0 {
			ep = append(ep, kv{"mtu", n.WGMTU})
		}
		if pn.upstream != "" {
			ep = append(ep, kv{"detour", pn.upstream})
		}
		return ep, true, nil
	default:
		return nil, false, fmt.Errorf("sing-box 不支持节点类型 %s", n.Type)
	}
	if t := singBoxTLS(n); t != nil {
		m = append(m, kv{"tls", t})
	}
	if t := singBoxTransport(n); t != nil {
		m = append(m, kv{"transport", t})
	}
	if !n.UDP {
		switch n.Type {
		case "shadowsocks", "vmess", "vless", "trojan", "socks":
			m = append(m, kv{"network", "tcp"})
		}
	}
	if pn.upstream != "" {
		m = append(m, kv{"detour", pn.upstream})
	}
	return m, false, nil
}
