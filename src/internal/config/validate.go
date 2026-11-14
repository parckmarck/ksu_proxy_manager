package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// FieldError is a validation failure tied to a JSON path.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

func fieldErr(field, format string, args ...any) error {
	return &FieldError{Field: field, Message: fmt.Sprintf(format, args...)}
}

var (
	reservedGroupNames = map[string]bool{"DIRECT": true, "REJECT": true, "GLOBAL": true, "PASS": true, "REJECT-DROP": true, "COMPATIBLE": true}
	idRE               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	pkgRE              = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$`)
	geoNameRE          = regexp.MustCompile(`^[a-z0-9][a-z0-9!@._-]{0,63}$`)
	ifPatternRE        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}\*?$`)
	hostRE             = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62}))*\.?$`)
	domainPatRE        = regexp.MustCompile(`^[A-Za-z0-9*+._-]{1,253}$`)
	portsRE            = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$`)
	headerRE           = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	shortIDRE          = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
)

var (
	nodeTypes = map[string]bool{"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "hysteria2": true, "tuic": true, "anytls": true, "socks": true, "http": true, "wireguard": true}
	ssCiphers = map[string]bool{
		"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true, "chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
		"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true, "none": true,
		"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true, "aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
		"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
	}
	vmessSecurity  = map[string]bool{"": true, "auto": true, "none": true, "zero": true, "aes-128-gcm": true, "chacha20-poly1305": true}
	transportTypes = map[string]bool{"tcp": true, "ws": true, "grpc": true, "http": true, "httpupgrade": true, "xhttp": true}
	fingerprints   = map[string]bool{"": true, "chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true, "360": true, "qq": true, "random": true, "randomized": true}
	logLevels      = map[string]bool{"debug": true, "info": true, "warn": true, "error": true, "silent": true}
	tunStacks      = map[string]bool{"": true, "system": true, "gvisor": true, "mixed": true, "mips": true}
	ruleTypes      = map[string]bool{"domain": true, "domain_suffix": true, "domain_keyword": true, "domain_regex": true, "ip_cidr": true, "source_ip_cidr": true, "geosite": true, "geoip": true, "package": true, "port": true, "network": true}
)

func ValidID(s string) bool          { return idRE.MatchString(s) }
func ValidPackageName(s string) bool { return len(s) <= 255 && pkgRE.MatchString(s) }
func ValidGeoName(s string) bool     { return geoNameRE.MatchString(s) }

// ValidHost accepts a hostname or an IP literal (without brackets).
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return hostRE.MatchString(s)
}

// Hard limits keep validation, cloning and the on-disk document bounded.
const (
	MaxNodes         = 10000
	MaxGroups        = 200
	MaxSubscriptions = 100
	MaxAppRoutes     = 500
)

// Validate checks the complete configuration together with its secrets.
func Validate(c *Config, sec *Secrets) error {
	if c.SchemaVersion != SchemaVersion {
		return fieldErr("schemaVersion", "不支持的配置版本 %d", c.SchemaVersion)
	}
	if err := validateSettings(&c.Settings); err != nil {
		return err
	}
	if len(c.Subscriptions) > MaxSubscriptions {
		return fieldErr("subscriptions", "订阅最多 %d 个", MaxSubscriptions)
	}
	if len(c.Nodes) > MaxNodes {
		return fieldErr("nodes", "节点最多 %d 个", MaxNodes)
	}
	if len(c.Groups) > MaxGroups {
		return fieldErr("groups", "代理组最多 %d 个", MaxGroups)
	}
	subs := map[string]bool{}
	for i, s := range c.Subscriptions {
		p := fmt.Sprintf("subscriptions[%d]", i)
		if !ValidID(s.ID) {
			return fieldErr(p+".id", "订阅 ID 格式无效")
		}
		if subs[s.ID] {
			return fieldErr(p+".id", "订阅 ID 重复")
		}
		subs[s.ID] = true
		if strings.TrimSpace(s.Name) == "" || len([]rune(s.Name)) > 64 || hasControl(s.Name) {
			return fieldErr(p+".name", "订阅名称不能为空、不能含控制字符且不超过 64 字")
		}
		if len(s.UserAgent) > 200 || strings.ContainsAny(s.UserAgent, "\r\n") {
			return fieldErr(p+".userAgent", "User-Agent 无效")
		}
		if s.AutoUpdateHours < 0 || s.AutoUpdateHours > 720 {
			return fieldErr(p+".autoUpdateHours", "自动更新间隔须在 0..720 小时")
		}
		if err := validRegex(p+".filter", s.Filter); err != nil {
			return err
		}
		if err := validRegex(p+".excludeFilter", s.ExcludeFilter); err != nil {
			return err
		}
		if sec != nil {
			if err := ValidateSubscriptionURL(sec.Subscriptions[s.ID]); err != nil {
				return fieldErr(p+".url", "%v", err)
			}
		}
	}
	nodes := map[string]*Node{}
	for i := range c.Nodes {
		n := &c.Nodes[i]
		p := fmt.Sprintf("nodes[%d]", i)
		if err := ValidateNode(n, p); err != nil {
			return err
		}
		if nodes[n.ID] != nil {
			return fieldErr(p+".id", "节点 ID 重复: %s", n.ID)
		}
		nodes[n.ID] = n
		if n.SubscriptionID != "" && !subs[n.SubscriptionID] {
			return fieldErr(p+".subscriptionId", "引用的订阅不存在")
		}
		if sec != nil {
			for _, f := range RequiredSecrets(*n) {
				if sec.NodeSecret(n.ID, f) == "" {
					return fieldErr(p+"."+f, "节点 %s 缺少必填凭据 %s", n.Name, f)
				}
			}
		}
	}
	for i := range c.Nodes {
		n := &c.Nodes[i]
		if n.Upstream == "" {
			continue
		}
		p := fmt.Sprintf("nodes[%d].upstream", i)
		if n.Upstream == n.ID {
			return fieldErr(p, "节点不能以自身为前置")
		}
		seen := map[string]bool{n.ID: true}
		cur := n.Upstream
		for depth := 0; cur != ""; depth++ {
			up := nodes[cur]
			if up == nil {
				return fieldErr(p, "前置节点不存在")
			}
			if seen[cur] {
				return fieldErr(p, "链式代理存在环路")
			}
			if depth >= 3 {
				return fieldErr(p, "链式代理最多 3 层")
			}
			seen[cur] = true
			cur = up.Upstream
		}
	}
	groups := map[string]*Group{}
	names := map[string]bool{}
	for i := range c.Groups {
		g := &c.Groups[i]
		p := fmt.Sprintf("groups[%d]", i)
		if !ValidID(g.ID) {
			return fieldErr(p+".id", "代理组 ID 格式无效")
		}
		if groups[g.ID] != nil {
			return fieldErr(p+".id", "代理组 ID 重复")
		}
		groups[g.ID] = g
		name := strings.TrimSpace(g.Name)
		if name == "" || len([]rune(name)) > 64 || strings.ContainsAny(name, ",#") || hasControl(name) {
			return fieldErr(p+".name", "代理组名称不能为空、不能含逗号或 #，且不超过 64 字")
		}
		if reservedGroupNames[name] || names[name] {
			return fieldErr(p+".name", "代理组名称重复或为保留名")
		}
		names[name] = true
		switch g.Type {
		case "select":
		case "urltest", "fallback", "load-balance":
			if g.Type == "load-balance" {
				if c.Settings.Engine == EngineSingBox {
					return fieldErr(p+".type", "sing-box 不支持负载均衡策略组 %s，请使用 Mihomo 或先更改该组类型", g.Name)
				}
				switch g.Strategy {
				case "", "consistent-hashing", "round-robin", "sticky-sessions":
				default:
					return fieldErr(p+".strategy", "均衡策略必须为 consistent-hashing、round-robin 或 sticky-sessions")
				}
			}
			if g.TestURL != "" {
				if u, err := url.Parse(g.TestURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return fieldErr(p+".testUrl", "测速地址必须为 http(s) URL")
				}
			}
			if g.IntervalSec != 0 && (g.IntervalSec < 30 || g.IntervalSec > 86400) {
				return fieldErr(p+".intervalSec", "测速间隔须在 30..86400 秒")
			}
			if g.ToleranceMs < 0 || g.ToleranceMs > 5000 {
				return fieldErr(p+".toleranceMs", "容差须在 0..5000 毫秒")
			}
		default:
			return fieldErr(p+".type", "代理组类型必须为 select、urltest、fallback 或 load-balance")
		}
		for _, id := range g.Nodes {
			if nodes[id] == nil {
				return fieldErr(p+".nodes", "引用的节点不存在: %s", id)
			}
		}
		for _, id := range g.Subscriptions {
			if !subs[id] {
				return fieldErr(p+".subscriptions", "引用的订阅不存在: %s", id)
			}
		}
		if err := validRegex(p+".filter", g.Filter); err != nil {
			return err
		}
		if err := validRegex(p+".excludeFilter", g.ExcludeFilter); err != nil {
			return err
		}
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		p := fmt.Sprintf("groups[%d]", i)
		for _, id := range g.Groups {
			if groups[id] == nil {
				return fieldErr(p+".groups", "引用的代理组不存在: %s", id)
			}
			if id == g.ID {
				return fieldErr(p+".groups", "代理组不能包含自身")
			}
		}
		if g.Selected != "" {
			kind, id := ParseRef(g.Selected)
			switch kind {
			case TargetDirect:
			case "node":
				if nodes[id] == nil {
					return fieldErr(p+".selected", "选中的节点不存在")
				}
			case "group":
				if groups[id] == nil {
					return fieldErr(p+".selected", "选中的代理组不存在")
				}
			default:
				return fieldErr(p+".selected", "选中项格式无效")
			}
		}
	}
	if err := detectGroupCycle(c.Groups); err != nil {
		return err
	}
	if err := validateRouting(&c.Routing, groups); err != nil {
		return err
	}
	if err := validateDNS(&c.DNS); err != nil {
		return err
	}
	return validateApps(&c.Apps, groups)
}

func validateSettings(s *Settings) error {
	if s.Engine != EngineMihomo && s.Engine != EngineSingBox {
		return fieldErr("settings.engine", "核心必须为 mihomo 或 sing-box")
	}
	for eng, v := range s.CoreVersions {
		if eng != EngineMihomo && eng != EngineSingBox {
			return fieldErr("settings.coreVersions", "未知核心 %s", eng)
		}
		if v != "" && (len(v) > 64 || strings.ContainsAny(v, "/\\ \t\r\n")) {
			return fieldErr("settings.coreVersions."+eng, "版本号格式无效")
		}
	}
	if !logLevels[s.LogLevel] {
		return fieldErr("settings.logLevel", "日志级别必须为 debug/info/warn/error/silent")
	}
	if !tunStacks[s.TunStack] {
		return fieldErr("settings.tunStack", "TUN 协议栈无效")
	}
	if s.MTU < 1280 || s.MTU > 65535 {
		return fieldErr("settings.mtu", "MTU 须在 1280..65535")
	}
	for i, c := range s.BypassCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(c)); err != nil {
			return fieldErr(fmt.Sprintf("settings.bypassCidrs[%d]", i), "CIDR 格式无效")
		}
	}
	if len(s.Hotspot.Interfaces) > 32 {
		return fieldErr("settings.hotspot.interfaces", "共享网卡模式最多 32 个")
	}
	for i, p := range s.Hotspot.Interfaces {
		if !ifPatternRE.MatchString(p) {
			return fieldErr(fmt.Sprintf("settings.hotspot.interfaces[%d]", i), "网卡名称模式无效")
		}
	}
	if s.WebAccess.Port < 1024 || s.WebAccess.Port > 65535 {
		return fieldErr("settings.webAccess.port", "端口须在 1024..65535")
	}
	switch s.Download.Mode {
	case "auto", "direct", "proxy":
	default:
		return fieldErr("settings.download.mode", "下载方式必须为 auto/direct/proxy")
	}
	if m := s.Download.GitHubMirror; m != "" {
		u, err := url.Parse(m)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fieldErr("settings.download.githubMirror", "镜像前缀必须为不含凭据与查询串的 https URL")
		}
	}
	return nil
}

// ValidateNode checks one node's public fields.
func ValidateNode(n *Node, p string) error {
	if !ValidID(n.ID) {
		return fieldErr(p+".id", "节点 ID 格式无效")
	}
	if n.Name == "" || len([]rune(n.Name)) > 128 || hasControl(n.Name) {
		return fieldErr(p+".name", "节点名称不能为空、不能含控制字符且不超过 128 字")
	}
	if !nodeTypes[n.Type] {
		return fieldErr(p+".type", "不支持的节点类型 %q", n.Type)
	}
	if !ValidHost(n.Server) {
		return fieldErr(p+".server", "服务器地址无效")
	}
	if n.Port < 1 || n.Port > 65535 {
		return fieldErr(p+".port", "端口须在 1..65535")
	}
	if n.Upstream != "" && !ValidID(n.Upstream) {
		return fieldErr(p+".upstream", "前置节点 ID 无效")
	}
	switch n.Type {
	case "shadowsocks":
		if !ssCiphers[n.Cipher] {
			return fieldErr(p+".cipher", "不支持的加密方式 %q", n.Cipher)
		}
		switch n.Plugin {
		case "":
			if len(n.PluginOpts) > 0 {
				return fieldErr(p+".pluginOpts", "未指定插件时不能设置插件参数")
			}
		case "obfs":
			if m := n.PluginOpts["mode"]; m != "http" && m != "tls" {
				return fieldErr(p+".pluginOpts.mode", "obfs 模式必须为 http 或 tls")
			}
		case "v2ray-plugin":
			if m := n.PluginOpts["mode"]; m != "" && m != "websocket" {
				return fieldErr(p+".pluginOpts.mode", "v2ray-plugin 仅支持 websocket 模式")
			}
		default:
			return fieldErr(p+".plugin", "不支持的插件 %q", n.Plugin)
		}
		for k, v := range n.PluginOpts {
			switch k {
			case "mode", "host", "path", "tls", "mux":
			default:
				return fieldErr(p+".pluginOpts", "不支持的插件参数 %s", k)
			}
			if len(v) > 256 || strings.ContainsAny(v, ";\r\n") {
				return fieldErr(p+".pluginOpts."+k, "插件参数无效")
			}
		}
	case "vmess":
		if !vmessSecurity[n.Security] {
			return fieldErr(p+".security", "不支持的 VMess 加密 %q", n.Security)
		}
		if n.AlterID < 0 || n.AlterID > 65535 {
			return fieldErr(p+".alterId", "alterId 无效")
		}
	case "vless":
		if n.Flow != "" && n.Flow != "xtls-rprx-vision" {
			return fieldErr(p+".flow", "仅支持 xtls-rprx-vision 流控")
		}
	case "hysteria2":
		if n.UpMbps < 0 || n.UpMbps > 100000 || n.DownMbps < 0 || n.DownMbps > 100000 {
			return fieldErr(p+".upMbps", "带宽须在 0..100000 Mbps")
		}
		if n.Obfs != "" && n.Obfs != "salamander" {
			return fieldErr(p+".obfs", "仅支持 salamander 混淆")
		}
		if n.Ports != "" {
			if !portsRE.MatchString(n.Ports) {
				return fieldErr(p+".ports", "端口跳跃格式应为 20000-30000,40000")
			}
			for _, part := range strings.Split(n.Ports, ",") {
				lo, hi, _ := strings.Cut(part, "-")
				a, _ := strconv.Atoi(lo)
				b := a
				if hi != "" {
					b, _ = strconv.Atoi(hi)
				}
				if a < 1 || b > 65535 || a > b {
					return fieldErr(p+".ports", "端口跳跃范围无效")
				}
			}
		}
	case "tuic":
		switch n.CongestionControl {
		case "", "cubic", "new_reno", "bbr":
		default:
			return fieldErr(p+".congestionControl", "拥塞控制必须为 cubic/new_reno/bbr")
		}
		switch n.UDPRelayMode {
		case "", "native", "quic":
		default:
			return fieldErr(p+".udpRelayMode", "UDP 中继模式必须为 native/quic")
		}
	case "wireguard":
		if len(n.LocalAddress) == 0 {
			return fieldErr(p+".localAddress", "WireGuard 需要本地地址")
		}
		for _, a := range n.LocalAddress {
			if _, err := netip.ParsePrefix(a); err != nil {
				return fieldErr(p+".localAddress", "本地地址必须为 CIDR，如 10.0.0.2/32")
			}
		}
		if !validWGKey(n.PeerPublicKey) {
			return fieldErr(p+".peerPublicKey", "对端公钥必须为 32 字节 Base64")
		}
		if len(n.Reserved) != 0 && len(n.Reserved) != 3 {
			return fieldErr(p+".reserved", "reserved 必须为 3 个字节")
		}
		for _, b := range n.Reserved {
			if b < 0 || b > 255 {
				return fieldErr(p+".reserved", "reserved 字节须在 0..255")
			}
		}
		if n.WGMTU != 0 && (n.WGMTU < 576 || n.WGMTU > 9000) {
			return fieldErr(p+".wgMtu", "MTU 须在 576..9000")
		}
	}
	if n.Type != "shadowsocks" && (n.Cipher != "" || n.Plugin != "") {
		return fieldErr(p+".cipher", "该类型不使用加密方式/插件字段")
	}
	if n.Type != "hysteria2" && (n.Obfs != "" || n.Ports != "" || n.UpMbps != 0 || n.DownMbps != 0) {
		return fieldErr(p+".obfs", "该类型不支持 Hysteria2 参数")
	}
	if n.Type != "vless" && n.Flow != "" {
		return fieldErr(p+".flow", "仅 VLESS 支持流控")
	}
	if n.Type == "http" && n.UDP {
		return fieldErr(p+".udp", "HTTP 代理不支持 UDP")
	}
	if t := n.Transport; t != nil {
		if !transportTypes[t.Type] {
			return fieldErr(p+".transport.type", "不支持的传输方式 %q", t.Type)
		}
		if t.Type != "tcp" && n.Type != "vmess" && n.Type != "vless" && n.Type != "trojan" {
			return fieldErr(p+".transport", "该节点类型不支持传输层设置")
		}
		if len(t.Path) > 512 || len(t.Host) > 253 || len(t.ServiceName) > 256 || strings.ContainsAny(t.Path+t.Host+t.ServiceName, "\r\n") {
			return fieldErr(p+".transport", "传输参数过长或包含换行")
		}
		for k, v := range t.Headers {
			if !headerRE.MatchString(k) || len(v) > 512 || strings.ContainsAny(v, "\r\n") {
				return fieldErr(p+".transport.headers", "请求头 %q 无效", k)
			}
		}
	}
	tlsRequired := n.Type == "trojan" || n.Type == "hysteria2" || n.Type == "tuic" || n.Type == "anytls"
	if tlsRequired && (n.TLS == nil || !n.TLS.Enabled) {
		return fieldErr(p+".tls.enabled", "该节点类型必须启用 TLS")
	}
	if t := n.TLS; t != nil {
		if n.Type == "shadowsocks" || n.Type == "wireguard" || n.Type == "socks" {
			return fieldErr(p+".tls", "该节点类型不支持 TLS 设置")
		}
		if t.SNI != "" && !ValidHost(t.SNI) {
			return fieldErr(p+".tls.sni", "SNI 无效")
		}
		if !fingerprints[t.Fingerprint] {
			return fieldErr(p+".tls.fingerprint", "不支持的指纹 %q", t.Fingerprint)
		}
		for _, a := range t.ALPN {
			if a == "" || len(a) > 32 || strings.ContainsAny(a, ", \r\n") {
				return fieldErr(p+".tls.alpn", "ALPN 项无效")
			}
		}
		if t.RealityPublicKey != "" || t.RealityShortID != "" {
			if n.Type != "vless" {
				return fieldErr(p+".tls.realityPublicKey", "Reality 仅支持 VLESS")
			}
			if !t.Enabled {
				return fieldErr(p+".tls.enabled", "Reality 需要启用 TLS")
			}
			if b, err := base64.RawURLEncoding.DecodeString(t.RealityPublicKey); err != nil || len(b) != 32 {
				return fieldErr(p+".tls.realityPublicKey", "Reality 公钥必须为 32 字节 Base64URL")
			}
			if !shortIDRE.MatchString(t.RealityShortID) || len(t.RealityShortID)%2 != 0 {
				return fieldErr(p+".tls.realityShortId", "Reality shortId 必须为偶数位十六进制")
			}
		}
	}
	return nil
}

func validWGKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// hasControl reports whether s contains ASCII control characters.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func validRegex(field, expr string) error {
	if expr == "" {
		return nil
	}
	if len(expr) > 256 {
		return fieldErr(field, "正则表达式不能超过 256 字符")
	}
	if _, err := regexp.Compile(expr); err != nil {
		return fieldErr(field, "正则表达式无效: %v", err)
	}
	return nil
}

func detectGroupCycle(groups []Group) error {
	byID := map[string]*Group{}
	for i := range groups {
		byID[groups[i].ID] = &groups[i]
	}
	state := map[string]int{}
	var visit func(id string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fieldErr("groups", "代理组之间存在循环引用（%s）", id)
		case 2:
			return nil
		}
		state[id] = 1
		for _, child := range byID[id].Groups {
			if byID[child] != nil {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		state[id] = 2
		return nil
	}
	for i := range groups {
		if err := visit(groups[i].ID); err != nil {
			return err
		}
	}
	return nil
}

func validTarget(field, target string, groups map[string]*Group) error {
	kind, id := ParseRef(target)
	switch kind {
	case TargetDirect, TargetReject:
		return nil
	case "group":
		if groups[id] == nil {
			return fieldErr(field, "目标代理组不存在")
		}
		return nil
	}
	return fieldErr(field, "目标必须为代理组、DIRECT 或 REJECT")
}

func validateRouting(r *Routing, groups map[string]*Group) error {
	switch r.Mode {
	case "rule", "global", "direct":
	default:
		return fieldErr("routing.mode", "运行模式必须为 rule/global/direct")
	}
	switch r.Preset {
	case "cn", "global", "custom":
	default:
		return fieldErr("routing.preset", "预设必须为 cn/global/custom")
	}
	if err := validTarget("routing.final", r.Final, groups); err != nil {
		return err
	}
	if len(r.Rules) > 500 {
		return fieldErr("routing.rules", "规则最多 500 条")
	}
	ids := map[string]bool{}
	for i, rule := range r.Rules {
		p := fmt.Sprintf("routing.rules[%d]", i)
		if !ValidID(rule.ID) || ids[rule.ID] {
			return fieldErr(p+".id", "规则 ID 无效或重复")
		}
		ids[rule.ID] = true
		if !ruleTypes[rule.Type] {
			return fieldErr(p+".type", "不支持的规则类型 %q", rule.Type)
		}
		if len(rule.Values) == 0 || len(rule.Values) > 2000 {
			return fieldErr(p+".values", "规则值数量须在 1..2000")
		}
		for _, v := range rule.Values {
			if err := ValidateRuleValue(rule.Type, v); err != nil {
				return fieldErr(p+".values", "%q: %v", v, err)
			}
		}
		if err := validTarget(p+".target", rule.Target, groups); err != nil {
			return err
		}
		if len([]rune(rule.Note)) > 120 {
			return fieldErr(p+".note", "备注不超过 120 字")
		}
	}
	return nil
}

// ValidateRuleValue checks a single rule value for its type.
func ValidateRuleValue(typ, v string) error {
	if v == "" || len(v) > 256 || strings.ContainsAny(v, ", \t\r\n") {
		return fmt.Errorf("不能为空、不能含逗号或空白")
	}
	switch typ {
	case "domain", "domain_suffix":
		if !ValidHost(strings.TrimPrefix(v, ".")) {
			return fmt.Errorf("域名格式无效")
		}
	case "domain_keyword":
		if strings.ContainsAny(v, "/\\") {
			return fmt.Errorf("关键字格式无效")
		}
	case "domain_regex":
		if _, err := regexp.Compile(v); err != nil {
			return fmt.Errorf("正则无效")
		}
	case "ip_cidr", "source_ip_cidr":
		if typ == "source_ip_cidr" && strings.Contains(v, "%") {
			return fmt.Errorf("来源 IP 不能包含接口区域，请填写 IP 地址或 CIDR")
		}
		if _, err := netip.ParsePrefix(v); err != nil {
			if _, err := netip.ParseAddr(v); err != nil {
				return fmt.Errorf("CIDR 格式无效")
			}
		}
	case "geosite", "geoip":
		if !ValidGeoName(v) {
			return fmt.Errorf("规则集名称只能含小写字母、数字与 !@._-")
		}
	case "package":
		if !ValidPackageName(v) {
			return fmt.Errorf("包名格式无效")
		}
	case "port":
		lo, hi, isRange := strings.Cut(v, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			return fmt.Errorf("端口或端口范围无效")
		}
	case "network":
		if v != "tcp" && v != "udp" {
			return fmt.Errorf("网络类型必须为 tcp 或 udp")
		}
	}
	return nil
}

// DNSServer is a parsed resolver address.
type DNSServer struct {
	Scheme string // udp tcp tls https quic
	Host   string
	Port   int
	Path   string
}

func (s DNSServer) IsIP() bool {
	_, err := netip.ParseAddr(s.Host)
	return err == nil
}

// ParseDNSServer accepts 1.2.3.4, udp://, tcp://, tls://, https://, quic:// forms.
func ParseDNSServer(raw string) (DNSServer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 || strings.ContainsAny(raw, " \t\r\n,") {
		return DNSServer{}, fmt.Errorf("DNS 服务器地址无效")
	}
	if !strings.Contains(raw, "://") {
		if _, err := netip.ParseAddr(strings.Trim(raw, "[]")); err != nil {
			return DNSServer{}, fmt.Errorf("不带协议的 DNS 服务器必须是 IP 地址")
		}
		return DNSServer{Scheme: "udp", Host: strings.Trim(raw, "[]"), Port: 53}, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return DNSServer{}, fmt.Errorf("DNS 服务器地址无效")
	}
	s := DNSServer{Scheme: u.Scheme, Host: u.Hostname()}
	defPort := map[string]int{"udp": 53, "tcp": 53, "tls": 853, "https": 443, "quic": 853}
	d, ok := defPort[u.Scheme]
	if !ok {
		return DNSServer{}, fmt.Errorf("DNS 协议必须为 udp/tcp/tls/https/quic")
	}
	s.Port = d
	if ps := u.Port(); ps != "" {
		pn, err := strconv.Atoi(ps)
		if err != nil || pn < 1 || pn > 65535 {
			return DNSServer{}, fmt.Errorf("DNS 端口无效")
		}
		s.Port = pn
	}
	if !ValidHost(s.Host) {
		return DNSServer{}, fmt.Errorf("DNS 主机名无效")
	}
	if u.Scheme == "https" {
		s.Path = u.EscapedPath()
		if s.Path == "" {
			s.Path = "/dns-query"
		}
		if u.RawQuery != "" {
			return DNSServer{}, fmt.Errorf("DoH 地址不能带查询串")
		}
	} else if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return DNSServer{}, fmt.Errorf("该 DNS 协议不能带路径")
	}
	return s, nil
}

func validateDNS(d *DNS) error {
	if d.Mode != "fakeip" && d.Mode != "realip" {
		return fieldErr("dns.mode", "DNS 模式必须为 fakeip 或 realip")
	}
	if len(d.Direct) == 0 || len(d.Direct) > 8 {
		return fieldErr("dns.direct", "直连 DNS 需 1..8 个")
	}
	if len(d.Proxy) == 0 || len(d.Proxy) > 8 {
		return fieldErr("dns.proxy", "代理 DNS 需 1..8 个")
	}
	hasIP := false
	for i, s := range d.Direct {
		srv, err := ParseDNSServer(s)
		if err != nil {
			return fieldErr(fmt.Sprintf("dns.direct[%d]", i), "%v", err)
		}
		if srv.IsIP() {
			hasIP = true
		}
	}
	if !hasIP {
		return fieldErr("dns.direct", "直连 DNS 至少需要一个 IP 形式的服务器用于引导解析")
	}
	for i, s := range d.Proxy {
		if _, err := ParseDNSServer(s); err != nil {
			return fieldErr(fmt.Sprintf("dns.proxy[%d]", i), "%v", err)
		}
	}
	if len(d.FakeIPFilter) > 500 {
		return fieldErr("dns.fakeipFilter", "fake-ip 排除最多 500 条")
	}
	for i, f := range d.FakeIPFilter {
		if !domainPatRE.MatchString(f) || strings.Contains(f, "**") {
			return fieldErr(fmt.Sprintf("dns.fakeipFilter[%d]", i), "域名模式无效")
		}
	}
	return nil
}

func validateApps(a *AppPolicy, groups map[string]*Group) error {
	if len(a.Routes) > MaxAppRoutes {
		return fieldErr("apps.routes", "应用出口最多 %d 条", MaxAppRoutes)
	}
	routed := map[string]bool{}
	for i, r := range a.Routes {
		p := fmt.Sprintf("apps.routes[%d]", i)
		if !ValidPackageName(r.Package) {
			return fieldErr(p+".package", "包名格式无效: %s", r.Package)
		}
		if routed[r.Package] {
			return fieldErr(p+".package", "应用 %s 重复指定了出口", r.Package)
		}
		routed[r.Package] = true
		if err := validTarget(p+".target", r.Target, groups); err != nil {
			return err
		}
	}
	switch a.Mode {
	case "all", "include", "exclude":
	default:
		return fieldErr("apps.mode", "应用模式必须为 all/include/exclude")
	}
	if len(a.Packages) > 2000 {
		return fieldErr("apps.packages", "应用名单最多 2000 个")
	}
	for _, p := range a.Packages {
		if !ValidPackageName(p) {
			return fieldErr("apps.packages", "包名格式无效: %s", p)
		}
	}
	if len(a.Users) == 0 || len(a.Users) > 16 {
		return fieldErr("apps.users", "Android 用户需 1..16 个")
	}
	for _, u := range a.Users {
		if u < 0 || u > 999 {
			return fieldErr("apps.users", "Android 用户 ID 须在 0..999")
		}
	}
	return nil
}

// ValidateSubscriptionURL accepts http(s) URLs without fragments.
func ValidateSubscriptionURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("订阅地址不能为空")
	}
	if len(raw) > 4096 || strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("订阅地址无效")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("订阅地址必须为 http(s) URL")
	}
	if !ValidHost(u.Hostname()) {
		return fmt.Errorf("订阅主机名无效")
	}
	return nil
}

// FakeIPPatternRegex converts a Mihomo-style fake-ip filter pattern into an
// anchored Go regular expression usable by sing-box domain_regex.
func FakeIPPatternRegex(p string) string {
	var b strings.Builder
	b.WriteString("^")
	if strings.HasPrefix(p, "+.") {
		b.WriteString(`(?:[^.]+\.)*`)
		p = p[2:]
	}
	for _, r := range p {
		switch r {
		case '*':
			b.WriteString(`[^.]+`)
		case '+':
			b.WriteString(`.+`)
		case '.':
			b.WriteString(`\.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// ParseCIDROrIP returns a prefix for "1.2.3.4" or "1.2.3.0/24".
func ParseCIDROrIP(v string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
