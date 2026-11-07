package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"ksu_proxy_manager/internal/config"
)

// ParseLink parses one share link.
func ParseLink(link string) (Parsed, error) {
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return Parsed{}, errors.New("不是分享链接")
	}
	switch strings.ToLower(scheme) {
	case "ss":
		return parseSS(link)
	case "vmess":
		return parseVMess(link)
	case "vless":
		return parseVLESS(link)
	case "trojan":
		return parseTrojan(link)
	case "hysteria2", "hy2":
		return parseHysteria2(link)
	case "tuic":
		return parseTUIC(link)
	case "anytls":
		return parseAnyTLS(link)
	case "socks", "socks5":
		return parseSocks(link)
	case "http", "https":
		return parseHTTP(link)
	case "wireguard", "wg":
		return parseWireGuard(link)
	}
	return Parsed{}, fmt.Errorf("不支持的链接类型 %s", scheme)
}

func newParsed(typ, name, server string, port int) Parsed {
	return Parsed{Node: config.Node{Type: typ, Name: name, Server: server, Port: port, UDP: true}, Secrets: map[string]string{}}
}

func fragmentName(u *url.URL) string {
	if u.Fragment != "" {
		return u.Fragment
	}
	if u.RawFragment != "" {
		if s, err := url.PathUnescape(u.RawFragment); err == nil {
			return s
		}
	}
	return ""
}

func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	ps := u.Port()
	if host == "" || ps == "" {
		return "", 0, errors.New("缺少服务器地址或端口")
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, errors.New("端口无效")
	}
	return host, p, nil
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func first(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// applyTLS sets TLS fields from common share-link parameters.
func applyTLS(n *config.Node, q url.Values, enabled bool) {
	if !enabled {
		return
	}
	n.TLS = &config.TLS{
		Enabled:          true,
		SNI:              first(q, "sni", "peer", "servername"),
		ALPN:             splitList(q.Get("alpn")),
		Insecure:         truthy(first(q, "allowInsecure", "insecure", "allow_insecure", "skip-cert-verify")),
		Fingerprint:      strings.ToLower(q.Get("fp")),
		RealityPublicKey: q.Get("pbk"),
		RealityShortID:   q.Get("sid"),
	}
	if n.TLS.Fingerprint == "none" {
		n.TLS.Fingerprint = ""
	}
}

// applyTransport maps the Xray share-link transport parameters.
func applyTransport(n *config.Node, typ, host, path, service, headerType string) error {
	switch strings.ToLower(typ) {
	case "", "tcp", "raw":
		if headerType == "http" {
			return errors.New("不支持 TCP HTTP 伪装传输")
		}
		return nil
	case "ws", "websocket":
		n.Transport = &config.Transport{Type: "ws", Path: path, Host: host}
	case "grpc", "gun":
		n.Transport = &config.Transport{Type: "grpc", ServiceName: firstNonEmpty(service, path)}
	case "http", "h2":
		n.Transport = &config.Transport{Type: "http", Path: path, Host: host}
	case "httpupgrade":
		n.Transport = &config.Transport{Type: "httpupgrade", Path: path, Host: host}
	case "xhttp", "splithttp":
		n.Transport = &config.Transport{Type: "xhttp", Path: path, Host: host}
	default:
		return fmt.Errorf("不支持的传输方式 %s", typ)
	}
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func parseSS(link string) (Parsed, error) {
	rest := link[len("ss://"):]
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	var method, password, hostport string
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		userinfo, err := url.PathUnescape(rest[:at])
		if err != nil {
			return Parsed{}, errors.New("SS 用户信息编码无效")
		}
		hostport = rest[at+1:]
		if strings.Contains(userinfo, ":") {
			method, password, _ = strings.Cut(userinfo, ":")
		} else if b, ok := decodeBase64Text(userinfo); ok && strings.Contains(b, ":") {
			method, password, _ = strings.Cut(b, ":")
		} else {
			return Parsed{}, errors.New("SS 用户信息无法解析")
		}
	} else {
		b, ok := decodeBase64Text(rest)
		if !ok {
			return Parsed{}, errors.New("SS 链接无法解码")
		}
		at := strings.LastIndexByte(b, '@')
		if at < 0 {
			return Parsed{}, errors.New("SS 链接缺少服务器")
		}
		method, password, _ = strings.Cut(b[:at], ":")
		hostport = b[at+1:]
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Parsed{}, errors.New("SS 服务器地址无效")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Parsed{}, errors.New("SS 端口无效")
	}
	p := newParsed("shadowsocks", name, host, port)
	p.Node.Cipher = strings.ToLower(method)
	p.Secrets["password"] = password
	if query != "" {
		q, err := url.ParseQuery(strings.ReplaceAll(query, ";", "%3B"))
		if err != nil {
			return Parsed{}, errors.New("SS 查询参数无效")
		}
		if plugin := q.Get("plugin"); plugin != "" {
			if err := applySSPlugin(&p.Node, plugin); err != nil {
				return Parsed{}, err
			}
		}
	}
	return p, nil
}

// applySSPlugin parses SIP003 "name;key=value;flag" strings.
func applySSPlugin(n *config.Node, spec string) error {
	parts := strings.Split(spec, ";")
	name := strings.TrimSpace(parts[0])
	opts := map[string]string{}
	for _, kv := range parts[1:] {
		k, v, _ := strings.Cut(kv, "=")
		opts[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	switch name {
	case "obfs-local", "simple-obfs", "obfs":
		mode := firstNonEmpty(opts["obfs"], opts["mode"])
		n.Plugin = "obfs"
		n.PluginOpts = map[string]string{"mode": mode}
		if h := firstNonEmpty(opts["obfs-host"], opts["host"]); h != "" {
			n.PluginOpts["host"] = h
		}
	case "v2ray-plugin":
		n.Plugin = "v2ray-plugin"
		n.PluginOpts = map[string]string{"mode": "websocket"}
		if opts["mode"] != "" && opts["mode"] != "websocket" {
			return fmt.Errorf("v2ray-plugin 模式 %s 不受支持", opts["mode"])
		}
		for _, k := range []string{"host", "path"} {
			if opts[k] != "" {
				n.PluginOpts[k] = opts[k]
			}
		}
		if _, ok := opts["tls"]; ok {
			n.PluginOpts["tls"] = "true"
		}
		if opts["mux"] != "" {
			n.PluginOpts["mux"] = opts["mux"]
		}
	default:
		return fmt.Errorf("不支持的 SS 插件 %s", name)
	}
	return nil
}

type vmessJSON struct {
	PS   string          `json:"ps"`
	Add  string          `json:"add"`
	Port json.RawMessage `json:"port"`
	ID   string          `json:"id"`
	Aid  json.RawMessage `json:"aid"`
	Scy  string          `json:"scy"`
	Net  string          `json:"net"`
	Type string          `json:"type"`
	Host string          `json:"host"`
	Path string          `json:"path"`
	TLS  string          `json:"tls"`
	SNI  string          `json:"sni"`
	ALPN string          `json:"alpn"`
	FP   string          `json:"fp"`
	Ins  json.RawMessage `json:"allowInsecure"`
}

func rawInt(r json.RawMessage) int {
	s := strings.Trim(strings.TrimSpace(string(r)), `"`)
	n, _ := strconv.Atoi(s)
	return n
}

func parseVMess(link string) (Parsed, error) {
	body := strings.TrimSpace(link[len("vmess://"):])
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	text, ok := decodeBase64Text(body)
	if !ok {
		return Parsed{}, errors.New("VMess 链接不是 Base64 JSON")
	}
	var v vmessJSON
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return Parsed{}, errors.New("VMess 链接 JSON 无效")
	}
	port := rawInt(v.Port)
	p := newParsed("vmess", v.PS, strings.TrimSpace(v.Add), port)
	p.Secrets["uuid"] = strings.TrimSpace(v.ID)
	p.Node.AlterID = rawInt(v.Aid)
	p.Node.Security = strings.ToLower(v.Scy)
	if p.Node.Security == "" {
		p.Node.Security = "auto"
	}
	netType := v.Net
	if netType == "grpc" {
		if err := applyTransport(&p.Node, netType, v.Host, "", v.Path, ""); err != nil {
			return Parsed{}, err
		}
	} else if err := applyTransport(&p.Node, netType, v.Host, v.Path, "", v.Type); err != nil {
		return Parsed{}, err
	}
	if strings.EqualFold(v.TLS, "tls") {
		q := url.Values{}
		q.Set("sni", v.SNI)
		q.Set("alpn", v.ALPN)
		q.Set("fp", v.FP)
		q.Set("allowInsecure", strings.Trim(string(v.Ins), `"`))
		applyTLS(&p.Node, q, true)
	}
	return p, nil
}

func parseVLESS(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("VLESS 链接无效")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("vless", fragmentName(u), host, port)
	p.Secrets["uuid"] = u.User.Username()
	q := u.Query()
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		return Parsed{}, fmt.Errorf("VLESS encryption=%s 不受支持", enc)
	}
	p.Node.Flow = q.Get("flow")
	if err := applyTransport(&p.Node, q.Get("type"), q.Get("host"), q.Get("path"), q.Get("serviceName"), q.Get("headerType")); err != nil {
		return Parsed{}, err
	}
	switch sec := q.Get("security"); sec {
	case "tls", "reality", "xtls":
		applyTLS(&p.Node, q, true)
		if sec == "reality" && p.Node.TLS.RealityPublicKey == "" {
			return Parsed{}, errors.New("Reality 链接缺少 pbk 公钥")
		}
	case "", "none":
	default:
		return Parsed{}, fmt.Errorf("VLESS security=%s 不受支持", sec)
	}
	return p, nil
}

func parseTrojan(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("Trojan 链接无效")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("trojan", fragmentName(u), host, port)
	p.Secrets["password"] = u.User.Username()
	q := u.Query()
	if err := applyTransport(&p.Node, q.Get("type"), q.Get("host"), q.Get("path"), q.Get("serviceName"), q.Get("headerType")); err != nil {
		return Parsed{}, err
	}
	if sec := q.Get("security"); sec == "reality" {
		return Parsed{}, errors.New("Trojan 不支持 Reality")
	}
	applyTLS(&p.Node, q, true)
	return p, nil
}

func parseHysteria2(link string) (Parsed, error) {
	// The port section may hold a hopping spec ("443,1000-2000"), which
	// url.Parse rejects, so split it out manually first.
	rest := link[strings.Index(link, "://")+3:]
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	auth := ""
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		auth, _ = url.PathUnescape(rest[:at])
		rest = rest[at+1:]
	}
	var host, portSpec string
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return Parsed{}, errors.New("Hysteria2 地址无效")
		}
		host = rest[1:end]
		portSpec = strings.TrimPrefix(rest[end+1:], ":")
	} else {
		i := strings.LastIndexByte(rest, ':')
		if i < 0 {
			host, portSpec = rest, "443"
		} else {
			host, portSpec = rest[:i], rest[i+1:]
		}
	}
	q, _ := url.ParseQuery(query)
	firstPort := portSpec
	if i := strings.IndexAny(firstPort, ",-"); i >= 0 {
		firstPort = firstPort[:i]
	}
	port, err := strconv.Atoi(firstPort)
	if err != nil || host == "" {
		return Parsed{}, errors.New("Hysteria2 地址或端口无效")
	}
	p := newParsed("hysteria2", name, host, port)
	if portSpec != firstPort {
		p.Node.Ports = portSpec
	}
	// mport carries the hopping range; the authority keeps the main port.
	if mp := q.Get("mport"); mp != "" {
		p.Node.Ports = mp
	}
	p.Secrets["password"] = auth
	if o := q.Get("obfs"); o != "" {
		if o != "salamander" {
			return Parsed{}, fmt.Errorf("不支持的 Hysteria2 混淆 %s", o)
		}
		p.Node.Obfs = o
		p.Secrets["obfsPassword"] = q.Get("obfs-password")
	}
	p.Node.UpMbps = parseMbps(first(q, "up", "upmbps"))
	p.Node.DownMbps = parseMbps(first(q, "down", "downmbps"))
	applyTLS(&p.Node, q, true)
	return p, nil
}

// parseMbps accepts "100", "100 Mbps", "100mbps".
func parseMbps(v string) int {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(v, "mbps"), "m"))
	n, _ := strconv.Atoi(v)
	if n < 0 {
		return 0
	}
	return n
}

func parseTUIC(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("TUIC 链接无效")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("tuic", fragmentName(u), host, port)
	p.Secrets["uuid"] = u.User.Username()
	pw, _ := u.User.Password()
	p.Secrets["password"] = pw
	q := u.Query()
	p.Node.CongestionControl = first(q, "congestion_control", "congestion-control")
	p.Node.UDPRelayMode = first(q, "udp_relay_mode", "udp-relay-mode")
	applyTLS(&p.Node, q, true)
	return p, nil
}

func parseAnyTLS(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("AnyTLS 链接无效")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("anytls", fragmentName(u), host, port)
	p.Secrets["password"] = u.User.Username()
	applyTLS(&p.Node, u.Query(), true)
	return p, nil
}

func userPass(u *url.URL) (string, string) {
	if u.User == nil {
		return "", ""
	}
	user := u.User.Username()
	pw, has := u.User.Password()
	if !has && user != "" {
		if dec, ok := decodeBase64Text(user); ok && strings.Contains(dec, ":") {
			user, pw, _ = strings.Cut(dec, ":")
		}
	}
	return user, pw
}

func parseSocks(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("SOCKS 链接无效")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("socks", fragmentName(u), host, port)
	p.Secrets["username"], p.Secrets["password"] = userPass(u)
	return p, nil
}

func parseHTTP(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("HTTP 代理链接无效")
	}
	if u.Port() == "" || (u.Path != "" && u.Path != "/") {
		return Parsed{}, errors.New("不是 HTTP 代理链接")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("http", fragmentName(u), host, port)
	p.Node.UDP = false
	p.Secrets["username"], p.Secrets["password"] = userPass(u)
	if u.Scheme == "https" {
		applyTLS(&p.Node, u.Query(), true)
	}
	return p, nil
}

func parseWireGuard(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, errors.New("WireGuard 链接无效")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	p := newParsed("wireguard", fragmentName(u), host, port)
	priv := u.User.Username()
	if dec, err := url.PathUnescape(priv); err == nil {
		priv = dec
	}
	p.Secrets["privateKey"] = priv
	q, err := url.ParseQuery(strings.ReplaceAll(u.RawQuery, "+", "%2B"))
	if err != nil {
		return Parsed{}, errors.New("WireGuard 查询参数无效")
	}
	p.Node.PeerPublicKey = first(q, "publickey", "publicKey", "public-key", "peer")
	p.Secrets["preSharedKey"] = first(q, "presharedkey", "preSharedKey", "pre-shared-key")
	for _, a := range splitList(first(q, "address", "ip")) {
		if !strings.Contains(a, "/") {
			if strings.Contains(a, ":") {
				a += "/128"
			} else {
				a += "/32"
			}
		}
		p.Node.LocalAddress = append(p.Node.LocalAddress, a)
	}
	if r := q.Get("reserved"); r != "" {
		for _, s := range splitList(r) {
			b, err := strconv.Atoi(s)
			if err != nil {
				return Parsed{}, errors.New("reserved 无效")
			}
			p.Node.Reserved = append(p.Node.Reserved, b)
		}
	}
	if m := q.Get("mtu"); m != "" {
		p.Node.WGMTU, _ = strconv.Atoi(m)
	}
	return p, nil
}
