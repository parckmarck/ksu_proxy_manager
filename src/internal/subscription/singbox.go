package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"ksu_proxy_manager/internal/config"
)

type sbTLS struct {
	Enabled    bool       `json:"enabled"`
	ServerName string     `json:"server_name"`
	Insecure   bool       `json:"insecure"`
	ALPN       stringList `json:"alpn"`
	UTLS       *struct {
		Enabled     bool   `json:"enabled"`
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
}

type sbTransport struct {
	Type        string          `json:"type"`
	Path        string          `json:"path"`
	Host        json.RawMessage `json:"host"`
	Headers     map[string]any  `json:"headers"`
	ServiceName string          `json:"service_name"`
}

type sbPeer struct {
	Address      string `json:"address"`
	Port         int    `json:"port"`
	PublicKey    string `json:"public_key"`
	PreSharedKey string `json:"pre_shared_key"`
	Reserved     []int  `json:"reserved"`
}

type sbOutbound struct {
	Type              string          `json:"type"`
	Tag               string          `json:"tag"`
	Server            string          `json:"server"`
	ServerPort        int             `json:"server_port"`
	ServerPorts       stringList      `json:"server_ports"`
	Detour            string          `json:"detour"`
	Multiplex         json.RawMessage `json:"multiplex"`
	Network           string          `json:"network"`
	Method            string          `json:"method"`
	Password          string          `json:"password"`
	Plugin            string          `json:"plugin"`
	PluginOpts        string          `json:"plugin_opts"`
	UUID              string          `json:"uuid"`
	Security          string          `json:"security"`
	AlterID           int             `json:"alter_id"`
	Flow              string          `json:"flow"`
	Username          string          `json:"username"`
	Version           string          `json:"version"`
	UpMbps            int             `json:"up_mbps"`
	DownMbps          int             `json:"down_mbps"`
	CongestionControl string          `json:"congestion_control"`
	UDPRelayMode      string          `json:"udp_relay_mode"`
	PrivateKey        string          `json:"private_key"`
	PeerPublicKey     string          `json:"peer_public_key"`
	PreSharedKey      string          `json:"pre_shared_key"`
	LocalAddress      json.RawMessage `json:"local_address"`
	Address           json.RawMessage `json:"address"`
	Reserved          []int           `json:"reserved"`
	MTU               int             `json:"mtu"`
	Peers             []sbPeer        `json:"peers"`
	Obfs              *struct {
		Type     string `json:"type"`
		Password string `json:"password"`
	} `json:"obfs"`
	TLS       *sbTLS       `json:"tls"`
	Transport *sbTransport `json:"transport"`
}

type stringList []string

func (list *stringList) UnmarshalJSON(data []byte) error {
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*list = many
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*list = []string{one}
	return nil
}

func rawStrings(r json.RawMessage) []string {
	if len(r) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(r, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(r, &many)
	return many
}

func parseSingBox(data []byte) Result {
	r := Result{Format: "sing-box"}
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		r.issue("", "JSON 解析失败: %v", err)
		return r
	}
	groups := map[string]bool{}
	for _, raw := range append(doc.Outbounds, doc.Endpoints...) {
		var ob sbOutbound
		if err := json.Unmarshal(raw, &ob); err != nil {
			r.issue("", "出站解析失败: %v", err)
			continue
		}
		switch ob.Type {
		case "selector", "urltest":
			groups[ob.Tag] = true
			continue
		case "direct", "block", "dns":
			continue
		}
		if len(ob.Multiplex) > 0 && string(ob.Multiplex) != "null" && string(ob.Multiplex) != "false" {
			r.issue(ob.Tag, "multiplex 多路复用参数未导入")
		}
		p, err := singBoxNode(ob)
		if err != nil {
			r.issue(ob.Tag, "%v", err)
			continue
		}
		p.key, p.via = ob.Tag, ob.Detour
		r.add(p)
	}
	r.resolveChains(groups)
	if len(r.Nodes) == 0 && len(r.Issues) == 0 {
		r.issue("", "未找到代理出站")
	}
	return r
}

func sbApplyTLS(n *config.Node, t *sbTLS, force bool) {
	if t == nil || !t.Enabled {
		if force {
			n.TLS = &config.TLS{Enabled: true}
		}
		return
	}
	n.TLS = &config.TLS{Enabled: true, SNI: t.ServerName, Insecure: t.Insecure, ALPN: t.ALPN}
	if t.UTLS != nil && t.UTLS.Enabled {
		n.TLS.Fingerprint = t.UTLS.Fingerprint
	}
	if t.Reality != nil && t.Reality.Enabled {
		n.TLS.RealityPublicKey = t.Reality.PublicKey
		n.TLS.RealityShortID = t.Reality.ShortID
	}
}

func sbApplyTransport(n *config.Node, t *sbTransport) error {
	if t == nil {
		return nil
	}
	hosts := rawStrings(t.Host)
	host := ""
	if len(hosts) > 0 {
		host = hosts[0]
	}
	tr := &config.Transport{Path: t.Path, Host: host, ServiceName: t.ServiceName}
	for k, v := range t.Headers {
		s := ""
		switch x := v.(type) {
		case string:
			s = x
		case []any:
			if len(x) > 0 {
				s = fmt.Sprint(x[0])
			}
		}
		if strings.EqualFold(k, "host") {
			if tr.Host == "" {
				tr.Host = s
			}
			continue
		}
		if tr.Headers == nil {
			tr.Headers = map[string]string{}
		}
		tr.Headers[k] = s
	}
	switch t.Type {
	case "ws", "grpc", "http", "httpupgrade":
		tr.Type = t.Type
	default:
		return fmt.Errorf("不支持的传输方式 %s", t.Type)
	}
	n.Transport = tr
	return nil
}

func singBoxNode(ob sbOutbound) (Parsed, error) {
	var p Parsed
	switch ob.Type {
	case "shadowsocks":
		p = newParsed("shadowsocks", ob.Tag, ob.Server, ob.ServerPort)
		p.Node.Cipher = ob.Method
		p.Secrets["password"] = ob.Password
		if ob.Plugin != "" {
			if err := applySSPlugin(&p.Node, ob.Plugin+";"+ob.PluginOpts); err != nil {
				return Parsed{}, err
			}
		}
	case "vmess":
		p = newParsed("vmess", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["uuid"] = ob.UUID
		p.Node.Security = firstNonEmpty(ob.Security, "auto")
		p.Node.AlterID = ob.AlterID
		if err := sbApplyTransport(&p.Node, ob.Transport); err != nil {
			return Parsed{}, err
		}
		sbApplyTLS(&p.Node, ob.TLS, false)
	case "vless":
		p = newParsed("vless", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["uuid"] = ob.UUID
		p.Node.Flow = ob.Flow
		if err := sbApplyTransport(&p.Node, ob.Transport); err != nil {
			return Parsed{}, err
		}
		if ob.TLS != nil && ob.TLS.Enabled && ob.TLS.Reality != nil && ob.TLS.Reality.Enabled && ob.TLS.Reality.PublicKey == "" {
			return Parsed{}, errors.New("tls.reality 缺少 public_key")
		}
		sbApplyTLS(&p.Node, ob.TLS, false)
	case "trojan":
		p = newParsed("trojan", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["password"] = ob.Password
		if err := sbApplyTransport(&p.Node, ob.Transport); err != nil {
			return Parsed{}, err
		}
		sbApplyTLS(&p.Node, ob.TLS, true)
	case "hysteria2":
		p = newParsed("hysteria2", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["password"] = ob.Password
		p.Node.UpMbps, p.Node.DownMbps = ob.UpMbps, ob.DownMbps
		if ob.Obfs != nil && ob.Obfs.Type != "" {
			if ob.Obfs.Type != "salamander" {
				return Parsed{}, fmt.Errorf("不支持的 Hysteria2 混淆 %s", ob.Obfs.Type)
			}
			p.Node.Obfs = "salamander"
			p.Secrets["obfsPassword"] = ob.Obfs.Password
		}
		if ports := ob.ServerPorts; len(ports) > 0 {
			var parts []string
			for _, sp := range ports {
				parts = append(parts, strings.ReplaceAll(sp, ":", "-"))
			}
			p.Node.Ports = strings.Join(parts, ",")
			if p.Node.Port == 0 {
				first := strings.FieldsFunc(parts[0], func(r rune) bool { return r == '-' })
				if len(first) > 0 {
					p.Node.Port, _ = strconv.Atoi(first[0])
				}
			}
		}
		sbApplyTLS(&p.Node, ob.TLS, true)
	case "tuic":
		p = newParsed("tuic", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["uuid"] = ob.UUID
		p.Secrets["password"] = ob.Password
		p.Node.CongestionControl = ob.CongestionControl
		p.Node.UDPRelayMode = ob.UDPRelayMode
		sbApplyTLS(&p.Node, ob.TLS, true)
	case "anytls":
		p = newParsed("anytls", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["password"] = ob.Password
		sbApplyTLS(&p.Node, ob.TLS, true)
	case "socks":
		if ob.Version != "" && ob.Version != "5" {
			return Parsed{}, fmt.Errorf("仅支持 SOCKS5")
		}
		p = newParsed("socks", ob.Tag, ob.Server, ob.ServerPort)
		p.Secrets["username"], p.Secrets["password"] = ob.Username, ob.Password
	case "http":
		p = newParsed("http", ob.Tag, ob.Server, ob.ServerPort)
		p.Node.UDP = false
		p.Secrets["username"], p.Secrets["password"] = ob.Username, ob.Password
		sbApplyTLS(&p.Node, ob.TLS, false)
	case "wireguard":
		addrs := append(rawStrings(ob.LocalAddress), rawStrings(ob.Address)...)
		server, port, peerKey, psk, reserved := ob.Server, ob.ServerPort, ob.PeerPublicKey, ob.PreSharedKey, ob.Reserved
		if len(ob.Peers) > 1 {
			return Parsed{}, errors.New("不支持多 peer WireGuard")
		}
		if len(ob.Peers) == 1 {
			pe := ob.Peers[0]
			server, port, peerKey, psk, reserved = pe.Address, pe.Port, pe.PublicKey, pe.PreSharedKey, pe.Reserved
		}
		p = newParsed("wireguard", ob.Tag, server, port)
		p.Secrets["privateKey"] = ob.PrivateKey
		p.Secrets["preSharedKey"] = psk
		p.Node.PeerPublicKey = peerKey
		p.Node.LocalAddress = addrs
		p.Node.Reserved = reserved
		p.Node.WGMTU = ob.MTU
	default:
		return Parsed{}, fmt.Errorf("不支持的出站类型 %q", ob.Type)
	}
	if ob.Network == "tcp" {
		p.Node.UDP = false
	}
	return p, nil
}
