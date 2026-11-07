package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Legacy (schema 2, release 1.0.x) documents.
type legacyNode struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Protocol           string         `json:"protocol"`
	Server             string         `json:"server"`
	Port               int            `json:"port"`
	Credentials        map[string]any `json:"credentials"`
	Transport          map[string]any `json:"transport"`
	TLS                map[string]any `json:"tls"`
	UDPEnabled         bool           `json:"udpEnabled"`
	UpstreamID         string         `json:"upstreamId"`
	SourceSubscription string         `json:"sourceSubscription"`
}

type legacyTarget struct {
	Action       string `json:"action"`
	ProxyGroupID string `json:"proxyGroupId"`
}

type legacyModel struct {
	SchemaVersion int   `json:"schemaVersion"`
	Revision      int64 `json:"revision"`
	Settings      struct {
		AutoStart           bool   `json:"autoStart"`
		SelectedEngine      string `json:"selectedEngine"`
		SelectedCoreVersion string `json:"selectedCoreVersion"`
		LogLevel            string `json:"logLevel"`
	} `json:"settings"`
	AppPolicy struct {
		Mode          string   `json:"mode"`
		AndroidUserID int      `json:"androidUserId"`
		PackageNames  []string `json:"packageNames"`
	} `json:"appPolicy"`
	ProxyGroups []struct {
		ID             string   `json:"id"`
		Name           string   `json:"name"`
		NodeIDs        []string `json:"nodeIds"`
		SelectedNodeID string   `json:"selectedNodeId"`
	} `json:"proxyGroups"`
	Nodes         []legacyNode `json:"nodes"`
	Subscriptions []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"subscriptions"`
	TrafficRules []struct {
		ID           string `json:"id"`
		Network      string `json:"network"`
		Action       string `json:"action"`
		ProxyGroupID string `json:"proxyGroupId"`
		Priority     int    `json:"priority"`
	} `json:"trafficRules"`
	Fallback struct {
		TCP legacyTarget `json:"tcp"`
		UDP legacyTarget `json:"udp"`
	} `json:"fallback"`
}

type legacySecrets struct {
	Nodes         map[string]map[string]string `json:"nodes"`
	Subscriptions map[string]string            `json:"subscriptions"`
}

// LegacySchemaVersion reports the schemaVersion of a raw JSON document.
func LegacySchemaVersion(raw []byte) int {
	var probe struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.SchemaVersion
}

var idSanitizer = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizeID(s, fallback string) string {
	s = idSanitizer.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if len(s) > 64 {
		s = s[:64]
	}
	if !ValidID(s) {
		return fallback
	}
	return s
}

// uniqueID sanitizes s and appends a counter while the result is already in
// used; distinct legacy IDs such as "a/b" and "a?b" must stay distinct.
func uniqueID(s, fallback string, used map[string]bool) string {
	id := sanitizeID(s, fallback)
	if !used[id] {
		used[id] = true
		return id
	}
	base := id
	if len(base) > 56 {
		base = base[:56]
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", base, i)
		if !used[cand] {
			used[cand] = true
			return cand
		}
	}
}

// MigrateV2 converts a 1.0.x model and secrets file into schema 3. Nodes that
// cannot be represented are dropped and reported in warnings.
func MigrateV2(modelJSON, secretsJSON []byte) (Config, Secrets, []string, error) {
	var old legacyModel
	if err := json.Unmarshal(modelJSON, &old); err != nil {
		return Config{}, Secrets{}, nil, fmt.Errorf("旧版配置无法解析: %w", err)
	}
	if old.SchemaVersion != 2 && old.SchemaVersion != 1 {
		return Config{}, Secrets{}, nil, fmt.Errorf("不支持迁移 schemaVersion=%d 的旧配置", old.SchemaVersion)
	}
	var oldSec legacySecrets
	if len(secretsJSON) > 0 {
		if err := json.Unmarshal(secretsJSON, &oldSec); err != nil {
			return Config{}, Secrets{}, nil, fmt.Errorf("旧版凭据无法解析: %w", err)
		}
	}
	var warnings []string
	cfg := Default()
	sec := DefaultSecrets()
	cfg.Revision = old.Revision + 1

	switch old.Settings.SelectedEngine {
	case EngineMihomo, EngineSingBox:
		cfg.Settings.Engine = old.Settings.SelectedEngine
	}
	if old.Settings.SelectedCoreVersion != "" {
		cfg.Settings.CoreVersions[cfg.Settings.Engine] = old.Settings.SelectedCoreVersion
		if err := validateSettings(&cfg.Settings); err != nil {
			delete(cfg.Settings.CoreVersions, cfg.Settings.Engine)
			warnings = append(warnings, "旧版核心版本号无效，已改为自动选择")
		}
	}
	cfg.Settings.AutoStart = old.Settings.AutoStart
	switch old.Settings.LogLevel {
	case "warning":
		cfg.Settings.LogLevel = "warn"
	case "debug", "info", "warn", "error", "silent":
		cfg.Settings.LogLevel = old.Settings.LogLevel
	}

	subIDs := map[string]string{}
	usedSubIDs := map[string]bool{}
	for _, s := range old.Subscriptions {
		id := uniqueID(s.ID, fmt.Sprintf("sub-%d", len(usedSubIDs)+1), usedSubIDs)
		subIDs[s.ID] = id
		name := strings.TrimSpace(s.Name)
		if name == "" {
			name = id
		}
		url := oldSec.Subscriptions[s.ID]
		if ValidateSubscriptionURL(url) != nil {
			warnings = append(warnings, fmt.Sprintf("订阅 %s 的地址缺失或无效，已跳过", name))
			delete(subIDs, s.ID)
			continue
		}
		name = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, name)
		if strings.TrimSpace(name) == "" {
			name = id
		}
		if len(cfg.Subscriptions) >= MaxSubscriptions {
			warnings = append(warnings, "旧版订阅数量超过上限，已跳过超出部分")
			delete(subIDs, s.ID)
			continue
		}
		cfg.Subscriptions = append(cfg.Subscriptions, Subscription{ID: id, Name: truncateRunes(strings.TrimSpace(name), 64)})
		sec.Subscriptions[id] = url
	}

	nodeIDs := map[string]string{}
	usedNodeIDs := map[string]bool{}
	var upstreams []string
	for i, ln := range old.Nodes {
		if len(cfg.Nodes) >= MaxNodes {
			warnings = append(warnings, "旧版节点数量超过上限，已跳过超出部分")
			break
		}
		n, secrets, err := migrateNode(ln, oldSec.Nodes[ln.ID], i)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("节点 %s 无法迁移: %v", ln.Name, err))
			continue
		}
		if usedNodeIDs[n.ID] {
			n.ID = uniqueID(fmt.Sprintf("node-%d", i+1), fmt.Sprintf("node-%d", i+1), usedNodeIDs)
		} else {
			usedNodeIDs[n.ID] = true
		}
		if sid, ok := subIDs[ln.SourceSubscription]; ok {
			n.SubscriptionID = sid
		}
		nodeIDs[ln.ID] = n.ID
		cfg.Nodes = append(cfg.Nodes, n)
		upstreams = append(upstreams, ln.UpstreamID)
		if len(secrets) > 0 {
			sec.SetNodeSecrets(n.ID, secrets)
		}
	}
	originalIDs := make([]string, len(cfg.Nodes))
	for index, node := range cfg.Nodes {
		originalIDs[index] = node.ID
	}
	for _, sub := range cfg.Subscriptions {
		var indexes []int
		var nodes []Node
		for index, node := range cfg.Nodes {
			if node.SubscriptionID == sub.ID {
				indexes = append(indexes, index)
				nodes = append(nodes, node)
			}
		}
		AssignSubscriptionIDs(sub.ID, nodes)
		for index, node := range nodes {
			cfg.Nodes[indexes[index]] = node
		}
	}
	replacements := map[string]string{}
	previousSecrets := sec.Nodes
	sec.Nodes = map[string]map[string]string{}
	for index, node := range cfg.Nodes {
		replacements[originalIDs[index]] = node.ID
		sec.SetNodeSecrets(node.ID, previousSecrets[originalIDs[index]])
	}
	for legacyID, identifier := range nodeIDs {
		nodeIDs[legacyID] = replacements[identifier]
	}
	for i := range cfg.Nodes {
		cfg.Nodes[i].Upstream = nodeIDs[upstreams[i]]
	}
	nodeIndex := map[string]*Node{}
	for i := range cfg.Nodes {
		nodeIndex[cfg.Nodes[i].ID] = &cfg.Nodes[i]
	}
	for i := range cfg.Nodes {
		node := &cfg.Nodes[i]
		seen := map[string]bool{node.ID: true}
		cur := node.Upstream
		for depth := 0; cur != ""; depth++ {
			upstream := nodeIndex[cur]
			if upstream == nil || seen[cur] || depth >= 3 {
				node.Upstream = ""
				warnings = append(warnings, fmt.Sprintf("节点 %s 的前置关系无效，已移除该关系", node.Name))
				break
			}
			seen[cur] = true
			cur = upstream.Upstream
		}
	}

	groupIDs := map[string]string{}
	if len(old.ProxyGroups) > 0 {
		cfg.Groups = cfg.Groups[:0]
		usedGroupIDs := map[string]bool{}
		usedNames := map[string]bool{}
		for i, g := range old.ProxyGroups {
			if len(cfg.Groups) >= MaxGroups {
				warnings = append(warnings, "旧版代理组数量超过上限，已跳过超出部分")
				break
			}
			id := uniqueID(g.ID, fmt.Sprintf("group-%d", i+1), usedGroupIDs)
			groupIDs[g.ID] = id
			ng := Group{ID: id, Name: truncateRunes(strings.TrimSpace(g.Name), 64), Type: "select", Nodes: []string{}, Groups: []string{}, Subscriptions: []string{}, IncludeDirect: true}
			if ng.Name == "" {
				ng.Name = id
			}
			ng.Name = migratedGroupName(ng.Name, id, usedNames)
			if ng.Name != strings.TrimSpace(g.Name) {
				warnings = append(warnings, fmt.Sprintf("代理组名称已规范化为 %s", ng.Name))
			}
			for _, nid := range g.NodeIDs {
				if v, ok := nodeIDs[nid]; ok {
					ng.Nodes = append(ng.Nodes, v)
				}
			}
			if v, ok := nodeIDs[g.SelectedNodeID]; ok {
				ng.Selected = NodeRef(v)
			}
			cfg.Groups = append(cfg.Groups, ng)
		}
	}
	target := func(t legacyTarget) string {
		switch t.Action {
		case "proxy":
			if id, ok := groupIDs[t.ProxyGroupID]; ok {
				return GroupRef(id)
			}
			return TargetDirect
		case "block":
			return TargetReject
		default:
			return TargetDirect
		}
	}
	if len(old.TrafficRules) > 0 || old.Fallback.TCP.Action != "" {
		cfg.Routing.Preset = "custom"
		rules := old.TrafficRules
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
		used := map[string]bool{}
		for i, r := range rules {
			if r.Network != "tcp" && r.Network != "udp" {
				continue
			}
			id := uniqueID(r.ID, fmt.Sprintf("rule-%d", i+1), used)
			cfg.Routing.Rules = append(cfg.Routing.Rules, Rule{ID: id, Enabled: true, Type: "network", Values: []string{r.Network}, Target: target(legacyTarget{Action: r.Action, ProxyGroupID: r.ProxyGroupID})})
		}
		cfg.Routing.Final = target(old.Fallback.TCP)
		if udp := target(old.Fallback.UDP); udp != cfg.Routing.Final {
			id := uniqueID("legacy-udp-fallback", "legacy-udp-fallback", used)
			cfg.Routing.Rules = append(cfg.Routing.Rules, Rule{ID: id, Enabled: true, Type: "network", Values: []string{"udp"}, Target: udp})
		}
		if len(cfg.Routing.Rules) > 500 {
			cfg.Routing.Rules = cfg.Routing.Rules[:500]
			warnings = append(warnings, "旧版规则超过 500 条，已保留优先级最高的部分")
		}
	}
	switch old.AppPolicy.Mode {
	case "allowlist":
		cfg.Apps.Mode = "include"
	case "denylist":
		cfg.Apps.Mode = "exclude"
	default:
		cfg.Apps.Mode = "all"
	}
	for _, name := range old.AppPolicy.PackageNames {
		name = strings.TrimSpace(name)
		if !ValidPackageName(name) {
			warnings = append(warnings, "旧版应用名单中存在无效包名，已跳过")
			continue
		}
		cfg.Apps.Packages = append(cfg.Apps.Packages, name)
	}
	if old.AppPolicy.AndroidUserID < 0 || old.AppPolicy.AndroidUserID > 999 {
		warnings = append(warnings, "旧版 Android 用户编号无效，已改为机主")
	} else {
		cfg.Apps.Users = []int{old.AppPolicy.AndroidUserID}
	}
	// Legacy groups replace the defaults; a final target that pointed at a
	// default group must follow.
	if kind, id := ParseRef(cfg.Routing.Final); kind == "group" && cfg.GroupByID(id) == nil {
		cfg.Routing.Final = TargetDirect
		if len(cfg.Groups) > 0 {
			cfg.Routing.Final = GroupRef(cfg.Groups[0].ID)
		}
	}

	cfg.Normalize()
	if len(cfg.Apps.Packages) > 2000 {
		cfg.Apps.Packages = cfg.Apps.Packages[:2000]
		warnings = append(warnings, "旧版应用名单超过 2000 个，已保留上限以内的部分")
	}
	sec.Normalize()
	if err := Validate(&cfg, &sec); err != nil {
		return Config{}, Secrets{}, warnings, fmt.Errorf("迁移结果未通过校验: %w", err)
	}
	return cfg, sec, warnings, nil
}

func migratedGroupName(name, fallback string, used map[string]bool) string {
	name = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f || character == ',' || character == '#' {
			return ' '
		}
		return character
	}, name))
	if name == "" {
		name = fallback
	}
	base := name
	name = truncateRunes(base, 64)
	for counter := 2; used[name] || reservedGroupNames[name]; counter++ {
		suffix := fmt.Sprintf(" (%d)", counter)
		name = truncateRunes(base, 64-len(suffix)) + suffix
	}
	used[name] = true
	return name
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func legacyString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" && v != "***" {
			return v
		}
	}
	return ""
}

func legacyInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(v, "Mbps")))
		return n
	}
	return 0
}

func legacyBool(m map[string]any, keys ...string) (bool, bool) {
	for _, k := range keys {
		switch v := m[k].(type) {
		case bool:
			return v, true
		case string:
			if b, err := strconv.ParseBool(v); err == nil {
				return b, true
			}
		}
	}
	return false, false
}

func migrateNode(ln legacyNode, oldSecrets map[string]string, index int) (Node, map[string]string, error) {
	cred := func(key string) string {
		if v := legacyString(ln.Credentials, key); v != "" {
			return v
		}
		return oldSecrets[key]
	}
	n := Node{
		ID:     sanitizeID(ln.ID, fmt.Sprintf("node-%d", index+1)),
		Name:   truncateRunes(strings.TrimSpace(ln.Name), 128),
		Server: strings.TrimSpace(ln.Server),
		Port:   ln.Port,
		UDP:    ln.UDPEnabled,
	}
	if n.Name == "" {
		n.Name = n.ID
	}
	secrets := map[string]string{}
	switch ln.Protocol {
	case "shadowsocks":
		n.Type = "shadowsocks"
		n.Cipher = legacyString(ln.Credentials, "cipher")
		secrets["password"] = cred("password")
	case "vmess":
		n.Type = "vmess"
		n.Security = legacyString(ln.Credentials, "cipher")
		n.AlterID = legacyInt(ln.Credentials, "alterId")
		secrets["uuid"] = cred("uuid")
	case "vless":
		n.Type = "vless"
		n.Flow = legacyString(ln.Credentials, "flow")
		secrets["uuid"] = cred("uuid")
	case "trojan":
		n.Type = "trojan"
		secrets["password"] = cred("password")
	case "hysteria2":
		n.Type = "hysteria2"
		n.UpMbps = legacyInt(ln.Credentials, "up")
		n.DownMbps = legacyInt(ln.Credentials, "down")
		secrets["password"] = cred("password")
	case "tuic":
		n.Type = "tuic"
		n.CongestionControl = legacyString(ln.Credentials, "congestionControl")
		n.UDPRelayMode = legacyString(ln.Credentials, "udpRelayMode")
		secrets["uuid"] = cred("uuid")
		secrets["password"] = cred("password")
	case "wireguard":
		n.Type = "wireguard"
		secrets["privateKey"] = cred("privateKey")
		n.PeerPublicKey = cred("publicKey")
		for _, k := range []string{"ip", "ipv6"} {
			if a := legacyString(ln.Credentials, k); a != "" {
				if !strings.Contains(a, "/") {
					if strings.Contains(a, ":") {
						a += "/128"
					} else {
						a += "/32"
					}
				}
				n.LocalAddress = append(n.LocalAddress, a)
			}
		}
		n.WGMTU = legacyInt(ln.Credentials, "mtu")
	case "socks5":
		n.Type = "socks"
		secrets["username"] = cred("username")
		secrets["password"] = cred("password")
	case "http":
		n.Type = "http"
		n.UDP = false
		secrets["username"] = cred("username")
		secrets["password"] = cred("password")
	default:
		return Node{}, nil, fmt.Errorf("不支持的协议 %q", ln.Protocol)
	}
	network, _ := ln.Transport["network"].(string)
	if network == "" {
		if _, ok := ln.Transport["ws"]; ok {
			network = "ws"
		} else if _, ok := ln.Transport["grpc"]; ok {
			network = "grpc"
		}
	}
	switch network {
	case "ws":
		t := &Transport{Type: "ws"}
		if ws, ok := ln.Transport["ws"].(map[string]any); ok {
			t.Path = legacyString(ws, "path")
			if h, ok := ws["headers"].(map[string]any); ok {
				for k, v := range h {
					s, _ := v.(string)
					if strings.EqualFold(k, "host") {
						t.Host = s
					} else if s != "" {
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
		t := &Transport{Type: "grpc"}
		if g, ok := ln.Transport["grpc"].(map[string]any); ok {
			t.ServiceName = legacyString(g, "serviceName")
		}
		n.Transport = t
	}
	tlsOn, explicit := legacyBool(ln.TLS, "enabled", "tls")
	if !explicit {
		tlsOn, explicit = legacyBool(ln.Transport, "tls")
	}
	sni := legacyString(ln.TLS, "serverName", "sni", "server_name")
	reality, _ := ln.TLS["reality"].(map[string]any)
	if !explicit {
		tlsOn = n.Type == "trojan" || n.Type == "hysteria2" || n.Type == "tuic" || reality != nil || sni != ""
	}
	if tlsOn && n.Type != "shadowsocks" && n.Type != "wireguard" && n.Type != "socks" {
		t := &TLS{Enabled: true, SNI: sni, Fingerprint: legacyString(ln.TLS, "fingerprint")}
		if ins, ok := legacyBool(ln.TLS, "insecure", "skipCertVerify", "allowInsecure"); ok {
			t.Insecure = ins
		}
		switch a := ln.TLS["alpn"].(type) {
		case string:
			for _, s := range strings.Split(a, ",") {
				if s = strings.TrimSpace(s); s != "" {
					t.ALPN = append(t.ALPN, s)
				}
			}
		case []any:
			for _, v := range a {
				if s, ok := v.(string); ok && s != "" {
					t.ALPN = append(t.ALPN, s)
				}
			}
		}
		if reality != nil {
			t.RealityPublicKey = legacyString(reality, "publicKey")
			t.RealityShortID = legacyString(reality, "shortId")
		}
		n.TLS = t
	}
	n.Normalize()
	if err := ValidateNode(&n, "node"); err != nil {
		return Node{}, nil, err
	}
	for _, f := range RequiredSecrets(n) {
		if secrets[f] == "" {
			return Node{}, nil, fmt.Errorf("缺少凭据 %s", f)
		}
	}
	return n, secrets, nil
}
