// Package render turns the shared configuration into Mihomo or sing-box
// configuration files. Both renderers consume the same engine-neutral plan.
package render

import (
	"errors"
	"fmt"
	"net/textproto"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ksu_proxy_manager/internal/capture"
	"ksu_proxy_manager/internal/config"
)

// Runtime carries per-start values chosen by the daemon.
type Runtime struct {
	TunName          string
	TunIPv4          string
	TunIPv6          string
	ControllerPort   int
	ControllerSecret string
	MixedPort        int
	MixedUser        string
	MixedPass        string
	WorkDir          string
	RulesetDir       string
}

// RulesetID identifies a geosite/geoip rule set.
type RulesetID struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

func (r RulesetID) Tag() string { return r.Kind + "-" + r.Name }

// RulesetLookup returns the local file for a rule set if it is available.
type RulesetLookup func(id RulesetID) (string, bool)

type Input struct {
	Config   config.Config
	Secrets  config.Secrets
	Engine   string
	Version  string
	Runtime  Runtime
	Rulesets RulesetLookup
}

type Output struct {
	Engine   string            `json:"engine"`
	FileName string            `json:"fileName"`
	Content  []byte            `json:"-"`
	Warnings []string          `json:"warnings"`
	Needed   []RulesetID       `json:"needed"`
	Missing  []RulesetID       `json:"missing"`
	TagOf    map[string]string `json:"-"`
	RefOf    map[string]string `json:"-"`
	// Selected maps each select group's tag to its configured member tag.
	Selected map[string]string `json:"-"`
	Env      []string          `json:"-"`
}

const (
	defaultTestURL  = "https://www.gstatic.com/generate_204"
	defaultInterval = 300
	defaultTolerate = 50
	FakeIPv4Range   = "198.18.0.0/15"
	FakeIPv6Range   = "fc00::/18"
	coreRouteTable  = capture.CoreTable
)

// MinVersion is the oldest core release each renderer targets.
var MinVersion = map[string]string{config.EngineMihomo: "1.19.33", config.EngineSingBox: "1.13.21"}

var reservedTags = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "GLOBAL": true, "COMPATIBLE": true}

type planNode struct {
	node     config.Node
	tag      string
	upstream string
	secrets  map[string]string
}

type planGroup struct {
	group    config.Group
	tag      string
	members  []string
	selected string
}

type planRule struct {
	typ    string
	values []string
	target string
}

type plan struct {
	in        *Input
	nodes     []planNode
	nodeTag   map[string]string
	groups    []planGroup
	groupTag  map[string]string
	rules     []planRule
	final     string
	global    string
	rulesets  map[RulesetID]string
	needed    map[RulesetID]bool
	missing   map[RulesetID]bool
	warnings  []string
	directDNS []config.DNSServer
	proxyDNS  []config.DNSServer
	cnDNS     bool
	hasPkg    bool
}

// Render produces the configuration for in.Engine.
func Render(in Input) (*Output, error) {
	if in.Engine != config.EngineMihomo && in.Engine != config.EngineSingBox {
		return nil, fmt.Errorf("未知核心 %q", in.Engine)
	}
	if in.Version != "" && VersionLess(in.Version, MinVersion[in.Engine]) {
		return nil, fmt.Errorf("%s %s 过旧，至少需要 %s", in.Engine, in.Version, MinVersion[in.Engine])
	}
	if in.Runtime.TunName == "" || in.Runtime.ControllerPort == 0 || in.Runtime.ControllerSecret == "" || in.Runtime.MixedPort == 0 {
		return nil, errors.New("运行参数不完整")
	}
	cfg := config.Clone(in.Config)
	sec := config.Clone(in.Secrets)
	cfg.Normalize()
	sec.Normalize()
	if err := config.Validate(&cfg, &sec); err != nil {
		return nil, err
	}
	if in.Engine == config.EngineMihomo {
		for _, node := range cfg.Nodes {
			if why := unsupported(in.Engine, node); why != "" {
				return nil, fmt.Errorf("节点 %s 无法启动：%s", node.Name, why)
			}
		}
	}
	in.Config, in.Secrets = cfg, sec
	p := &plan{in: &in, nodeTag: map[string]string{}, groupTag: map[string]string{}, rulesets: map[RulesetID]string{}, needed: map[RulesetID]bool{}, missing: map[RulesetID]bool{}}
	p.buildNodes()
	p.buildGroups()
	if err := p.buildDNS(); err != nil {
		return nil, err
	}
	p.buildRules()
	out := &Output{Engine: in.Engine, TagOf: map[string]string{}, RefOf: map[string]string{}, Selected: map[string]string{}}
	var err error
	switch in.Engine {
	case config.EngineMihomo:
		out.FileName = "config.yaml"
		out.Content, err = renderMihomo(p)
		out.Env = append(out.Env, "SAFE_PATHS="+in.Runtime.RulesetDir)
		if cfg.Settings.IPv6 {
			out.Env = append(out.Env, "SKIP_SYSTEM_IPV6_CHECK=1")
		}
	case config.EngineSingBox:
		out.FileName = "config.json"
		out.Content, err = renderSingBox(p)
	}
	if err != nil {
		return nil, err
	}
	for id, tag := range p.nodeTag {
		out.TagOf[config.NodeRef(id)] = tag
		out.RefOf[tag] = config.NodeRef(id)
	}
	for id, tag := range p.groupTag {
		out.TagOf[config.GroupRef(id)] = tag
		out.RefOf[tag] = config.GroupRef(id)
	}
	out.TagOf[config.TargetDirect] = "DIRECT"
	out.RefOf["DIRECT"] = config.TargetDirect
	for _, g := range p.groups {
		if g.group.Type == "select" {
			out.Selected[g.tag] = g.selected
		}
	}
	for id := range p.needed {
		out.Needed = append(out.Needed, id)
	}
	for id := range p.missing {
		out.Missing = append(out.Missing, id)
	}
	sortIDs(out.Needed)
	sortIDs(out.Missing)
	out.Warnings = p.warnings
	return out, nil
}

func sortIDs(ids []RulesetID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].Tag() < ids[j].Tag() })
}

func (p *plan) warn(format string, args ...any) {
	if len(p.warnings) < 100 {
		p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
	}
}

func transportHeaders(transport *config.Transport) map[string]string {
	headers := map[string]string{}
	for _, key := range sortedKeys(transport.Headers) {
		name := textproto.CanonicalMIMEHeaderKey(key)
		// The explicit transport Host takes precedence over custom headers.
		if name == "Host" && transport.Host != "" {
			continue
		}
		headers[name] = transport.Headers[key]
	}
	return headers
}

// unsupported reports why a node cannot be rendered for the engine.
func unsupported(engine string, n config.Node) string {
	if engine == config.EngineSingBox && n.Transport != nil && n.Transport.Type == "xhttp" {
		return "sing-box 不支持 xhttp 传输"
	}
	if engine == config.EngineMihomo && n.Transport != nil {
		if n.Transport.Type == "xhttp" && n.Type != "vless" {
			return "Mihomo 的 xhttp 传输仅支持 VLESS"
		}
		if n.Type == "trojan" && n.Transport.Type == "http" {
			return "Mihomo 的 Trojan 不支持 HTTP/2 传输"
		}
	}
	return ""
}

func (p *plan) buildNodes() {
	cfg := &p.in.Config
	used := map[string]bool{}
	for k := range reservedTags {
		used[k] = true
	}
	for _, g := range cfg.Groups {
		used[strings.TrimSpace(g.Name)] = true
	}
	eligible := map[string]bool{}
	for _, n := range cfg.Nodes {
		if why := unsupported(p.in.Engine, n); why != "" {
			p.warn("节点 %s 已跳过：%s", n.Name, why)
			continue
		}
		eligible[n.ID] = true
		if p.in.Engine == config.EngineSingBox && (n.Type == "hysteria2" || n.Type == "tuic") &&
			n.TLS != nil && n.TLS.Fingerprint != "" {
			p.warn("节点 %s：QUIC 不支持 uTLS，已忽略 TLS 指纹", n.Name)
		}
	}
	// A node whose upstream chain is not renderable is skipped as well.
	changed := true
	for changed {
		changed = false
		for _, n := range cfg.Nodes {
			if eligible[n.ID] && n.Upstream != "" && !eligible[n.Upstream] {
				eligible[n.ID] = false
				changed = true
				p.warn("节点 %s 已跳过：前置节点不可用", n.Name)
			}
		}
	}
	for _, n := range cfg.Nodes {
		if !eligible[n.ID] {
			continue
		}
		tag := n.Name
		for i := 2; used[tag]; i++ {
			tag = fmt.Sprintf("%s (%d)", n.Name, i)
		}
		used[tag] = true
		p.nodeTag[n.ID] = tag
		p.nodes = append(p.nodes, planNode{node: n, tag: tag, secrets: p.in.Secrets.Nodes[n.ID]})
	}
	for i := range p.nodes {
		if up := p.nodes[i].node.Upstream; up != "" {
			p.nodes[i].upstream = p.nodeTag[up]
		}
	}
	for _, g := range cfg.Groups {
		p.groupTag[g.ID] = strings.TrimSpace(g.Name)
	}
}

func compileOptional(expr string) *regexp.Regexp {
	if expr == "" {
		return nil
	}
	return regexp.MustCompile(expr)
}

func (p *plan) buildGroups() {
	cfg := &p.in.Config
	nodes := make(map[string]*config.Node, len(cfg.Nodes))
	for i := range cfg.Nodes {
		nodes[cfg.Nodes[i].ID] = &cfg.Nodes[i]
	}
	for _, g := range cfg.Groups {
		inc, exc := compileOptional(g.Filter), compileOptional(g.ExcludeFilter)
		seen := map[string]bool{}
		var members []string
		addNode := func(id string) {
			tag, ok := p.nodeTag[id]
			if !ok || seen[tag] {
				return
			}
			n := nodes[id]
			if n == nil {
				return
			}
			if inc != nil && !inc.MatchString(n.Name) {
				return
			}
			if exc != nil && exc.MatchString(n.Name) {
				return
			}
			seen[tag] = true
			members = append(members, tag)
		}
		for _, gid := range g.Groups {
			if tag := p.groupTag[gid]; tag != "" && !seen[tag] {
				seen[tag] = true
				members = append(members, tag)
			}
		}
		for _, id := range g.Nodes {
			addNode(id)
		}
		if len(g.Subscriptions) > 0 {
			subs := map[string]bool{}
			for _, s := range g.Subscriptions {
				subs[s] = true
			}
			for _, n := range cfg.Nodes {
				if subs[n.SubscriptionID] {
					addNode(n.ID)
				}
			}
		}
		if g.IncludeAll {
			for _, n := range cfg.Nodes {
				addNode(n.ID)
			}
		}
		if g.Type == "select" && g.IncludeDirect && !seen["DIRECT"] {
			members = append(members, "DIRECT")
			seen["DIRECT"] = true
		}
		if len(members) == 0 {
			members = []string{"DIRECT"}
			p.warn("代理组 %s 没有可用成员，暂以直连代替", g.Name)
		}
		pg := planGroup{group: g, tag: p.groupTag[g.ID], members: members}
		if g.Type == "select" && g.Selected != "" {
			want := ""
			switch kind, id := config.ParseRef(g.Selected); kind {
			case config.TargetDirect:
				want = "DIRECT"
			case "node":
				want = p.nodeTag[id]
			case "group":
				want = p.groupTag[id]
			}
			for _, m := range members {
				if m == want {
					pg.selected = want
				}
			}
		}
		if pg.selected != "" {
			reordered := []string{pg.selected}
			for _, m := range members {
				if m != pg.selected {
					reordered = append(reordered, m)
				}
			}
			pg.members = reordered
		} else {
			pg.selected = pg.members[0]
		}
		p.groups = append(p.groups, pg)
	}
	p.final = p.in.Config.Routing.Final
	p.global = config.TargetDirect
	if kind, _ := config.ParseRef(p.final); kind == "group" {
		p.global = p.final
	} else {
		for _, g := range cfg.Groups {
			if g.Type == "select" {
				p.global = config.GroupRef(g.ID)
				break
			}
		}
	}
}

// targetTag maps a reference to an outbound tag; REJECT stays REJECT.
func (p *plan) targetTag(ref string) string {
	kind, id := config.ParseRef(ref)
	switch kind {
	case "group":
		return p.groupTag[id]
	case config.TargetReject:
		return "REJECT"
	}
	return "DIRECT"
}

// useRuleset records a rule set reference and reports whether it is usable.
func (p *plan) useRuleset(kind, name string) bool {
	id := RulesetID{Kind: kind, Name: name}
	p.needed[id] = true
	if path, ok := p.rulesets[id]; ok && path != "" {
		return true
	}
	if p.in.Rulesets != nil {
		if path, ok := p.in.Rulesets(id); ok {
			p.rulesets[id] = path
			return true
		}
	}
	if !p.missing[id] {
		p.missing[id] = true
		p.warn("规则集 %s 尚未下载，相关规则暂不生效", id.Tag())
	}
	return false
}

func (p *plan) buildDNS() error {
	d := p.in.Config.DNS
	for _, s := range d.Direct {
		srv, err := config.ParseDNSServer(s)
		if err != nil {
			return err
		}
		p.directDNS = append(p.directDNS, srv)
	}
	for _, s := range d.Proxy {
		srv, err := config.ParseDNSServer(s)
		if err != nil {
			return err
		}
		p.proxyDNS = append(p.proxyDNS, srv)
	}
	if p.in.Config.Routing.Preset == "cn" {
		p.cnDNS = p.useRuleset("geosite", "cn")
	}
	return nil
}

func (p *plan) buildRules() {
	r := p.in.Config.Routing
	for _, rule := range r.Rules {
		if !rule.Enabled {
			continue
		}
		vals := rule.Values
		if rule.Type == "geosite" || rule.Type == "geoip" {
			vals = nil
			for _, v := range rule.Values {
				if p.useRuleset(rule.Type, v) {
					vals = append(vals, v)
				}
			}
			if len(vals) == 0 {
				continue
			}
		}
		if rule.Type == "package" {
			p.hasPkg = true
		}
		p.rules = append(p.rules, planRule{typ: rule.Type, values: vals, target: rule.Target})
	}
	if r.BlockAds && p.useRuleset("geosite", "category-ads-all") {
		p.rules = append(p.rules, planRule{typ: "geosite", values: []string{"category-ads-all"}, target: config.TargetReject})
	}
	if r.BlockQUIC {
		p.rules = append(p.rules, planRule{typ: "quic", target: config.TargetReject})
	}
	if r.Preset == "cn" {
		if p.useRuleset("geosite", "cn") {
			p.rules = append(p.rules, planRule{typ: "geosite", values: []string{"cn"}, target: config.TargetDirect})
		}
		if p.useRuleset("geoip", "cn") {
			p.rules = append(p.rules, planRule{typ: "geoip", values: []string{"cn"}, target: config.TargetDirect})
		}
	}
}

// fakeIPRegexes converts the fake-ip filter into sing-box domain_regex values.
func (p *plan) fakeIPRegexes() []string {
	var out []string
	for _, f := range p.in.Config.DNS.FakeIPFilter {
		out = append(out, config.FakeIPPatternRegex(f))
	}
	return out
}

// Members expands every group's members into references ("node:id",
// "group:id", "DIRECT") and reports each group's effective selection.
func Members(cfg config.Config, sec config.Secrets, engine string) (members map[string][]string, selected map[string]string) {
	cfg = config.Clone(cfg)
	sec = config.Clone(sec)
	cfg.Normalize()
	sec.Normalize()
	p := &plan{in: &Input{Config: cfg, Secrets: sec, Engine: engine}, nodeTag: map[string]string{}, groupTag: map[string]string{},
		rulesets: map[RulesetID]string{}, needed: map[RulesetID]bool{}, missing: map[RulesetID]bool{}}
	p.buildNodes()
	p.buildGroups()
	refOf := map[string]string{"DIRECT": config.TargetDirect}
	for id, tag := range p.nodeTag {
		refOf[tag] = config.NodeRef(id)
	}
	for id, tag := range p.groupTag {
		refOf[tag] = config.GroupRef(id)
	}
	members, selected = map[string][]string{}, map[string]string{}
	for _, g := range p.groups {
		refs := make([]string, 0, len(g.members))
		for _, m := range g.members {
			refs = append(refs, refOf[m])
		}
		members[g.group.ID] = refs
		selected[g.group.ID] = refOf[g.selected]
	}
	return members, selected
}

// VersionLess compares dotted versions numerically ("v1.19.3" < "1.19.10").
func VersionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionParts(s string) [3]int {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	for i := 0; i < len(parts) && i < 3; i++ {
		digits := parts[i]
		for j, r := range digits {
			if r < '0' || r > '9' {
				digits = digits[:j]
				break
			}
		}
		out[i], _ = strconv.Atoi(digits)
	}
	return out
}

// PrivateCIDRs are always routed directly inside the core.
var PrivateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
	"100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32",
	"fc00::/7", "fe80::/10", "ff00::/8", "::1/128",
}
