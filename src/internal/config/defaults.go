package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// DefaultHotspotInterfaces are name patterns of common Android tethering interfaces.
var DefaultHotspotInterfaces = []string{"ap*", "swlan*", "softap*", "wlan1", "wlan2", "rndis*", "ncm*", "usb*", "bt-pan"}

// DefaultFakeIPFilter lists domains that must resolve to real addresses.
var DefaultFakeIPFilter = []string{
	"*.lan", "*.local", "*.localdomain", "*.home.arpa", "localhost",
	"+.msftconnecttest.com", "+.msftncsi.com",
	"time.*.com", "time.*.gov", "time.*.edu.cn", "time.*.apple.com", "ntp.*.com",
	"+.pool.ntp.org", "+.ntp.org.cn", "+.time.edu.cn",
	"stun.*.*", "stun.*.*.*", "+.stun.*.*", "+.stun.*.*.*",
	"+.srv.nintendo.net", "+.stun.playstation.net", "xbox.*.microsoft.com", "+.xboxlive.com",
	"+.market.xiaomi.com", "+.push.apple.com", "+.mtalk.google.com",
}

func Default() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Revision:      0,
		Settings: Settings{
			Engine:            EngineMihomo,
			CoreVersions:      map[string]string{},
			AutoStart:         true,
			AutoRestart:       true,
			FailClosed:        false,
			IPv6:              false,
			BypassLAN:         false,
			BypassCIDRs:       []string{},
			LogLevel:          "warn",
			TunStack:          "",
			MTU:               9000,
			Hotspot:           Hotspot{Enabled: false, Interfaces: append([]string(nil), DefaultHotspotInterfaces...)},
			WebAccess:         WebAccess{Enabled: false, Port: 9097},
			Download:          Download{Mode: "auto"},
			RulesetAutoUpdate: true,
		},
		Nodes: []Node{},
		Groups: []Group{
			{ID: "proxy", Name: "节点选择", Type: "select", Nodes: []string{}, Groups: []string{"auto"}, Subscriptions: []string{}, IncludeAll: true, IncludeDirect: true},
			{ID: "auto", Name: "自动选择", Type: "urltest", Nodes: []string{}, Groups: []string{}, Subscriptions: []string{}, IncludeAll: true},
		},
		Subscriptions: []Subscription{},
		Routing: Routing{
			Mode:   "rule",
			Preset: "cn",
			Rules:  []Rule{},
			Final:  GroupRef("proxy"),
		},
		DNS: DNS{
			Mode:         "fakeip",
			Direct:       []string{"223.5.5.5", "119.29.29.29"},
			Proxy:        []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
			FakeIPFilter: append([]string(nil), DefaultFakeIPFilter...),
		},
		Apps: AppPolicy{Mode: "all", Packages: []string{}, Users: []int{0}},
	}
}

func DefaultSecrets() Secrets {
	return Secrets{Nodes: map[string]map[string]string{}, Subscriptions: map[string]string{}}
}

func SubscriptionNodeID(subscriptionID, name string) string {
	sum := sha256.Sum256([]byte(subscriptionID + "\x00" + name))
	return "n" + hex.EncodeToString(sum[:8])
}

func AssignSubscriptionIDs(subscriptionID string, nodes []Node) {
	used := map[string]bool{}
	for index := range nodes {
		base := nodes[index].Name
		name := base
		for counter := 2; used[name]; counter++ {
			name = fmt.Sprintf("%s (%d)", base, counter)
			if runes := []rune(name); len(runes) > 128 {
				name = string(runes[len(runes)-128:])
			}
		}
		used[name] = true
		nodes[index].Name = name
		nodes[index].ID = SubscriptionNodeID(subscriptionID, name)
		nodes[index].SubscriptionID = subscriptionID
		nodes[index].Upstream = ""
	}
}

// Normalize fills fields that older or hand-written documents may omit and
// canonicalises ordering. It never invents values for explicitly empty lists.
func (c *Config) Normalize() {
	d := Default()
	if c.SchemaVersion == 0 {
		c.SchemaVersion = SchemaVersion
	}
	s := &c.Settings
	if s.Engine == "" {
		s.Engine = d.Settings.Engine
	}
	if s.CoreVersions == nil {
		s.CoreVersions = map[string]string{}
	}
	if s.BypassCIDRs == nil {
		s.BypassCIDRs = []string{}
	}
	cidrs := make([]string, 0, len(s.BypassCIDRs))
	for _, c := range s.BypassCIDRs {
		if c = strings.TrimSpace(c); c != "" {
			cidrs = append(cidrs, c)
		}
	}
	s.BypassCIDRs = cidrs
	if s.LogLevel == "" {
		s.LogLevel = d.Settings.LogLevel
	}
	if s.MTU == 0 {
		s.MTU = d.Settings.MTU
	}
	if s.Hotspot.Interfaces == nil {
		s.Hotspot.Interfaces = append([]string(nil), DefaultHotspotInterfaces...)
	}
	if s.WebAccess.Port == 0 {
		s.WebAccess.Port = d.Settings.WebAccess.Port
	}
	if s.Download.Mode == "" {
		s.Download.Mode = "auto"
	}
	if c.Nodes == nil {
		c.Nodes = []Node{}
	}
	for i := range c.Nodes {
		c.Nodes[i].Normalize()
	}
	if c.Groups == nil {
		c.Groups = []Group{}
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		if g.Nodes == nil {
			g.Nodes = []string{}
		}
		if g.Groups == nil {
			g.Groups = []string{}
		}
		if g.Subscriptions == nil {
			g.Subscriptions = []string{}
		}
		if g.Type == "urltest" {
			g.IncludeDirect = false
			g.Selected = ""
		}
	}
	if c.Subscriptions == nil {
		c.Subscriptions = []Subscription{}
	}
	if c.Routing.Mode == "" {
		c.Routing.Mode = "rule"
	}
	if c.Routing.Preset == "" {
		c.Routing.Preset = "cn"
	}
	if c.Routing.Rules == nil {
		c.Routing.Rules = []Rule{}
	}
	if c.Routing.Final == "" {
		c.Routing.Final = TargetDirect
	}
	for i := range c.Routing.Rules {
		r := &c.Routing.Rules[i]
		vals := make([]string, 0, len(r.Values))
		for _, v := range r.Values {
			if v = strings.TrimSpace(v); v != "" {
				vals = append(vals, v)
			}
		}
		r.Values = vals
	}
	if c.DNS.Mode == "" {
		c.DNS.Mode = d.DNS.Mode
	}
	if c.DNS.Direct == nil {
		c.DNS.Direct = d.DNS.Direct
	}
	if c.DNS.Proxy == nil {
		c.DNS.Proxy = d.DNS.Proxy
	}
	if c.DNS.FakeIPFilter == nil {
		c.DNS.FakeIPFilter = d.DNS.FakeIPFilter
	}
	if c.Apps.Mode == "" {
		c.Apps.Mode = "all"
	}
	if c.Apps.Packages == nil {
		c.Apps.Packages = []string{}
	}
	pk := map[string]bool{}
	pkgs := make([]string, 0, len(c.Apps.Packages))
	for _, p := range c.Apps.Packages {
		p = strings.TrimSpace(p)
		if p != "" && !pk[p] {
			pk[p] = true
			pkgs = append(pkgs, p)
		}
	}
	sort.Strings(pkgs)
	c.Apps.Packages = pkgs
	if len(c.Apps.Users) == 0 {
		c.Apps.Users = []int{0}
	}
	users := map[int]bool{}
	us := make([]int, 0, len(c.Apps.Users))
	for _, u := range c.Apps.Users {
		if !users[u] {
			users[u] = true
			us = append(us, u)
		}
	}
	sort.Ints(us)
	c.Apps.Users = us
}

// Normalize trims whitespace and drops empty optional blocks of a node.
func (n *Node) Normalize() {
	n.Name = strings.TrimSpace(n.Name)
	n.Server = strings.Trim(strings.TrimSpace(n.Server), "[]")
	if t := n.Transport; t != nil {
		if t.Type == "" {
			t.Type = "tcp"
		}
		if t.Type == "tcp" && t.Path == "" && t.Host == "" && t.ServiceName == "" && len(t.Headers) == 0 {
			n.Transport = nil
		}
	}
	if t := n.TLS; t != nil && !t.Enabled && t.SNI == "" && len(t.ALPN) == 0 && !t.Insecure && t.Fingerprint == "" && t.RealityPublicKey == "" {
		n.TLS = nil
	}
	if len(n.PluginOpts) == 0 {
		n.PluginOpts = nil
	}
}

func (s *Secrets) Normalize() {
	if s.Nodes == nil {
		s.Nodes = map[string]map[string]string{}
	}
	if s.Subscriptions == nil {
		s.Subscriptions = map[string]string{}
	}
	for id, m := range s.Nodes {
		for k, v := range m {
			if v == "" {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(s.Nodes, id)
		}
	}
}

// NodeSecret returns a credential field for a node.
func (s Secrets) NodeSecret(nodeID, field string) string { return s.Nodes[nodeID][field] }

// SetNodeSecrets replaces the stored fields listed in values; empty values delete.
func (s *Secrets) SetNodeSecrets(nodeID string, values map[string]string) {
	if s.Nodes == nil {
		s.Nodes = map[string]map[string]string{}
	}
	m := s.Nodes[nodeID]
	if m == nil {
		m = map[string]string{}
	}
	for k, v := range values {
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	if len(m) == 0 {
		delete(s.Nodes, nodeID)
	} else {
		s.Nodes[nodeID] = m
	}
}

// Clone deep-copies a value through JSON; all model types are JSON-safe.
func Clone[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}
