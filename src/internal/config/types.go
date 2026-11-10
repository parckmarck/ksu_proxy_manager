// Package config defines the persisted configuration model (schema 3).
package config

const SchemaVersion = 3

// Engines supported by the renderer.
const (
	EngineMihomo  = "mihomo"
	EngineSingBox = "sing-box"
)

// Target and member references.
const (
	TargetDirect = "DIRECT"
	TargetReject = "REJECT"
	refGroup     = "group:"
	refNode      = "node:"
)

type Config struct {
	SchemaVersion int            `json:"schemaVersion"`
	Revision      int64          `json:"revision"`
	Settings      Settings       `json:"settings"`
	Nodes         []Node         `json:"nodes"`
	Groups        []Group        `json:"groups"`
	Subscriptions []Subscription `json:"subscriptions"`
	Routing       Routing        `json:"routing"`
	DNS           DNS            `json:"dns"`
	Apps          AppPolicy      `json:"apps"`
}

// Secrets never leave the daemon through the API.
type Secrets struct {
	Nodes         map[string]map[string]string `json:"nodes"`
	Subscriptions map[string]string            `json:"subscriptions"`
	WebAccessKey  string                       `json:"webAccessKey,omitempty"`
}

// Document is the on-disk representation.
type Document struct {
	Config
	Secrets Secrets `json:"secrets"`
}

type Settings struct {
	Engine            string            `json:"engine"`
	CoreVersions      map[string]string `json:"coreVersions"`
	AutoStart         bool              `json:"autoStart"`
	AutoRestart       bool              `json:"autoRestart"`
	FailClosed        bool              `json:"failClosed"`
	IPv6              bool              `json:"ipv6"`
	BypassLAN         bool              `json:"bypassLan"`
	BypassCIDRs       []string          `json:"bypassCidrs"`
	LogLevel          string            `json:"logLevel"`
	TunStack          string            `json:"tunStack"`
	MTU               int               `json:"mtu"`
	Hotspot           Hotspot           `json:"hotspot"`
	WebAccess         WebAccess         `json:"webAccess"`
	Download          Download          `json:"download"`
	RulesetAutoUpdate bool              `json:"rulesetAutoUpdate"`
}

type Hotspot struct {
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
}

type WebAccess struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

type Download struct {
	Mode         string `json:"mode"`
	GitHubMirror string `json:"githubMirror"`
}

type Node struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
	UDP            bool   `json:"udp"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	Upstream       string `json:"upstream,omitempty"`

	Cipher     string            `json:"cipher,omitempty"`
	Plugin     string            `json:"plugin,omitempty"`
	PluginOpts map[string]string `json:"pluginOpts,omitempty"`

	AlterID  int    `json:"alterId,omitempty"`
	Security string `json:"security,omitempty"`
	Flow     string `json:"flow,omitempty"`

	UpMbps   int    `json:"upMbps,omitempty"`
	DownMbps int    `json:"downMbps,omitempty"`
	Obfs     string `json:"obfs,omitempty"`
	Ports    string `json:"ports,omitempty"`

	CongestionControl string `json:"congestionControl,omitempty"`
	UDPRelayMode      string `json:"udpRelayMode,omitempty"`

	LocalAddress  []string `json:"localAddress,omitempty"`
	PeerPublicKey string   `json:"peerPublicKey,omitempty"`
	Reserved      []int    `json:"reserved,omitempty"`
	WGMTU         int      `json:"wgMtu,omitempty"`

	Transport *Transport `json:"transport,omitempty"`
	TLS       *TLS       `json:"tls,omitempty"`
}

type Transport struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"serviceName,omitempty"`
}

type TLS struct {
	Enabled          bool     `json:"enabled"`
	SNI              string   `json:"sni,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	Insecure         bool     `json:"insecure,omitempty"`
	Fingerprint      string   `json:"fingerprint,omitempty"`
	RealityPublicKey string   `json:"realityPublicKey,omitempty"`
	RealityShortID   string   `json:"realityShortId,omitempty"`
}

type Group struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Nodes         []string `json:"nodes"`
	Groups        []string `json:"groups"`
	Subscriptions []string `json:"subscriptions"`
	IncludeAll    bool     `json:"includeAll"`
	Filter        string   `json:"filter,omitempty"`
	ExcludeFilter string   `json:"excludeFilter,omitempty"`
	IncludeDirect bool     `json:"includeDirect"`
	Selected      string   `json:"selected,omitempty"`
	TestURL       string   `json:"testUrl,omitempty"`
	IntervalSec   int      `json:"intervalSec,omitempty"`
	ToleranceMs   int      `json:"toleranceMs,omitempty"`
}

type Usage struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

type Subscription struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	UserAgent       string `json:"userAgent,omitempty"`
	ViaProxy        bool   `json:"viaProxy"`
	AutoUpdateHours int    `json:"autoUpdateHours"`
	Filter          string `json:"filter,omitempty"`
	ExcludeFilter   string `json:"excludeFilter,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
	LastError       string `json:"lastError,omitempty"`
	Usage           *Usage `json:"usage,omitempty"`
}

type Routing struct {
	Mode      string `json:"mode"`
	Preset    string `json:"preset"`
	BlockAds  bool   `json:"blockAds"`
	BlockQUIC bool   `json:"blockQuic"`
	Rules     []Rule `json:"rules"`
	Final     string `json:"final"`
}

type Rule struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Type    string   `json:"type"`
	Values  []string `json:"values"`
	Target  string   `json:"target"`
	Note    string   `json:"note,omitempty"`
}

type DNS struct {
	Mode         string   `json:"mode"`
	Direct       []string `json:"direct"`
	Proxy        []string `json:"proxy"`
	FakeIPFilter []string `json:"fakeipFilter"`
}

type AppPolicy struct {
	Mode     string   `json:"mode"`
	Packages []string `json:"packages"`
	Users    []int    `json:"users"`

	// Routes pins individual apps to a target. It is omitted while empty so
	// that documents without per-app targets keep their previous shape.
	Routes []AppRoute `json:"routes,omitempty"`
}

// AppRoute sends every connection of one app to a fixed target (a proxy
// group, DIRECT or REJECT), ahead of the custom routing rules.
type AppRoute struct {
	Package string `json:"package"`
	Target  string `json:"target"`
}

// SameRoutes reports whether both policies pin the same apps to the same
// targets. Both sides are expected to be normalized.
func (a AppPolicy) SameRoutes(b AppPolicy) bool {
	if len(a.Routes) != len(b.Routes) {
		return false
	}
	for i := range a.Routes {
		if a.Routes[i] != b.Routes[i] {
			return false
		}
	}
	return true
}

// GroupRef / NodeRef build member references used by Selected and targets.
func GroupRef(id string) string { return refGroup + id }
func NodeRef(id string) string  { return refNode + id }

// ParseRef splits "group:x" / "node:x"; DIRECT and REJECT are returned as kind.
func ParseRef(ref string) (kind, id string) {
	switch {
	case ref == TargetDirect || ref == TargetReject:
		return ref, ""
	case len(ref) > len(refGroup) && ref[:len(refGroup)] == refGroup:
		return "group", ref[len(refGroup):]
	case len(ref) > len(refNode) && ref[:len(refNode)] == refNode:
		return "node", ref[len(refNode):]
	}
	return "", ""
}

func (c *Config) NodeByID(id string) *Node {
	for i := range c.Nodes {
		if c.Nodes[i].ID == id {
			return &c.Nodes[i]
		}
	}
	return nil
}

func (c *Config) GroupByID(id string) *Group {
	for i := range c.Groups {
		if c.Groups[i].ID == id {
			return &c.Groups[i]
		}
	}
	return nil
}

func (c *Config) SubscriptionByID(id string) *Subscription {
	for i := range c.Subscriptions {
		if c.Subscriptions[i].ID == id {
			return &c.Subscriptions[i]
		}
	}
	return nil
}

// SecretFields lists credential fields stored in Secrets for each node type.
var SecretFields = map[string][]string{
	"shadowsocks": {"password"},
	"vmess":       {"uuid"},
	"vless":       {"uuid"},
	"trojan":      {"password"},
	"hysteria2":   {"password", "obfsPassword"},
	"tuic":        {"uuid", "password"},
	"anytls":      {"password"},
	"socks":       {"username", "password"},
	"http":        {"username", "password"},
	"wireguard":   {"privateKey", "preSharedKey"},
}

// RequiredSecrets lists fields that must be non-empty for the node type.
func RequiredSecrets(n Node) []string {
	switch n.Type {
	case "shadowsocks", "trojan", "anytls":
		return []string{"password"}
	case "vmess", "vless":
		return []string{"uuid"}
	case "hysteria2":
		if n.Obfs != "" {
			return []string{"password", "obfsPassword"}
		}
		return []string{"password"}
	case "tuic":
		return []string{"uuid", "password"}
	case "wireguard":
		return []string{"privateKey"}
	}
	return nil
}
