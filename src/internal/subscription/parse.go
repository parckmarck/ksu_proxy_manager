// Package subscription parses share links, Clash/Mihomo YAML and sing-box JSON
// into configuration nodes, and computes differences between node sets.
package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"ksu_proxy_manager/internal/config"
)

// MaxSize bounds subscription bodies and pasted imports.
const MaxSize = 8 << 20

// MaxNodes bounds the number of nodes accepted from one source.
const MaxNodes = 3000

// maxIssues bounds the problems reported for one source.
const maxIssues = 200

type Parsed struct {
	Node    config.Node       `json:"node"`
	Secrets map[string]string `json:"-"`

	// key is the node's own name in the source document and via the name of
	// the outbound it dials through (Clash dialer-proxy, sing-box detour).
	// LinkUpstreams turns them into Node.Upstream once IDs are final.
	key, via string
}

type Issue struct {
	Name    string `json:"name,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	Format string   `json:"format"`
	Nodes  []Parsed `json:"nodes"`
	Issues []Issue  `json:"issues"`
}

func (r *Result) issue(name, format string, args ...any) {
	if len(r.Issues) < maxIssues {
		r.Issues = append(r.Issues, Issue{Name: name, Message: fmt.Sprintf(format, args...)})
	}
}

// add validates a parsed node and appends it, recording an issue on failure.
func (r *Result) add(p Parsed) {
	if len(r.Nodes) >= MaxNodes {
		r.issue(p.Node.Name, "节点数量超过上限 %d，已忽略其余节点", MaxNodes)
		return
	}
	p.Node.Name = cleanName(p.Node.Name, p.Node.Server, p.Node.Port)
	p.Node.Normalize()
	if p.Node.ID == "" {
		p.Node.ID = "pending"
	}
	if err := config.ValidateNode(&p.Node, "node"); err != nil {
		r.issue(p.Node.Name, "%v", err)
		return
	}
	for _, f := range config.RequiredSecrets(p.Node) {
		if p.Secrets[f] == "" {
			r.issue(p.Node.Name, "缺少必填凭据 %s", f)
			return
		}
	}
	for k, v := range p.Secrets {
		if v == "" {
			delete(p.Secrets, k)
		}
	}
	r.Nodes = append(r.Nodes, p)
}

var spaceRE = regexp.MustCompile(`[\s\x00-\x1f\x7f]+`)

func cleanName(name, server string, port int) string {
	name = strings.TrimSpace(spaceRE.ReplaceAllString(name, " "))
	if !utf8.ValidString(name) {
		name = strings.ToValidUTF8(name, "")
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}
	if r := []rune(name); len(r) > 128 {
		name = string(r[:128])
	}
	return name
}

// Parse detects the format of data and extracts nodes.
func Parse(data []byte) Result {
	if len(data) > MaxSize {
		return Result{Format: "invalid", Issues: []Issue{{Message: "内容超过 8 MiB 上限"}}}
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	text := strings.TrimSpace(string(data))
	if text == "" {
		return Result{Format: "empty", Issues: []Issue{{Message: "内容为空"}}}
	}
	if strings.HasPrefix(text, "{") {
		var probe map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &probe) == nil {
			if _, ok := probe["outbounds"]; ok {
				return parseSingBox([]byte(text))
			}
			if _, ok := probe["endpoints"]; ok {
				return parseSingBox([]byte(text))
			}
		}
	}
	if looksLikeClash(text) {
		return parseClash([]byte(text))
	}
	if !strings.Contains(text, "://") {
		if decoded, ok := decodeBase64Text(text); ok {
			// Clash documents routinely contain URLs (providers, external-ui),
			// so the structural check must come first.
			if looksLikeClash(decoded) {
				return parseClash([]byte(decoded))
			}
			if strings.Contains(decoded, "://") {
				r := parseLinks(decoded)
				r.Format = "base64"
				return r
			}
		}
		return Result{Format: "unknown", Issues: []Issue{{Message: "无法识别订阅格式（支持分享链接、Base64、Clash YAML、sing-box JSON）"}}}
	}
	return parseLinks(text)
}

func parseLinks(text string) Result {
	r := Result{Format: "links"}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		p, err := ParseLink(line)
		if err != nil {
			name := line
			if i := strings.Index(name, "://"); i > 0 {
				name = name[:i] + "://…"
			}
			r.issue(name, "%v", err)
			continue
		}
		r.add(p)
	}
	if len(r.Nodes) == 0 && len(r.Issues) == 0 {
		r.issue("", "未找到任何节点")
	}
	return r
}

var clashKeyRE = regexp.MustCompile(`(?m)^(proxies|proxy-providers|proxy-groups|Proxy)\s*:`)

func looksLikeClash(s string) bool { return clashKeyRE.MatchString(s) }

// decodeBase64Text tolerates standard/URL alphabets, missing padding and line breaks.
func decodeBase64Text(s string) (string, bool) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && utf8.Valid(b) {
			return string(b), true
		}
	}
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil && utf8.Valid(b) {
			return string(b), true
		}
	}
	return "", false
}

// NodeIDFor derives a stable node ID for a subscription node name.
func NodeIDFor(subID, name string) string {
	return config.SubscriptionNodeID(subID, name)
}

// ApplyFilters keeps nodes matching include and not matching exclude.
func ApplyFilters(nodes []Parsed, include, exclude string) ([]Parsed, error) {
	var inc, exc *regexp.Regexp
	var err error
	if include != "" {
		if inc, err = regexp.Compile(include); err != nil {
			return nil, err
		}
	}
	if exclude != "" {
		if exc, err = regexp.Compile(exclude); err != nil {
			return nil, err
		}
	}
	out := make([]Parsed, 0, len(nodes))
	for _, p := range nodes {
		if inc != nil && !inc.MatchString(p.Node.Name) {
			continue
		}
		if exc != nil && exc.MatchString(p.Node.Name) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// AssignSubscriptionIDs makes names unique within the set and assigns IDs.
func AssignSubscriptionIDs(subID string, nodes []Parsed) {
	model := make([]config.Node, len(nodes))
	for index := range nodes {
		model[index] = nodes[index].Node
	}
	config.AssignSubscriptionIDs(subID, model)
	for index := range nodes {
		nodes[index].Node = model[index]
	}
}
