package subscription

import (
	"fmt"
	"strings"
	"testing"

	"ksu_proxy_manager/internal/config"
)

// clashProxy renders one Clash proxy, optionally dialing through via.
func clashProxy(name, via string) string {
	s := fmt.Sprintf("  - {name: %s, type: trojan, server: %s.example.com, port: 443, password: pw", name, name)
	if via != "" {
		s += ", dialer-proxy: " + via
	}
	return s + "}"
}

func clashDoc(proxies ...string) []byte {
	return []byte("proxies:\n" + strings.Join(proxies, "\n") + "\n")
}

func byName(t *testing.T, nodes []Parsed, name string) Parsed {
	t.Helper()
	for _, p := range nodes {
		if p.Node.Name == name {
			return p
		}
	}
	t.Fatalf("node %s missing", name)
	return Parsed{}
}

func issuesByName(issues []Issue) map[string]string {
	m := map[string]string{}
	for _, is := range issues {
		m[is.Name] = is.Message
	}
	return m
}

func TestClashDialerProxyBecomesUpstream(t *testing.T) {
	doc := clashDoc(
		clashProxy("relay", ""),
		clashProxy("exit", "relay"),
		clashProxy("viagroup", "中转"),
		clashProxy("missing", "nowhere"),
		clashProxy("loopa", "loopb"),
		clashProxy("loopb", "loopa"),
		clashProxy("self", "self"),
	)
	doc = append(doc, "proxy-groups:\n  - {name: 中转, type: select, proxies: [relay]}\n"...)
	r := Parse(doc)
	if r.Format != "clash" || len(r.Nodes) != 2 || len(r.Issues) != 5 {
		t.Fatalf("parse: %+v", r)
	}
	why := issuesByName(r.Issues)
	for name, want := range map[string]string{"viagroup": "代理组", "missing": "nowhere", "loopa": "环路", "loopb": "环路", "self": "环路"} {
		if !strings.Contains(why[name], want) {
			t.Errorf("%s: issue %q does not mention %q", name, why[name], want)
		}
	}
	// Nothing is linked before the final IDs exist.
	for _, p := range r.Nodes {
		if p.Node.Upstream != "" {
			t.Fatalf("%s linked while parsing: %+v", p.Node.Name, p.Node)
		}
	}
	AssignSubscriptionIDs("s1", r.Nodes)
	nodes, issues := LinkUpstreams(r.Nodes)
	if len(nodes) != 2 || len(issues) != 0 {
		t.Fatalf("link: %d nodes, issues %+v", len(nodes), issues)
	}
	relay, exit := byName(t, nodes, "relay"), byName(t, nodes, "exit")
	if relay.Node.Upstream != "" || exit.Node.Upstream != relay.Node.ID || relay.Node.ID != NodeIDFor("s1", "relay") {
		t.Fatalf("upstreams: relay %+v exit %+v", relay.Node, exit.Node)
	}
}

func TestChainDepthLimit(t *testing.T) {
	proxies := []string{clashProxy("n0", "")}
	for i := 1; i <= 5; i++ {
		proxies = append(proxies, clashProxy(fmt.Sprintf("n%d", i), fmt.Sprintf("n%d", i-1)))
	}
	r := Parse(clashDoc(proxies...))
	if len(r.Nodes) != 4 || len(r.Issues) != 2 {
		t.Fatalf("parse: %d nodes, issues %+v", len(r.Nodes), r.Issues)
	}
	why := issuesByName(r.Issues)
	for _, name := range []string{"n4", "n5"} {
		if !strings.Contains(why[name], "3 层") {
			t.Errorf("%s: issue %q does not mention the depth limit", name, why[name])
		}
	}
	AssignSubscriptionIDs("s1", r.Nodes)
	nodes, issues := LinkUpstreams(r.Nodes)
	if len(nodes) != 4 || len(issues) != 0 {
		t.Fatalf("link: %d nodes, issues %+v", len(nodes), issues)
	}
	for i := 1; i <= 3; i++ {
		if got := byName(t, nodes, fmt.Sprintf("n%d", i)).Node.Upstream; got != NodeIDFor("s1", fmt.Sprintf("n%d", i-1)) {
			t.Fatalf("n%d upstream = %q", i, got)
		}
	}
}

func TestAmbiguousUpstreamNameIsRejected(t *testing.T) {
	r := Parse(clashDoc(clashProxy("relay", ""), clashProxy("relay", ""), clashProxy("exit", "relay")))
	if len(r.Nodes) != 2 || len(r.Issues) != 1 || r.Issues[0].Name != "exit" || !strings.Contains(r.Issues[0].Message, "重复") {
		t.Fatalf("parse: %d nodes, issues %+v", len(r.Nodes), r.Issues)
	}
}

func TestFilteredUpstreamDropsChainedNode(t *testing.T) {
	r := Parse(clashDoc(clashProxy("relay", ""), clashProxy("exit", "relay"), clashProxy("plain", "")))
	if len(r.Nodes) != 3 || len(r.Issues) != 0 {
		t.Fatalf("parse: %+v", r)
	}
	nodes, err := ApplyFilters(r.Nodes, "", "^relay$")
	if err != nil || len(nodes) != 2 {
		t.Fatalf("filters: %d %v", len(nodes), err)
	}
	AssignSubscriptionIDs("s1", nodes)
	nodes, issues := LinkUpstreams(nodes)
	if len(nodes) != 1 || nodes[0].Node.Name != "plain" || nodes[0].Node.Upstream != "" {
		t.Fatalf("link: %+v", nodes)
	}
	if len(issues) != 1 || issues[0].Name != "exit" || !strings.Contains(issues[0].Message, "relay") {
		t.Fatalf("issues: %+v", issues)
	}
}

func TestSingBoxDetourBecomesUpstream(t *testing.T) {
	ss := func(tag, detour string) string {
		s := `{"type":"shadowsocks","tag":"` + tag + `","server":"1.2.3.4","server_port":8388,"method":"aes-128-gcm","password":"pw"`
		if detour != "" {
			s += `,"detour":"` + detour + `"`
		}
		return s + "}"
	}
	// exit refers to an outbound that is listed after it.
	doc := `{"outbounds":[` + strings.Join([]string{
		ss("exit", "relay"),
		ss("relay", ""),
		ss("viasel", "sel"),
		ss("viadirect", "direct"),
		`{"type":"selector","tag":"sel","outbounds":["relay"]}`,
		`{"type":"direct","tag":"direct"}`,
	}, ",") + `]}`
	r := Parse([]byte(doc))
	if r.Format != "sing-box" || len(r.Nodes) != 2 || len(r.Issues) != 2 {
		t.Fatalf("parse: %+v", r)
	}
	why := issuesByName(r.Issues)
	if !strings.Contains(why["viasel"], "代理组") || !strings.Contains(why["viadirect"], "direct") {
		t.Fatalf("issues: %+v", r.Issues)
	}
	AssignSubscriptionIDs("s1", r.Nodes)
	nodes, issues := LinkUpstreams(r.Nodes)
	if len(nodes) != 2 || len(issues) != 0 {
		t.Fatalf("link: %d nodes, issues %+v", len(nodes), issues)
	}
	relay, exit := byName(t, nodes, "relay"), byName(t, nodes, "exit")
	if relay.Node.Upstream != "" || exit.Node.Upstream != relay.Node.ID {
		t.Fatalf("upstreams: relay %+v exit %+v", relay.Node, exit.Node)
	}
}

func TestCompareReportsSubscriptionChain(t *testing.T) {
	r := Parse(clashDoc(clashProxy("relay", ""), clashProxy("exit", "relay")))
	AssignSubscriptionIDs("s1", r.Nodes)
	next, _ := LinkUpstreams(r.Nodes)
	relay, exit := byName(t, next, "relay"), byName(t, next, "exit")
	sec := config.DefaultSecrets()
	sec.SetNodeSecrets(relay.Node.ID, relay.Secrets)
	sec.SetNodeSecrets(exit.Node.ID, exit.Secrets)

	// The stored node has no chain yet: the subscription's chain is a change.
	stored := exit.Node
	stored.Upstream = ""
	d := Compare([]config.Node{relay.Node, stored}, sec, next)
	if len(d.Changed) != 1 || d.Changed[0] != "exit" || d.Unchanged != 1 {
		t.Fatalf("new chain: %+v", d)
	}
	// The same chain again is not.
	d = Compare([]config.Node{relay.Node, exit.Node}, sec, next)
	if len(d.Changed) != 0 || d.Unchanged != 2 {
		t.Fatalf("same chain: %+v", d)
	}
	// A chain the user added to a node the subscription leaves alone is kept,
	// so it is not reported either.
	chosen := relay.Node
	chosen.Upstream = "m1"
	d = Compare([]config.Node{chosen, exit.Node}, sec, next)
	if len(d.Changed) != 0 || d.Unchanged != 2 {
		t.Fatalf("user chain: %+v", d)
	}
}

func TestLinkUpstreamsLeavesPlainNodesAlone(t *testing.T) {
	r := Parse([]byte("trojan://pw@a.example.com:443#A\ntrojan://pw@b.example.com:443#B\n"))
	AssignSubscriptionIDs("s1", r.Nodes)
	nodes, issues := LinkUpstreams(r.Nodes)
	if len(nodes) != 2 || len(issues) != 0 || nodes[0].Node.Upstream != "" || nodes[1].Node.Upstream != "" {
		t.Fatalf("link: %+v %+v", nodes, issues)
	}
}
