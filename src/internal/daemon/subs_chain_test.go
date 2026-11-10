package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ksu_proxy_manager/internal/config"
)

// chainClash renders a Clash document from {name, dialer-proxy} pairs.
func chainClash(proxies ...[2]string) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, p := range proxies {
		fmt.Fprintf(&b, "  - {name: %s, type: trojan, server: %s.example.com, port: 443, password: pw", p[0], p[0])
		if p[1] != "" {
			fmt.Fprintf(&b, ", dialer-proxy: %s", p[1])
		}
		b.WriteString("}\n")
	}
	return b.String()
}

func TestSubscriptionChainsBecomeUpstreams(t *testing.T) {
	e := newEnv(t, false, nil)
	var mu sync.Mutex
	// deep2 uses all three layers the configuration allows.
	body := chainClash([2]string{"relay", ""}, [2]string{"exit", "relay"}, [2]string{"deep1", "exit"}, [2]string{"deep2", "deep1"}, [2]string{"plain", ""})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	serve := func(s string) {
		mu.Lock()
		body = s
		mu.Unlock()
	}
	var created struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/subscriptions", map[string]any{"subscription": map[string]any{"name": "链式"}, "url": srv.URL + "/sub"}, &created)
	id := func(name string) string { return config.SubscriptionNodeID(created.ID, name) }
	check := func(stage string, want map[string]string) {
		t.Helper()
		cfg, _ := e.d.store.Snapshot()
		count := 0
		for _, n := range cfg.Nodes {
			if n.SubscriptionID == created.ID {
				count++
			}
		}
		if count != len(want) {
			t.Fatalf("%s: %d subscription nodes, want %d", stage, count, len(want))
		}
		for name, up := range want {
			n := cfg.NodeByID(id(name))
			if n == nil {
				t.Fatalf("%s: node %s missing", stage, name)
			}
			if n.Upstream != up {
				t.Fatalf("%s: upstream of %s = %q, want %q", stage, name, n.Upstream, up)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := e.d.refreshAndCommit(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	check("first refresh", map[string]string{"relay": "", "exit": id("relay"), "deep1": id("exit"), "deep2": id("deep1"), "plain": ""})

	// A chain the user adds to a node the subscription leaves alone survives.
	if _, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.NodeByID(id("plain")).Upstream = id("relay")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.d.refreshAndCommit(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	check("user chain", map[string]string{"relay": "", "exit": id("relay"), "deep1": id("exit"), "deep2": id("deep1"), "plain": id("relay")})

	// The subscription now chains relay -> exit -> plain. Together with the
	// user's plain -> relay that is a loop: the subscription wins, the user's
	// link is cut and reported, and the commit still goes through.
	serve(chainClash([2]string{"relay", "exit"}, [2]string{"exit", "plain"}, [2]string{"deep1", "exit"}, [2]string{"deep2", "deep1"}, [2]string{"plain", ""}))
	var task Task
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/refresh", nil, &task)
	task = e.waitTask(task.ID)
	if task.State != TaskSucceeded {
		t.Fatalf("refresh failed: %+v", task)
	}
	res, _ := json.Marshal(task.Result)
	var pv previewView
	_ = json.Unmarshal(res, &pv)
	if pv.Count != 5 || len(pv.Diff.Changed) != 2 || pv.Diff.Unchanged != 3 || len(pv.Issues) != 0 {
		t.Fatalf("preview: %s", res)
	}
	var committed struct {
		Notes []string `json:"notes"`
	}
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/commit", map[string]string{"previewId": pv.PreviewID}, &committed)
	if len(committed.Notes) != 1 || !strings.Contains(committed.Notes[0], "plain") {
		t.Fatalf("notes: %q", committed.Notes)
	}
	check("subscription chain wins", map[string]string{"relay": id("exit"), "exit": id("plain"), "deep1": id("exit"), "deep2": id("deep1"), "plain": ""})

	// A node whose upstream is filtered out is dropped with a visible reason,
	// never imported without its chain.
	serve(chainClash([2]string{"relay", ""}, [2]string{"exit", "relay"}, [2]string{"plain", ""}))
	if _, err := e.d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		c.SubscriptionByID(created.ID).ExcludeFilter = "^relay$"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/refresh", nil, &task)
	task = e.waitTask(task.ID)
	if task.State != TaskSucceeded {
		t.Fatalf("filtered refresh failed: %+v", task)
	}
	res, _ = json.Marshal(task.Result)
	pv = previewView{}
	_ = json.Unmarshal(res, &pv)
	if pv.Count != 1 || len(pv.Issues) != 1 || pv.Issues[0].Name != "exit" || len(pv.Diff.Removed) != 4 {
		t.Fatalf("filtered preview: %s", res)
	}
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/commit", map[string]string{"previewId": pv.PreviewID}, nil)
	check("filtered upstream", map[string]string{"plain": ""})
}

func TestImportLinksChains(t *testing.T) {
	e := newEnv(t, false, nil)
	var imp struct {
		Added  int `json:"added"`
		Issues []struct {
			Name string `json:"name"`
		} `json:"issues"`
	}
	text := chainClash([2]string{"hop", ""}, [2]string{"tail", "hop"}, [2]string{"lost", "gone"})
	e.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": text}, &imp)
	if imp.Added != 2 || len(imp.Issues) != 1 || imp.Issues[0].Name != "lost" {
		t.Fatalf("import: %+v", imp)
	}
	cfg, _ := e.d.store.Snapshot()
	nodes := map[string]config.Node{}
	for _, n := range cfg.Nodes {
		nodes[n.Name] = n
	}
	hop, tail := nodes["hop"], nodes["tail"]
	if hop.ID == "" || hop.Upstream != "" || tail.Upstream != hop.ID || tail.SubscriptionID != "" {
		t.Fatalf("imported nodes: %+v", cfg.Nodes)
	}
	if _, kept := nodes["lost"]; kept {
		t.Fatal("a node with an unknown upstream was imported without its chain")
	}
}
