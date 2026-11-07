package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ksu_proxy_manager/internal/clashapi"
	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/netx"
	"ksu_proxy_manager/internal/render"
	"ksu_proxy_manager/internal/subscription"
)

func (d *Daemon) hNodes(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	return map[string]any{"nodes": nodeViews(cfg, sec), "revision": cfg.Revision}, nil
}

type nodeBody struct {
	Node    config.Node       `json:"node"`
	Secrets map[string]string `json:"secrets"`
}

func checkSecretFields(n config.Node, secrets map[string]string) error {
	fields, known := config.SecretFields[n.Type]
	if !known {
		return &config.FieldError{Field: "node.type", Message: fmt.Sprintf("不支持的节点类型 %q", n.Type)}
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	for k, v := range secrets {
		if !allowed[k] {
			return badRequest("节点类型 %s 不使用凭据字段 %s", n.Type, k)
		}
		if len(v) > 4096 || strings.ContainsAny(v, "\r\n") {
			return badRequest("凭据字段 %s 无效", k)
		}
	}
	return nil
}

func (d *Daemon) hCreateNode(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b nodeBody
	if err := decode(r, 256<<10, &b); err != nil {
		return nil, err
	}
	if b.Node.ID == "" {
		b.Node.ID = "m" + fsutil.RandomHex(6)
	}
	if err := checkSecretFields(b.Node, b.Secrets); err != nil {
		return nil, err
	}
	b.Node.SubscriptionID = ""
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, s *config.Secrets) error {
		if c.NodeByID(b.Node.ID) != nil {
			return badRequest("节点 ID 已存在")
		}
		c.Nodes = append(c.Nodes, b.Node)
		s.SetNodeSecrets(b.Node.ID, b.Secrets)
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := d.savedResult(next)
	return map[string]any{"id": b.Node.ID, "revision": res.Revision, "pending": res.Pending}, nil
}

func (d *Daemon) hUpdateNode(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var b nodeBody
	if err := decode(r, 256<<10, &b); err != nil {
		return nil, err
	}
	b.Node.ID = id
	if err := checkSecretFields(b.Node, b.Secrets); err != nil {
		return nil, err
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, s *config.Secrets) error {
		n := c.NodeByID(id)
		if n == nil {
			return errNotFound
		}
		b.Node.SubscriptionID = n.SubscriptionID
		if n.Type != b.Node.Type {
			// Credentials of another protocol do not carry over.
			delete(s.Nodes, id)
		}
		*n = b.Node
		s.SetNodeSecrets(id, b.Secrets)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.savedResult(next), nil
}

// detachNodes removes references to deleted nodes from groups and chains.
func detachNodes(c *config.Config, removed map[string]bool) []string {
	var notes []string
	for i := range c.Groups {
		g := &c.Groups[i]
		keep := g.Nodes[:0]
		for _, id := range g.Nodes {
			if !removed[id] {
				keep = append(keep, id)
			}
		}
		g.Nodes = keep
		if kind, id := config.ParseRef(g.Selected); kind == "node" && removed[id] {
			g.Selected = ""
		}
	}
	for i := range c.Nodes {
		if removed[c.Nodes[i].Upstream] {
			notes = append(notes, fmt.Sprintf("节点 %s 的前置节点已删除，已改为直接连接", c.Nodes[i].Name))
			c.Nodes[i].Upstream = ""
		}
	}
	return notes
}

func (d *Daemon) hDeleteNode(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var notes []string
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, s *config.Secrets) error {
		idx := -1
		for i := range c.Nodes {
			if c.Nodes[i].ID == id {
				idx = i
			}
		}
		if idx < 0 {
			return errNotFound
		}
		c.Nodes = append(c.Nodes[:idx], c.Nodes[idx+1:]...)
		delete(s.Nodes, id)
		notes = detachNodes(c, map[string]bool{id: true})
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := d.savedResult(next)
	return map[string]any{"revision": res.Revision, "pending": res.Pending, "notes": notes}, nil
}

func (d *Daemon) hCopyNode(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	newID := "m" + fsutil.RandomHex(6)
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, s *config.Secrets) error {
		n := c.NodeByID(id)
		if n == nil {
			return errNotFound
		}
		cp := config.Clone(*n)
		cp.ID = newID
		cp.SubscriptionID = ""
		name := []rune(cp.Name + " 副本")
		if len(name) > 128 {
			name = name[:128]
		}
		cp.Name = string(name)
		c.Nodes = append(c.Nodes, cp)
		fields := map[string]string{}
		for k, v := range s.Nodes[id] {
			fields[k] = v
		}
		s.SetNodeSecrets(newID, fields)
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := d.savedResult(next)
	return map[string]any{"id": newID, "revision": res.Revision, "pending": res.Pending}, nil
}

func (d *Daemon) hImportNodes(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b struct {
		Text string `json:"text"`
	}
	if err := decode(r, subscription.MaxSize+1024, &b); err != nil {
		return nil, err
	}
	res := subscription.Parse([]byte(b.Text))
	if res.Issues == nil {
		res.Issues = []subscription.Issue{}
	}
	if len(res.Nodes) == 0 {
		return map[string]any{"added": 0, "issues": res.Issues, "format": res.Format}, nil
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, s *config.Secrets) error {
		for _, p := range res.Nodes {
			p.Node.ID = "m" + fsutil.RandomHex(6)
			p.Node.SubscriptionID = ""
			c.Nodes = append(c.Nodes, p.Node)
			s.SetNodeSecrets(p.Node.ID, p.Secrets)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	saved := d.savedResult(next)
	return map[string]any{"added": len(res.Nodes), "issues": res.Issues, "format": res.Format, "revision": saved.Revision, "pending": saved.Pending}, nil
}

type delayResult struct {
	Delay  int    `json:"delay"`
	Error  string `json:"error,omitempty"`
	Method string `json:"method"`
}

func (d *Daemon) hDelay(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b struct {
		IDs     []string `json:"ids"`
		URL     string   `json:"url"`
		Timeout int      `json:"timeout"`
	}
	if err := decode(r, 256<<10, &b); err != nil {
		return nil, err
	}
	if len(b.IDs) == 0 || len(b.IDs) > 500 {
		return nil, badRequest("一次测速 1..500 个节点")
	}
	if b.URL == "" {
		b.URL = "https://www.gstatic.com/generate_204"
	}
	if _, err := netx.CheckURL(b.URL, true, false); err != nil {
		return nil, badRequest("测速地址无效: %v", err)
	}
	if b.Timeout <= 0 || b.Timeout > 15000 {
		b.Timeout = 5000
	}
	cfg, _ := d.store.Snapshot()
	api, out, apiErr := d.engine.API()
	results := map[string]delayResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, id := range b.IDs {
		n := cfg.NodeByID(id)
		if n == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(n config.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			var res delayResult
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(b.Timeout+2000)*time.Millisecond)
			defer cancel()
			if apiErr == nil {
				if tag, ok := out.TagOf[config.NodeRef(n.ID)]; ok {
					res.Method = "core"
					ms, err := api.Delay(ctx, tag, b.URL, b.Timeout)
					if err != nil {
						res.Error = err.Error()
					} else {
						res.Delay = ms
					}
					mu.Lock()
					results[n.ID] = res
					mu.Unlock()
					return
				}
			}
			res.Method = "tcp"
			ms, err := tcpPing(ctx, cfg, n, time.Duration(b.Timeout)*time.Millisecond)
			if err != nil {
				res.Error = err.Error()
			} else {
				res.Delay = ms
			}
			mu.Lock()
			results[n.ID] = res
			mu.Unlock()
		}(*n)
	}
	wg.Wait()
	return map[string]any{"results": results}, nil
}

// tcpPing measures the TCP handshake time to a node's server.
func tcpPing(ctx context.Context, cfg config.Config, n config.Node, timeout time.Duration) (int, error) {
	res := netx.Resolver(ipServers(cfg.DNS.Direct))
	host := n.Server
	if net.ParseIP(host) == nil {
		ips, err := res.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return 0, fmt.Errorf("域名解析失败")
		}
		host = ips[0].IP.String()
	}
	dialer := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(n.Port)))
	if err != nil {
		return 0, fmt.Errorf("连接失败")
	}
	conn.Close()
	return int(time.Since(start).Milliseconds()) + 1, nil
}

func (d *Daemon) hGroups(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	members, selected := render.Members(cfg, sec, cfg.Settings.Engine)
	return map[string]any{"groups": cfg.Groups, "members": members, "selected": selected, "revision": cfg.Revision}, nil
}

func (d *Daemon) hCreateGroup(_ http.ResponseWriter, r *http.Request) (any, error) {
	var g config.Group
	if err := decode(r, 256<<10, &g); err != nil {
		return nil, err
	}
	if g.ID == "" {
		g.ID = "g" + fsutil.RandomHex(5)
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		if c.GroupByID(g.ID) != nil {
			return badRequest("代理组 ID 已存在")
		}
		c.Groups = append(c.Groups, g)
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := d.savedResult(next)
	return map[string]any{"id": g.ID, "revision": res.Revision, "pending": res.Pending}, nil
}

func (d *Daemon) hUpdateGroup(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var g config.Group
	if err := decode(r, 256<<10, &g); err != nil {
		return nil, err
	}
	g.ID = id
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		cur := c.GroupByID(id)
		if cur == nil {
			return errNotFound
		}
		*cur = g
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.savedResult(next), nil
}

func (d *Daemon) hDeleteGroup(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	ref := config.GroupRef(id)
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, _ *config.Secrets) error {
		idx := -1
		for i := range c.Groups {
			if c.Groups[i].ID == id {
				idx = i
			}
		}
		if idx < 0 {
			return errNotFound
		}
		if c.Routing.Final == ref {
			return badRequest("该代理组是兜底出口，请先修改分流设置")
		}
		for _, rule := range c.Routing.Rules {
			if rule.Target == ref {
				return badRequest("规则 %s 正在使用该代理组", rule.ID)
			}
		}
		c.Groups = append(c.Groups[:idx], c.Groups[idx+1:]...)
		for i := range c.Groups {
			g := &c.Groups[i]
			keep := g.Groups[:0]
			for _, gid := range g.Groups {
				if gid != id {
					keep = append(keep, gid)
				}
			}
			g.Groups = keep
			if g.Selected == ref {
				g.Selected = ""
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.savedResult(next), nil
}

func (d *Daemon) hSelect(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b struct {
		Member string `json:"member"`
	}
	if err := decode(r, 1024, &b); err != nil {
		return nil, err
	}
	if err := d.engine.SelectMember(r.Context(), r.PathValue("id"), b.Member); err != nil {
		return nil, badRequest("%v", err)
	}
	return map[string]bool{"ok": true}, nil
}

type proxyMember struct {
	Ref   string `json:"ref"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Delay int    `json:"delay"`
}

type proxyGroupView struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Selected string        `json:"selected"`
	Now      string        `json:"now"`
	Members  []proxyMember `json:"members"`
}

// hProxies returns live group state from the core, or the configured state.
func (d *Daemon) hProxies(_ http.ResponseWriter, r *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	members, selected := render.Members(cfg, sec, cfg.Settings.Engine)
	names := map[string]string{config.TargetDirect: "直连"}
	types := map[string]string{config.TargetDirect: "direct"}
	for _, n := range cfg.Nodes {
		names[config.NodeRef(n.ID)] = n.Name
		types[config.NodeRef(n.ID)] = n.Type
	}
	for _, g := range cfg.Groups {
		names[config.GroupRef(g.ID)] = g.Name
		types[config.GroupRef(g.ID)] = g.Type
	}
	views := make([]proxyGroupView, 0, len(cfg.Groups))
	api, out, err := d.engine.API()
	running := err == nil
	var px map[string]clashapi.Proxy
	delays := map[string]int{}
	if running {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if list, err := api.Proxies(ctx); err == nil {
			px = list
			for name, p := range px {
				if len(p.History) > 0 {
					delays[name] = p.History[len(p.History)-1].Delay
				}
			}
		}
	}
	for _, g := range cfg.Groups {
		v := proxyGroupView{ID: g.ID, Name: g.Name, Type: g.Type, Selected: selected[g.ID], Now: selected[g.ID], Members: []proxyMember{}}
		refs := members[g.ID]
		if px != nil {
			if lg, ok := px[out.TagOf[config.GroupRef(g.ID)]]; ok {
				if ref := out.RefOf[lg.Now]; ref != "" {
					v.Now = ref
				}
				if len(lg.All) > 0 {
					refs = nil
					for _, tag := range lg.All {
						if ref := out.RefOf[tag]; ref != "" {
							refs = append(refs, ref)
						}
					}
				}
			}
		}
		for _, ref := range refs {
			m := proxyMember{Ref: ref, Name: names[ref], Type: types[ref]}
			if px != nil {
				m.Delay = delays[out.TagOf[ref]]
			}
			v.Members = append(v.Members, m)
		}
		views = append(views, v)
	}
	return map[string]any{"running": running, "groups": views}, nil
}
