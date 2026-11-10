package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/logx"
	"ksu_proxy_manager/internal/subscription"
)

func (d *Daemon) hSubscriptions(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg, sec := d.store.Snapshot()
	return map[string]any{"subscriptions": subViews(cfg, sec), "revision": cfg.Revision}, nil
}

type subBody struct {
	Subscription config.Subscription `json:"subscription"`
	// URL nil keeps the stored address on update.
	URL *string `json:"url"`
}

func (d *Daemon) hCreateSubscription(_ http.ResponseWriter, r *http.Request) (any, error) {
	var b subBody
	if err := decode(r, 64<<10, &b); err != nil {
		return nil, err
	}
	if b.URL == nil || strings.TrimSpace(*b.URL) == "" {
		return nil, badRequest("请填写订阅地址")
	}
	s := b.Subscription
	s.ID = "s" + fsutil.RandomHex(5)
	s.UpdatedAt, s.LastError, s.Usage = "", "", nil
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, sec *config.Secrets) error {
		c.Subscriptions = append(c.Subscriptions, s)
		sec.Subscriptions[s.ID] = strings.TrimSpace(*b.URL)
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := d.savedResult(next)
	return map[string]any{"id": s.ID, "revision": res.Revision, "pending": res.Pending}, nil
}

func (d *Daemon) hUpdateSubscription(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var b subBody
	if err := decode(r, 64<<10, &b); err != nil {
		return nil, err
	}
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, sec *config.Secrets) error {
		cur := c.SubscriptionByID(id)
		if cur == nil {
			return errNotFound
		}
		s := b.Subscription
		s.ID, s.UpdatedAt, s.LastError, s.Usage = id, cur.UpdatedAt, cur.LastError, cur.Usage
		*cur = s
		if b.URL != nil {
			u := strings.TrimSpace(*b.URL)
			if u == "" {
				return badRequest("请填写订阅地址")
			}
			sec.Subscriptions[id] = u
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.savedResult(next), nil
}

func (d *Daemon) hDeleteSubscription(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var notes []string
	next, err := d.store.Update(expectedRev(r), func(c *config.Config, sec *config.Secrets) error {
		idx := -1
		for i := range c.Subscriptions {
			if c.Subscriptions[i].ID == id {
				idx = i
			}
		}
		if idx < 0 {
			return errNotFound
		}
		c.Subscriptions = append(c.Subscriptions[:idx], c.Subscriptions[idx+1:]...)
		delete(sec.Subscriptions, id)
		removed := map[string]bool{}
		keep := c.Nodes[:0]
		for _, n := range c.Nodes {
			if n.SubscriptionID == id {
				removed[n.ID] = true
				continue
			}
			keep = append(keep, n)
		}
		c.Nodes = keep
		notes = detachNodes(c, removed)
		for i := range c.Groups {
			g := &c.Groups[i]
			ks := g.Subscriptions[:0]
			for _, sid := range g.Subscriptions {
				if sid != id {
					ks = append(ks, sid)
				}
			}
			g.Subscriptions = ks
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := d.savedResult(next)
	return map[string]any{"revision": res.Revision, "pending": res.Pending, "notes": notes}, nil
}

type previewView struct {
	PreviewID string               `json:"previewId"`
	Format    string               `json:"format"`
	Count     int                  `json:"count"`
	Diff      subscription.Diff    `json:"diff"`
	Issues    []subscription.Issue `json:"issues"`
	Usage     *config.Usage        `json:"usage,omitempty"`
}

// prepareRefresh downloads and parses a subscription into a pending preview.
func (d *Daemon) prepareRefresh(ctx context.Context, subID string) (*preview, error) {
	cfg, sec := d.store.Snapshot()
	sub := cfg.SubscriptionByID(subID)
	if sub == nil {
		return nil, errNotFound
	}
	rawURL := sec.Subscriptions[subID]
	if rawURL == "" {
		return nil, badRequest("订阅地址为空")
	}
	f, err := d.fetchSubscription(ctx, *sub, rawURL)
	if err != nil {
		return nil, err
	}
	res := subscription.Parse(f.Body)
	nodes, err := subscription.ApplyFilters(res.Nodes, sub.Filter, sub.ExcludeFilter)
	if err != nil {
		return nil, badRequest("过滤表达式无效: %v", err)
	}
	if len(nodes) == 0 {
		msg := "订阅中没有可用节点"
		if len(res.Nodes) > 0 {
			msg = "过滤后没有剩余节点"
		} else if len(res.Issues) > 0 {
			msg += "：" + res.Issues[0].Message
		}
		return nil, fmt.Errorf("%s", msg)
	}
	subscription.AssignSubscriptionIDs(subID, nodes)
	// Chains inside the subscription become upstream references now that the
	// IDs are known. A node whose upstream was filtered out is dropped.
	nodes, chainIssues := subscription.LinkUpstreams(nodes)
	if len(nodes) == 0 {
		return nil, errors.New("过滤后没有剩余节点：其余节点的前置节点已被过滤")
	}
	issues := append(res.Issues, chainIssues...)
	var current []config.Node
	for _, n := range cfg.Nodes {
		if n.SubscriptionID == subID {
			current = append(current, n)
		}
	}
	p := &preview{
		ID: fsutil.RandomHex(8), SubID: subID, Revision: cfg.Revision, Nodes: nodes, Diff: subscription.Compare(current, sec, nodes),
		Usage: f.Usage, Issues: issues, Format: res.Format, ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	return p, nil
}

func (p *preview) view() previewView {
	issues := p.Issues
	if issues == nil {
		issues = []subscription.Issue{}
	}
	return previewView{PreviewID: p.ID, Format: p.Format, Count: len(p.Nodes), Diff: p.Diff, Issues: issues, Usage: p.Usage}
}

// commitNodes replaces a subscription's nodes. A chain defined by the
// subscription itself wins; other nodes keep the chain the user chose.
func (d *Daemon) commitNodes(p *preview) (config.Config, []string, error) {
	var notes []string
	next, err := d.store.Update(p.Revision, func(c *config.Config, sec *config.Secrets) error {
		sub := c.SubscriptionByID(p.SubID)
		if sub == nil {
			return errNotFound
		}
		upstream := map[string]string{}
		incoming := map[string]bool{}
		for _, n := range p.Nodes {
			incoming[n.Node.ID] = true
		}
		removed := map[string]bool{}
		keep := c.Nodes[:0]
		insertAt := -1
		for _, n := range c.Nodes {
			if n.SubscriptionID == p.SubID {
				if insertAt < 0 {
					insertAt = len(keep)
				}
				upstream[n.ID] = n.Upstream
				if !incoming[n.ID] {
					removed[n.ID] = true
				}
				delete(sec.Nodes, n.ID)
				continue
			}
			keep = append(keep, n)
		}
		fresh := make([]config.Node, 0, len(p.Nodes))
		provided := map[string]bool{}
		for _, pn := range p.Nodes {
			n := config.Clone(pn.Node)
			if n.Upstream != "" {
				provided[n.ID] = true
			} else if up := upstream[n.ID]; up != "" && !removed[up] {
				n.Upstream = up
			}
			fresh = append(fresh, n)
			sec.SetNodeSecrets(n.ID, pn.Secrets)
		}
		if insertAt < 0 {
			insertAt = len(keep)
		}
		nodes := make([]config.Node, 0, len(keep)+len(fresh))
		nodes = append(nodes, keep[:insertAt]...)
		nodes = append(nodes, fresh...)
		nodes = append(nodes, keep[insertAt:]...)
		c.Nodes = nodes
		notes = detachNodes(c, removed)
		notes = append(notes, repairChains(c, provided)...)
		sub.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		sub.LastError = ""
		if p.Usage != nil {
			sub.Usage = p.Usage
		}
		return nil
	})
	return next, notes, err
}

// repairChains cuts chain links that would make the configuration invalid
// after a subscription refresh: a loop, a missing upstream or more layers
// than allowed. Links of the nodes in provided come from the subscription
// itself and are only cut when no other link of the chain can be, so a chain
// the user added earlier gives way instead of blocking every later update.
func repairChains(c *config.Config, provided map[string]bool) []string {
	index := make(map[string]int, len(c.Nodes))
	for i := range c.Nodes {
		index[c.Nodes[i].ID] = i
	}
	var notes []string
	for i := range c.Nodes {
		for c.Nodes[i].Upstream != "" {
			path, ok := chainPath(c.Nodes, index, i)
			if ok {
				break
			}
			cut := i
			for _, j := range path {
				if !provided[c.Nodes[j].ID] {
					cut = j
					break
				}
			}
			notes = append(notes, fmt.Sprintf("节点 %s 的前置关系与本次订阅更新冲突，已改为直接连接", c.Nodes[cut].Name))
			c.Nodes[cut].Upstream = ""
		}
	}
	return notes
}

// chainPath follows the chain of node i the way config.Validate does. It
// returns the nodes whose links were followed and whether the chain is valid;
// every returned node has a non-empty upstream when it is not.
func chainPath(nodes []config.Node, index map[string]int, i int) ([]int, bool) {
	path := []int{i}
	seen := map[string]bool{nodes[i].ID: true}
	cur := nodes[i].Upstream
	for depth := 0; cur != ""; depth++ {
		j, found := index[cur]
		if !found || seen[cur] || depth >= 3 {
			return path, false
		}
		seen[cur] = true
		path = append(path, j)
		cur = nodes[j].Upstream
	}
	return path, true
}

// scrubSubError removes the subscription address and secret-looking parts
// from an error before it is stored or returned.
func (d *Daemon) scrubSubError(subID string, err error) error {
	msg := err.Error()
	_, sec := d.store.Snapshot()
	if u := sec.Subscriptions[subID]; u != "" {
		msg = strings.ReplaceAll(msg, u, "<订阅地址>")
		if pu, perr := url.Parse(u); perr == nil && pu.RawQuery != "" {
			msg = strings.ReplaceAll(msg, pu.RawQuery, "…")
		}
	}
	msg = logx.Redact(msg)
	if r := []rune(msg); len(r) > 300 {
		msg = string(r[:300])
	}
	var api *APIError
	if errors.As(err, &api) {
		return &APIError{Status: api.Status, Code: api.Code, Message: msg}
	}
	return errors.New(msg)
}

func (d *Daemon) recordSubError(subID string, err error) {
	msg := d.scrubSubError(subID, err).Error()
	_, _ = d.store.Update(-1, func(c *config.Config, _ *config.Secrets) error {
		if s := c.SubscriptionByID(subID); s != nil {
			s.LastError = msg
			return nil
		}
		return errNotFound
	})
}

func (d *Daemon) hRefreshSubscription(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	cfg, _ := d.store.Snapshot()
	if cfg.SubscriptionByID(id) == nil {
		return nil, errNotFound
	}
	return d.tasks.Start(d.ctx, "subscription:"+id, func(ctx context.Context, t *TaskHandle) (any, error) {
		t.Progress("正在下载订阅", 0, 0)
		p, err := d.prepareRefresh(ctx, id)
		if err != nil {
			if ctx.Err() == nil {
				d.recordSubError(id, err)
			}
			return nil, d.scrubSubError(id, err)
		}
		d.mu.Lock()
		d.previews[p.ID] = p
		d.mu.Unlock()
		return p.view(), nil
	})
}

func (d *Daemon) hCommitSubscription(_ http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var b struct {
		PreviewID string `json:"previewId"`
	}
	if err := decode(r, 1024, &b); err != nil {
		return nil, err
	}
	d.mu.Lock()
	p := d.previews[b.PreviewID]
	if p != nil && p.SubID == id {
		delete(d.previews, b.PreviewID)
	}
	d.mu.Unlock()
	if p == nil || p.SubID != id || time.Now().After(p.ExpiresAt) {
		return nil, badRequest("预览已失效，请重新更新订阅")
	}
	next, notes, err := d.commitNodes(p)
	if err != nil {
		return nil, err
	}
	d.log.Info("subscription", "订阅已更新", "id", id, "nodes", len(p.Nodes))
	res := d.savedResult(next)
	return map[string]any{"revision": res.Revision, "pending": res.Pending, "notes": notes}, nil
}

// refreshAndCommit updates one subscription without a preview step.
func (d *Daemon) refreshAndCommit(ctx context.Context, subID string) error {
	p, err := d.prepareRefresh(ctx, subID)
	if err != nil {
		if ctx.Err() == nil {
			d.recordSubError(subID, err)
		}
		return d.scrubSubError(subID, err)
	}
	_, notes, err := d.commitNodes(p)
	// Nobody sees the notes of an unattended update, so keep them in the log.
	for _, note := range notes {
		d.log.Info("subscription", "订阅更新调整了节点引用", "id", subID, "note", note)
	}
	return err
}

func (d *Daemon) hUpdateAllSubscriptions(_ http.ResponseWriter, _ *http.Request) (any, error) {
	return d.tasks.Start(d.ctx, "subscription:all", func(ctx context.Context, t *TaskHandle) (any, error) {
		cfg, _ := d.store.Snapshot()
		type result struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Error string `json:"error,omitempty"`
		}
		out := make([]result, 0, len(cfg.Subscriptions))
		failed := 0
		for i, s := range cfg.Subscriptions {
			t.Progress("正在更新 "+s.Name, int64(i), int64(len(cfg.Subscriptions)))
			c, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := d.refreshAndCommit(c, s.ID)
			cancel()
			res := result{ID: s.ID, Name: s.Name}
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				res.Error = err.Error()
				failed++
			}
			out = append(out, res)
		}
		t.Progress("完成", int64(len(cfg.Subscriptions)), int64(len(cfg.Subscriptions)))
		return map[string]any{"results": out, "failed": failed}, nil
	})
}
