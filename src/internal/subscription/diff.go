package subscription

import (
	"encoding/json"
	"sort"

	"ksu_proxy_manager/internal/config"
)

// Diff summarises how a refreshed node set differs from the stored one.
type Diff struct {
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
	Changed   []string `json:"changed"`
	Unchanged int      `json:"unchanged"`
}

func fingerprint(n config.Node, secrets map[string]string) string {
	n.ID, n.SubscriptionID, n.Upstream = "", "", ""
	b, _ := json.Marshal(struct {
		N config.Node
		S map[string]string
	}{n, secrets})
	return string(b)
}

// Compare matches nodes by ID (derived from subscription + name).
func Compare(current []config.Node, secrets config.Secrets, next []Parsed) Diff {
	d := Diff{Added: []string{}, Removed: []string{}, Changed: []string{}}
	old := map[string]config.Node{}
	for _, n := range current {
		old[n.ID] = n
	}
	seen := map[string]bool{}
	for _, p := range next {
		seen[p.Node.ID] = true
		o, ok := old[p.Node.ID]
		if !ok {
			d.Added = append(d.Added, p.Node.Name)
			continue
		}
		changed := fingerprint(o, secrets.Nodes[o.ID]) != fingerprint(p.Node, p.Secrets)
		// A chain supplied by the subscription replaces the stored one; an
		// incoming node without one keeps whatever the user configured.
		if p.Node.Upstream != "" && p.Node.Upstream != o.Upstream {
			changed = true
		}
		if changed {
			d.Changed = append(d.Changed, p.Node.Name)
		} else {
			d.Unchanged++
		}
	}
	for _, n := range current {
		if !seen[n.ID] {
			d.Removed = append(d.Removed, n.Name)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	return d
}
