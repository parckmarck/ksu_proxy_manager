package subscription

import (
	"fmt"
	"strings"
)

// maxChain is the number of upstream layers config.Validate accepts.
const maxChain = 3

// keyIndex maps source names to node positions; ambiguous names map to -1.
func keyIndex(nodes []Parsed) map[string]int {
	index := make(map[string]int, len(nodes))
	for i := range nodes {
		key := nodes[i].key
		if key == "" {
			continue
		}
		if _, dup := index[key]; dup {
			index[key] = -1
		} else {
			index[key] = i
		}
	}
	return index
}

// brief shortens a source name for display in an issue.
func brief(s string) string {
	s = strings.TrimSpace(spaceRE.ReplaceAllString(strings.ToValidUTF8(s, ""), " "))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64]) + "…"
	}
	return s
}

// chainProblem explains why the chain of p cannot be kept, or returns "".
// The walk mirrors config.Validate, so a node that passes here also has every
// node of its chain passing.
func chainProblem(nodes []Parsed, index map[string]int, groups map[string]bool, p Parsed) string {
	if p.via == "" {
		return ""
	}
	seen := map[string]bool{p.key: true}
	cur := p.via
	for depth := 0; cur != ""; depth++ {
		i, found := index[cur]
		switch {
		case seen[cur]:
			return "前置关系存在环路，已跳过该节点"
		case depth > 0 && (!found || i < 0):
			return fmt.Sprintf("前置节点 %s 自身的前置不可用，已跳过该节点", brief(p.via))
		case !found && groups[cur]:
			return fmt.Sprintf("前置 %s 是代理组，暂不支持以代理组作为前置节点，已跳过该节点", brief(cur))
		case !found:
			return fmt.Sprintf("前置节点 %s 不在本次导入的节点中，已跳过该节点", brief(cur))
		case i < 0:
			return fmt.Sprintf("前置节点 %s 名称重复，无法确定指向，已跳过该节点", brief(cur))
		case depth >= maxChain:
			return fmt.Sprintf("链式代理最多 %d 层，已跳过该节点", maxChain)
		}
		seen[cur] = true
		cur = nodes[i].via
	}
	return ""
}

// pruneChains drops every node whose chain cannot be kept intact: its
// upstream is not one of the nodes (a proxy group, a skipped or filtered
// node, an unknown name), is ambiguous, or the chain loops or is too deep.
// A chained node is never kept with its chain removed.
func pruneChains(nodes []Parsed, groups map[string]bool) ([]Parsed, []Issue) {
	chained := false
	for i := range nodes {
		if nodes[i].via != "" {
			chained = true
			break
		}
	}
	if !chained {
		return nodes, nil
	}
	index := keyIndex(nodes)
	kept := make([]Parsed, 0, len(nodes))
	var issues []Issue
	for _, p := range nodes {
		if why := chainProblem(nodes, index, groups, p); why != "" {
			if len(issues) < maxIssues {
				issues = append(issues, Issue{Name: p.Node.Name, Message: why})
			}
			continue
		}
		kept = append(kept, p)
	}
	return kept, issues
}

// resolveChains applies pruneChains to a parsed document. groups holds the
// names of proxy groups so that a chain through a group is reported as such.
func (r *Result) resolveChains(groups map[string]bool) {
	nodes, issues := pruneChains(r.Nodes, groups)
	r.Nodes = nodes
	for _, is := range issues {
		r.issue(is.Name, "%s", is.Message)
	}
}

// LinkUpstreams turns the chains recorded while parsing (Clash dialer-proxy,
// sing-box detour) into Upstream references between the given nodes. It must
// run after the final IDs are assigned. Nodes whose upstream is no longer in
// the set, for example because a filter removed it, are dropped and reported
// instead of being kept without their chain.
func LinkUpstreams(nodes []Parsed) ([]Parsed, []Issue) {
	kept, issues := pruneChains(nodes, nil)
	var index map[string]int
	for i := range kept {
		via := kept[i].via
		if via == "" {
			continue
		}
		if index == nil {
			index = keyIndex(kept)
		}
		kept[i].Node.Upstream = kept[index[via]].Node.ID
	}
	return kept, issues
}
