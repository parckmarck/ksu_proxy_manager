// Package capture owns the policy-routing state that steers selected traffic
// into the core's TUN device. It keeps the kernel in line with a desired plan
// through a reconcile loop and never touches resources outside its reserved
// rule-priority range and routing table.
package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"ksu_proxy_manager/internal/apps"
)

const (
	Table = 20260
	// TunTable only routes into the TUN, without the bypass exceptions of
	// Table. It serves DNS queries (a LAN resolver must not leak or poison
	// them) and traffic sourced from the TUN subnet.
	TunTable = 20261
	// CoreTable isolates TUN-library auxiliary routes from other VPN tools.
	// These are preserved while the core runs and cleared after its exit.
	CoreTable = 20262
	// DefaultBase is the rule priority base when netd's rules are not found.
	DefaultBase    = 20260
	offsetTunSrc   = 1
	offsetHotspot  = 2
	offsetApps     = 10
	metricTun      = 10
	metricFallback = 4000000000
	ForwardChain   = "KPM_FWD"

	// netd's ROUTE_TABLE_LOCAL_NETWORK.
	localNetworkTable = 97
)

// TetherDNSUID is the uid of the tethering DNS forwarder (AID_DNS_TETHER);
// its queries are captured while hotspot traffic is.
var TetherDNSUID uint32 = 1052

// Plan is the desired capture state. A nil plan removes capture rules; the
// core's auxiliary state is managed separately by ClearCore after its exit.
type Plan struct {
	TunName    string          `json:"tunName"`
	Ranges     []apps.UIDRange `json:"ranges"`
	Hotspot    []string        `json:"hotspotPatterns"`
	IPv6       bool            `json:"ipv6"`
	FailClosed bool            `json:"failClosed"`
	Blocked    bool            `json:"blocked,omitempty"`
	Bypass     []netip.Prefix  `json:"bypass"`
	KeepInTun  []netip.Prefix  `json:"keepInTun,omitempty"`
}

// DefaultBypass are destinations that must never enter the TUN.
var DefaultBypass = []netip.Prefix{
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// LANBypass is added when the user chooses to bypass private networks.
var LANBypass = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// Status summarises the last reconcile.
type Status struct {
	Active      bool     `json:"active"`
	Tun         string   `json:"tun"`
	TunPresent  bool     `json:"tunPresent"`
	Priority    int      `json:"priority"`
	DNSPriority int      `json:"dnsPriority"`
	Rules       int      `json:"rules"`
	Routes      int      `json:"routes"`
	Hotspot     []string `json:"hotspot"`
	LastChange  string   `json:"lastChange,omitempty"`
	LastError   string   `json:"lastError,omitempty"`
	Unavailable int      `json:"unavailableStreak"`
}

// Netlink abstracts the kernel calls for testing.
type Netlink interface {
	RuleList(family int) ([]netlink.Rule, error)
	RuleAdd(r *netlink.Rule) error
	RuleDel(r *netlink.Rule) error
	RouteList(family, table int) ([]netlink.Route, error)
	RouteAdd(r *netlink.Route) error
	RouteDel(r *netlink.Route) error
	LinkByName(name string) (netlink.Link, error)
	LinkList() ([]netlink.Link, error)
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
}

type kernel struct{}

func (kernel) RuleList(f int) ([]netlink.Rule, error) { return netlink.RuleList(f) }
func (kernel) RuleAdd(r *netlink.Rule) error          { return netlink.RuleAdd(r) }
func (kernel) RuleDel(r *netlink.Rule) error          { return netlink.RuleDel(r) }
func (kernel) RouteList(f, table int) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(f, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
}
func (kernel) RouteAdd(r *netlink.Route) error           { return netlink.RouteAdd(r) }
func (kernel) RouteDel(r *netlink.Route) error           { return netlink.RouteDel(r) }
func (kernel) LinkByName(n string) (netlink.Link, error) { return netlink.LinkByName(n) }
func (kernel) LinkList() ([]netlink.Link, error)         { return netlink.LinkList() }
func (kernel) AddrList(l netlink.Link, f int) ([]netlink.Addr, error) {
	return netlink.AddrList(l, f)
}

// Firewall manages the forwarding chain needed for hotspot sharing.
type Firewall interface {
	Ensure(tun string, v6 bool) error
	Remove() error
}

type Manager struct {
	nl        Netlink
	fw        Firewall
	sysctl    string
	opMu      sync.Mutex
	mu        sync.Mutex
	plan      *Plan
	status    Status
	fwOn      bool
	fwV6      bool
	fwAt      time.Time
	pending   bool
	fwPending bool
}

func New() *Manager {
	return &Manager{nl: kernel{}, fw: &iptables{}, sysctl: "/proc/sys"}
}

// NewWith is used by tests to inject fakes.
func NewWith(nl Netlink, fw Firewall, sysctlRoot string) *Manager {
	return &Manager{nl: nl, fw: fw, sysctl: sysctlRoot}
}

// Apply replaces the desired plan and reconciles immediately.
func (m *Manager) Apply(ctx context.Context, p *Plan) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	m.plan = clonePlan(p)
	m.mu.Unlock()
	_, err := m.reconcile(ctx)
	return err
}

func (m *Manager) Plan() *Plan {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clonePlan(m.plan)
}

func clonePlan(p *Plan) *Plan {
	if p == nil {
		return nil
	}
	out := *p
	out.Ranges = append([]apps.UIDRange(nil), p.Ranges...)
	out.Hotspot = append([]string(nil), p.Hotspot...)
	out.Bypass = append([]netip.Prefix(nil), p.Bypass...)
	out.KeepInTun = append([]netip.Prefix(nil), p.KeepInTun...)
	return &out
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Hotspot = append([]string(nil), s.Hotspot...)
	return s
}

// ErrUnavailable marks a transient failure to read kernel state.
var ErrUnavailable = errors.New("暂时无法读取内核路由状态")
var ErrFirewall = errors.New("热点防火墙规则待重试")

// Reconcile converges kernel state to the plan and reports the number of
// changes. A read failure returns ErrUnavailable without modifying anything.
func (m *Manager) Reconcile(ctx context.Context) (int, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.reconcile(ctx)
}

func (m *Manager) reconcile(ctx context.Context) (int, error) {
	m.mu.Lock()
	changes, err := m.reconcileLocked(ctx)
	m.pending = m.plan == nil && err != nil
	m.mu.Unlock()
	if err == nil {
		err = m.syncFirewall()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.status.LastError = err.Error()
		if errors.Is(err, ErrUnavailable) {
			m.status.Unavailable++
		}
	} else {
		m.status.LastError = ""
		m.status.Unavailable = 0
	}
	if changes > 0 {
		m.status.LastChange = time.Now().UTC().Format(time.RFC3339)
	}
	return changes, err
}

func (m *Manager) reconcileLocked(ctx context.Context) (int, error) {
	p := m.plan
	tunIndex := 0
	hotspot := []string(nil)
	var tunNets []*net.IPNet
	if p != nil {
		l, err := m.nl.LinkByName(p.TunName)
		var notFound netlink.LinkNotFoundError
		switch {
		case err == nil:
			tunIndex = l.Attrs().Index
			if tunNets, err = m.tunNets(l); err != nil {
				return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
		case errors.As(err, &notFound):
		default:
			// A failed lookup must not be mistaken for a missing TUN.
			return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		if hotspot, err = m.matchHotspot(p); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	m.status.Active = p != nil
	m.status.TunPresent = tunIndex != 0
	m.status.Hotspot = hotspot
	if p != nil {
		m.status.Tun = p.TunName
	}
	m.status.Rules, m.status.Routes = 0, 0
	changes := 0
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if err := ctx.Err(); err != nil {
			return changes, err
		}
		n, err := m.syncRules(family, p, hotspot, tunNets)
		changes += n
		if err != nil {
			return changes, err
		}
		for _, table := range []int{Table, TunTable} {
			n, err = m.syncRoutes(family, table, desiredRoutes(p, family, tunIndex, table))
			changes += n
			if err != nil {
				return changes, err
			}
		}
	}
	if p != nil && tunIndex != 0 {
		m.setRPFilter(p.TunName)
	}
	return changes, nil
}

// opMu serializes kernel work, but slow xtables calls never hold the status
// lock. Mark a chain as touched before Ensure, which may succeed only in IPv4.
func (m *Manager) syncFirewall() error {
	m.mu.Lock()
	p := m.plan
	wantFW := p != nil && len(m.status.Hotspot) > 0
	needEnsure := wantFW && (m.fwPending || !m.fwOn || m.fwV6 != p.IPv6 || time.Since(m.fwAt) > 30*time.Second)
	needRemove := !wantFW && (m.fwOn || m.fwPending)
	if needEnsure {
		m.fwOn = true
	}
	m.mu.Unlock()
	if wantFW {
		if needEnsure {
			err := m.fw.Ensure(p.TunName, p.IPv6)
			m.mu.Lock()
			if err == nil {
				m.fwV6, m.fwAt, m.fwPending = p.IPv6, time.Now(), false
			} else {
				m.fwAt = time.Time{}
			}
			m.mu.Unlock()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrFirewall, err)
			}
		}
	} else if needRemove {
		err := m.fw.Remove()
		m.mu.Lock()
		m.fwOn, m.fwPending = err != nil, err != nil
		m.mu.Unlock()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrFirewall, err)
		}
	}
	return nil
}

// Clear removes capture resources regardless of the current plan, preserving
// the core's auxiliary state. CleanupPending remains true until it succeeds.
func (m *Manager) Clear(ctx context.Context) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	m.plan = nil
	m.pending = true
	m.fwPending = true
	m.mu.Unlock()
	var err error
	for i := 0; i < 3; i++ {
		if _, err = m.reconcile(ctx); err == nil || !errors.Is(err, ErrUnavailable) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil && !errors.Is(err, ErrFirewall) {
		err = errors.Join(err, m.syncFirewall())
	}
	return err
}

// CleanupPending reports whether a previous Clear did not complete.
func (m *Manager) CleanupPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending || m.fwPending
}

// ClearCore removes core-owned auxiliary state only after its process has
// exited. Normal reconciliation must not race the core's own rule cleanup.
func (m *Manager) ClearCore(ctx context.Context) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		rules, err := listRetry(func() ([]netlink.Rule, error) { return m.nl.RuleList(family) })
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, rule := range rules {
			if rule.Table == CoreTable {
				rule.Family = family
				if err := m.nl.RuleDel(&rule); err != nil && !errors.Is(err, syscall.ENOENT) {
					errs = append(errs, err)
				}
			}
		}
		routes, err := listRetry(func() ([]netlink.Route, error) { return m.nl.RouteList(family, CoreTable) })
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, route := range routes {
			if err := m.nl.RouteDel(&route); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

var hotspotExclude = []string{"lo", "rmnet*", "ccmni*", "seth*", "v4-*", "dummy*", "tun*", "ip6tnl*", "sit*", "ifb*"}

func matchPattern(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

func (m *Manager) matchHotspot(p *Plan) ([]string, error) {
	if len(p.Hotspot) == 0 {
		return nil, nil
	}
	links, err := m.nl.LinkList()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range links {
		a := l.Attrs()
		name := a.Name
		if name == p.TunName || a.Flags&net.FlagUp == 0 {
			continue
		}
		excluded := false
		for _, x := range hotspotExclude {
			if matchPattern(x, name) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		for _, pat := range p.Hotspot {
			if matchPattern(pat, name) {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func newRule(family, prio int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = family
	r.Priority = prio
	r.Table = Table
	return r
}

// tunNets returns the TUN's own subnets. The cores' system/mixed stacks
// answer TUN connections from a kernel socket bound to the TUN address; on
// Android no consulted table has the connected route, so the replies need a
// rule of their own.
func (m *Manager) tunNets(l netlink.Link) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := m.nl.AddrList(l, family)
		if err != nil {
			if family == netlink.FAMILY_V6 && errors.Is(err, syscall.EAFNOSUPPORT) {
				continue
			}
			return nil, err
		}
		for _, a := range addrs {
			if a.IPNet == nil || a.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, &net.IPNet{IP: a.IP.Mask(a.Mask), Mask: a.Mask})
		}
	}
	return out, nil
}

func desiredRules(p *Plan, family int, hotspot []string, tunNets []*net.IPNet, base, dnsPrio int) []*netlink.Rule {
	if p == nil {
		return nil
	}
	var out []*netlink.Rule
	for _, n := range tunNets {
		if (n.IP.To4() != nil) != (family == netlink.FAMILY_V4) {
			continue
		}
		r := newRule(family, base+offsetTunSrc)
		r.Table = TunTable
		r.Src = n
		r.IifName = "lo"
		out = append(out, r)
	}
	for _, ifn := range hotspot {
		r := newRule(family, base+offsetHotspot)
		r.IifName = ifn
		out = append(out, r)
	}
	for _, rg := range p.Ranges {
		r := newRule(family, base+offsetApps)
		r.UIDRange = netlink.NewRuleUIDRange(rg.Start, rg.End)
		out = append(out, r)
	}
	if dnsPrio > 0 {
		ranges := p.Ranges
		if len(hotspot) > 0 {
			ranges = append(append([]apps.UIDRange(nil), ranges...), apps.UIDRange{Start: TetherDNSUID, End: TetherDNSUID})
		}
		for _, rg := range ranges {
			r := newRule(family, dnsPrio)
			r.Table = TunTable
			r.UIDRange = netlink.NewRuleUIDRange(rg.Start, rg.End)
			r.Dport = netlink.NewRulePortRange(53, 53)
			out = append(out, r)
		}
	}
	return out
}

func ruleKey(r netlink.Rule) string {
	uid := ""
	if r.UIDRange != nil {
		uid = fmt.Sprintf("%d-%d", r.UIDRange.Start, r.UIDRange.End)
	}
	mask := uint32(0)
	if r.Mask != nil {
		mask = *r.Mask
	}
	dport := ""
	if r.Dport != nil {
		dport = fmt.Sprintf("%d-%d", r.Dport.Start, r.Dport.End)
	}
	return fmt.Sprintf("%d|%d|%d|%s|%s|%d|%s|%s|%v|%d|%x/%x|%s", r.Family, r.Priority, r.Table, r.IifName, uid, r.Type,
		ipnetString(r.Src), ipnetString(r.Dst), r.Invert, r.Goto, r.Mark, mask, dport)
}

func ipnetString(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}

// Owned reports whether a rule belongs to this module: only rules that point
// at the module's own routing tables are ever modified or removed.
func Owned(r netlink.Rule) bool {
	return r.Table == Table || r.Table == TunTable || r.Table == CoreTable
}

// DescribeRule renders a rule in `ip rule` style for diagnostics.
func DescribeRule(r netlink.Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d:", r.Priority)
	if r.Invert {
		b.WriteString(" not")
	}
	if r.Src != nil {
		fmt.Fprintf(&b, " from %s", r.Src)
	} else {
		b.WriteString(" from all")
	}
	if r.IifName != "" {
		fmt.Fprintf(&b, " iif %s", r.IifName)
	}
	if r.UIDRange != nil {
		fmt.Fprintf(&b, " uidrange %d-%d", r.UIDRange.Start, r.UIDRange.End)
	}
	if r.Dport != nil {
		fmt.Fprintf(&b, " dport %d-%d", r.Dport.Start, r.Dport.End)
	}
	switch {
	case r.Goto >= 0:
		fmt.Fprintf(&b, " goto %d", r.Goto)
	case r.Table > 0:
		fmt.Fprintf(&b, " lookup %d", r.Table)
	default:
		b.WriteString(" nop")
	}
	return b.String()
}

// DescribeRoute renders a route of the module's tables for diagnostics.
func DescribeRoute(r netlink.Route) string {
	kind := map[int]string{unix.RTN_THROW: "throw ", unix.RTN_UNREACHABLE: "unreachable "}[r.Type]
	dst := strings.SplitN(routeKey(r), "|", 2)[0]
	s := fmt.Sprintf("table %d: %s%s", r.Table, kind, dst)
	if kind == "" && r.LinkIndex > 0 {
		s += fmt.Sprintf(" dev #%d", r.LinkIndex)
	}
	return s
}

// detectBase places the module's rules right after netd's LOCAL_NETWORK rule
// ("fwmark 0x0/0x10000 lookup local_network"): after VPN and explicitly bound
// sockets, before tethering and the implicit/default network rules. netd uses
// 17000 on Android 10-11 and 20000 on Android 12+.
func detectBase(rules []netlink.Rule) int {
	for _, r := range rules {
		if r.Table == localNetworkTable && r.IifName == "" && r.UIDRange == nil && r.Mark == 0 &&
			r.Mask != nil && *r.Mask == 0x10000 && r.Priority >= 10000 && r.Priority < 30000 {
			return r.Priority + 260
		}
	}
	return DefaultBase
}

// dnsPriority places the DNS rules just before netd's EXPLICIT_NETWORK rules
// ("fwmark 0x1xxxx/0x1ffff iif lo lookup <table>"). The system resolver sends
// an app's queries on sockets owned by the app's uid but marked for an
// explicitly selected network, so they would never reach the capture rules
// further down. All EXPLICIT_NETWORK rules share one priority and nothing of
// that shape sits between them and the base, so the highest match is used:
// VPN rules of a similar shape only ever have lower priorities and keep
// precedence.
func dnsPriority(rules []netlink.Rule, base int) int {
	best := 0
	for _, r := range rules {
		if r.Mask != nil && *r.Mask&0x1ffff == 0x1ffff && r.Mark&0x10000 != 0 && r.Table != 0 && r.UIDRange == nil &&
			r.Priority >= 10000 && r.Priority < base && r.Priority > best {
			best = r.Priority
		}
	}
	if best == 0 {
		return base - 1
	}
	return best - 100
}

// portRulesSupported reports whether the kernel matches rule port ranges
// (Linux 4.17+). Older kernels silently drop unknown selectors, which would
// turn a DNS rule into a catch-all.
var portRulesSupported = sync.OnceValue(func() bool {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return false
	}
	return kernelAtLeast(unix.ByteSliceToString(u.Release[:]), 4, 17)
})

func kernelAtLeast(release string, major, minor int) bool {
	var ma, mi int
	if _, err := fmt.Sscanf(release, "%d.%d", &ma, &mi); err != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

// listRetry retries dumps interrupted by concurrent kernel updates.
func listRetry[T any](fn func() ([]T, error)) ([]T, error) {
	var last error
	for i := 0; i < 3; i++ {
		v, err := fn()
		if err == nil {
			return v, nil
		}
		last = err
		if !errors.Is(err, netlink.ErrDumpInterrupted) && !errors.Is(err, syscall.EINTR) && !errors.Is(err, syscall.EBUSY) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("%w: %v", ErrUnavailable, last)
}

func (m *Manager) syncRules(family int, p *Plan, hotspot []string, tunNets []*net.IPNet) (int, error) {
	current, err := listRetry(func() ([]netlink.Rule, error) { return m.nl.RuleList(family) })
	if err != nil {
		return 0, err
	}
	base := detectBase(current)
	dnsPrio := 0
	if portRulesSupported() {
		dnsPrio = dnsPriority(current, base)
	}
	if family == netlink.FAMILY_V4 {
		m.status.Priority = base
		m.status.DNSPriority = dnsPrio
	}
	want := desiredRules(p, family, hotspot, tunNets, base, dnsPrio)
	have := map[string]netlink.Rule{}
	count := 0
	for _, r := range current {
		if !Owned(r) || r.Table == CoreTable {
			continue
		}
		r.Family = family
		have[ruleKey(r)] = r
	}
	wantKeys := map[string]bool{}
	changes := 0
	for _, r := range want {
		k := ruleKey(*r)
		wantKeys[k] = true
		if _, ok := have[k]; ok {
			count++
			continue
		}
		if err := m.nl.RuleAdd(r); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				count++
				continue
			}
			if r.UIDRange != nil && (errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP)) {
				return changes, fmt.Errorf("内核不支持 uidrange 策略路由（需要 4.10+）: %w", err)
			}
			if family == netlink.FAMILY_V6 && errors.Is(err, syscall.EAFNOSUPPORT) {
				return changes, nil
			}
			return changes, fmt.Errorf("添加策略路由失败: %w", err)
		}
		count++
		changes++
	}
	for k, r := range have {
		if wantKeys[k] {
			continue
		}
		del := r
		if err := m.nl.RuleDel(&del); err != nil && !errors.Is(err, syscall.ENOENT) {
			return changes, fmt.Errorf("删除策略路由失败: %w", err)
		}
		changes++
	}
	m.status.Rules += count
	return changes, nil
}

func defaultDst(family int) *net.IPNet {
	if family == netlink.FAMILY_V6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
}

func desiredRoutes(p *Plan, family int, tunIndex int, table int) []*netlink.Route {
	if p == nil {
		return nil
	}
	var out []*netlink.Route
	v6 := family == netlink.FAMILY_V6
	if p.Blocked {
		tunIndex = 0
	}
	if !v6 || p.IPv6 {
		if tunIndex != 0 {
			out = append(out, &netlink.Route{Family: family, Table: table, Dst: defaultDst(family), LinkIndex: tunIndex, Scope: netlink.SCOPE_LINK, Priority: metricTun})
		}
		if p.FailClosed {
			out = append(out, &netlink.Route{Family: family, Table: table, Dst: defaultDst(family), Type: unix.RTN_UNREACHABLE, Priority: metricFallback})
		}
	} else {
		out = append(out, &netlink.Route{Family: family, Table: table, Dst: defaultDst(family), Type: unix.RTN_UNREACHABLE, Priority: metricTun})
	}
	if table != Table {
		return out
	}
	for _, prefix := range p.KeepInTun {
		if prefix.Addr().Is6() != v6 {
			continue
		}
		dst := &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
		route := &netlink.Route{Family: family, Table: table, Dst: dst, Priority: metricTun - 1}
		if tunIndex != 0 && (!v6 || p.IPv6) {
			route.LinkIndex, route.Scope = tunIndex, netlink.SCOPE_LINK
		} else if p.FailClosed || (v6 && !p.IPv6) {
			route.Type = unix.RTN_UNREACHABLE
		} else {
			continue
		}
		out = append(out, route)
	}
	for _, pfx := range p.Bypass {
		if pfx.Addr().Is6() != v6 {
			continue
		}
		ipn := &net.IPNet{IP: net.IP(pfx.Addr().AsSlice()), Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen())}
		out = append(out, &netlink.Route{Family: family, Table: table, Dst: ipn, Type: unix.RTN_THROW, Priority: metricTun})
	}
	return out
}

func routeKey(r netlink.Route) string {
	dst := "default"
	if r.Dst != nil {
		if ones, _ := r.Dst.Mask.Size(); ones != 0 || !r.Dst.IP.IsUnspecified() {
			dst = r.Dst.String()
		}
	}
	typ := r.Type
	if typ == 0 {
		typ = unix.RTN_UNICAST
	}
	link := r.LinkIndex
	if typ != unix.RTN_UNICAST {
		link = 0
	}
	return fmt.Sprintf("%s|%d|%d|%d", dst, typ, link, r.Priority)
}

func (m *Manager) syncRoutes(family, table int, want []*netlink.Route) (int, error) {
	current, err := listRetry(func() ([]netlink.Route, error) { return m.nl.RouteList(family, table) })
	if err != nil {
		return 0, err
	}
	have := map[string]netlink.Route{}
	for _, r := range current {
		if r.Table != table {
			continue
		}
		have[routeKey(r)] = r
	}
	wantKeys := map[string]bool{}
	for _, r := range want {
		wantKeys[routeKey(*r)] = true
	}
	changes, count := 0, 0
	// Delete first: the kernel identifies routes by destination and metric,
	// so a stale route of another type would make the add fail with EEXIST.
	for k, r := range have {
		if wantKeys[k] {
			continue
		}
		del := r
		if err := m.nl.RouteDel(&del); err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.ENOENT) {
			return changes, fmt.Errorf("删除路由失败 (%s): %w", k, err)
		}
		changes++
	}
	for _, r := range want {
		k := routeKey(*r)
		if _, ok := have[k]; ok {
			count++
			continue
		}
		if err := m.nl.RouteAdd(r); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				count++
				continue
			}
			if family == netlink.FAMILY_V6 && errors.Is(err, syscall.EAFNOSUPPORT) {
				continue
			}
			return changes, fmt.Errorf("添加路由失败 (%s): %w", k, err)
		}
		count++
		changes++
	}
	m.status.Routes += count
	return changes, nil
}

func (m *Manager) setRPFilter(tun string) {
	p := filepath.Join(m.sysctl, "net", "ipv4", "conf", tun, "rp_filter")
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == "2" {
		return
	}
	_ = os.WriteFile(p, []byte("2\n"), 0o644)
}
