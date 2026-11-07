package capture

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"ksu_proxy_manager/internal/apps"
)

// inNetns re-runs the calling test inside an unprivileged user+network
// namespace. It returns true when already running inside it.
func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv("KPM_IN_NETNS") == "1" {
		return true
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "KPM_IN_NETNS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "unshare failed") {
			t.Skipf("user namespaces unavailable: %s", out)
		}
		t.Fatalf("netns run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("netns run did not pass:\n%s", out)
	}
	t.Logf("netns output:\n%s", out)
	return false
}

type fw struct{ ensured, removed int }

func (f *fw) Ensure(string, bool) error { f.ensured++; return nil }
func (f *fw) Remove() error             { f.removed++; return nil }

func ownedRules(t *testing.T, family int) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatal(err)
	}
	var out []netlink.Rule
	for _, r := range rules {
		if Owned(r) {
			out = append(out, r)
		}
	}
	return out
}

func rulesIn(t *testing.T, family, table int) []netlink.Rule {
	t.Helper()
	var out []netlink.Rule
	for _, r := range ownedRules(t, family) {
		if r.Table == table {
			out = append(out, r)
		}
	}
	return out
}

func tableRoutes(t *testing.T, family int) []netlink.Route {
	t.Helper()
	return routesIn(t, family, Table)
}

func routesIn(t *testing.T, family, table int) []netlink.Route {
	t.Helper()
	routes, err := kernel{}.RouteList(family, table)
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

func makeTun(t *testing.T, name string) int {
	t.Helper()
	tun := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: name}, Mode: netlink.TUNTAP_MODE_TUN, Flags: netlink.TUNTAP_DEFAULTS}
	if err := netlink.LinkAdd(tun); err != nil {
		t.Fatalf("create tun: %v", err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	return l.Attrs().Index
}

func TestCoreAuxiliaryCleanup(t *testing.T) {
	if !inNetns(t) {
		return
	}
	idx := makeTun(t, "ksu-proxy0")
	coreRule := netlink.NewRule()
	coreRule.Family, coreRule.Priority, coreRule.Table = netlink.FAMILY_V6, 9999, CoreTable
	coreRule.OifName = "ksu-proxy0"
	foreign := *coreRule
	foreign.Priority, foreign.Table = 9998, 2022
	for _, rule := range []*netlink.Rule{coreRule, &foreign} {
		if err := netlink.RuleAdd(rule); err != nil {
			t.Fatal(err)
		}
	}
	route := &netlink.Route{Table: CoreTable, LinkIndex: idx,
		Dst: &net.IPNet{IP: net.ParseIP("fdfe:dcba:9877::"), Mask: net.CIDRMask(126, 128)}}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	manager := NewWith(kernel{}, &fw{}, "/proc/sys")
	ctx := context.Background()
	plan := &Plan{TunName: "ksu-proxy0", IPv6: true}
	if err := manager.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if len(rulesIn(t, netlink.FAMILY_V6, CoreTable)) != 1 {
		t.Fatal("reconcile removed the live core's auxiliary rule")
	}
	if err := manager.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rulesIn(t, netlink.FAMILY_V6, CoreTable)) != 1 {
		t.Fatal("capture clear raced the still-running core's own cleanup")
	}
	if err := manager.ClearCore(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rulesIn(t, netlink.FAMILY_V6, CoreTable)) != 0 || len(routesIn(t, netlink.FAMILY_V6, CoreTable)) != 0 {
		t.Fatal("dead core auxiliary state was not removed")
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Table == foreign.Table && rule.Priority == foreign.Priority && rule.OifName == foreign.OifName {
			return
		}
	}
	t.Fatal("foreign VPN table was modified")
}

func TestCaptureNetns(t *testing.T) {
	if !inNetns(t) {
		return
	}
	lo, _ := netlink.LinkByName("lo")
	_ = netlink.LinkSetUp(lo)
	idx := makeTun(t, "ksu-proxy0")
	// Only uid 0 is mapped inside the namespace.
	TetherDNSUID = 0

	foreign := []*netlink.Rule{}
	// Rules of other owners, including one inside our priority band, survive.
	for _, prio := range []int{20259, 20265, 20270, 20280} {
		r := netlink.NewRule()
		r.Priority, r.Table, r.Family = prio, 254, netlink.FAMILY_V4
		if err := netlink.RuleAdd(r); err != nil {
			t.Fatal(err)
		}
		foreign = append(foreign, r)
	}

	f := &fw{}
	m := NewWith(kernel{}, f, "/proc/sys")
	// Only uid 0 is mapped inside an unprivileged user namespace, and the
	// kernel rejects uidrange selectors for unmapped uids.
	plan := &Plan{TunName: "ksu-proxy0", Ranges: []apps.UIDRange{{Start: 0, End: 0}}, FailClosed: true, Bypass: DefaultBypass}
	ctx := context.Background()
	if err := m.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if got := len(rulesIn(t, netlink.FAMILY_V4, Table)); got != 1 {
		t.Fatalf("v4 owned rules = %d", got)
	}
	if got := len(rulesIn(t, netlink.FAMILY_V6, Table)); got != 1 {
		t.Fatalf("v6 owned rules = %d", got)
	}
	// Without netd's rules the DNS rule sits right before the base.
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		dns := rulesIn(t, fam, TunTable)
		if len(dns) != 1 || dns[0].Priority != DefaultBase-1 || dns[0].Dport == nil || dns[0].Dport.Start != 53 || dns[0].Dport.End != 53 ||
			dns[0].UIDRange == nil || dns[0].UIDRange.Start != 0 {
			t.Fatalf("family %d dns rules %+v", fam, dns)
		}
	}
	if dr := routesIn(t, netlink.FAMILY_V4, TunTable); len(dr) != 2 {
		t.Fatalf("dns table v4 routes (tun + fail-closed, no throws): %+v", dr)
	}
	if dr := routesIn(t, netlink.FAMILY_V6, TunTable); len(dr) != 1 || dr[0].Type != unix.RTN_UNREACHABLE {
		t.Fatalf("dns table v6 routes with IPv6 off: %+v", dr)
	}
	v4 := tableRoutes(t, netlink.FAMILY_V4)
	var haveTun, haveUnreach, throws int
	for _, r := range v4 {
		switch {
		case r.Type == unix.RTN_UNREACHABLE:
			haveUnreach++
		case r.Type == unix.RTN_THROW:
			throws++
		case r.LinkIndex == idx:
			haveTun++
		}
	}
	if haveTun != 1 || haveUnreach != 1 || throws != 3 {
		t.Fatalf("v4 routes tun=%d unreachable=%d throw=%d: %+v", haveTun, haveUnreach, throws, v4)
	}
	v6 := tableRoutes(t, netlink.FAMILY_V6)
	unreach6 := 0
	for _, r := range v6 {
		if r.Type == unix.RTN_UNREACHABLE {
			unreach6++
		}
		if r.LinkIndex == idx && r.Type != unix.RTN_UNREACHABLE && r.Type != unix.RTN_THROW {
			t.Fatalf("IPv6 must not be routed into the TUN when disabled: %+v", r)
		}
	}
	if unreach6 != 1 {
		t.Fatalf("expected IPv6 unreachable default, got %+v", v6)
	}
	if n, err := m.Reconcile(ctx); err != nil || n != 0 {
		t.Fatalf("second reconcile must be a no-op: n=%d err=%v", n, err)
	}

	// Self-heal: an externally deleted route is restored.
	for _, r := range tableRoutes(t, netlink.FAMILY_V4) {
		if r.LinkIndex == idx {
			del := r
			if err := netlink.RouteDel(&del); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n, err := m.Reconcile(ctx); err != nil || n != 1 {
		t.Fatalf("expected one repair, n=%d err=%v", n, err)
	}

	// The TUN is recreated (core restart) with a new index.
	l, _ := netlink.LinkByName("ksu-proxy0")
	if err := netlink.LinkDel(l); err != nil {
		t.Fatal(err)
	}
	idx2 := makeTun(t, "ksu-proxy0")
	if _, err := m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range tableRoutes(t, netlink.FAMILY_V4) {
		if r.LinkIndex == idx2 && r.Type != unix.RTN_UNREACHABLE {
			found = true
		}
	}
	if !found {
		t.Fatal("route to recreated TUN missing")
	}

	// Plan change: IPv6 on, fail-open, app rules replaced by a hotspot rule.
	d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ap0"}}
	if err := netlink.LinkAdd(d); err != nil {
		t.Fatal(err)
	}
	_ = netlink.LinkSetUp(d)
	plan2 := &Plan{TunName: "ksu-proxy0", IPv6: true, Bypass: DefaultBypass, Hotspot: []string{"ap*"}}
	if err := m.Apply(ctx, plan2); err != nil {
		t.Fatal(err)
	}
	if got := rulesIn(t, netlink.FAMILY_V4, Table); len(got) != 1 || got[0].IifName != "ap0" || got[0].UIDRange != nil {
		t.Fatalf("rules after plan change: %+v", got)
	}
	// The tethering DNS forwarder is captured along with hotspot traffic.
	if got := rulesIn(t, netlink.FAMILY_V4, TunTable); len(got) != 1 || got[0].UIDRange == nil || got[0].UIDRange.Start != TetherDNSUID {
		t.Fatalf("dns rules after plan change: %+v", got)
	}
	v6tun := false
	for _, r := range tableRoutes(t, netlink.FAMILY_V6) {
		if r.Type == unix.RTN_UNREACHABLE {
			t.Fatal("unreachable must be gone when IPv6 enabled and fail-open")
		}
		if r.LinkIndex == idx2 {
			v6tun = true
		}
	}
	if !v6tun {
		t.Fatal("IPv6 default via TUN missing")
	}
	if f.ensured != 1 {
		t.Fatalf("firewall ensured %d times, want 1", f.ensured)
	}

	if err := m.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ownedRules(t, netlink.FAMILY_V4))+len(ownedRules(t, netlink.FAMILY_V6)) != 0 {
		t.Fatal("rules left after Clear")
	}
	if len(tableRoutes(t, netlink.FAMILY_V4))+len(tableRoutes(t, netlink.FAMILY_V6)) != 0 {
		t.Fatal("routes left after Clear")
	}
	if len(routesIn(t, netlink.FAMILY_V4, TunTable))+len(routesIn(t, netlink.FAMILY_V6, TunTable)) != 0 {
		t.Fatal("dns routes left after Clear")
	}
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	for _, fr := range foreign {
		ok := false
		for _, r := range rules {
			if r.Priority == fr.Priority && r.Table == 254 {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("foreign rule at %d was removed", fr.Priority)
		}
	}
}

func TestDetectBase(t *testing.T) {
	mask := uint32(0x10000)
	vpn := netlink.Rule{Priority: 12000, Table: localNetworkTable, IifName: "tun0"}
	local := netlink.Rule{Priority: 17000, Table: localNetworkTable, Mask: &mask}
	if b := detectBase([]netlink.Rule{vpn, local}); b != 17260 {
		t.Fatalf("android 10/11 base = %d", b)
	}
	local.Priority = 20000
	if b := detectBase([]netlink.Rule{local, vpn}); b != 20260 {
		t.Fatalf("android 12+ base = %d", b)
	}
	if b := detectBase([]netlink.Rule{vpn}); b != DefaultBase {
		t.Fatalf("fallback base = %d", b)
	}
}

func TestCaptureFollowsNetdPriorityNetns(t *testing.T) {
	if !inNetns(t) {
		return
	}
	makeTun(t, "ksu-proxy0")
	netd := netlink.NewRule()
	mask := uint32(0x10000)
	netd.Family, netd.Priority, netd.Table, netd.Mark, netd.Mask = netlink.FAMILY_V4, 17000, localNetworkTable, 0, &mask
	if err := netlink.RuleAdd(netd); err != nil {
		t.Fatal(err)
	}
	m := NewWith(kernel{}, &fw{}, "/proc/sys")
	ctx := context.Background()
	if err := m.Apply(ctx, &Plan{TunName: "ksu-proxy0", Ranges: []apps.UIDRange{{Start: 0, End: 0}}, Bypass: DefaultBypass}); err != nil {
		t.Fatal(err)
	}
	got := rulesIn(t, netlink.FAMILY_V4, Table)
	if len(got) != 1 || got[0].Priority != 17270 || m.Status().Priority != 17260 {
		t.Fatalf("rules %+v status %+v", got, m.Status())
	}
	// IPv6 has no netd rule here, so it uses the default base.
	if v6 := rulesIn(t, netlink.FAMILY_V6, Table); len(v6) != 1 || v6[0].Priority != DefaultBase+offsetApps {
		t.Fatalf("v6 rules %+v", v6)
	}
	// When netd's layout changes, stale rules move instead of piling up.
	if err := netlink.RuleDel(netd); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got = rulesIn(t, netlink.FAMILY_V4, Table)
	if len(got) != 1 || got[0].Priority != DefaultBase+offsetApps {
		t.Fatalf("rules after move %+v", got)
	}
	if dns := rulesIn(t, netlink.FAMILY_V4, TunTable); len(dns) != 1 || dns[0].Priority != DefaultBase-1 {
		t.Fatalf("dns rules after move %+v", dns)
	}
	if err := m.Clear(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDNSPriority(t *testing.T) {
	mask := uint32(0x1ffff)
	explicit := netlink.Rule{Priority: 16000, Table: 1003, Mark: 0x10064, Mask: &mask, IifName: "lo"}
	local := netlink.Rule{Priority: 16000, Table: localNetworkTable, Mark: 0x10063, Mask: &mask, IifName: "lo"}
	vpnMask := uint32(0xd0000)
	vpn := netlink.Rule{Priority: 10000, Table: 99, Mark: 0xc0000, Mask: &vpnMask}
	uidExplicit := netlink.Rule{Priority: 12000, Table: 1005, Mark: 0x10065, Mask: &mask, UIDRange: netlink.NewRuleUIDRange(0, 99999)}
	// A VPN rule of the same mark/mask shape but at a VPN priority must not
	// pull the DNS rules ahead of the VPN.
	vpnExplicit := netlink.Rule{Priority: 13000, Table: 1010, Mark: 0x10066, Mask: &mask, IifName: "lo"}
	if p := dnsPriority([]netlink.Rule{vpn, uidExplicit, vpnExplicit, local, explicit}, 20260); p != 15900 {
		t.Fatalf("android 12+ dns priority = %d", p)
	}
	explicit.Priority, local.Priority = 13000, 13000
	if p := dnsPriority([]netlink.Rule{explicit, local, vpn}, 17260); p != 12900 {
		t.Fatalf("android 10/11 dns priority = %d", p)
	}
	if p := dnsPriority([]netlink.Rule{vpn}, 20260); p != 20259 {
		t.Fatalf("fallback dns priority = %d", p)
	}
}

func TestDescribe(t *testing.T) {
	r := *newRule(netlink.FAMILY_V4, 15900)
	r.Table = TunTable
	r.UIDRange = netlink.NewRuleUIDRange(10000, 19999)
	r.Dport = netlink.NewRulePortRange(53, 53)
	if s := DescribeRule(r); s != "15900: from all uidrange 10000-19999 dport 53-53 lookup 20261" {
		t.Fatal(s)
	}
	src := *newRule(netlink.FAMILY_V4, 20261)
	src.Src = &net.IPNet{IP: net.IPv4(172, 19, 0, 0).To4(), Mask: net.CIDRMask(30, 32)}
	src.IifName = "lo"
	if s := DescribeRule(src); s != "20261: from 172.19.0.0/30 iif lo lookup 20260" {
		t.Fatal(s)
	}
	g := netlink.NewRule()
	g.Priority, g.Goto = 20260, 20270
	if s := DescribeRule(*g); s != "20260: from all goto 20270" {
		t.Fatal(s)
	}
	routes := desiredRoutes(&Plan{Bypass: DefaultBypass[:1], FailClosed: true}, netlink.FAMILY_V4, 7, Table)
	var got []string
	for _, rt := range routes {
		got = append(got, DescribeRoute(*rt))
	}
	if strings.Join(got, "; ") != "table 20260: default dev #7; table 20260: unreachable default; table 20260: throw 224.0.0.0/4" {
		t.Fatal(got)
	}
}

func TestKernelAtLeast(t *testing.T) {
	for rel, want := range map[string]bool{"4.14.186-perf+": false, "4.17.0": true, "4.19.157-g1": true, "5.4.0": true, "6.1.90-perf+": true, "3.18": false, "x": false} {
		if kernelAtLeast(rel, 4, 17) != want {
			t.Errorf("%s: want %v", rel, want)
		}
	}
}

// TestDNSCaptureNetns checks the kernel's routing decisions with real
// sockets on an Android-like rule layout: a resolver socket marked for an
// explicitly selected network still reaches the TUN for port 53 only, LAN
// bypass does not apply to DNS, and the core's replies from the TUN address
// go back into the TUN although the main table is never consulted.
func TestDNSCaptureNetns(t *testing.T) {
	if !inNetns(t) {
		return
	}
	lo, _ := netlink.LinkByName("lo")
	_ = netlink.LinkSetUp(lo)
	makeTun(t, "ksu-proxy0")
	tun, _ := netlink.LinkByName("ksu-proxy0")
	if err := netlink.AddrAdd(tun, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(172, 19, 0, 1), Mask: net.CIDRMask(30, 32)}}); err != nil {
		t.Fatal(err)
	}
	wlan := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wlan0"}}
	if err := netlink.LinkAdd(wlan); err != nil {
		t.Fatal(err)
	}
	_ = netlink.LinkSetUp(wlan)
	if err := netlink.AddrAdd(wlan, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 2), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatal(err)
	}
	// netd's layout: per-network table plus explicit and local-network rules.
	if err := netlink.RouteAdd(&netlink.Route{Table: 1003, LinkIndex: wlan.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)}, Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatal(err)
	}
	mask, localMask := uint32(0x1ffff), uint32(0x10000)
	explicit := netlink.NewRule()
	explicit.Priority, explicit.Table, explicit.Mark, explicit.Mask = 16000, 1003, 0x10064, &mask
	local := netlink.NewRule()
	local.Priority, local.Table, local.Mask = 20000, localNetworkTable, &localMask
	unreachable := netlink.NewRule()
	unreachable.Priority, unreachable.Type = 32000, unix.FR_ACT_UNREACHABLE
	for _, r := range []*netlink.Rule{explicit, local, unreachable} {
		if err := netlink.RuleAdd(r); err != nil {
			t.Fatal(err)
		}
	}
	m := NewWith(kernel{}, &fw{}, "/proc/sys")
	plan := &Plan{TunName: "ksu-proxy0", Ranges: []apps.UIDRange{{Start: 0, End: 0}}, Bypass: append(append([]netip.Prefix(nil), DefaultBypass...), LANBypass...)}
	if err := m.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.Priority != 20260 || st.DNSPriority != 15900 {
		t.Fatalf("status %+v", st)
	}
	src := func(addr string, mark int) string {
		return srcFrom(t, nil, addr, mark)
	}
	if got := src("192.168.1.1:53", 0x10064); got != "172.19.0.1" {
		t.Fatalf("resolver query with explicit mark left via %s", got)
	}
	if got := src("192.168.1.1:443", 0x10064); got != "192.168.1.2" {
		t.Fatalf("explicitly bound non-DNS traffic must keep its network, got %s", got)
	}
	if got := src("8.8.8.8:443", 0); got != "172.19.0.1" {
		t.Fatalf("app traffic left via %s", got)
	}
	tunAddr := &net.UDPAddr{IP: net.IPv4(172, 19, 0, 1)}
	if got := srcFrom(t, tunAddr, "172.19.0.2:40000", 0); got != "172.19.0.1" {
		t.Fatalf("reply from the TUN address is not routable: %s", got)
	}
	if err := m.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := src("192.168.1.1:53", 0x10064); got != "192.168.1.2" {
		t.Fatalf("after Clear the query left via %s", got)
	}
	if got := srcFrom(t, tunAddr, "172.19.0.2:40000", 0); got != "error" {
		t.Fatalf("without the rule the reply must be unroutable here, got %s", got)
	}
}

// srcFrom connects a UDP socket and reports the chosen source address, or
// "error" when the kernel has no route.
func srcFrom(t *testing.T, local *net.UDPAddr, addr string, mark int) string {
	t.Helper()
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if mark != 0 {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	if local != nil {
		d.LocalAddr = local
	}
	c, err := d.Dial("udp4", addr)
	if err != nil {
		return "error"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func TestOnlyOwnedTableRulesRemovedNetns(t *testing.T) {
	if !inNetns(t) {
		return
	}
	add := func(r *netlink.Rule) {
		t.Helper()
		if err := netlink.RuleAdd(r); err != nil {
			t.Fatal(err)
		}
	}
	// Priority alone cannot distinguish old goto/nop rules from other owners.
	g := netlink.NewRule()
	g.Family, g.Priority, g.Goto, g.UIDRange = netlink.FAMILY_V4, 20260, 20270, netlink.NewRuleUIDRange(0, 0)
	add(g)
	nop := netlink.NewRule()
	nop.Family, nop.Priority, nop.Type = netlink.FAMILY_V4, 20270, unix.FR_ACT_NOP
	add(nop)
	inv := netlink.NewRule()
	inv.Family, inv.Priority, inv.Table, inv.IifName, inv.Invert = netlink.FAMILY_V4, 20262, Table, "lo", true
	add(inv)
	src := netlink.NewRule()
	src.Family, src.Priority, src.Table, src.IifName = netlink.FAMILY_V4, 20262, Table, "lo"
	src.Src = &net.IPNet{IP: net.IPv4(198, 18, 0, 0).To4(), Mask: net.CIDRMask(30, 32)}
	add(src)
	foreign := netlink.NewRule()
	foreign.Family, foreign.Priority, foreign.Table = netlink.FAMILY_V4, 20265, 254
	add(foreign)
	m := NewWith(kernel{}, &fw{}, "/proc/sys")
	if err := m.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	var left []netlink.Rule
	for _, r := range rules {
		if r.Priority >= 20260 && r.Priority <= 20279 {
			left = append(left, r)
		}
	}
	if len(left) != 3 {
		t.Fatalf("after cleanup: %v", left)
	}
	for _, rule := range left {
		if Owned(rule) {
			t.Fatalf("owned-table rule remained: %v", rule)
		}
	}
}

func TestCaptureHotspotNetns(t *testing.T) {
	if !inNetns(t) {
		return
	}
	makeTun(t, "ksu-proxy0")
	TetherDNSUID = 0
	d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "swlan0"}}
	if err := netlink.LinkAdd(d); err != nil {
		t.Fatal(err)
	}
	_ = netlink.LinkSetUp(d)
	f := &fw{}
	m := NewWith(kernel{}, f, "/proc/sys")
	plan := &Plan{TunName: "ksu-proxy0", Ranges: []apps.UIDRange{{Start: 0, End: 0}}, Hotspot: []string{"swlan*", "rmnet*"}, Bypass: DefaultBypass}
	if err := m.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	iif := 0
	for _, r := range ownedRules(t, netlink.FAMILY_V4) {
		if r.IifName == "swlan0" && r.Priority == DefaultBase+offsetHotspot {
			iif++
		}
	}
	if iif != 1 || f.ensured != 1 {
		t.Fatalf("hotspot rule=%d firewall ensured=%d", iif, f.ensured)
	}
	if st := m.Status(); len(st.Hotspot) != 1 {
		t.Fatalf("status hotspot = %v", st.Hotspot)
	}
	if err := m.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.removed == 0 {
		t.Fatal("firewall chain not removed on Clear")
	}
}

type flakyNetlink struct {
	kernelFake
	failRules int
}

type kernelFake struct {
	rules  []netlink.Rule
	routes []netlink.Route
	adds   int
}

func (k *kernelFake) RuleList(int) ([]netlink.Rule, error) { return k.rules, nil }
func (k *kernelFake) RuleAdd(r *netlink.Rule) error {
	k.adds++
	k.rules = append(k.rules, *r)
	return nil
}
func (k *kernelFake) RuleDel(*netlink.Rule) error { return nil }
func (k *kernelFake) RouteList(int, int) ([]netlink.Route, error) {
	return k.routes, nil
}
func (k *kernelFake) RouteAdd(r *netlink.Route) error { k.adds++; return nil }
func (k *kernelFake) RouteDel(*netlink.Route) error   { return nil }
func (k *kernelFake) LinkByName(string) (netlink.Link, error) {
	return nil, netlink.LinkNotFoundError{}
}
func (k *kernelFake) LinkList() ([]netlink.Link, error) { return nil, nil }
func (k *kernelFake) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

func (f *flakyNetlink) RuleList(fam int) ([]netlink.Rule, error) {
	if f.failRules > 0 {
		f.failRules--
		return nil, netlink.ErrDumpInterrupted
	}
	return f.kernelFake.RuleList(fam)
}

type brokenLinks struct{ kernelFake }

func (b *brokenLinks) LinkByName(string) (netlink.Link, error) { return nil, syscall.EBUSY }
func (b *brokenLinks) LinkList() ([]netlink.Link, error)       { return nil, syscall.EBUSY }

func TestLinkLookupFailureMakesNoChanges(t *testing.T) {
	k := &brokenLinks{}
	k.routes = []netlink.Route{{Table: Table, LinkIndex: 7, Priority: metricTun}}
	m := NewWith(k, &fw{}, t.TempDir())
	err := m.Apply(context.Background(), &Plan{TunName: "ksu-proxy0", Ranges: []apps.UIDRange{{Start: 10000, End: 10000}}, Hotspot: []string{"wlan*"}})
	if !errors.Is(err, ErrUnavailable) || k.adds != 0 {
		t.Fatalf("err=%v adds=%d", err, k.adds)
	}
}

func TestClearFailureIsRetried(t *testing.T) {
	k := &flakyNetlink{failRules: 100}
	m := NewWith(k, &fw{}, t.TempDir())
	if err := m.Clear(context.Background()); err == nil || !m.CleanupPending() {
		t.Fatalf("clear should fail and stay pending: %v", err)
	}
	k.failRules = 0
	if err := m.Clear(context.Background()); err != nil || m.CleanupPending() {
		t.Fatalf("retry: %v pending=%v", err, m.CleanupPending())
	}
}

type failingFW struct {
	fw
	fail bool
}

func (f *failingFW) Remove() error {
	f.removed++
	if f.fail {
		return errors.New("xtables lock")
	}
	return nil
}

func TestFirewallRemoveFailureKeepsCleanupPending(t *testing.T) {
	f := &failingFW{fail: true}
	m := NewWith(&kernelFake{}, f, t.TempDir())
	m.fwOn = true
	if err := m.Clear(context.Background()); err == nil || !m.CleanupPending() || !m.fwOn {
		t.Fatalf("firewall failure must keep cleanup pending: err=%v pending=%v fwOn=%v", err, m.CleanupPending(), m.fwOn)
	}
	f.fail = false
	if err := m.Clear(context.Background()); err != nil || m.CleanupPending() || m.fwOn {
		t.Fatalf("retry: %v pending=%v fwOn=%v", err, m.CleanupPending(), m.fwOn)
	}
}

func TestReconcileUnavailableMakesNoChanges(t *testing.T) {
	k := &flakyNetlink{failRules: 10}
	m := NewWith(k, &fw{}, t.TempDir())
	err := m.Apply(context.Background(), &Plan{TunName: "x", Ranges: []apps.UIDRange{{Start: 10000, End: 10000}}})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if k.adds != 0 {
		t.Fatal("must not modify kernel state when it cannot be read")
	}
	if m.Status().Unavailable != 1 {
		t.Fatal("unavailable streak not recorded")
	}
	k.failRules = 2
	if _, err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("interrupted dumps must be retried: %v", err)
	}
}

func TestRouteKeyNormalisesDefault(t *testing.T) {
	a := netlink.Route{Dst: nil, LinkIndex: 3, Priority: 10}
	b := netlink.Route{Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, LinkIndex: 3, Priority: 10, Type: unix.RTN_UNICAST}
	if routeKey(a) != routeKey(b) {
		t.Fatalf("%s != %s", routeKey(a), routeKey(b))
	}
}
