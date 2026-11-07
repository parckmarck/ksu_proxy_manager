package capture

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestForeignActionRulesAreNotOwned(t *testing.T) {
	for _, action := range []uint8{unix.FR_ACT_UNREACHABLE, unix.FR_ACT_PROHIBIT, unix.FR_ACT_BLACKHOLE, unix.FR_ACT_NOP, unix.FR_ACT_GOTO} {
		rule := netlink.NewRule()
		rule.Priority, rule.Type = 20265, action
		if action == unix.FR_ACT_GOTO {
			rule.Goto = 20270
		}
		if Owned(*rule) {
			t.Errorf("foreign action %d in the module priority band was claimed", action)
		}
	}
}

type slowFirewall struct {
	started chan struct{}
	release chan struct{}
}

func (f *slowFirewall) Ensure(string, bool) error {
	close(f.started)
	<-f.release
	return errors.New("IPv6 setup failed after IPv4 succeeded")
}
func (f *slowFirewall) Remove() error { return nil }

type hotspotKernel struct{ kernelFake }

func (*hotspotKernel) LinkList() ([]netlink.Link, error) {
	return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ap0", Flags: net.FlagUp}}}, nil
}

func TestFirewallWorkDoesNotBlockStatus(t *testing.T) {
	firewall := &slowFirewall{started: make(chan struct{}), release: make(chan struct{})}
	manager := NewWith(&hotspotKernel{}, firewall, t.TempDir())
	finished := make(chan error, 1)
	go func() {
		finished <- manager.Apply(context.Background(), &Plan{TunName: "ksu-proxy0", Hotspot: []string{"ap0"}, IPv6: true})
	}()
	<-firewall.started
	status := make(chan Status, 1)
	go func() { status <- manager.Status() }()
	select {
	case <-status:
	case <-time.After(time.Second):
		close(firewall.release)
		<-finished
		t.Fatal("status was blocked on iptables")
	}
	close(firewall.release)
	if err := <-finished; !errors.Is(err, ErrFirewall) {
		t.Fatal("partial firewall failure was not classified", err)
	}
	if !manager.fwOn {
		t.Fatal("partial firewall setup was forgotten")
	}
	if err := manager.Apply(context.Background(), nil); err != nil || manager.fwOn {
		t.Fatal("partial setup was not cleaned after disabling hotspot", err)
	}
}

func TestHotspotEnsureDoesNotFlushAndFollowsBandwidth(t *testing.T) {
	var commands []string
	firewall := iptables{run: func(_ string, args ...string) (string, error) {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if strings.Contains(command, "-S FORWARD") {
			return "-P FORWARD ACCEPT\n-A FORWARD -j bw_FORWARD\n-A FORWARD -j KPM_FWD", nil
		}
		return "", nil
	}}
	if err := firewall.Ensure("ksu-proxy0", true); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		for _, mutation := range []string{" -F ", " -A ", " -I ", " -D "} {
			if strings.Contains(command, mutation) {
				t.Fatalf("idempotent Ensure mutated an existing chain: %s", command)
			}
		}
	}
	commands = nil
	firewall.run = func(_ string, args ...string) (string, error) {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if strings.Contains(command, "-S FORWARD") {
			return "-A FORWARD -j bw_FORWARD", nil
		}
		return "", nil
	}
	if err := firewall.Ensure("ksu-proxy0", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "-I FORWARD 2 -j KPM_FWD") {
		t.Fatal("new chain was not placed after bandwidth accounting")
	}
}

func TestFakeIPv6WinsOverLANBypass(t *testing.T) {
	fake := netip.MustParsePrefix("fc00::/18")
	plan := &Plan{IPv6: true, FailClosed: true, Bypass: LANBypass, KeepInTun: []netip.Prefix{fake}}
	for _, blocked := range []bool{false, true} {
		plan.Blocked = blocked
		routes := desiredRoutes(plan, netlink.FAMILY_V6, 7, Table)
		found := false
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == fake.String() {
				found = true
				if blocked && route.Type != unix.RTN_UNREACHABLE {
					t.Fatal("recovery plan routed through the old core")
				}
				if !blocked && route.LinkIndex != 7 {
					t.Fatal("fake-ip did not have a specific TUN route")
				}
			}
		}
		if !found {
			t.Fatal("ULA bypass swallowed the fake-ip range")
		}
	}
}

func TestReconcileKeepsFirewallCleanupPending(t *testing.T) {
	firewall := &failingFW{fail: true}
	manager := NewWith(&kernelFake{}, firewall, t.TempDir())
	if err := manager.Clear(context.Background()); err == nil {
		t.Fatal("expected initial firewall cleanup failure")
	}
	_, _ = manager.Reconcile(context.Background())
	if !manager.CleanupPending() {
		t.Fatal("routing reconcile forgot the failed firewall cleanup")
	}
}

type interruptedFirewall struct {
	ensures int
}

func (f *interruptedFirewall) Ensure(string, bool) error {
	f.ensures++
	return nil
}

func (*interruptedFirewall) Remove() error {
	return errors.New("cleanup interrupted after detaching the chain")
}

func TestHotspotReenableRetriesInterruptedCleanup(t *testing.T) {
	firewall := &interruptedFirewall{}
	manager := NewWith(&hotspotKernel{}, firewall, t.TempDir())
	plan := &Plan{TunName: "ksu-proxy0", Hotspot: []string{"ap0"}, IPv6: true}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), nil); !errors.Is(err, ErrFirewall) {
		t.Fatal("failed cleanup was not retained", err)
	}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if firewall.ensures != 2 || manager.CleanupPending() {
		t.Fatalf("re-enable left a partially deleted firewall: ensures=%d pending=%v", firewall.ensures, manager.CleanupPending())
	}
}
