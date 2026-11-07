package capture

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// iptables manages the KPM_FWD chain that lets hotspot traffic traverse the TUN.
type iptables struct {
	run func(string, ...string) (string, error)
}

func (f iptables) command(bin string, args ...string) (string, error) {
	if f.run != nil {
		return f.run(bin, args...)
	}
	return runIPT(bin, args...)
}

func runIPT(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	full := append([]string{"-w", "5"}, args...)
	out, err := exec.CommandContext(ctx, bin, full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (f iptables) Ensure(tun string, v6 bool) error {
	bins := []string{"iptables"}
	if v6 {
		bins = append(bins, "ip6tables")
	}
	for _, bin := range bins {
		if f.run == nil {
			if _, err := exec.LookPath(bin); err != nil {
				return fmt.Errorf("缺少 %s", bin)
			}
		}
		_, _ = f.command(bin, "-t", "filter", "-N", ForwardChain)
		for _, dir := range []string{"-i", "-o"} {
			if _, err := f.command(bin, "-t", "filter", "-C", ForwardChain, dir, tun, "-j", "ACCEPT"); err != nil {
				if out, err := f.command(bin, "-t", "filter", "-A", ForwardChain, dir, tun, "-j", "ACCEPT"); err != nil {
					return fmt.Errorf("%s -A: %v %s", bin, err, out)
				}
			}
		}
		rules, err := f.command(bin, "-t", "filter", "-S", "FORWARD")
		if err != nil {
			return fmt.Errorf("%s -S FORWARD: %w", bin, err)
		}
		index, bandwidth, jump := 0, 0, 0
		for _, line := range strings.Split(rules, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || fields[1] != "FORWARD" {
				continue
			}
			index++
			for i := 2; i+1 < len(fields); i++ {
				if fields[i] == "-j" && fields[i+1] == "bw_FORWARD" {
					bandwidth = index
				}
			}
			if len(fields) == 4 && fields[2] == "-j" && fields[3] == ForwardChain && jump == 0 {
				jump = index
			}
		}
		if jump == 0 || jump < bandwidth {
			if out, err := f.command(bin, "-t", "filter", "-I", "FORWARD", strconv.Itoa(bandwidth+1), "-j", ForwardChain); err != nil {
				return fmt.Errorf("%s -I FORWARD: %v %s", bin, err, out)
			}
			if jump != 0 {
				if out, err := f.command(bin, "-t", "filter", "-D", "FORWARD", strconv.Itoa(jump)); err != nil {
					return fmt.Errorf("%s -D FORWARD: %v %s", bin, err, out)
				}
			}
		}
	}
	if !v6 {
		return f.removeChain("ip6tables")
	}
	return nil
}

func (f iptables) Remove() error {
	return errors.Join(f.removeChain("iptables"), f.removeChain("ip6tables"))
}

// removeChain detaches and deletes the chain; a chain that does not exist is
// not an error, anything else is reported so that cleanup is retried.
func (f iptables) removeChain(bin string) error {
	if f.run == nil {
		if _, err := exec.LookPath(bin); err != nil {
			return nil
		}
	}
	for i := 0; i < 8; i++ {
		if _, err := f.command(bin, "-t", "filter", "-D", "FORWARD", "-j", ForwardChain); err != nil {
			break
		}
	}
	if out, err := f.command(bin, "-t", "filter", "-L", ForwardChain, "-n"); err != nil {
		if strings.Contains(out, "No chain/target/match") || strings.Contains(out, "does not exist") {
			return nil
		}
		return fmt.Errorf("%s -L %s: %v %s", bin, ForwardChain, err, out)
	}
	if out, err := f.command(bin, "-t", "filter", "-F", ForwardChain); err != nil {
		return fmt.Errorf("%s -F %s: %v %s", bin, ForwardChain, err, out)
	}
	if out, err := f.command(bin, "-t", "filter", "-X", ForwardChain); err != nil {
		return fmt.Errorf("%s -X %s: %v %s", bin, ForwardChain, err, out)
	}
	return nil
}
