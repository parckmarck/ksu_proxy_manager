package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/netx"
	"ksu_proxy_manager/internal/render"
	"ksu_proxy_manager/internal/subscription"
)

// fetchClient is an HTTP client labelled with its route for error messages.
type fetchClient struct {
	label string
	*http.Client
}

// clients returns the HTTP clients to try in order for a download mode.
// timeout bounds a whole request; 0 leaves it to the caller (core downloads
// use a stall watchdog instead).
func (d *Daemon) clients(mode string, allowHTTP, allowPrivate bool, timeout time.Duration) ([]fetchClient, error) {
	cfg, _ := d.store.Snapshot()
	direct := func() fetchClient {
		return fetchClient{"直连", netx.NewClient(netx.Options{DNS: ipServers(cfg.DNS.Direct), AllowHTTP: allowHTTP, AllowPrivate: allowPrivate, Timeout: timeout})}
	}
	viaProxy := func() (fetchClient, bool) {
		if u := d.engine.ProxyURL(); u != nil {
			return fetchClient{"经代理", netx.NewClient(netx.Options{Proxy: u, DNS: ipServers(cfg.DNS.Direct), AllowHTTP: allowHTTP, AllowPrivate: allowPrivate, Timeout: timeout})}, true
		}
		return fetchClient{}, false
	}
	switch mode {
	case "direct":
		return []fetchClient{direct()}, nil
	case "proxy":
		if c, ok := viaProxy(); ok {
			return []fetchClient{c}, nil
		}
		return nil, unavailable("经代理下载需要核心处于运行状态")
	default:
		out := []fetchClient{direct()}
		if c, ok := viaProxy(); ok {
			out = append(out, c)
		}
		return out, nil
	}
}

func ipServers(list []string) []string {
	var out []string
	for _, s := range list {
		if srv, err := config.ParseDNSServer(s); err == nil && srv.IsIP() {
			out = append(out, srv.Host)
		}
	}
	return out
}

// Every transport resolves, validates all answers, and pins its own addresses.
// A proxy retry is safe even when a poisoned local DNS answer was rejected.
func tryClients(ctx context.Context, clients []fetchClient, fn func(*http.Client) error) error {
	var errs []error
	for _, c := range clients {
		err := fn(c.Client)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		errs = append(errs, fmt.Errorf("%s: %w", c.label, err))
	}
	return errors.Join(errs...)
}

// downloadRulesets fetches rule sets for engine using the configured mode.
func (d *Daemon) downloadRulesets(ctx context.Context, engineName string, ids []render.RulesetID) error {
	cfg, _ := d.store.Snapshot()
	clients, err := d.clients(cfg.Settings.Download.Mode, false, false, 5*time.Minute)
	if err != nil {
		return err
	}
	var failed []string
	for _, id := range ids {
		err := tryClients(ctx, clients, func(c *http.Client) error {
			return d.rulesets.Download(ctx, c, engineName, id)
		})
		if err != nil {
			failed = append(failed, id.Tag()+": "+err.Error())
			d.log.Warn("ruleset", "规则集下载失败", "ruleset", id.Tag(), "error", err)
			continue
		}
		d.log.Info("ruleset", "规则集已更新", "engine", engineName, "ruleset", id.Tag())
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "；"))
	}
	return nil
}

// privateHost reports whether a subscription host is explicitly local.
func privateHost(u *url.URL) bool {
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "localhost" || strings.HasSuffix(h, ".lan") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && !netx.PublicAddr(a)
}

// requestError strips the request URL (which may carry tokens in its path or
// query) from transport errors.
func requestError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

type fetched struct {
	Body  []byte
	Usage *config.Usage
}

// fetchSubscription downloads a subscription body with the chosen route.
func (d *Daemon) fetchSubscription(ctx context.Context, sub config.Subscription, rawURL string) (*fetched, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, badRequest("订阅地址无效")
	}
	local := privateHost(u)
	mode := "auto"
	if sub.ViaProxy {
		mode = "proxy"
	}
	if local {
		mode = "direct"
	}
	if _, err := netx.CheckURL(rawURL, true, local); err != nil {
		return nil, badRequest("%v", err)
	}
	clients, err := d.clients(mode, true, local, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	ua := sub.UserAgent
	if ua == "" {
		ua = "clash.meta"
	}
	var res *fetched
	err = tryClients(ctx, clients, func(c *http.Client) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return errors.New("订阅地址无效")
		}
		req.Header.Set("User-Agent", ua)
		resp, err := c.Do(req)
		if err != nil {
			return requestError(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, subscription.MaxSize+1))
		if err != nil {
			return err
		}
		if len(b) > subscription.MaxSize {
			return errors.New("订阅内容超过 8 MiB")
		}
		res = &fetched{Body: b, Usage: parseUserInfo(resp.Header.Get("Subscription-Userinfo"))}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// parseUserInfo reads "upload=1; download=2; total=3; expire=4". Values are
// bounded so that a hostile header cannot overflow int64 or break clients.
func parseUserInfo(h string) *config.Usage {
	if h == "" {
		return nil
	}
	// 2^53 is exact in JSON/JavaScript numbers; the expiry cap is 3000-01-01.
	const maxBytes = float64(1 << 53)
	const maxExpire = float64(32503680000)
	u := &config.Usage{}
	ok := false
	for _, part := range strings.Split(h, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || n < 0 || n != n {
			continue
		}
		switch strings.ToLower(k) {
		case "upload":
			u.Upload, ok = int64(min(n, maxBytes)), true
		case "download":
			u.Download, ok = int64(min(n, maxBytes)), true
		case "total":
			u.Total, ok = int64(min(n, maxBytes)), true
		case "expire":
			if n > maxExpire {
				continue
			}
			u.Expire, ok = int64(n), true
		}
	}
	if !ok {
		return nil
	}
	return u
}
