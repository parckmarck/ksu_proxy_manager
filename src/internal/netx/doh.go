package netx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var proxyDNSEndpoints = []struct {
	host, path string
	addresses  []string
}{
	{"cloudflare-dns.com", "/dns-query", []string{"1.1.1.1", "2606:4700:4700::1111", "1.0.0.1", "2606:4700:4700::1001"}},
	{"dns.google", "/resolve", []string{"8.8.8.8", "2001:4860:4860::8888", "8.8.4.4", "2001:4860:4860::8844"}},
}

// Bootstrap only the DoH endpoint with fixed public addresses. Both the DNS
// exchange and the subsequent IP-pinned download use the authenticated core,
// without a dependency on local DNS or weakening the destination policy.
func proxyLookup(proxy *url.URL) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		var failures []error
		for _, endpoint := range proxyDNSEndpoints {
			for _, address := range endpoint.addresses {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				attempt, cancel := context.WithTimeout(ctx, 6*time.Second)
				client := newClient(Options{Proxy: proxy, Timeout: 6 * time.Second},
					func(_ context.Context, _, name string) ([]netip.Addr, error) {
						if name != endpoint.host {
							return nil, errors.New("代理 DNS 引导地址无效")
						}
						return []netip.Addr{netip.MustParseAddr(address)}, nil
					})
				addresses, err := lookupDoH(attempt, client, "https://"+endpoint.host+endpoint.path, network, host)
				client.CloseIdleConnections()
				cancel()
				if err == nil {
					return addresses, nil
				}
				failures = append(failures, err)
			}
		}
		return nil, fmt.Errorf("代理 DNS 入口均不可用: %w", errors.Join(failures...))
	}
}

func lookupDoH(ctx context.Context, client *http.Client, endpoint, network, host string) ([]netip.Addr, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\\x00\r\n") {
		return nil, errors.New("DNS 主机名无效")
	}
	types := []string{"A", "AAAA"}
	switch network {
	case "ip4":
		types = []string{"A"}
	case "ip6":
		types = []string{"AAAA"}
	case "ip":
	default:
		return nil, errors.New("DNS 地址类型无效")
	}
	var addresses []netip.Addr
	for _, recordType := range types {
		query := url.Values{"name": {host}, "type": {recordType}}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/dns-json")
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if response.StatusCode != http.StatusOK || len(data) > 64<<10 {
			return nil, fmt.Errorf("代理 DNS 响应无效（HTTP %d）", response.StatusCode)
		}
		var answer struct {
			Status    *int `json:"Status"`
			Truncated bool `json:"TC"`
			Answer    []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.Unmarshal(data, &answer); err != nil || answer.Status == nil || *answer.Status != 0 || answer.Truncated {
			return nil, errors.New("代理 DNS 查询失败或响应不完整")
		}
		for _, record := range answer.Answer {
			if record.Type != 1 && record.Type != 28 {
				continue
			}
			address, err := netip.ParseAddr(record.Data)
			if err != nil || (record.Type == 1) != address.Is4() {
				return nil, errors.New("代理 DNS 返回无效地址")
			}
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("代理 DNS 未返回可用地址")
	}
	return addresses, nil
}
