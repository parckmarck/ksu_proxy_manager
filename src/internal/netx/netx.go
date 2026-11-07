// Package netx builds HTTP clients for downloads. Direct clients resolve names
// with explicit DNS servers (Android has no resolv.conf for Go) and refuse
// non-public destinations; proxied clients go through the core's local
// authenticated mixed inbound.
package netx

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed ca_bundle.pem
var bundledCAs []byte

var (
	rootsOnce sync.Once
	roots     *x509.CertPool
)

// RootCAs loads the Android system store, then the host store, then the bundle.
func RootCAs() *x509.CertPool {
	rootsOnce.Do(func() {
		pool := x509.NewCertPool()
		n := 0
		for _, dir := range []string{"/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts"} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err == nil && pool.AppendCertsFromPEM(b) {
					n++
				}
			}
		}
		if n == 0 {
			if sys, err := x509.SystemCertPool(); err == nil && sys != nil {
				pool = sys
			}
			pool.AppendCertsFromPEM(bundledCAs)
		}
		roots = pool
	})
	return roots
}

// PublicAddr rejects loopback, private, link-local, CGNAT, multicast and
// documentation ranges.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2001::/32"),
}

// Resolver queries the given DNS servers over UDP/TCP port 53.
func Resolver(servers []string) *net.Resolver {
	var addrs []string
	for _, s := range servers {
		if a, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, net.JoinHostPort(a.String(), "53"))
		}
	}
	if len(addrs) == 0 {
		addrs = []string{"223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"}
	}
	var mu sync.Mutex
	next := 0
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			mu.Lock()
			addr := addrs[next%len(addrs)]
			next++
			mu.Unlock()
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

type Options struct {
	DNS          []string
	AllowPrivate bool
	Proxy        *url.URL
	// Timeout bounds a whole request including the body; 0 means no limit.
	Timeout   time.Duration
	AllowHTTP bool
}

// ErrNotPublic is returned when a download targets a non-public address.
var ErrNotPublic = errors.New("目标地址不是公网地址，已拒绝")

// NewClient builds an HTTP client according to opt.
func NewClient(opt Options) *http.Client {
	if opt.Proxy != nil {
		return newClient(opt, proxyLookup(opt.Proxy))
	}
	return newClient(opt, Resolver(opt.DNS).LookupNetIP)
}

func newClient(opt Options, lookup func(context.Context, string, string) ([]netip.Addr, error)) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{RootCAs: RootCAs(), MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
		ForceAttemptHTTP2:     true,
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		var candidates []netip.Addr
		if literal, err := netip.ParseAddr(host); err == nil {
			candidates = []netip.Addr{literal}
		} else {
			candidates, err = lookup(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("解析 %s 失败: %w", host, err)
			}
		}
		for _, candidate := range candidates {
			if !opt.AllowPrivate && !PublicAddr(candidate) {
				return nil, ErrNotPublic
			}
		}
		var lastErr error = ErrNotPublic
		for _, candidate := range candidates {
			pinned := net.JoinHostPort(candidate.Unmap().String(), port)
			var connection net.Conn
			if opt.Proxy != nil {
				connection, err = dialProxy(ctx, dialer, opt.Proxy, pinned)
			} else {
				connection, err = dialer.DialContext(ctx, network, pinned)
			}
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return &http.Client{
		Transport: tr,
		Timeout:   opt.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("重定向次数过多")
			}
			if req.URL.Scheme != "https" && !(opt.AllowHTTP && req.URL.Scheme == "http") {
				return errors.New("拒绝重定向到非 HTTPS 地址")
			}
			if err := checkHostLiteral(req.URL, opt.AllowPrivate); err != nil {
				return err
			}
			return nil
		},
	}
}

type proxyConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *proxyConnection) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}

func dialProxy(ctx context.Context, dialer *net.Dialer, proxy *url.URL, address string) (net.Conn, error) {
	if proxy.Scheme != "http" {
		return nil, errors.New("本机代理必须使用 HTTP")
	}
	connection, err := dialer.DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline := time.Now().Add(15 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := connection.SetDeadline(deadline); err != nil {
		connection.Close()
		return nil, err
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: address}, Host: address, Header: make(http.Header)}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		credential := proxy.User.Username() + ":" + password
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credential)))
	}
	if err := request.Write(connection); err != nil {
		connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		connection.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		connection.Close()
		response.Body.Close()
		return nil, fmt.Errorf("本机代理拒绝 CONNECT（HTTP %d）", response.StatusCode)
	}
	if !stop() || ctx.Err() != nil {
		connection.Close()
		return nil, ctx.Err()
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		return nil, err
	}
	return &proxyConnection{Conn: connection, reader: reader}, nil
}

// checkHostLiteral rejects private literals before direct or proxied requests.
func checkHostLiteral(u *url.URL, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return ErrNotPublic
	}
	if a, err := netip.ParseAddr(h); err == nil && !PublicAddr(a) {
		return ErrNotPublic
	}
	return nil
}

// CheckURL validates a URL before any request is made.
func CheckURL(raw string, allowHTTP, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("URL 无效")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("只允许 HTTPS 地址")
	}
	if err := checkHostLiteral(u, allowPrivate); err != nil {
		return nil, err
	}
	return u, nil
}
