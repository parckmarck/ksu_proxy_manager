// Package clashapi talks to the Clash-compatible controller exposed by both
// Mihomo and sing-box.
package clashapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Client struct {
	Base   string
	Secret string
	HTTP   *http.Client
}

func New(addr, secret string) *Client {
	return &Client{
		Base:   "http://" + addr,
		Secret: secret,
		// Callers pass per-request contexts; this only caps delay tests, whose
		// own timeout may be up to 15 seconds.
		HTTP: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: false, MaxIdleConns: 4}},
	}
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("核心 API %d: %s", e.Status, e.Message) }

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: e.Message}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Version(ctx context.Context) (string, error) {
	var v struct {
		Version string `json:"version"`
		Meta    bool   `json:"meta"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		return "", err
	}
	return v.Version, nil
}

type Connection struct {
	ID       string         `json:"id"`
	Upload   int64          `json:"upload"`
	Download int64          `json:"download"`
	Start    string         `json:"start"`
	Chains   []string       `json:"chains"`
	Rule     string         `json:"rule"`
	Payload  string         `json:"rulePayload"`
	Metadata map[string]any `json:"metadata"`
}

type Connections struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Connections   []Connection `json:"connections"`
	Memory        int64        `json:"memory,omitempty"`
}

func (c *Client) Connections(ctx context.Context) (*Connections, error) {
	var out Connections
	if err := c.do(ctx, http.MethodGet, "/connections", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CloseConnection(ctx context.Context, id string) error {
	if id == "" {
		return c.do(ctx, http.MethodDelete, "/connections", nil, nil)
	}
	return c.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

type Proxy struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now,omitempty"`
	All     []string `json:"all,omitempty"`
	History []struct {
		Time  string `json:"time"`
		Delay int    `json:"delay"`
	} `json:"history,omitempty"`
}

func (c *Client) Proxies(ctx context.Context) (map[string]Proxy, error) {
	var out struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := c.do(ctx, http.MethodGet, "/proxies", nil, &out); err != nil {
		return nil, err
	}
	return out.Proxies, nil
}

func (c *Client) Select(ctx context.Context, group, member string) error {
	return c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": member}, nil)
}

// Delay measures latency through one outbound; timeout is in milliseconds.
func (c *Client) Delay(ctx context.Context, name, testURL string, timeout int) (int, error) {
	q := url.Values{}
	q.Set("url", testURL)
	q.Set("timeout", strconv.Itoa(timeout))
	var out struct {
		Delay int `json:"delay"`
	}
	if err := c.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(name)+"/delay?"+q.Encode(), nil, &out); err != nil {
		return 0, err
	}
	return out.Delay, nil
}

func (c *Client) SetMode(ctx context.Context, mode string) error {
	return c.do(ctx, http.MethodPatch, "/configs", map[string]string{"mode": mode}, nil)
}

// UpdateRuleProvider makes Mihomo re-read a rule provider file.
func (c *Client) UpdateRuleProvider(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPut, "/providers/rules/"+url.PathEscape(name), nil, nil)
}
