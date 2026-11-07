package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/netx"
	"ksu_proxy_manager/internal/subscription"
)

func TestMetadataRefreshKeepsSubscriptionPreviewUsable(t *testing.T) {
	e := newEnv(t, false, nil)
	var created struct{ ID string }
	e.mustOK("POST", "/api/v1/subscriptions", map[string]any{
		"subscription": map[string]any{"name": "Audit"}, "url": "https://example.com/sub",
	}, &created)
	parsed := subscription.Parse([]byte("trojan://audit-password@example.com:443#Node"))
	subscription.AssignSubscriptionIDs(created.ID, parsed.Nodes)
	p := &preview{SubID: created.ID, Revision: e.d.store.Revision(), Nodes: parsed.Nodes}
	first, _, err := e.d.commitNodes(p)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := e.d.store.Backups()
	p.Revision = first.Revision
	for i := 0; i < 12; i++ {
		e.d.recordSubError(created.ID, errors.New("offline"))
	}
	after, _ := e.d.store.Backups()
	if e.d.store.Revision() != first.Revision || len(before) != len(after) {
		t.Fatal("background error writes consumed revisions or backup history")
	}
	p.Usage = &config.Usage{Download: 42}
	next, _, err := e.d.commitNodes(p)
	if err != nil || next.Revision != first.Revision {
		t.Fatal("metadata-only refresh invalidated its preview", err)
	}
	if next.SubscriptionByID(created.ID).LastError != "" || next.SubscriptionByID(created.ID).Usage.Download != 42 {
		t.Fatal("metadata was not persisted")
	}
}

func TestSubscriptionRetryBackoffIsBounded(t *testing.T) {
	for i, want := range []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute, 320 * time.Minute, 6 * time.Hour, 6 * time.Hour} {
		if got := subscriptionRetryDelay(i + 1); got != want {
			t.Errorf("failure %d: delay=%v, want=%v", i+1, got, want)
		}
	}
}

func TestProxyFallbackRevalidatesAfterPoisonedDirectDNS(t *testing.T) {
	called := 0
	err := tryClients(context.Background(), []fetchClient{{label: "direct"}, {label: "proxy"}}, func(*http.Client) error {
		called++
		if called == 1 {
			return netx.ErrNotPublic
		}
		return nil
	})
	if err != nil || called != 2 {
		t.Fatal("independently checked proxy fallback was suppressed", err, called)
	}
}

func TestBrowserCannotExecuteLocalCoreImportsOrRestorePaths(t *testing.T) {
	e := newEnv(t, false, nil)
	const key = "audit-only-browser-key"
	e.d.webKey.Store(key)
	handler := e.d.tcpGuard(e.d.apiMux(), 9097)
	for _, test := range []struct{ path, body string }{
		{"/api/v1/cores/import", `{"path":"/sdcard/Download/audit-core"}`},
		{"/api/v1/backup/restore", `{"path":"/sdcard/Download/audit-config.json"}`},
	} {
		request := httptest.NewRequest("POST", test.path, strings.NewReader(test.body))
		request.Host = "127.0.0.1:9097"
		request.Header.Set("Authorization", "Bearer "+key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s: local import reached the filesystem over TCP: %d %s", test.path, response.Code, response.Body.String())
		}
	}
}
