package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/cores"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/render"
	"ksu_proxy_manager/internal/subscription"
)

type testEnv struct {
	t      *testing.T
	d      *Daemon
	layout paths.Layout
	http   *http.Client
}

func writeModuleProp(t *testing.T, l paths.Layout) {
	t.Helper()
	if err := os.MkdirAll(l.ModuleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prop := "id=ksu_proxy_manager\nname=KSU Proxy Manager\nversion=2.0.0\nversionCode=20000\nauthor=test\ndescription=old\n"
	if err := os.WriteFile(l.ModuleProp(), []byte(prop), 0o644); err != nil {
		t.Fatal(err)
	}
}

// testEngineTick lets individual tests speed up engine maintenance.
var testEngineTick time.Duration

func newEnv(t *testing.T, capture bool, prepare func(l paths.Layout)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	l := paths.Layout{ModuleDir: filepath.Join(dir, "m"), DataDir: filepath.Join(dir, "d")}
	writeModuleProp(t, l)
	if prepare != nil {
		if err := l.Ensure(); err != nil {
			t.Fatal(err)
		}
		prepare(l)
	}
	d, err := New(Options{Layout: l, CaptureEnabled: capture, ABI: ABI(), EngineTick: testEngineTick})
	if err != nil {
		t.Fatal(err)
	}
	d.apps.PackagesList = filepath.Join(dir, "packages.list")
	d.apps.UserDir = filepath.Join(dir, "users")
	if err := d.Serve(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Shutdown(30 * time.Second) })
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dd net.Dialer
		return dd.DialContext(ctx, "unix", l.Socket())
	}}
	return &testEnv{t: t, d: d, layout: l, http: &http.Client{Transport: tr, Timeout: 3 * time.Minute}}
}

// call performs a request and decodes the JSON response into out.
func (e *testEnv) call(method, path string, in any, out any) int {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			e.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://kpm"+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode
}

func (e *testEnv) mustOK(method, path string, in any, out any) {
	e.t.Helper()
	var raw json.RawMessage
	if st := e.call(method, path, in, &raw); st != http.StatusOK {
		e.t.Fatalf("%s %s: HTTP %d %s", method, path, st, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatal(err)
		}
	}
}

// waitTask polls a task until it finishes and returns it.
func (e *testEnv) waitTask(id string) Task {
	e.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		var t Task
		e.mustOK("GET", "/api/v1/tasks/"+id, nil, &t)
		if t.State != TaskRunning {
			return t
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.t.Fatalf("task %s timed out", id)
	return Task{}
}

func TestAPIStatusAndValidation(t *testing.T) {
	e := newEnv(t, false, nil)
	var st struct {
		Daemon struct {
			Version string `json:"version"`
		} `json:"daemon"`
		Core struct {
			State string `json:"state"`
		} `json:"core"`
		Revision int64 `json:"revision"`
	}
	e.mustOK("GET", "/api/v1/status", nil, &st)
	if st.Daemon.Version == "" {
		t.Fatal("missing version")
	}
	// Invalid settings are rejected with the field path.
	var settings struct {
		Settings map[string]any `json:"settings"`
	}
	e.mustOK("GET", "/api/v1/settings", nil, &settings)
	settings.Settings["mtu"] = 10
	var apiErr struct {
		Error APIError `json:"error"`
	}
	if code := e.call("PUT", "/api/v1/settings", settings.Settings, &apiErr); code != 400 || apiErr.Error.Field != "settings.mtu" {
		t.Fatalf("want 400 settings.mtu, got %d %+v", code, apiErr)
	}
	// Unknown fields are rejected.
	settings.Settings["mtu"] = 1500
	settings.Settings["bogus"] = true
	if code := e.call("PUT", "/api/v1/settings", settings.Settings, &apiErr); code != 400 {
		t.Fatalf("unknown field accepted: %d", code)
	}
	delete(settings.Settings, "bogus")
	// Stale revisions conflict.
	if code := e.call("PUT", fmt.Sprintf("/api/v1/settings?rev=%d", st.Revision+5), settings.Settings, &apiErr); code != 409 {
		t.Fatalf("want 409, got %d", code)
	}
	if code := e.call("PUT", "/api/v1/settings?rev=abc", settings.Settings, &apiErr); code != 409 {
		t.Fatalf("invalid rev must conflict, got %d", code)
	}
	var saved saved
	e.mustOK("PUT", fmt.Sprintf("/api/v1/settings?rev=%d", st.Revision), settings.Settings, &saved)
	if saved.Revision != st.Revision+1 {
		t.Fatalf("revision not bumped: %+v", saved)
	}
	if code := e.call("GET", "/api/v1/nope", nil, &apiErr); code != 404 {
		t.Fatalf("want 404, got %d", code)
	}
	// module.prop reflects the state without losing other keys.
	b, _ := os.ReadFile(e.layout.ModuleProp())
	if !strings.Contains(string(b), "versionCode=20000") || !strings.Contains(string(b), "description=") {
		t.Fatalf("module.prop damaged: %s", b)
	}
}

func TestAPINodesNeverExposeSecrets(t *testing.T) {
	e := newEnv(t, false, nil)
	const secret = "s3cr3t-password-value"
	node := map[string]any{"name": "香港 01", "type": "shadowsocks", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "udp": true}
	var created struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/nodes", map[string]any{"node": node, "secrets": map[string]string{"password": secret}}, &created)
	var raw json.RawMessage
	e.mustOK("GET", "/api/v1/nodes", nil, &raw)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("secret leaked in node list")
	}
	var list struct {
		Nodes []struct {
			ID      string          `json:"id"`
			Secrets map[string]bool `json:"secrets"`
		} `json:"nodes"`
	}
	_ = json.Unmarshal(raw, &list)
	if len(list.Nodes) != 1 || !list.Nodes[0].Secrets["password"] {
		t.Fatalf("unexpected nodes: %s", raw)
	}
	e.mustOK("GET", "/api/v1/config", nil, &raw)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("secret leaked in config")
	}
	e.mustOK("GET", "/api/v1/backup", nil, &raw)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("secret leaked in backup without secrets")
	}
	e.mustOK("GET", "/api/v1/backup?secrets=1", nil, &raw)
	if !bytes.Contains(raw, []byte(secret)) {
		t.Fatal("backup with secrets lacks the secret")
	}
	// Updating without secrets keeps them; wrong secret fields are rejected.
	node["name"] = "香港 02"
	e.mustOK("PUT", "/api/v1/nodes/"+created.ID, map[string]any{"node": node}, nil)
	_, sec := e.d.store.Snapshot()
	if sec.NodeSecret(created.ID, "password") != secret {
		t.Fatal("secret lost on update")
	}
	var apiErr struct {
		Error APIError `json:"error"`
	}
	if code := e.call("PUT", "/api/v1/nodes/"+created.ID, map[string]any{"node": node, "secrets": map[string]string{"uuid": "x"}}, &apiErr); code != 400 {
		t.Fatalf("foreign secret field accepted: %d", code)
	}
	// Copy duplicates secrets under a new ID.
	var cp struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/nodes/"+created.ID+"/copy", nil, &cp)
	_, sec = e.d.store.Snapshot()
	if cp.ID == created.ID || sec.NodeSecret(cp.ID, "password") != secret {
		t.Fatal("copy did not duplicate secrets")
	}
	// Groups referencing a node lose the reference when it is deleted.
	var g struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/groups", map[string]any{"name": "手动", "type": "select", "nodes": []string{created.ID, cp.ID}, "selected": "node:" + created.ID}, &g)
	e.mustOK("DELETE", "/api/v1/nodes/"+created.ID, nil, nil)
	cfg, sec := e.d.store.Snapshot()
	grp := cfg.GroupByID(g.ID)
	if grp == nil || len(grp.Nodes) != 1 || grp.Selected != "" {
		t.Fatalf("group not detached: %+v", grp)
	}
	if _, ok := sec.Nodes[created.ID]; ok {
		t.Fatal("secrets of deleted node kept")
	}
	// A group used by routing cannot be deleted.
	if code := e.call("DELETE", "/api/v1/groups/proxy", nil, &apiErr); code != 400 {
		t.Fatalf("final group deleted: %d", code)
	}
	var groups struct {
		Members map[string][]string `json:"members"`
	}
	e.mustOK("GET", "/api/v1/groups", nil, &groups)
	if len(groups.Members[g.ID]) != 1 || groups.Members[g.ID][0] != "node:"+cp.ID {
		t.Fatalf("members: %+v", groups.Members)
	}
	var proxies struct {
		Running bool `json:"running"`
		Groups  []struct {
			ID      string `json:"id"`
			Members []struct {
				Ref  string `json:"ref"`
				Name string `json:"name"`
			} `json:"members"`
		} `json:"groups"`
	}
	e.mustOK("GET", "/api/v1/proxies", nil, &proxies)
	if proxies.Running || len(proxies.Groups) != 3 {
		t.Fatalf("proxies: %+v", proxies)
	}
}

func TestAPIImportAndSubscriptionFlow(t *testing.T) {
	e := newEnv(t, false, nil)
	var imp struct {
		Added  int `json:"added"`
		Issues []struct {
			Message string `json:"message"`
		} `json:"issues"`
	}
	text := "trojan://pw1@example.com:443?sni=example.com#T1\nvless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@example.org:443?security=tls&type=ws&path=%2Fws#V1\nbogus://x\n"
	e.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": text}, &imp)
	if imp.Added != 2 || len(imp.Issues) != 1 {
		t.Fatalf("import: %+v", imp)
	}

	body := "ss://YWVzLTEyOC1nY206cGFzcw@5.6.7.8:8388#S1\ntrojan://pw2@sub.example.com:443#S2\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "clash.meta" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=1073741824; expire=1900000000")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	var created struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/subscriptions", map[string]any{"subscription": map[string]any{"name": "机场"}, "url": srv.URL + "/sub?token=abc"}, &created)
	var subs struct {
		Subscriptions []struct {
			URLHost string `json:"urlHost"`
		} `json:"subscriptions"`
	}
	var raw json.RawMessage
	e.mustOK("GET", "/api/v1/subscriptions", nil, &raw)
	if bytes.Contains(raw, []byte("token=abc")) {
		t.Fatal("subscription URL leaked")
	}
	_ = json.Unmarshal(raw, &subs)
	if len(subs.Subscriptions) != 1 || !strings.HasPrefix(subs.Subscriptions[0].URLHost, "127.0.0.1:") {
		t.Fatalf("subs: %s", raw)
	}

	var task Task
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/refresh", nil, &task)
	task = e.waitTask(task.ID)
	if task.State != TaskSucceeded {
		t.Fatalf("refresh failed: %+v", task)
	}
	res, _ := json.Marshal(task.Result)
	var pv previewView
	_ = json.Unmarshal(res, &pv)
	if pv.Count != 2 || len(pv.Diff.Added) != 2 || pv.Usage == nil || pv.Usage.Total != 1<<30 {
		t.Fatalf("preview: %s", res)
	}
	// Previews are bound to their subscription.
	var apiErr struct {
		Error APIError `json:"error"`
	}
	if code := e.call("POST", "/api/v1/subscriptions/other/commit", map[string]string{"previewId": pv.PreviewID}, &apiErr); code != 400 {
		t.Fatalf("foreign commit accepted: %d", code)
	}
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/commit", map[string]string{"previewId": pv.PreviewID}, nil)
	if code := e.call("POST", "/api/v1/subscriptions/"+created.ID+"/commit", map[string]string{"previewId": pv.PreviewID}, &apiErr); code != 400 {
		t.Fatalf("preview reused: %d", code)
	}
	cfg, _ := e.d.store.Snapshot()
	count := 0
	for _, n := range cfg.Nodes {
		if n.SubscriptionID == created.ID {
			count++
		}
	}
	if count != 2 || cfg.SubscriptionByID(created.ID).UpdatedAt == "" {
		t.Fatalf("commit: %d nodes", count)
	}

	// A refresh with one node removed keeps user chains on the survivors.
	var s1 string
	for _, n := range cfg.Nodes {
		if n.Name == "S1" {
			s1 = n.ID
		}
	}
	var manual string
	for _, n := range cfg.Nodes {
		if n.SubscriptionID == "" {
			manual = n.ID
		}
	}
	nodes := []map[string]any{}
	e.mustOK("GET", "/api/v1/nodes", nil, &struct {
		Nodes *[]map[string]any `json:"nodes"`
	}{&nodes})
	for _, n := range nodes {
		if n["id"] == s1 {
			n["upstream"] = manual
			delete(n, "secrets")
			delete(n, "subscriptionName")
			e.mustOK("PUT", "/api/v1/nodes/"+s1, map[string]any{"node": n}, nil)
		}
	}
	body = "ss://YWVzLTEyOC1nY206cGFzcw@5.6.7.8:8388#S1\n"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := e.d.refreshAndCommit(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	cfg, _ = e.d.store.Snapshot()
	if n := cfg.NodeByID(s1); n == nil || n.Upstream != manual {
		t.Fatalf("chain lost: %+v", n)
	}

	// Failed refresh records the error without touching nodes.
	srv.Close()
	if err := e.d.refreshAndCommit(ctx, created.ID); err == nil {
		t.Fatal("refresh of closed server succeeded")
	}
	cfg, _ = e.d.store.Snapshot()
	if cfg.SubscriptionByID(created.ID).LastError == "" || cfg.NodeByID(s1) == nil {
		t.Fatal("failure handling wrong")
	}
	// Errors never carry the subscription address or its token.
	for _, path := range []string{"/api/v1/subscriptions", "/api/v1/backup", "/api/v1/config", "/api/v1/logs?limit=2000"} {
		var raw json.RawMessage
		e.mustOK("GET", path, nil, &raw)
		if bytes.Contains(raw, []byte("token=abc")) || bytes.Contains(raw, []byte("/sub?")) {
			t.Fatalf("%s leaks the subscription URL: %s", path, raw)
		}
	}
	var task2 Task
	e.mustOK("POST", "/api/v1/subscriptions/"+created.ID+"/refresh", nil, &task2)
	task2 = e.waitTask(task2.ID)
	if task2.State != TaskFailed || strings.Contains(task2.Error, "token") {
		t.Fatalf("task error: %+v", task2)
	}

	e.mustOK("DELETE", "/api/v1/subscriptions/"+created.ID, nil, nil)
	cfg, sec := e.d.store.Snapshot()
	for _, n := range cfg.Nodes {
		if n.SubscriptionID == created.ID {
			t.Fatal("subscription nodes kept")
		}
	}
	if _, ok := sec.Subscriptions[created.ID]; ok {
		t.Fatal("subscription URL kept")
	}
}

func TestAPIBackupRestore(t *testing.T) {
	e := newEnv(t, false, nil)
	e.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": "trojan://pw1@example.com:443#T1"}, nil)
	var exp struct {
		Document json.RawMessage `json:"document"`
	}
	e.mustOK("GET", "/api/v1/backup", nil, &exp)
	cfg, _ := e.d.store.Snapshot()
	id := cfg.Nodes[0].ID
	e.mustOK("DELETE", "/api/v1/nodes/"+id, nil, nil)
	// Restoring a backup without secrets keeps credentials it lacks only if
	// they still exist; the deleted node's password is gone, so validation
	// must reject the restore rather than produce an unusable node.
	var apiErr struct {
		Error APIError `json:"error"`
	}
	if code := e.call("POST", "/api/v1/backup/restore", map[string]any{"document": exp.Document}, &apiErr); code != 400 {
		t.Fatalf("restore without credentials accepted: %d", code)
	}
	var withSec struct {
		Document json.RawMessage `json:"document"`
	}
	e.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": "trojan://pw1@example.com:443#T1"}, nil)
	e.mustOK("GET", "/api/v1/backup?secrets=1", nil, &withSec)
	cfg, _ = e.d.store.Snapshot()
	e.mustOK("DELETE", "/api/v1/nodes/"+cfg.Nodes[0].ID, nil, nil)
	e.mustOK("POST", "/api/v1/backup/restore", map[string]any{"document": withSec.Document}, nil)
	cfg, sec := e.d.store.Snapshot()
	if len(cfg.Nodes) != 1 || sec.NodeSecret(cfg.Nodes[0].ID, "password") != "pw1" {
		t.Fatal("restore incomplete")
	}
	var backups struct {
		Backups []struct {
			Name string `json:"name"`
		} `json:"backups"`
	}
	e.mustOK("GET", "/api/v1/backups", nil, &backups)
	if len(backups.Backups) == 0 {
		t.Fatal("no rolling backups")
	}
	e.mustOK("POST", "/api/v1/backup/restore", map[string]any{"backup": backups.Backups[0].Name}, nil)
	if code := e.call("POST", "/api/v1/backup/restore", map[string]any{"backup": "../config.json"}, &apiErr); code != 400 {
		t.Fatalf("path traversal accepted: %d", code)
	}

	// File-based export/import through the Download folder.
	dl := t.TempDir()
	t.Setenv("KPM_IMPORT_ROOT", dl)
	e.mustOK("POST", "/api/v1/nodes/import", map[string]string{"text": "trojan://pw9@example.com:443#T9"}, nil)
	cfg, _ = e.d.store.Snapshot()
	nodeCount := len(cfg.Nodes)
	var exported struct {
		Path string `json:"path"`
	}
	e.mustOK("POST", "/api/v1/backup/export", map[string]bool{"secrets": true}, &exported)
	if filepath.Dir(exported.Path) != dl {
		t.Fatalf("exported to %s", exported.Path)
	}
	var files struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	e.mustOK("GET", "/api/v1/backup/files", nil, &files)
	if len(files.Files) != 1 || files.Files[0].Path != exported.Path {
		t.Fatalf("files: %+v", files)
	}
	cfg, _ = e.d.store.Snapshot()
	e.mustOK("DELETE", "/api/v1/nodes/"+cfg.Nodes[0].ID, nil, nil)
	e.mustOK("POST", "/api/v1/backup/restore", map[string]any{"path": exported.Path}, nil)
	cfg, _ = e.d.store.Snapshot()
	if len(cfg.Nodes) != nodeCount {
		t.Fatal("restore from file failed")
	}
	if code := e.call("POST", "/api/v1/backup/restore", map[string]any{"path": "/etc/passwd"}, &apiErr); code != 400 {
		t.Fatalf("restore outside allowed roots: %d", code)
	}
}

func TestTCPGuard(t *testing.T) {
	e := newEnv(t, false, nil)
	if err := os.MkdirAll(e.layout.WebRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(e.layout.WebRoot(), "index.html"), []byte("<!doctype html>ok"), 0o644)
	var key struct {
		Key string `json:"key"`
	}
	e.mustOK("POST", "/api/v1/system/web-key", nil, &key)
	h := e.d.tcpGuard(e.d.apiMux(), 9097)
	do := func(method, path, host, origin, auth string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Host = host
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do("GET", "/api/v1/status", "127.0.0.1:9097", "", key.Key); c != 200 {
		t.Fatalf("authorized request: %d", c)
	}
	if c := do("GET", "/api/v1/status", "evil.example:9097", "", key.Key); c != 403 {
		t.Fatalf("DNS rebinding host accepted: %d", c)
	}
	if c := do("GET", "/api/v1/status", "127.0.0.1:9097", "http://evil.example", key.Key); c != 403 {
		t.Fatalf("foreign origin accepted: %d", c)
	}
	if c := do("POST", "/api/v1/daemon/shutdown", "127.0.0.1:9097", "", key.Key); c != 403 {
		t.Fatalf("daemon endpoint reachable over TCP: %d", c)
	}
	if c := do("GET", "/", "localhost:9097", "", ""); c != 200 {
		t.Fatalf("static: %d", c)
	}
	if c := do("GET", "/../../etc/passwd", "localhost:9097", "", ""); c != 404 {
		t.Fatalf("traversal: %d", c)
	}
	for i := 0; i < 10; i++ {
		if c := do("GET", "/api/v1/status", "127.0.0.1:9097", "", "wrong"); c != 401 {
			t.Fatalf("bad key: %d", c)
		}
	}
	if c := do("GET", "/api/v1/status", "127.0.0.1:9097", "", "wrong"); c != 429 {
		t.Fatalf("rate limit not applied: %d", c)
	}
	// The correct key is never locked out by someone else's failures.
	if c := do("GET", "/api/v1/status", "127.0.0.1:9097", "", key.Key); c != 200 {
		t.Fatalf("valid key locked out: %d", c)
	}
	// The access key manages the daemon but must not export stored credentials.
	if c := do("GET", "/api/v1/backup?secrets=1", "127.0.0.1:9097", "", key.Key); c != 403 {
		t.Fatalf("backup with secrets over TCP: %d", c)
	}
	if c := do("GET", "/api/v1/backup", "127.0.0.1:9097", "", key.Key); c != 200 {
		t.Fatalf("backup without secrets over TCP: %d", c)
	}
	request := httptest.NewRequest("POST", "/api/v1/backup/export", strings.NewReader(`{"secrets":true}`))
	request.Host = "127.0.0.1:9097"
	request.Header.Set("Authorization", "Bearer "+key.Key)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("TCP credential export was not rejected", response.Code)
	}
}

func TestMihomoMinimumImportRejectsOldCore(t *testing.T) {
	fixture := os.Getenv("KPM_TEST_OLD_MIHOMO")
	if fixture == "" {
		t.Skip("KPM_TEST_OLD_MIHOMO must point to the official Mihomo 1.18.0 fixture")
	}
	environment := newEnv(t, false, nil)
	_, err := environment.d.installCandidate(context.Background(), fixture, t.TempDir(), config.EngineMihomo, cores.Installation{Source: "test"})
	if err == nil || !strings.Contains(err.Error(), render.MinVersion[config.EngineMihomo]) {
		t.Fatalf("old unauthenticated core was not rejected by the installer: %v", err)
	}
	installed, err := environment.d.cores.List()
	if err != nil || len(installed) != 0 {
		t.Fatal("rejected core was installed", err)
	}
}

func TestSubscriptionPreviewConflicts(t *testing.T) {
	for _, change := range []string{"filter", "url", "restore", "competing refresh"} {
		t.Run(change, func(t *testing.T) { checkSubscriptionPreviewConflict(t, change) })
	}
}

func checkSubscriptionPreviewConflict(t *testing.T, change string) {
	environment := newEnv(t, false, nil)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, "trojan://test-password@example.com:443#old")
	}))
	defer origin.Close()
	var created struct {
		ID string `json:"id"`
	}
	environment.mustOK("POST", "/api/v1/subscriptions", map[string]any{"subscription": map[string]any{"name": "Test"}, "url": origin.URL}, &created)
	pending, err := environment.d.prepareRefresh(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	environment.d.mu.Lock()
	environment.d.previews[pending.ID] = pending
	environment.d.mu.Unlock()
	configuration, secrets := environment.d.store.Snapshot()
	changed := *configuration.SubscriptionByID(created.ID)
	switch change {
	case "filter":
		changed.Filter = "^new$"
		environment.mustOK("PUT", "/api/v1/subscriptions/"+created.ID, map[string]any{"subscription": changed}, nil)
	case "url":
		environment.mustOK("PUT", "/api/v1/subscriptions/"+created.ID, map[string]any{"subscription": changed, "url": origin.URL + "/changed"}, nil)
	case "restore":
		environment.mustOK("POST", "/api/v1/backup/restore", map[string]any{"document": config.Document{Config: configuration, Secrets: secrets}}, nil)
	case "competing refresh":
		newer, err := environment.d.prepareRefresh(context.Background(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := environment.d.commitNodes(newer); err != nil {
			t.Fatal(err)
		}
	}
	revision := environment.d.store.Revision()
	if status := environment.call("POST", "/api/v1/subscriptions/"+created.ID+"/commit", map[string]string{"previewId": pending.ID}, nil); status != http.StatusConflict {
		t.Fatal("stale preview was not rejected", status)
	}
	if environment.d.store.Revision() != revision {
		t.Fatal("conflicting preview mutated the saved configuration")
	}
}

func TestMigratedSubscriptionRefreshKeepsReferences(t *testing.T) {
	model := []byte(`{"schemaVersion":2,"subscriptions":[{"id":"s1","name":"Legacy"}],"nodes":[{"id":"n1","name":"Legacy","protocol":"trojan","server":"example.com","port":443,"sourceSubscription":"s1"}],"proxyGroups":[{"id":"g1","name":"Home, VPN","nodeIds":["n1"],"selectedNodeId":"n1"}]}`)
	secretData := []byte(`{"nodes":{"n1":{"password":"test-password"}},"subscriptions":{"s1":"https://example.com/sub"}}`)
	configuration, secrets, _, err := config.MigrateV2(model, secretData)
	if err != nil {
		t.Fatal(err)
	}
	environment := newEnv(t, false, nil)
	saved, err := environment.d.store.Replace(-1, config.Document{Config: configuration, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	parsed := subscription.Parse([]byte("trojan://test-password@example.com:443#Legacy"))
	subscription.AssignSubscriptionIDs("s1", parsed.Nodes)
	next, _, err := environment.d.commitNodes(&preview{SubID: "s1", Revision: saved.Revision, Nodes: parsed.Nodes})
	if err != nil {
		t.Fatal(err)
	}
	group := next.GroupByID("g1")
	if len(group.Nodes) != 1 || group.Selected != config.NodeRef(group.Nodes[0]) {
		t.Fatal("first migrated subscription refresh lost references")
	}
}

func TestLargeBackupRoundTrip(t *testing.T) {
	for _, directory := range []string{"/sdcard/Download", "/storage/emulated/0/Download"} {
		if _, err := os.Stat(directory); err == nil {
			t.Skip("large backup fixture is host-only")
		}
	}
	checkLargeBackupRoundTrip(t)
}

func checkLargeBackupRoundTrip(t *testing.T) {
	t.Helper()
	t.Setenv("KPM_IMPORT_ROOT", t.TempDir())
	environment := newEnv(t, false, nil)
	_, err := environment.d.store.Update(-1, func(configuration *config.Config, secrets *config.Secrets) error {
		password := strings.Repeat("x", 4096)
		for index := 0; index < 4096; index++ {
			identifier := fmt.Sprintf("backup-%04d", index)
			configuration.Nodes = append(configuration.Nodes, config.Node{ID: identifier, Name: identifier, Type: "shadowsocks", Server: "example.com", Port: 8388, Cipher: "aes-128-gcm"})
			secrets.SetNodeSecrets(identifier, map[string]string{"password": password})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Path string `json:"path"`
	}
	environment.mustOK("POST", "/api/v1/backup/export", map[string]bool{"secrets": true}, &exported)
	t.Cleanup(func() { _ = os.Remove(exported.Path) })
	info, err := os.Stat(exported.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 16<<20 {
		t.Fatal("fixture is not large enough")
	}
	environment.mustOK("POST", "/api/v1/backup/restore", map[string]string{"path": exported.Path}, nil)
	raw, err := os.ReadFile(exported.Path)
	if err != nil {
		t.Fatal(err)
	}
	environment.mustOK("POST", "/api/v1/backup/restore", map[string]any{"document": json.RawMessage(raw)}, nil)
	configuration, secrets := environment.d.store.Snapshot()
	if len(configuration.Nodes) != 4096 || secrets.NodeSecret("backup-4095", "password") != strings.Repeat("x", 4096) {
		t.Fatal("large backup round trip lost nodes or credentials")
	}
	t.Logf("file and request-body backup round trips: %d bytes, %d nodes", info.Size(), len(configuration.Nodes))
}

func TestParseUserInfoBounds(t *testing.T) {
	u := parseUserInfo("upload=1; download=2; total=1e30; expire=9999999999999")
	if u == nil || u.Upload != 1 || u.Download != 2 || u.Total != 1<<53 || u.Expire != 0 {
		t.Fatalf("%+v", u)
	}
	if parseUserInfo("expire=NaN; total=-5") != nil {
		t.Fatal("invalid values must be ignored")
	}
	if u := parseUserInfo("expire=1893456000"); u == nil || u.Expire != 1893456000 {
		t.Fatalf("%+v", u)
	}
}

func TestAPIAppsAndSystem(t *testing.T) {
	e := newEnv(t, false, nil)
	_ = os.WriteFile(e.d.apps.PackagesList, []byte("com.example.a 10123 0 /data/user/0/com.example.a default:targetSdkVersion=34 3003 0 1\ncom.example.b 10200 0 /x\n"), 0o644)
	var apps struct {
		Apps []struct {
			Package string `json:"package"`
			UID     int    `json:"uid"`
		} `json:"apps"`
	}
	e.mustOK("GET", "/api/v1/apps", nil, &apps)
	if len(apps.Apps) != 2 || apps.Apps[0].UID != 10123 {
		t.Fatalf("apps: %+v", apps)
	}
	e.mustOK("PUT", "/api/v1/apps/policy", map[string]any{"mode": "include", "packages": []string{"com.example.a"}, "users": []int{0}}, nil)
	var apiErr struct {
		Error APIError `json:"error"`
	}
	if code := e.call("PUT", "/api/v1/apps/policy", map[string]any{"mode": "include", "packages": []string{"bad name;rm"}}, &apiErr); code != 400 {
		t.Fatalf("invalid package accepted: %d", code)
	}
	var sys struct {
		Delete bool `json:"deleteDataOnUninstall"`
	}
	e.mustOK("PUT", "/api/v1/system", map[string]bool{"deleteDataOnUninstall": true}, &sys)
	if !sys.Delete {
		t.Fatal("marker not set")
	}
	e.mustOK("PUT", "/api/v1/system", map[string]bool{"deleteDataOnUninstall": false}, &sys)
	if sys.Delete {
		t.Fatal("marker not cleared")
	}
	var logs struct {
		Lines []struct {
			Text string `json:"text"`
		} `json:"lines"`
	}
	e.mustOK("GET", "/api/v1/logs?limit=50", nil, &logs)
	if len(logs.Lines) == 0 {
		t.Fatal("no daemon logs")
	}
}
