package daemon

import (
	"reflect"
	"testing"

	"ksu_proxy_manager/internal/config"
)

func TestLoadBalanceAPIRejectsIncompatibleEngineAtomically(t *testing.T) {
	e := newEnv(t, false, nil)
	var created struct {
		ID string `json:"id"`
	}
	e.mustOK("POST", "/api/v1/groups", map[string]any{"name": "均衡组", "type": "load-balance", "strategy": "round-robin", "includeAll": true}, &created)
	before, beforeSec := e.d.store.Snapshot()
	var proxies struct {
		Groups []proxyGroupView `json:"groups"`
	}
	e.mustOK("GET", "/api/v1/proxies", nil, &proxies)
	for _, g := range proxies.Groups {
		if g.ID == created.ID && (g.Now != "" || g.Selected != "") {
			t.Fatal("load-balance has a fictitious fixed exit", g)
		}
	}
	settings := before.Settings
	settings.Engine = config.EngineSingBox
	var apiErr struct {
		Error config.FieldError `json:"error"`
	}
	if code := e.call("PUT", "/api/v1/settings", settings, &apiErr); code != 400 || apiErr.Error.Field != "groups[2].type" {
		t.Fatalf("want incompatible group field error, got %d %+v", code, apiErr)
	}
	after, afterSec := e.d.store.Snapshot()
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeSec, afterSec) {
		t.Fatal("failed switch changed persisted config")
	}
	e.mustOK("DELETE", "/api/v1/groups/"+created.ID, nil, nil)
	e.mustOK("PUT", "/api/v1/settings", settings, nil)
	before, _ = e.d.store.Snapshot()
	if code := e.call("POST", "/api/v1/groups", map[string]any{"name": "不兼容组", "type": "load-balance"}, &apiErr); code != 400 {
		t.Fatalf("sing-box accepted group: %d", code)
	}
	after, _ = e.d.store.Snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected group changed config")
	}
}
