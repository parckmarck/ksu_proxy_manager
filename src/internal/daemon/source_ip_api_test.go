package daemon

import (
	"reflect"
	"testing"

	"ksu_proxy_manager/internal/config"
)

func TestSourceIPRoutingAPI(t *testing.T) {
	e := newEnv(t, false, nil)
	before, _ := e.d.store.Snapshot()
	routing := before.Routing
	routing.Rules = []config.Rule{{ID: "source", Enabled: true, Type: "source_ip_cidr", Values: []string{"192.168.43.2", "2001:db8::/64"}, Target: config.TargetReject}}
	e.mustOK("PUT", "/api/v1/routing", routing, nil)
	var saved struct {
		Routing  config.Routing `json:"routing"`
		Revision int64          `json:"revision"`
	}
	e.mustOK("GET", "/api/v1/routing", nil, &saved)
	if saved.Revision != before.Revision+1 || !reflect.DeepEqual(saved.Routing.Rules, routing.Rules) {
		t.Fatal("source rule was not saved", saved)
	}
	before, beforeSec := e.d.store.Snapshot()
	routing.Rules[0].Values = []string{"192.168.43.0/33"}
	var apiErr struct {
		Error config.FieldError `json:"error"`
	}
	if code := e.call("PUT", "/api/v1/routing", routing, &apiErr); code != 400 || apiErr.Error.Field != "routing.rules[0].values" {
		t.Fatalf("invalid CIDR: status=%d error=%+v", code, apiErr)
	}
	after, afterSec := e.d.store.Snapshot()
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeSec, afterSec) {
		t.Fatal("rejected source rule changed config or revision")
	}
}
