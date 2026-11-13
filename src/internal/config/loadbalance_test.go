package config

import (
	"encoding/json"
	"testing"
)

func TestLoadBalanceGroupValidationAndNormalization(t *testing.T) {
	for _, strategy := range []string{"", "consistent-hashing", "round-robin", "sticky-sessions"} {
		t.Run("strategy/"+strategy, func(t *testing.T) {
			c, s := validBase()
			g := &c.Groups[1]
			if err := json.Unmarshal([]byte(`{"type":"load-balance","strategy":"`+strategy+`"}`), g); err != nil {
				t.Fatal(err)
			}
			g.IncludeDirect, g.Selected = true, NodeRef("a")
			c.Normalize()
			if err := Validate(&c, &s); err != nil {
				t.Fatal(err)
			}
			if g.IncludeDirect || g.Selected != "" {
				t.Fatal("load-balance retains manual selection", g)
			}
			c.Settings.Engine = EngineSingBox
			if got := fieldOf(t, Validate(&c, &s)); got != "groups[1].type" {
				t.Fatalf("sing-box field=%s", got)
			}
		})
	}
	for _, tc := range []struct{ name, patch, field string }{
		{"unknown strategy", `{"strategy":"random"}`, "groups[1].strategy"},
		{"invalid health URL", `{"testUrl":"ftp://health.example.test"}`, "groups[1].testUrl"},
		{"short interval", `{"intervalSec":29}`, "groups[1].intervalSec"},
		{"long interval", `{"intervalSec":86401}`, "groups[1].intervalSec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := validBase()
			c.Groups[1].Type = "load-balance"
			if err := json.Unmarshal([]byte(tc.patch), &c.Groups[1]); err != nil {
				t.Fatal(err)
			}
			if got := fieldOf(t, Validate(&c, &s)); got != tc.field {
				t.Fatalf("field=%s, want %s", got, tc.field)
			}
		})
	}
}
