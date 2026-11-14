package config

import (
	"encoding/json"
	"testing"
)

func TestSourceIPRuleValidation(t *testing.T) {
	for _, engine := range []string{EngineMihomo, EngineSingBox} {
		for _, value := range []string{"192.168.43.2", "192.168.43.0/24", "192.168.43.7/24", "0.0.0.0/0", "2001:db8::2", "2001:db8::/64", "::/0", "::1", "::ffff:192.0.2.1"} {
			t.Run(engine+"/"+value, func(t *testing.T) {
				c, s := validBase()
				c.Settings.Engine = engine
				c.Routing.Rules = []Rule{{ID: "source", Enabled: true, Type: "source_ip_cidr", Values: []string{value}, Target: TargetDirect}}
				if err := Validate(&c, &s); err != nil {
					t.Fatal(err)
				}
				// A schema-3 round trip must retain the new rule without a migration.
				b, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				var saved Config
				if err := json.Unmarshal(b, &saved); err != nil || saved.Routing.Rules[0].Values[0] != value || saved.SchemaVersion != 3 {
					t.Fatalf("round trip lost source rule: %v %+v", err, saved.Routing)
				}
			})
		}
	}
	for _, value := range []string{"", "example.com", "192.168.1.256", "192.168.1.0/33", "2001:db8::/129", "192.168.1.1-192.168.1.9", "192.168.1.1,REJECT", "[::1]", "fe80::1%wlan0", "fe80::1%wlan0/64"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			c, s := validBase()
			c.Routing.Rules = []Rule{{ID: "source", Enabled: true, Type: "source_ip_cidr", Values: []string{value}, Target: TargetDirect}}
			if got := fieldOf(t, Validate(&c, &s)); got != "routing.rules[0].values" {
				t.Fatalf("field=%s", got)
			}
		})
	}
}
