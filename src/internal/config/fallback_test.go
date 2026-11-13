package config

import "testing"

func TestFallbackGroupValidationAndNormalization(t *testing.T) {
	c, s := validBase()
	g := &c.Groups[1]
	g.Type = "fallback"
	g.TestURL = "http://health.example.test/check"
	g.IntervalSec = 30
	g.IncludeDirect = true
	g.Selected = NodeRef("a")
	c.Normalize()
	if err := Validate(&c, &s); err != nil {
		t.Fatal(err)
	}
	if g.IncludeDirect || g.Selected != "" {
		t.Fatalf("automatic group retains manual state: %+v", g)
	}
	for _, tc := range []struct {
		name, url, field string
		interval         int
	}{
		{"invalid URL", "ftp://health.example.test", "groups[1].testUrl", 30},
		{"short interval", "", "groups[1].intervalSec", 29},
		{"long interval", "", "groups[1].intervalSec", 86401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.TestURL, g.IntervalSec = tc.url, tc.interval
			if got := fieldOf(t, Validate(&c, &s)); got != tc.field {
				t.Fatalf("field=%s, want %s", got, tc.field)
			}
		})
	}
}
