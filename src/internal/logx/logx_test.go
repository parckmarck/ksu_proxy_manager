package logx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"fetch https://user:pass@sub.example.com/x?token=abc123&x=1": "pass",
		"link vless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@h:443#n":  "0f9e8d7c",
		`{"password":"hunter2","name":"a"}`:                          "hunter2",
		"Authorization: Bearer abcdef0123456789":                     "abcdef0123456789",
		"secret=topsecretvalue other=1":                              "topsecretvalue",
		"https://api.example.com/sub?key=k3y&uuid=uu1d":              "k3y",
	}
	for in, leaked := range cases {
		out := Redact(in)
		if strings.Contains(out, leaked) {
			t.Errorf("%q -> %q still contains %q", in, out, leaked)
		}
	}
	if out := Redact("plain message 1.2.3.4:443"); out != "plain message 1.2.3.4:443" {
		t.Errorf("over-redacted: %q", out)
	}
}

func TestSinkRotationTailAndSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.log")
	s, err := OpenSink(path, 2048, 50)
	if err != nil {
		t.Fatal(err)
	}
	s.AddSecret("CTRLSECRET")
	for i := 0; i < 100; i++ {
		s.Append("info", "line with CTRLSECRET number "+strings.Repeat("x", 20))
	}
	lines, last := s.Tail(0, 1000)
	if len(lines) != 50 || last != 100 {
		t.Fatalf("ring: %d last %d", len(lines), last)
	}
	more, _ := s.Tail(last-3, 10)
	if len(more) != 3 {
		t.Fatalf("tail after: %d", len(more))
	}
	for _, l := range lines {
		if strings.Contains(l.Text, "CTRLSECRET") {
			t.Fatal("secret in ring")
		}
	}
	_ = s.Close()
	b, _ := os.ReadFile(path)
	b1, _ := os.ReadFile(path + ".1")
	if len(b) > 4096 || len(b1) == 0 || strings.Contains(string(b)+string(b1), "CTRLSECRET") {
		t.Fatalf("rotation/secret: %d %d", len(b), len(b1))
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", st.Mode())
	}
}

func TestLineWriterAndLevels(t *testing.T) {
	s, _ := OpenSink(filepath.Join(t.TempDir(), "c.log"), 1<<20, 100)
	w := s.LineWriter()
	_, _ = w.Write([]byte("time=\"x\" level=error msg=\"boom\"\npartial "))
	_, _ = w.Write([]byte("WARN something\n"))
	w.Flush()
	lines, _ := s.Tail(0, 10)
	if len(lines) != 2 || lines[0].Level != "error" || lines[1].Level != "warn" || lines[1].Text != "partial WARN something" {
		t.Fatalf("%+v", lines)
	}
	s.Clear()
	if l, _ := s.Tail(0, 10); len(l) != 0 {
		t.Fatal("not cleared")
	}
}
