// Package logx implements rotating, redacting logs with an in-memory tail.
package logx

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Line struct {
	Seq   uint64 `json:"seq"`
	Time  string `json:"time"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Sink writes lines to a size-rotated file and keeps the newest lines in memory.
type Sink struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	size    int64
	maxSize int64
	ring    []Line
	next    int
	full    bool
	seq     uint64
	static  []string
	cur     []string
	prev    []string
	keys    []string
}

func OpenSink(path string, maxSize int64, ringCap int) (*Sink, error) {
	if ringCap < 16 {
		ringCap = 16
	}
	s := &Sink{path: path, maxSize: maxSize, ring: make([]Line, ringCap)}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sink) open() error {
	if s.path == "" {
		return nil
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	s.file, s.size = f, st.Size()
	return nil
}

// AddSecret registers a literal that must never appear in this log.
func (s *Sink) AddSecret(v string) {
	if len(v) < 6 {
		return
	}
	s.mu.Lock()
	s.static = append(s.static, v)
	s.rebuildLocked()
	s.mu.Unlock()
}

// SetSecrets replaces the rotating secret set (credentials of the running
// core). The previous set stays active so that late output is still covered.
func (s *Sink) SetSecrets(vals []string) {
	var keep []string
	for _, v := range vals {
		if len(v) >= 6 {
			keep = append(keep, v)
		}
	}
	s.mu.Lock()
	s.prev, s.cur = s.cur, keep
	s.rebuildLocked()
	s.mu.Unlock()
}

func (s *Sink) rebuildLocked() {
	seen := map[string]bool{}
	var keys []string
	for _, list := range [][]string{s.static, s.cur, s.prev} {
		for _, k := range list {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	s.keys = keys
}

// ScrubWith redacts credential patterns and the given literal secrets.
func ScrubWith(text string, secrets []string) string {
	text = Redact(text)
	keys := append([]string(nil), secrets...)
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		if len(k) >= 4 {
			text = strings.ReplaceAll(text, k, "***")
		}
	}
	return text
}

// Scrub redacts text with the patterns and the secrets known to this sink.
func (s *Sink) Scrub(text string) string {
	s.mu.Lock()
	keys := s.keys
	s.mu.Unlock()
	return ScrubWith(text, keys)
}

func (s *Sink) Append(level, text string) {
	text = strings.TrimRight(text, "\r\n")
	if text == "" {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	text = Redact(text)
	for _, k := range s.keys {
		text = strings.ReplaceAll(text, k, "***")
	}
	if len(text) > 8192 {
		text = text[:8192] + "…"
	}
	s.seq++
	ln := Line{Seq: s.seq, Time: now.Format("2006-01-02T15:04:05.000Z"), Level: level, Text: text}
	s.ring[s.next] = ln
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
	if s.file != nil {
		entry := ln.Time + " " + strings.ToUpper(level) + " " + text + "\n"
		if s.maxSize > 0 && s.size+int64(len(entry)) > s.maxSize {
			s.rotateLocked()
		}
		if s.file != nil {
			n, _ := s.file.WriteString(entry)
			s.size += int64(n)
		}
	}
}

func (s *Sink) rotateLocked() {
	_ = s.file.Close()
	s.file = nil
	_ = os.Rename(s.path, s.path+".1")
	_ = s.open()
}

// Tail returns up to limit lines with Seq > after, oldest first.
func (s *Sink) Tail(after uint64, limit int) ([]Line, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.ring) {
		limit = len(s.ring)
	}
	var all []Line
	if s.full {
		all = append(all, s.ring[s.next:]...)
	}
	all = append(all, s.ring[:s.next]...)
	out := make([]Line, 0, limit)
	for _, ln := range all {
		if ln.Seq > after {
			out = append(out, ln)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, s.seq
}

// Clear drops the in-memory tail and truncates the file.
func (s *Sink) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ring {
		s.ring[i] = Line{}
	}
	s.next, s.full = 0, false
	if s.file != nil {
		_ = s.file.Truncate(0)
		s.size = 0
	}
}

func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// LineWriter adapts a byte stream (for example core stdout) into log lines.
type LineWriter struct {
	sink *Sink
	mu   sync.Mutex
	buf  []byte
}

func (s *Sink) LineWriter() *LineWriter { return &LineWriter{sink: s} }

func (w *LineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		w.sink.Append(GuessLevel(line), line)
	}
	if len(w.buf) > 16<<10 {
		w.sink.Append(GuessLevel(string(w.buf)), string(w.buf))
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

func (w *LineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.sink.Append(GuessLevel(string(w.buf)), string(w.buf))
		w.buf = w.buf[:0]
	}
}

var levelPatterns = []struct {
	re    *regexp.Regexp
	level string
}{
	{regexp.MustCompile(`(?i)\b(fatal|panic|error)\b|level=error|ERROR\[`), "error"},
	{regexp.MustCompile(`(?i)\bwarn(ing)?\b|level=warning|WARN\[`), "warn"},
	{regexp.MustCompile(`(?i)level=debug|DEBUG\[|\bdebug\b`), "debug"},
}

// GuessLevel maps Mihomo/sing-box output lines onto our levels.
func GuessLevel(line string) string {
	head := line
	if len(head) > 160 {
		head = head[:160]
	}
	for _, p := range levelPatterns {
		if p.re.MatchString(head) {
			return p.level
		}
	}
	return "info"
}

var redactions = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)\b(ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|anytls|socks5?|wireguard|wg)://[^\s"'<>]+`), "$1://***"},
	{regexp.MustCompile(`(?i)\b(https?|wss?)://[^/\s:@"'<>]+:[^/\s@"'<>]+@`), "$1://***@"},
	{regexp.MustCompile(`(?i)([?&](?:token|key|secret|password|passwd|pass|auth|sig|signature|sign|uuid|psk|access_token)=)[^&\s"'<>]+`), "${1}***"},
	{regexp.MustCompile(`(?i)("(?:password|secret|token|uuid|private_key|privatekey|pre_shared_key|presharedkey|psk|auth|auth_str|obfs-password|obfs_password|url)"\s*:\s*")[^"]*(")`), "${1}***${2}"},
	{regexp.MustCompile(`(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}`), "$1 ***"},
	{regexp.MustCompile(`(?i)\b((?:password|secret|token|uuid|private-key|privatekey|psk)\s*[:=]\s*)[^\s,;"']{4,}`), "${1}***"},
}

// Redact removes credentials that may appear in free text.
func Redact(s string) string {
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Logger formats structured daemon messages into a Sink.
type Logger struct {
	sink  *Sink
	debug bool
	echo  *os.File
}

func NewLogger(s *Sink) *Logger { return &Logger{sink: s} }

func (l *Logger) Sink() *Sink        { return l.sink }
func (l *Logger) SetDebug(on bool)   { l.debug = on }
func (l *Logger) SetEcho(f *os.File) { l.echo = f }
func (l *Logger) Debug(c, m string, kv ...any) {
	if l.debug {
		l.log("debug", c, m, kv)
	}
}
func (l *Logger) Info(c, m string, kv ...any)  { l.log("info", c, m, kv) }
func (l *Logger) Warn(c, m string, kv ...any)  { l.log("warn", c, m, kv) }
func (l *Logger) Error(c, m string, kv ...any) { l.log("error", c, m, kv) }

func (l *Logger) log(level, component, msg string, kv []any) {
	if l == nil {
		return
	}
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(component)
	b.WriteString("] ")
	b.WriteString(msg)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, " %v=%s", kv[i], quote(fmt.Sprint(kv[i+1])))
	}
	text := b.String()
	if l.sink != nil {
		l.sink.Append(level, text)
	}
	if l.echo != nil {
		fmt.Fprintf(l.echo, "%s %s %s\n", time.Now().UTC().Format(time.RFC3339), strings.ToUpper(level), Redact(text))
	}
}

func quote(v string) string {
	if v == "" || strings.ContainsAny(v, " \t\"=") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Sprintf("%q", v)
	}
	return v
}
