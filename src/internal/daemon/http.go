package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ksu_proxy_manager/internal/config"
	"ksu_proxy_manager/internal/store"
)

// APIError is the JSON error payload returned by every endpoint.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e *APIError) Error() string { return e.Message }

var errNotFound = &APIError{Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "资源不存在"}

type tcpRequestKey struct{}

func requireLocalImport(r *http.Request) error {
	if r.Context().Value(tcpRequestKey{}) == true {
		return &APIError{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: "本地文件导入只能在管理器内操作"}
	}
	return nil
}

func requireSecretExport(r *http.Request, withSecrets bool) error {
	if withSecrets && r.Context().Value(tcpRequestKey{}) == true {
		return &APIError{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: "含密钥的备份只能在管理器内导出"}
	}
	return nil
}

func badRequest(format string, args ...any) error {
	return &APIError{Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: fmt.Sprintf(format, args...)}
}

func unavailable(msg string) error {
	return &APIError{Status: http.StatusServiceUnavailable, Code: "UNAVAILABLE", Message: msg}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	var api *APIError
	var fe *config.FieldError
	var conflict *store.ConflictError
	switch {
	case errors.As(err, &api):
		writeJSON(w, api.Status, map[string]any{"error": api})
	case errors.As(err, &fe):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": APIError{Code: "VALIDATION", Message: fe.Message, Field: fe.Field}})
	case errors.As(err, &conflict):
		writeJSON(w, http.StatusConflict, map[string]any{"error": APIError{Code: "CONFLICT", Message: conflict.Error()}})
	case errors.Is(err, ErrTaskBusy):
		writeJSON(w, http.StatusConflict, map[string]any{"error": APIError{Code: "BUSY", Message: err.Error()}})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": APIError{Code: "INTERNAL", Message: err.Error()}})
	}
}

// decode reads a JSON body with a size limit and rejects unknown fields.
func decode(r *http.Request, limit int64, v any) error {
	if limit <= 0 {
		limit = 1 << 20
	}
	body := io.LimitReader(r.Body, limit+1)
	data, err := io.ReadAll(body)
	if err != nil {
		return badRequest("读取请求失败")
	}
	if int64(len(data)) > limit {
		return &APIError{Status: http.StatusRequestEntityTooLarge, Code: "TOO_LARGE", Message: "请求体过大"}
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		data = []byte("{}")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("请求 JSON 无效: %v", err)
	}
	return nil
}

// expectedRev reads the optimistic-concurrency revision from ?rev=; an
// unparsable value can never match and therefore always conflicts.
func expectedRev(r *http.Request) int64 {
	v := r.URL.Query().Get("rev")
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 1 << 62
	}
	return n
}

// authLimiter throttles failed bearer-token attempts on the TCP listener.
type authLimiter struct {
	mu       sync.Mutex
	failures []time.Time
}

func (l *authLimiter) blocked() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	keep := l.failures[:0]
	for _, t := range l.failures {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	l.failures = keep
	return len(keep) >= 10
}

func (l *authLimiter) fail() {
	l.mu.Lock()
	l.failures = append(l.failures, time.Now())
	l.mu.Unlock()
}

// tcpGuard wraps the API for the optional loopback TCP listener.
func (d *Daemon) tcpGuard(next http.Handler, port int) http.Handler {
	allowedHosts := map[string]bool{fmt.Sprintf("127.0.0.1:%d", port): true, fmt.Sprintf("localhost:%d", port): true}
	allowedOrigins := map[string]bool{fmt.Sprintf("http://127.0.0.1:%d", port): true, fmt.Sprintf("http://localhost:%d", port): true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !allowedHosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !allowedOrigins[o] {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			d.serveStatic(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/daemon/") {
			writeError(w, &APIError{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: "该接口只能通过本机套接字调用"})
			return
		}
		key, _ := d.webKey.Load().(string)
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		valid := key != "" && len(got) == len(key) && subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1
		if !valid {
			// Failed attempts are throttled; a correct key is never locked out.
			if d.limiter.blocked() {
				writeError(w, &APIError{Status: http.StatusTooManyRequests, Code: "RATE_LIMITED", Message: "认证失败次数过多，请稍后再试"})
				return
			}
			d.limiter.fail()
			writeError(w, &APIError{Status: http.StatusUnauthorized, Code: "UNAUTHORIZED", Message: "访问密钥无效"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tcpRequestKey{}, true)))
	})
}

// serveStatic serves the WebUI for browser access with revalidation.
func (d *Daemon) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	root := d.layout.WebRoot()
	rel := filepath.Clean("/" + r.URL.Path)
	if rel == "/" {
		rel = "/index.html"
	}
	p := filepath.Join(root, filepath.FromSlash(rel))
	if !strings.HasPrefix(p, filepath.Clean(root)+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", rel, st.Size(), st.ModTime().UnixNano())))
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	w.Header().Set("Cache-Control", "no-cache")
	if ct := mime.TypeByExtension(filepath.Ext(p)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if strings.HasSuffix(p, ".html") {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	}
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

// listenUnix creates the root-only control socket.
func listenUnix(path string) (net.Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
