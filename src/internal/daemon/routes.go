package daemon

import (
	"context"
	"net/http"
	"time"
)

type handlerFunc func(w http.ResponseWriter, r *http.Request) (any, error)

func wrap(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := fn(w, r)
		if err != nil {
			writeError(w, err)
			return
		}
		if v != nil {
			writeJSON(w, http.StatusOK, v)
		}
	}
}

// apiMux registers every management endpoint shared by both listeners.
func (d *Daemon) apiMux() *http.ServeMux {
	mux := http.NewServeMux()
	h := func(pattern string, fn handlerFunc) { mux.HandleFunc(pattern, wrap(fn)) }

	h("GET /api/v1/status", d.hStatus)
	h("POST /api/v1/core/start", d.hCoreStart)
	h("POST /api/v1/core/stop", d.hCoreStop)
	h("POST /api/v1/core/restart", d.hCoreStart)
	h("GET /api/v1/traffic", d.hTraffic)
	h("GET /api/v1/connections", d.hConnections)
	h("DELETE /api/v1/connections", d.hCloseConnection)
	h("DELETE /api/v1/connections/{id}", d.hCloseConnection)

	h("GET /api/v1/config", d.hConfig)
	h("GET /api/v1/settings", d.hSettings)
	h("PUT /api/v1/settings", d.hPutSettings)
	h("GET /api/v1/routing", d.hRouting)
	h("PUT /api/v1/routing", d.hPutRouting)
	h("PUT /api/v1/routing/mode", d.hPutMode)
	h("GET /api/v1/dns", d.hDNS)
	h("PUT /api/v1/dns", d.hPutDNS)

	h("GET /api/v1/nodes", d.hNodes)
	h("POST /api/v1/nodes", d.hCreateNode)
	h("PUT /api/v1/nodes/{id}", d.hUpdateNode)
	h("DELETE /api/v1/nodes/{id}", d.hDeleteNode)
	h("POST /api/v1/nodes/{id}/copy", d.hCopyNode)
	h("POST /api/v1/nodes/import", d.hImportNodes)
	h("POST /api/v1/nodes/delay", d.hDelay)

	h("GET /api/v1/groups", d.hGroups)
	h("POST /api/v1/groups", d.hCreateGroup)
	h("PUT /api/v1/groups/{id}", d.hUpdateGroup)
	h("DELETE /api/v1/groups/{id}", d.hDeleteGroup)
	h("POST /api/v1/groups/{id}/select", d.hSelect)
	h("GET /api/v1/proxies", d.hProxies)

	h("GET /api/v1/subscriptions", d.hSubscriptions)
	h("POST /api/v1/subscriptions", d.hCreateSubscription)
	h("PUT /api/v1/subscriptions/{id}", d.hUpdateSubscription)
	h("DELETE /api/v1/subscriptions/{id}", d.hDeleteSubscription)
	h("POST /api/v1/subscriptions/{id}/refresh", d.hRefreshSubscription)
	h("POST /api/v1/subscriptions/{id}/commit", d.hCommitSubscription)
	h("POST /api/v1/subscriptions/update-all", d.hUpdateAllSubscriptions)

	h("GET /api/v1/apps", d.hApps)
	h("PUT /api/v1/apps/policy", d.hPutAppPolicy)

	h("GET /api/v1/cores", d.hCores)
	h("GET /api/v1/cores/releases", d.hReleases)
	h("POST /api/v1/cores/download", d.hDownloadCore)
	h("GET /api/v1/cores/files", d.hCoreFiles)
	h("POST /api/v1/cores/import", d.hImportCore)
	h("DELETE /api/v1/cores/{engine}/{version}", d.hDeleteCore)
	h("GET /api/v1/rulesets", d.hRulesets)
	h("POST /api/v1/rulesets/update", d.hUpdateRulesets)

	h("GET /api/v1/tasks", func(http.ResponseWriter, *http.Request) (any, error) { return d.tasks.List(), nil })
	h("GET /api/v1/tasks/{id}", func(_ http.ResponseWriter, r *http.Request) (any, error) { return d.tasks.Get(r.PathValue("id")) })
	h("POST /api/v1/tasks/{id}/cancel", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		return map[string]bool{"ok": true}, d.tasks.Cancel(r.PathValue("id"))
	})

	h("GET /api/v1/logs", d.hLogs)
	h("DELETE /api/v1/logs", d.hClearLogs)
	h("GET /api/v1/backup", d.hBackup)
	h("POST /api/v1/backup/export", d.hExportBackup)
	h("GET /api/v1/backup/files", d.hBackupFiles)
	h("GET /api/v1/backups", d.hBackups)
	h("POST /api/v1/backup/restore", d.hRestore)
	h("GET /api/v1/system", d.hSystem)
	h("PUT /api/v1/system", d.hPutSystem)
	h("POST /api/v1/system/web-key", d.hWebKey)
	h("GET /api/v1/diagnostics", d.hDiagnostics)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { writeError(w, errNotFound) })
	return mux
}

// unixHandler adds endpoints reserved for local root callers.
func (d *Daemon) unixHandler() http.Handler {
	mux := d.apiMux()
	mux.HandleFunc("POST /api/v1/daemon/shutdown", wrap(func(http.ResponseWriter, *http.Request) (any, error) {
		go func() {
			time.Sleep(100 * time.Millisecond)
			d.Shutdown(30 * time.Second)
		}()
		return map[string]string{"status": "shutting-down"}, nil
	}))
	sem := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			writeError(w, &APIError{Status: http.StatusTooManyRequests, Code: "BUSY", Message: "并发请求过多"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
