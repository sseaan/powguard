package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sseaan/powguard/internal/store/sqlite"
)

// handleEventStream 是 SSE 实时事件推送：每 interval 轮询增量事件，
// 无新事件时发注释心跳保活。前端断线自动回退到 /admin/events 分页轮询（PLAN.md §7）。
func (h *Handler) handleEventStream(w http.ResponseWriter, r *http.Request, _ string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Caddy/Nginx 不缓冲

	site := r.URL.Query().Get("site")
	if site == "" {
		site = "all"
	}

	// 从当前时间起推送（不重放历史；历史用 /admin/events）
	cursor := h.now()
	fmt.Fprintf(w, "event: hello\ndata: {\"site\":%q,\"since\":%d}\n\n", site, cursor)
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case <-ticker.C:
			filter := sqliteEventFilter(site, cursor)
			list, err := h.Events.List(filter)
			if err != nil {
				fmt.Fprintf(w, "event: error\ndata: {\"error\":\"query failed\"}\n\n")
				flusher.Flush()
				continue
			}
			// 按时间正序推送（List 是倒序）
			for i := len(list) - 1; i >= 0; i-- {
				e := list[i]
				if e.Ts < cursor {
					continue
				}
				cursor = e.Ts + 1
				payload, _ := json.Marshal(map[string]any{
					"id": e.ID, "ts": e.Ts, "site": e.SiteSlug, "type": e.Type,
					"outcome": e.Outcome, "reason": e.Reason,
					"protocol": e.Protocol, "dur_ms": e.DurMs,
				})
				fmt.Fprintf(w, "event: event\ndata: %s\n\n", payload)
			}
			flusher.Flush()
		}
	}
}

// sqliteEventFilter 构造 SSE 增量过滤条件。
func sqliteEventFilter(site string, since int64) sqlite.EventFilter {
	f := sqlite.EventFilter{Since: since, Limit: 200}
	if site != "" && site != "all" {
		f.Site = site
	}
	return f
}
