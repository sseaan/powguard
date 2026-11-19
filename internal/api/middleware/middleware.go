// Package middleware 提供 public API 的横切能力：CORS、限流、请求体上限、
// 请求 ID 与访问日志。P1 阶段 IP 直接取 RemoteAddr（可信反代模式在
// P2/P3 引入，见 PLAN.md §6.3）。
package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// ClientIP 提取客户端 IP（直连模式：仅 RemoteAddr）。
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Chain 从内到外包装：Chain(h, m1, m2) == m1(m2(h))。
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// RequestLogger 注入 request id 并记录基础访问日志。
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	var nextID atomic.Uint64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := nextID.Add(1)
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			if logger != nil {
				logger.Info("http",
					"rid", id,
					"method", r.Method,
					"path", r.URL.Path,
					"status", rec.status,
					"ip", ClientIP(r),
					"dur_ms", time.Since(start).Milliseconds(),
				)
			}
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Recover 把 panic 转成 500，避免拖垮进程。
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					if logger != nil {
						logger.Error("panic", "err", err, "path", r.URL.Path)
					}
					http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBytes 限制请求体大小，超限返回 413（capd redeem 语义：256 KiB）。
func MaxBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}
