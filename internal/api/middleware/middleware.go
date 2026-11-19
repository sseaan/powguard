// Package middleware 提供 public API 的横切能力：CORS、限流、请求体上限、
// 请求 ID 与访问日志。IP 取 RemoteAddr；配置可信反代后读取 X-Forwarded-For。
package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Chain 从内到外包装：Chain(h, m1, m2) == m1(m2(h))。
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// RequestLogger 注入 request id 并记录基础访问日志。
// 传入 IPExtractor 时按可信反代模式取真实客户端 IP；否则保持直连语义。
func RequestLogger(logger *slog.Logger, extractors ...*IPExtractor) func(http.Handler) http.Handler {
	var ips *IPExtractor
	if len(extractors) > 0 {
		ips = extractors[0]
	}
	var nextID atomic.Uint64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := nextID.Add(1)
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			if logger != nil {
				ip := ClientIP(r)
				if ips != nil {
					ip = ips.Client(r)
				}
				logger.Info("http",
					"rid", id,
					"method", r.Method,
					"path", r.URL.Path,
					"status", rec.status,
					"ip", ip,
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

// Flush 透传 http.Flusher：SSE 等流式响应依赖它（否则 handler 无法判定可流式）。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 让 http.ResponseController 能拿到原始 ResponseWriter。
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

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

// IPExtractor 从请求提取客户端 IP：直连模式只信 RemoteAddr；
// 配置可信 CIDR 后才读取 X-Forwarded-For。
type IPExtractor struct {
	Trusted []*net.IPNet
}

// NewIPExtractor 解析逗号分隔 CIDR（支持单个 IP）。
func NewIPExtractor(cidrs string) (*IPExtractor, error) {
	e := &IPExtractor{}
	for _, c := range strings.Split(cidrs, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			c += "/32"
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("middleware: 非法 CIDR %q: %w", c, err)
		}
		e.Trusted = append(e.Trusted, n)
	}
	return e, nil
}

func (e *IPExtractor) trusted(ip net.IP) bool {
	for _, n := range e.Trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Client 返回真实客户端 IP：
//   - RemoteAddr 不在可信网段 → 直连客户端，忽略 XFF；
//   - RemoteAddr 可信 → 从 XFF 最右侧往左走，跳过可信代理，
//     第一个不可信地址即客户端；全部可信则取最左。
func (e *IPExtractor) Client(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote == nil || !e.trusted(remote) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	ips := make([]net.IP, 0, len(parts))
	for _, p := range parts {
		if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return host
	}
	for i := len(ips) - 1; i >= 0; i-- {
		if !e.trusted(ips[i]) {
			return ips[i].String()
		}
	}
	return ips[0].String()
}

// ClientIP 保持直连语义（无反代配置时的默认行为）。
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
