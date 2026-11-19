// capgo —— 单二进制 Cap PoW 人机验证服务（P1：format-1 + Twikoo 纵向切片）。
//
// 环境变量（P1 阶段；SQLite/管理面板在后续里程碑接入）：
//
//	CAPGO_ADDR          监听地址（默认 127.0.0.1:3000）
//	CAPGO_SITE_SLUG     站点 slug（默认 twikoo；小写字母/数字/-/_，1–32）
//	CAPGO_SITE_SECRET   siteverify 密钥；未设置则每次启动随机生成（重启即失效，
//	                    仅适合本机演示；生产必须显式设置）
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"capgo/internal/api/middleware"
	"capgo/internal/api/public"
	"capgo/internal/policy"
	"capgo/internal/store/memory"
	"capgo/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	addr := env("CAPGO_ADDR", "127.0.0.1:3000")
	slug := env("CAPGO_SITE_SLUG", "twikoo")
	secret := os.Getenv("CAPGO_SITE_SECRET")
	ephemeralSecret := false
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			logger.Error("generate ephemeral secret failed", "err", err)
			os.Exit(1)
		}
		secret = hex.EncodeToString(buf)
		ephemeralSecret = true
	}

	site, err := policy.NewSite(slug, secret)
	if err != nil {
		logger.Error("invalid site config", "err", err)
		os.Exit(1)
	}
	if ephemeralSecret {
		// 不打印 secret 本体（PLAN.md §6.2：密钥不落日志）
		logger.Warn("CAPGO_SITE_SECRET 未设置，已生成临时密钥（重启失效，仅供本机演示）")
	}

	h := &public.Handler{
		Sites:      &policy.StaticResolver{Site: site},
		Challenges: memory.NewChallengeStore(),
		Tokens:     memory.NewTokenStore(),
		Limiter:    memory.NewRateLimiter(),
		Clock:      func() int64 { return time.Now().UnixMilli() },
		Logger:     logger,
	}

	mux := http.NewServeMux()
	h.Register(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	web.RegisterStatic(mux, site.Slug)

	root := middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.RequestLogger(logger),
	)

	srv := &http.Server{
		Addr:              addr,
		Handler:           root,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second, // SSE 预留（M4 事件流）
		IdleTimeout:       90 * time.Second,
	}

	// 后台惰性清理：对齐官方 _lazyCleanup 的 5 分钟节奏
	cleanupStop := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				now := time.Now().UnixMilli()
				h.Challenges.DeleteExpired(now)
				h.Tokens.DeleteExpired(now)
				h.Limiter.Cleanup(now, 10*60*1000)
			case <-cleanupStop:
				return
			}
		}
	}()

	go func() {
		logger.Info("capgo listening", "addr", addr, "site", site.Slug, "ephemeral_secret", ephemeralSecret)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Info("shutting down")
	close(cleanupStop)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", "err", err)
	}
	logger.Info("bye")
}
