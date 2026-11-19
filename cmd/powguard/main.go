// powguard —— 单二进制 Cap PoW 人机验证服务。
//
// 环境变量：
//
//	POWGUARD_ADDR            监听地址（默认 127.0.0.1:3000）
//	POWGUARD_DB_PATH         SQLite 路径（默认 ./powguard.sqlite3）
//	POWGUARD_MASTER_KEY      32 字节（hex 或 base64）。已有密文的库缺此 key 将拒绝启动；
//	                      全新库可缺省（自动生成临时 key，重启后密钥不可用，仅限本机演示）
//	POWGUARD_ADMIN_KEY       管理面板登录密钥；缺省则管理面板整体禁用
//	POWGUARD_TRUST_PROXY     可信反代网段（逗号分隔 CIDR，如 127.0.0.1/8）；
//	                      配置后才读取 X-Forwarded-For
//	POWGUARD_PUBLIC_URL      公开 URL（https 时 cookie 自动 Secure；展示用）
//
// 首次启动（库中无站点）会用 POWGUARD_SITE_SLUG / POWGUARD_SITE_SECRET 引导首个站点；
// 此后站点以 SQLite 为准（管理面板维护）。
//
// 运维子命令：
//
//	powguard keyrotate   --db <path> --old-key <k> --new-key <k>   # master key 轮换
//	powguard backup      --db <path> --out <file>                  # 一致性快照
//	powguard verify-keys --db <path> --master-key <k>              # 密文可解性校验
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sseaan/powguard/internal/api/admin"
	"github.com/sseaan/powguard/internal/api/middleware"
	"github.com/sseaan/powguard/internal/api/public"
	"github.com/sseaan/powguard/internal/events"
	"github.com/sseaan/powguard/internal/policy"
	"github.com/sseaan/powguard/internal/protocol/format1"
	"github.com/sseaan/powguard/internal/security/secretbox"
	"github.com/sseaan/powguard/internal/security/session"
	"github.com/sseaan/powguard/internal/store/memory"
	"github.com/sseaan/powguard/internal/store/model"
	"github.com/sseaan/powguard/internal/store/sqlite"
	"github.com/sseaan/powguard/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseMasterKey 解析 hex 或 base64 的 32 字节 key。
func parseMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	return nil, fmt.Errorf("POWGUARD_MASTER_KEY 必须是 32 字节（hex 或 base64）")
}

func main() {
	// 运维子命令（keyrotate / backup / verify-keys）不启动 HTTP 服务
	if handled, code := runOps(os.Args); handled {
		os.Exit(code)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	addr := env("POWGUARD_ADDR", "127.0.0.1:3000")
	dbPath := env("POWGUARD_DB_PATH", "powguard.sqlite3")
	publicURL := env("POWGUARD_PUBLIC_URL", "")

	db, err := sqlite.Open(dbPath)
	if err != nil {
		logger.Error("open db failed", "err", err)
		os.Exit(1)
	}
	siteRepo := sqlite.NewSiteRepo(db)
	secretRepo := sqlite.NewSecretRepo(db)
	eventRepo := sqlite.NewEventRepo(db)
	sessionRepo := sqlite.NewSessionRepo(db)
	settingsRepo := sqlite.NewSettingsRepo(db)

	// ---- master key：已有密文则必须提供，且需能解开
	masterRaw, err := parseMasterKey(os.Getenv("POWGUARD_MASTER_KEY"))
	if err != nil {
		logger.Error("invalid POWGUARD_MASTER_KEY", "err", err)
		os.Exit(1)
	}
	ephemeralMaster := false
	if masterRaw == nil {
		if has, _ := secretRepo.HasAnySecrets(); has {
			logger.Error("库中已有加密密钥但未提供 POWGUARD_MASTER_KEY，拒绝启动（密文不可恢复）")
			os.Exit(1)
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			logger.Error("generate ephemeral master key failed", "err", err)
			os.Exit(1)
		}
		masterRaw = buf
		ephemeralMaster = true
		logger.Warn("POWGUARD_MASTER_KEY 未设置：已生成临时 master key（重启后密文不可用，仅限本机演示；生产必须显式配置并独立备份）")
	}
	box, err := secretbox.New(masterRaw)
	if err != nil {
		logger.Error("secretbox init failed", "err", err)
		os.Exit(1)
	}

	// ---- 首站点 bootstrap（仅当库中无站点）
	if n, _ := siteRepo.Count(); n == 0 {
		slug := env("POWGUARD_SITE_SLUG", "twikoo")
		secret := os.Getenv("POWGUARD_SITE_SECRET")
		ephemeralSiteSecret := false
		if secret == "" {
			buf := make([]byte, 24)
			if _, err := rand.Read(buf); err != nil {
				logger.Error("generate ephemeral site secret failed", "err", err)
				os.Exit(1)
			}
			secret = hex.EncodeToString(buf)
			ephemeralSiteSecret = true
		}
		if err := bootstrapSite(siteRepo, secretRepo, box, slug, secret); err != nil {
			logger.Error("bootstrap site failed", "err", err)
			os.Exit(1)
		}
		if ephemeralSiteSecret {
			logger.Warn("POWGUARD_SITE_SECRET 未设置，首站点已生成临时 secret（重启失效，仅供本机演示）")
		}
		logger.Info("bootstrapped first site", "slug", slug)
	}

	resolver := policy.NewDBResolver(siteRepo, secretRepo, box)

	// ---- 事件 sink（异步审计）
	sink := events.NewSink(eventRepo, box.DeriveIPDigestKey(), 2048)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink.Start(ctx)

	// ---- IP 提取模式
	var ips *middleware.IPExtractor
	if cidrs := os.Getenv("POWGUARD_TRUST_PROXY"); cidrs != "" {
		e, err := middleware.NewIPExtractor(cidrs)
		if err != nil {
			logger.Error("invalid POWGUARD_TRUST_PROXY", "err", err)
			os.Exit(1)
		}
		ips = e
		logger.Info("trusted proxy mode enabled", "cidrs", cidrs)
	} else {
		logger.Info("direct mode: X-Forwarded-For 被忽略")
	}

	pub := &public.Handler{
		Sites:      resolver,
		Challenges: memory.NewChallengeStore(),
		Tokens:     memory.NewTokenStore(),
		Nonces:     memory.NewTokenStore(),
		Limiter:    memory.NewRateLimiter(),
		Clock:      func() int64 { return time.Now().UnixMilli() },
		Logger:     logger,
		Events:     sink,
		IPs:        ips,
	}

	mux := http.NewServeMux()
	pub.Register(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	cookieSecure := strings.HasPrefix(publicURL, "https://")
	if v := os.Getenv("POWGUARD_COOKIE_SECURE"); v != "" {
		cookieSecure, _ = strconv.ParseBool(v)
	}
	adminEnabled := false
	if adminKey := os.Getenv("POWGUARD_ADMIN_KEY"); adminKey != "" {
		adminEnabled = true
		adm := &admin.Handler{
			AdminKey:     []byte(adminKey),
			Sessions:     session.NewManager(sessionRepo, 0),
			Box:          box,
			Sites:        siteRepo,
			Secrets:      secretRepo,
			Events:       eventRepo,
			Resolver:     resolver,
			Limiter:      memory.NewRateLimiter(),
			Clock:        func() int64 { return time.Now().UnixMilli() },
			Logger:       logger,
			CookieSecure: cookieSecure,
			IPs:          ips,
		}
		if err := adm.Register(mux); err != nil {
			logger.Error("admin register failed", "err", err)
			os.Exit(1)
		}
	} else {
		logger.Warn("POWGUARD_ADMIN_KEY 未设置：管理面板已禁用")
	}

	// 首站点 slug 供 demo 页使用
	firstSlug := env("POWGUARD_SITE_SLUG", "twikoo")
	if sites, err := siteRepo.List(); err == nil && len(sites) > 0 {
		firstSlug = sites[0].Slug
	}

	assets := &web.Assets{
		Sessions:     session.NewManager(sessionRepo, 0),
		Box:          box,
		Sites:        siteRepo,
		FirstSlug:    firstSlug,
		AdminEnabled: adminEnabled,
		CookieSecure: cookieSecure,
	}
	if err := assets.Register(mux); err != nil {
		logger.Error("web register failed", "err", err)
		os.Exit(1)
	}

	root := middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.RequestLogger(logger, ips),
	)

	srv := &http.Server{
		Addr:              addr,
		Handler:           root,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	// 后台维护：惰性清理 + 事件保留期
	cleanupStop := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				now := time.Now().UnixMilli()
				pub.Challenges.DeleteExpired(now)
				pub.Tokens.DeleteExpired(now)
				pub.Nonces.DeleteExpired(now)
				pub.Limiter.Cleanup(now, 10*60*1000)
				session.NewManager(sessionRepo, 0).Cleanup(now)
				retention := model.DefaultEventRetentionDays
				if raw, ok, _ := settingsRepo.Get(model.SettingEventRetentionDays); ok {
					if v, err := strconv.Atoi(raw); err == nil && v > 0 {
						retention = v
					}
				}
				eventRepo.DeleteOlderThan(now, retention)
			case <-cleanupStop:
				return
			}
		}
	}()

	go func() {
		logger.Info("powguard listening", "addr", addr, "admin", adminEnabled,
			"db", dbPath, "ephemeral_master_key", ephemeralMaster)
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", "err", err)
	}
	// 排空事件 sink 后再关库
	sink.Close(shutdownCtx)
	if err := db.Close(); err != nil {
		logger.Error("db close failed", "err", err)
	}
	logger.Info("bye")
}

// bootstrapSite 建首站点并把 secret / signing key 加密入库。
func bootstrapSite(sites *sqlite.SiteRepo, secrets *sqlite.SecretRepo, box *secretbox.Box, slug, secretPlain string) error {
	m := &model.Site{
		Slug:                slug,
		Protocol:            policy.ProtocolFormat1,
		Name:                slug,
		Enabled:             true,
		ChallengeCount:      format1.DefaultChallengeCount,
		ChallengeSize:       format1.DefaultChallengeSize,
		ChallengeDifficulty: format1.DefaultChallengeDifficulty,
		ChallengeTTL:        format1.DefaultChallengeTTL,
		TokenTTL:            format1.DefaultTokenTTL,
		CORSAllowAll:        true,
		RateLimitPerWindow:  30,
		RateLimitWindowMs:   5000,
	}
	if err := sites.Create(m); err != nil {
		return err
	}
	ciphertext, err := box.Seal([]byte(secretPlain), m.Slug, model.FieldSiteVerify)
	if err != nil {
		return err
	}
	if err := secrets.Put(&model.SiteSecret{
		SiteID: m.ID, Field: model.FieldSiteVerify,
		Ciphertext: ciphertext, SchemaVersion: 1,
	}); err != nil {
		return err
	}
	// format-2 签名密钥（内部使用，永不外发）
	signPlain, err := format1.RandomHex(32)
	if err != nil {
		return err
	}
	signCT, err := box.Seal([]byte(signPlain), m.Slug, model.FieldSigning)
	if err != nil {
		return err
	}
	return secrets.Put(&model.SiteSecret{
		SiteID: m.ID, Field: model.FieldSigning,
		Ciphertext: signCT, SchemaVersion: 1,
	})
}
