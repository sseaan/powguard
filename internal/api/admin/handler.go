// Package admin 是管理面板 JSON API（M2 骨干，M4 WebUI 消费同一批端点）。
//
// 认证：POWGUARD_ADMIN_KEY 登录 → 不透明 session token（HttpOnly/SameSite=Lax
// cookie）→ 修改操作带 X-CSRF-Token（HMAC 绑定会话哈希）。
// 高危操作（reveal/rotate）要求 body 再次携带 admin key。
package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/sseaan/powguard/internal/api/middleware"
	"github.com/sseaan/powguard/internal/policy"
	"github.com/sseaan/powguard/internal/protocol/format1"
	"github.com/sseaan/powguard/internal/security/csrf"
	"github.com/sseaan/powguard/internal/security/session"
	"github.com/sseaan/powguard/internal/store/memory"
	"github.com/sseaan/powguard/internal/store/model"
	"github.com/sseaan/powguard/internal/store/sqlite"
)

// CookieName 是管理会话 cookie 名。
const CookieName = "powguard_admin"

// loginLimit 是登录尝试限流：每 IP 每 60 秒 5 次（PLAN.md §6.3）。
var loginLimits = struct {
	max      int
	windowMs int64
}{5, 60 * 1000}

// Handler 是管理 API。
type Handler struct {
	AdminKey []byte // nil = 管理面板禁用
	Sessions *session.Manager
	Box      interface {
		DeriveCSRFKey() []byte
		Seal([]byte, string, string) (string, error)
		Open(blob, siteSlug, field string) ([]byte, error)
	}
	Sites    *sqlite.SiteRepo
	Secrets  *sqlite.SecretRepo
	Events   *sqlite.EventRepo
	Resolver interface {
		Invalidate(slug string)
		InvalidateAll()
	}
	Limiter *memory.RateLimiter
	Clock   func() int64
	Logger  *slog.Logger
	// CookieSecure 在 HTTPS 反代后设 true。
	CookieSecure bool
	// IPs 为 nil 时用直连 RemoteAddr；配置可信网段后读 XFF（与公开 API 一致）。
	IPs *middleware.IPExtractor
}

// clientIP 取客户端 IP（直连或可信反代模式）。
func (h *Handler) clientIP(r *http.Request) string {
	if h.IPs != nil {
		return h.IPs.Client(r)
	}
	return middleware.ClientIP(r)
}

func (h *Handler) now() int64 {
	if h.Clock != nil {
		return h.Clock()
	}
	return time.Now().UnixMilli()
}

func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// Register 挂载路由；AdminKey 为空时不注册（管理面板整体禁用）。
func (h *Handler) Register(mux *http.ServeMux) error {
	if len(h.AdminKey) == 0 {
		return nil // 管理面板禁用
	}
	mux.HandleFunc("POST /admin/api/login", h.handleLogin)
	mux.Handle("POST /admin/api/logout", h.requireSession(h.handleLogout))
	mux.Handle("GET /admin/api/session", h.requireSession(h.handleWhoami))
	mux.Handle("GET /admin/api/sites", h.requireSession(h.handleSiteList))
	mux.Handle("POST /admin/api/sites", h.requireSession(h.handleSiteCreate))
	mux.Handle("GET /admin/api/sites/{slug}", h.requireSession(h.handleSiteGet))
	mux.Handle("POST /admin/api/sites/{slug}", h.requireSession(h.handleSiteUpdate))
	mux.Handle("DELETE /admin/api/sites/{slug}", h.requireSession(h.handleSiteDelete))
	mux.Handle("POST /admin/api/sites/{slug}/reveal", h.requireSession(h.handleSiteReveal))
	mux.Handle("POST /admin/api/sites/{slug}/rotate", h.requireSession(h.handleSiteRotate))
	mux.Handle("GET /admin/api/events", h.requireSession(h.handleEvents))
	mux.Handle("GET /admin/api/stats", h.requireSession(h.handleStats))
	mux.Handle("GET /admin/api/events/stream", h.requireSession(h.handleEventStream))
	return nil
}

// ---------------------------------------------------------------- 辅助

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// adminKeyMatch 常数时间比较 admin key。
func (h *Handler) adminKeyMatch(presented string) bool {
	if len(h.AdminKey) == 0 || presented == "" {
		return false
	}
	want := sha256.Sum256(h.AdminKey)
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

func (h *Handler) sessionCookie(token string, expiresAt int64) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((expiresAt - h.now()) / 1000),
	}
}

func readSessionCookie(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// requireSession 要求有效会话；修改方法还要求 CSRF。
func (h *Handler) requireSession(next func(w http.ResponseWriter, r *http.Request, tokenHash string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := readSessionCookie(r)
		ok, _, err := h.Sessions.Valid(token, h.now())
		if err != nil || !ok {
			writeErr(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		tokenHash := session.Hash(token)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !csrf.Verify(h.Box.DeriveCSRFKey(), tokenHash, r.Header.Get("X-CSRF-Token")) {
				writeErr(w, http.StatusForbidden, "CSRF token invalid")
				return
			}
		}
		next(w, r, tokenHash)
	})
}

func (h *Handler) rateLimited(w http.ResponseWriter, r *http.Request, key string, max int) bool {
	if !h.Limiter.Allow(key+"|"+h.clientIP(r), max, loginLimits.windowMs, h.now()) {
		writeErr(w, http.StatusTooManyRequests, "Too many requests")
		return true
	}
	return false
}

// ---------------------------------------------------------------- 登录

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(w, r, "login", loginLimits.max) {
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !h.adminKeyMatch(body.Key) {
		h.logger().Warn("admin_login_fail", "ip", h.clientIP(r))
		writeErr(w, http.StatusUnauthorized, "Invalid admin key")
		return
	}
	token, expiresAt, err := h.Sessions.Create(h.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	http.SetCookie(w, h.sessionCookie(token, expiresAt))
	h.logger().Info("admin_login_ok")
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf":    csrf.Token(h.Box.DeriveCSRFKey(), session.Hash(token)),
		"expires": expiresAt,
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request, _ string) {
	if err := h.Sessions.Revoke(readSessionCookie(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to revoke")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleWhoami(w http.ResponseWriter, r *http.Request, tokenHash string) {
	_, expiresAt, err := h.Sessions.Valid(readSessionCookie(r), h.now())
	if err != nil || expiresAt == 0 {
		writeErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	// 同时下发 CSRF token：新标签页（sessionStorage 为空）可据此恢复写能力。
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"expires":       expiresAt,
		"csrf":          csrf.Token(h.Box.DeriveCSRFKey(), tokenHash),
	})
}

// ---------------------------------------------------------------- 站点 CRUD

type sitePayload struct {
	Slug                string   `json:"slug"`
	Name                string   `json:"name"`
	Protocol            *string  `json:"protocol"` // format1 | format2
	Enabled             *bool    `json:"enabled"`
	ChallengeCount      *int     `json:"challenge_count"`
	ChallengeSize       *int     `json:"challenge_size"`
	ChallengeDifficulty *int     `json:"challenge_difficulty"`
	ChallengeTTL        *int64   `json:"challenge_ttl_ms"`
	TokenTTL            *int64   `json:"token_ttl_ms"`
	CORSAllowAll        *bool    `json:"cors_allow_all"`
	CORSOrigins         []string `json:"cors_origins"`
	RateLimitPerWindow  *int     `json:"rate_limit_per_window"`
	RateLimitWindowMs   *int64   `json:"rate_limit_window_ms"`
}

func siteToJSON(m *model.Site) map[string]any {
	return map[string]any{
		"slug":                  m.Slug,
		"protocol":              model.ProtocolOrDefault(m.Protocol),
		"name":                  m.Name,
		"enabled":               m.Enabled,
		"challenge_count":       m.ChallengeCount,
		"challenge_size":        m.ChallengeSize,
		"challenge_difficulty":  m.ChallengeDifficulty,
		"challenge_ttl_ms":      m.ChallengeTTL,
		"token_ttl_ms":          m.TokenTTL,
		"cors_allow_all":        m.CORSAllowAll,
		"cors_origins":          m.CORSOrigins,
		"rate_limit_per_window": m.RateLimitPerWindow,
		"rate_limit_window_ms":  m.RateLimitWindowMs,
		"created_at":            m.CreatedAt,
		"updated_at":            m.UpdatedAt,
	}
}

func applyPayload(m *model.Site, p sitePayload) error {
	if p.Name != "" {
		m.Name = p.Name
	}
	if p.Protocol != nil {
		if !policy.ValidProtocol(*p.Protocol) {
			return errors.New("protocol 仅支持 format1 / format2")
		}
		m.Protocol = *p.Protocol
	}
	if p.Enabled != nil {
		m.Enabled = *p.Enabled
	}
	if p.ChallengeCount != nil {
		m.ChallengeCount = *p.ChallengeCount
	}
	if p.ChallengeSize != nil {
		m.ChallengeSize = *p.ChallengeSize
	}
	if p.ChallengeDifficulty != nil {
		m.ChallengeDifficulty = *p.ChallengeDifficulty
	}
	if p.ChallengeTTL != nil {
		m.ChallengeTTL = *p.ChallengeTTL
	}
	if p.TokenTTL != nil {
		m.TokenTTL = *p.TokenTTL
	}
	if p.CORSAllowAll != nil {
		m.CORSAllowAll = *p.CORSAllowAll
	}
	if p.CORSOrigins != nil {
		m.CORSOrigins = p.CORSOrigins
	}
	if p.RateLimitPerWindow != nil {
		m.RateLimitPerWindow = *p.RateLimitPerWindow
	}
	if p.RateLimitWindowMs != nil {
		m.RateLimitWindowMs = *p.RateLimitWindowMs
	}
	// 校验
	cfg := format1.ChallengeConfig{Count: m.ChallengeCount, Size: m.ChallengeSize, Difficulty: m.ChallengeDifficulty}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if m.ChallengeTTL <= 0 || m.ChallengeTTL > 24*60*60*1000 {
		return errors.New("challenge_ttl_ms 超出范围")
	}
	if m.TokenTTL <= 0 || m.TokenTTL > 24*60*60*1000 {
		return errors.New("token_ttl_ms 超出范围")
	}
	if m.RateLimitPerWindow < 1 || m.RateLimitPerWindow > 10000 {
		return errors.New("rate_limit_per_window 超出范围")
	}
	if m.RateLimitWindowMs < 1000 || m.RateLimitWindowMs > 3600*1000 {
		return errors.New("rate_limit_window_ms 超出范围")
	}
	return nil
}

func (h *Handler) handleSiteList(w http.ResponseWriter, r *http.Request, _ string) {
	sites, err := h.Sites.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to list sites")
		return
	}
	out := []map[string]any{}
	for _, m := range sites {
		out = append(out, siteToJSON(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out})
}

func (h *Handler) handleSiteGet(w http.ResponseWriter, r *http.Request, _ string) {
	m, err := h.Sites.GetBySlug(r.PathValue("slug"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "Site not found")
		return
	}
	writeJSON(w, http.StatusOK, siteToJSON(m))
}

func (h *Handler) handleSiteCreate(w http.ResponseWriter, r *http.Request, _ string) {
	if h.rateLimited(w, r, "site-create", 10) {
		return
	}
	var p sitePayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !policy.ValidSlug(p.Slug) {
		writeErr(w, http.StatusBadRequest, "Invalid slug")
		return
	}
	if _, err := h.Sites.GetBySlugAny(p.Slug); err == nil {
		writeErr(w, http.StatusConflict, "Slug already exists（含软删除，需先改名或恢复）")
		return
	}
	m := &model.Site{
		Slug:                p.Slug,
		Protocol:            policy.ProtocolFormat1,
		Name:                p.Name,
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
	if err := applyPayload(m, p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.Sites.Create(m); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to create site")
		return
	}

	// 生成 siteverify secret（明文只在本次响应出现一次）
	secretPlain, err := format1.RandomHex(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to generate secret")
		return
	}
	ciphertext, err := h.Box.Seal([]byte(secretPlain), m.Slug, model.FieldSiteVerify)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to encrypt secret")
		return
	}
	if err := h.Secrets.Put(&model.SiteSecret{
		SiteID: m.ID, Field: model.FieldSiteVerify,
		Ciphertext: ciphertext, SchemaVersion: 1,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to store secret")
		return
	}
	// format-2 签名密钥（内部使用，永不外发）
	signPlain, err := format1.RandomHex(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to generate signing key")
		return
	}
	signCT, err := h.Box.Seal([]byte(signPlain), m.Slug, model.FieldSigning)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to encrypt signing key")
		return
	}
	if err := h.Secrets.Put(&model.SiteSecret{
		SiteID: m.ID, Field: model.FieldSigning,
		Ciphertext: signCT, SchemaVersion: 1,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to store signing key")
		return
	}

	h.Resolver.Invalidate(m.Slug)
	h.logger().Info("site_created", "slug", m.Slug, "protocol", m.Protocol)
	writeJSON(w, http.StatusCreated, map[string]any{
		"site":   siteToJSON(m),
		"secret": secretPlain,
		"hint":   "secret 只显示一次，请立即配置到 Twikoo CAP_SECRET_KEY",
	})
}

func (h *Handler) handleSiteUpdate(w http.ResponseWriter, r *http.Request, _ string) {
	m, err := h.Sites.GetBySlug(r.PathValue("slug"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "Site not found")
		return
	}
	var p sitePayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "Bad request")
		return
	}
	if p.Slug != "" && p.Slug != m.Slug {
		writeErr(w, http.StatusBadRequest, "slug 不可修改")
		return
	}
	if err := applyPayload(m, p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.Sites.Update(m); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to update site")
		return
	}
	h.Resolver.Invalidate(m.Slug)
	h.logger().Info("site_updated", "slug", m.Slug)
	writeJSON(w, http.StatusOK, siteToJSON(m))
}

func (h *Handler) handleSiteDelete(w http.ResponseWriter, r *http.Request, _ string) {
	slug := r.PathValue("slug")
	if err := h.Sites.SoftDelete(slug); err != nil {
		writeErr(w, http.StatusNotFound, "Site not found")
		return
	}
	h.Resolver.Invalidate(slug)
	h.logger().Info("site_deleted", "slug", slug)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- reveal / rotate

// reAuthPayload 是高危操作的二次认证。
type reAuthPayload struct {
	Key string `json:"key"`
}

func (h *Handler) reAuthOK(w http.ResponseWriter, r *http.Request) bool {
	if h.rateLimited(w, r, "reveal-rotate", 10) {
		return false
	}
	var p reAuthPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "Bad request")
		return false
	}
	if !h.adminKeyMatch(p.Key) {
		h.logger().Warn("admin_reauth_fail", "path", r.URL.Path)
		writeErr(w, http.StatusUnauthorized, "Invalid admin key")
		return false
	}
	return true
}

func (h *Handler) handleSiteReveal(w http.ResponseWriter, r *http.Request, _ string) {
	if !h.reAuthOK(w, r) {
		return
	}
	slug := r.PathValue("slug")
	m, err := h.Sites.GetBySlug(slug)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Site not found")
		return
	}
	sec, err := h.Secrets.Get(m.ID, model.FieldSiteVerify)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Secret not found")
		return
	}
	plaintext, err := h.Box.Open(sec.Ciphertext, m.Slug, model.FieldSiteVerify)
	if err != nil {
		h.logger().Error("secret_decrypt_fail", "slug", slug)
		writeErr(w, http.StatusInternalServerError, "Secret decrypt failed（master key 不匹配？）")
		return
	}
	h.logger().Info("secret_revealed", "slug", slug)
	writeJSON(w, http.StatusOK, map[string]string{"secret": string(plaintext)})
}

func (h *Handler) handleSiteRotate(w http.ResponseWriter, r *http.Request, _ string) {
	if !h.reAuthOK(w, r) {
		return
	}
	slug := r.PathValue("slug")
	m, err := h.Sites.GetBySlug(slug)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Site not found")
		return
	}
	secretPlain, err := format1.RandomHex(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to generate secret")
		return
	}
	ciphertext, err := h.Box.Seal([]byte(secretPlain), m.Slug, model.FieldSiteVerify)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to encrypt secret")
		return
	}
	if err := h.Secrets.Put(&model.SiteSecret{
		SiteID: m.ID, Field: model.FieldSiteVerify,
		Ciphertext: ciphertext, SchemaVersion: 1,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to store secret")
		return
	}
	h.Resolver.Invalidate(slug)
	h.logger().Info("secret_rotated", "slug", slug)
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secretPlain,
		"hint":   "旧 secret 立即失效；请同步更新 Twikoo CAP_SECRET_KEY",
	})
}

// ---------------------------------------------------------------- 事件/统计

func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	list, err := h.Events.List(sqlite.EventFilter{
		Site:  q.Get("site"),
		Type:  q.Get("type"),
		Limit: limit,
		Since: since,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to query events")
		return
	}
	out := []map[string]any{}
	for _, e := range list {
		out = append(out, map[string]any{
			"id": e.ID, "ts": e.Ts, "site": e.SiteSlug, "type": e.Type,
			"outcome": e.Outcome, "reason": e.Reason, "protocol": e.Protocol,
			"ip_digest": e.IPDigest, "token_id": e.TokenID, "dur_ms": e.DurMs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > 90 {
		days = 7
	}
	typ := q.Get("type")
	daily, err := h.Events.DailyStats(h.now(), days, typ)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to aggregate stats")
		return
	}
	if daily == nil {
		daily = []sqlite.DailyStat{}
	}
	reasons, err := h.Events.TopReasons(typ, h.now(), days, 10)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to aggregate reasons")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"days":    days,
		"type":    typ,
		"daily":   daily,
		"reasons": reasons,
	})
}
