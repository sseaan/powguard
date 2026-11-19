// Package public 实现 Cap 公开线协议端点：
//
//	POST /{site}/challenge      签发 format-1 挑战
//	POST /{site}/redeem         校验解并签发一次性通行 token
//	POST /{site}/siteverify     通行 token 消费（Twikoo 服务端调用）
//	POST /siteverify            全局 siteverify（通行 token 必须为三段式）
//
// 错误响应形状对齐 capd 4.0.15（docs/protocol-notes.md §5）。
package public

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"capgo/internal/api/middleware"
	"capgo/internal/events"
	"capgo/internal/policy"
	"capgo/internal/protocol/format1"
	"capgo/internal/store/memory"
	"capgo/internal/store/model"
)

// 挑战/兑换请求体上限（capd redeem 语义：256 KiB）。
const maxBodyBytes = 256 * 1024

// Handler 是公开 API 的处理器。
type Handler struct {
	Sites      policy.SiteResolver
	Challenges *memory.ChallengeStore
	Tokens     *memory.TokenStore
	Limiter    *memory.RateLimiter
	// Clock 返回当前 Unix 毫秒；测试可注入。
	Clock  func() int64
	Logger *slog.Logger
	// Events 非 nil 时异步审计；IP 取摘要不落明文（PLAN.md §6.3）。
	Events *events.Sink
	// IPs 为 nil 时用直连 RemoteAddr；配置可信网段后读 XFF。
	IPs *middleware.IPExtractor
}

// clientIP 取客户端 IP（直连或可信反代模式）。
func (h *Handler) clientIP(r *http.Request) string {
	if h.IPs != nil {
		return h.IPs.Client(r)
	}
	return middleware.ClientIP(r)
}

// emit 非阻塞投递审计事件；Events 未配置时为空操作。
func (h *Handler) emit(r *http.Request, siteSlug, typ, outcome, reason, protocol, tokenID string, durMs int64) {
	if h.Events == nil {
		return
	}
	e := &model.Event{
		SiteSlug: siteSlug,
		Type:     typ,
		Outcome:  outcome,
		Reason:   reason,
		Protocol: protocol,
		TokenID:  tokenID,
	}
	if durMs >= 0 {
		e.DurMs = &durMs
	}
	if h.Events != nil {
		e.IPDigest = h.Events.IPDigest(h.clientIP(r))
	}
	h.Events.Emit(e)
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

// Register 把路由挂到 mux（含预检与中间件）。
func (h *Handler) Register(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.Handler {
		return middleware.MaxBytes(maxBodyBytes)(http.HandlerFunc(fn))
	}
	mux.Handle("POST /{site}/challenge", wrap(h.handleChallenge))
	mux.Handle("POST /{site}/redeem", wrap(h.handleRedeem))
	mux.Handle("POST /{site}/siteverify", wrap(h.handleSiteVerify))
	mux.Handle("POST /siteverify", wrap(h.handleGlobalSiteVerify))
	// CORS 预检：widget 只会预检 challenge/redeem；siteverify 由服务端调用。
	mux.HandleFunc("OPTIONS /{site}/challenge", h.handlePreflight)
	mux.HandleFunc("OPTIONS /{site}/redeem", h.handlePreflight)
	mux.HandleFunc("OPTIONS /{site}/siteverify", h.handlePreflight)
	mux.HandleFunc("OPTIONS /siteverify", h.handlePreflight)
}

// ---------------------------------------------------------------- 响应辅助

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeRedeemError 是 redeem 失败响应（PLAN.md §3.1：{success:false, error}）。
func writeRedeemError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "error": msg})
}

func writeSiteVerifyError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "error": msg})
}

// bodyTooLarge 把 http.MaxBytesError 映射为 413（capd 语义）。
func bodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// resolveSite 解析路径站点；失败时已写出 404 并返回 nil。
func (h *Handler) resolveSite(w http.ResponseWriter, r *http.Request) (*policy.Site, bool) {
	slug := r.PathValue("site")
	if !policy.ValidSlug(slug) {
		writeError(w, http.StatusNotFound, "Invalid site key or secret")
		return nil, false
	}
	site, ok := h.Sites.Resolve(slug)
	if !ok || !site.Enabled {
		writeError(w, http.StatusNotFound, "Invalid site key or secret")
		return nil, false
	}
	return site, true
}

// applyCORS 设置站点级 CORS 响应头（capd app.js onRequest 语义）。
func (h *Handler) applyCORS(w http.ResponseWriter, r *http.Request, site *policy.Site) {
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin == "" || !site.CORSAllowed(origin) {
		return
	}
	if site.CORSAllowAll {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

// rateLimited 执行 challenge/redeem 的每 IP 每站点限流。
func (h *Handler) rateLimited(w http.ResponseWriter, r *http.Request, site *policy.Site) bool {
	ip := h.clientIP(r)
	key := site.Slug + "|" + ip
	if !h.Limiter.Allow(key, site.RateLimitPerWindow, site.RateLimitWindowMs, h.now()) {
		w.Header().Set("Retry-After", strconv.FormatInt(site.RateLimitWindowMs/1000+1, 10))
		writeError(w, http.StatusTooManyRequests, "Too many requests")
		h.logger().Warn("rate_limited", "site", site.Slug, "ip_digest", h.ipDigestOrEmpty(r))
		h.emit(r, site.Slug, "challenge", "limit", "rate_limited", "format1", "", -1)
		return true
	}
	return false
}

func (h *Handler) ipDigestOrEmpty(r *http.Request) string {
	if h.Events == nil {
		return ""
	}
	return h.Events.IPDigest(h.clientIP(r))
}

// ---------------------------------------------------------------- challenge

func (h *Handler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	site, ok := h.resolveSite(w, r)
	if !ok {
		return
	}
	h.applyCORS(w, r, site)
	if h.rateLimited(w, r, site) {
		return
	}
	// widget 在 WASM 不可用时携带 ?wasm=0（sha256-pow 场景下容忍并忽略）。
	// 其余未知 query 参数同样忽略。

	token, err := format1.NewChallengeToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate challenge")
		return
	}
	now := h.now()
	expires := now + site.ChallengeTTL
	h.Challenges.Put(token, format1.ChallengeData{Config: site.Challenge, Expires: expires})

	h.logger().Info("challenge_issued", "site", site.Slug)
	h.emit(r, site.Slug, "challenge", "pass", "", "format1", "", h.now()-start)
	writeJSON(w, http.StatusOK, format1.ChallengeResponse{
		Challenge: site.Challenge,
		Token:     token,
		Expires:   expires,
	})
}

// ---------------------------------------------------------------- redeem

// redeemBody 是 POST /redeem 请求体（solutions 保留原始 JSON 以严格校验整数）。
type redeemBody struct {
	Token     string            `json:"token"`
	Solutions []json.RawMessage `json:"solutions"`
}

// integerSolutions 把 solutions 规范化为十进制整数字符串。
// 已知偏差：官方接受任意 JS number（含浮点/指数）；capgo 拒绝非整数语法
// （docs/protocol-notes.md §9.1）。
func integerSolutions(raw []json.RawMessage) ([]string, bool) {
	out := make([]string, len(raw))
	for i, s := range raw {
		t := strings.TrimSpace(string(s))
		if t == "" {
			return nil, false
		}
		if _, err := strconv.ParseInt(t, 10, 64); err != nil {
			// 超出 int64 的纯十进制整数仍然接受（与 JS 大整数行为对齐）
			if !isDecimalInteger(t) {
				return nil, false
			}
		}
		out[i] = t
	}
	return out, true
}

func isDecimalInteger(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (h *Handler) handleRedeem(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	site, ok := h.resolveSite(w, r)
	if !ok {
		return
	}
	h.applyCORS(w, r, site)
	if h.rateLimited(w, r, site) {
		return
	}

	var body redeemBody
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		if bodyTooLarge(err) {
			writeRedeemError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		writeRedeemError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeRedeemError(w, http.StatusBadRequest, "Missing required fields")
			return
		}
	}
	if body.Token == "" || body.Solutions == nil {
		writeRedeemError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	solutions, ok2 := integerSolutions(body.Solutions)
	if !ok2 {
		writeRedeemError(w, http.StatusBadRequest, "Invalid solutions")
		return
	}

	now := h.now()
	// 官方语义：读取即删除（失败的 redeem 也烧掉挑战）。
	data, found := h.Challenges.Consume(body.Token)
	if !found || data.Expires < now {
		h.logger().Info("redeem_fail", "site", site.Slug, "reason", "challenge_invalid_or_expired")
		h.emit(r, site.Slug, "redeem", "fail", "challenge_invalid_or_expired", "format1", tokenID(body.Token), h.now()-start)
		writeRedeemError(w, http.StatusForbidden, "Challenge invalid or expired")
		return
	}
	if len(solutions) != data.Config.Count {
		h.logger().Info("redeem_fail", "site", site.Slug, "reason", "invalid_solution")
		h.emit(r, site.Slug, "redeem", "fail", "invalid_solution_count", "format1", tokenID(body.Token), h.now()-start)
		writeRedeemError(w, http.StatusForbidden, "Invalid solution")
		return
	}
	if err := format1.VerifySolutions(body.Token, data, solutions); err != nil {
		h.logger().Info("redeem_fail", "site", site.Slug, "reason", "invalid_solution")
		h.emit(r, site.Slug, "redeem", "fail", "invalid_solution", "format1", tokenID(body.Token), h.now()-start)
		writeRedeemError(w, http.StatusForbidden, "Invalid solution")
		return
	}

	// 签发 capd 风格三段式通行 token："site:id:vertoken"（兼容 capd 生态的
	// 全局 /siteverify；legacy 两段式由 SplitVerificationToken 同样支持）。
	vt, err := format1.NewVerificationToken(now, site.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}
	h.Tokens.Put(vt.Key, vt.Expires)

	h.logger().Info("redeem_pass", "site", site.Slug)
	h.emit(r, site.Slug, "redeem", "pass", "", "format1", tokenID(site.Slug+":"+vt.Token), h.now()-start)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"token":   site.Slug + ":" + vt.Token,
		"expires": vt.Expires,
	})
}

// ---------------------------------------------------------------- siteverify

type siteVerifyBody struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
}

// verifyAgainstSite 执行 secret 与通行 token 的一次性校验（capd siteverify 语义）。
func (h *Handler) verifyAgainstSite(w http.ResponseWriter, r *http.Request, site *policy.Site, body siteVerifyBody, start int64) {
	// 常数时间比较：比较 sha256 摘要，避免长度/早退泄露。
	want := sha256.Sum256([]byte(site.Secret))
	got := sha256.Sum256([]byte(body.Secret))
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		h.logger().Info("siteverify_fail", "site", site.Slug, "reason", "invalid_secret")
		h.emit(r, site.Slug, "siteverify", "fail", "invalid_secret", "format1", tokenID(body.Response), h.now()-start)
		writeSiteVerifyError(w, http.StatusForbidden, "Invalid site key or secret")
		return
	}

	key, err := format1.SplitVerificationToken(body.Response, site.Slug)
	if err != nil {
		// capd：parts 数量/空段非法 → 400；site 段与路径不匹配 → 404
		if strings.Count(body.Response, ":") == 2 && site.Slug != "" {
			h.emit(r, site.Slug, "siteverify", "fail", "site_mismatch", "format1", tokenID(body.Response), h.now()-start)
			writeSiteVerifyError(w, http.StatusNotFound, "Invalid site key or secret")
			return
		}
		h.emit(r, site.Slug, "siteverify", "fail", "malformed_token", "format1", "", h.now()-start)
		writeSiteVerifyError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}

	switch h.Tokens.Consume(key, h.now()) {
	case memory.TokenConsumed:
		h.logger().Info("siteverify_pass", "site", site.Slug)
		h.emit(r, site.Slug, "siteverify", "pass", "", "format1", tokenID(body.Response), h.now()-start)
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case memory.TokenExpired:
		h.logger().Info("siteverify_fail", "site", site.Slug, "reason", "token_expired")
		h.emit(r, site.Slug, "siteverify", "fail", "token_expired", "format1", tokenID(body.Response), h.now()-start)
		writeSiteVerifyError(w, http.StatusForbidden, "Token expired")
	default: // TokenMissing：从未签发或已消费（重放）
		h.logger().Info("siteverify_fail", "site", site.Slug, "reason", "token_not_found")
		h.emit(r, site.Slug, "siteverify", "fail", "token_not_found", "format1", tokenID(body.Response), h.now()-start)
		writeSiteVerifyError(w, http.StatusNotFound, "Token not found")
	}
}

// tokenID 提取 "site:id:ver" / "id:ver" 形式的 id 段（审计不落完整 token）。
func tokenID(token string) string {
	parts := strings.Split(token, ":")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func (h *Handler) handleSiteVerify(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	site, ok := h.resolveSite(w, r)
	if !ok {
		return
	}
	h.applyCORS(w, r, site)

	var body siteVerifyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&body); err != nil {
		writeSiteVerifyError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}
	if body.Secret == "" || body.Response == "" {
		writeSiteVerifyError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}
	h.verifyAgainstSite(w, r, site, body, start)
}

// handleGlobalSiteVerify 是无路径站点版：通行 token 必须为三段式，
// 站点从 token 第一段恢复（capd POST /siteverify 语义）。
func (h *Handler) handleGlobalSiteVerify(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	h.applyCORSNoSite(w, r)

	var body siteVerifyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&body); err != nil {
		writeSiteVerifyError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}
	if body.Secret == "" || body.Response == "" {
		writeSiteVerifyError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}
	parts := strings.Split(body.Response, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		writeSiteVerifyError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}
	if !policy.ValidSlug(parts[0]) {
		writeSiteVerifyError(w, http.StatusNotFound, "Invalid site key or secret")
		return
	}
	site, ok := h.Sites.Resolve(parts[0])
	if !ok || !site.Enabled {
		writeSiteVerifyError(w, http.StatusNotFound, "Invalid site key or secret")
		return
	}
	h.verifyAgainstSite(w, r, site, body, start)
}

// applyCORSNoSite：全局端点无法提前按站点取策略，放行但保持 Vary 语义。
func (h *Handler) applyCORSNoSite(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Origin")
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

// ---------------------------------------------------------------- 预检

func (h *Handler) handlePreflight(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("site")
	w.Header().Add("Vary", "Origin")
	if site, ok := h.Sites.Resolve(slug); ok && site.Enabled {
		h.applyCORS(w, r, site)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	if asked := r.Header.Get("Access-Control-Request-Headers"); asked != "" {
		w.Header().Set("Access-Control-Allow-Headers", asked)
	}
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}
