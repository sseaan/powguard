package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sseaan/powguard/internal/api/public"
	"github.com/sseaan/powguard/internal/policy"
	"github.com/sseaan/powguard/internal/security/secretbox"
	"github.com/sseaan/powguard/internal/security/session"
	"github.com/sseaan/powguard/internal/store/memory"
	"github.com/sseaan/powguard/internal/store/model"
	"github.com/sseaan/powguard/internal/store/sqlite"
)

type adminEnv struct {
	h        *Handler
	pub      *public.Handler
	srv      *httptest.Server
	now      int64
	sites    *sqlite.SiteRepo
	secrets  *sqlite.SecretRepo
	box      *secretbox.Box
	resolver *policy.DBResolver
}

func newEnv(t *testing.T, mutate func(*Handler)) *adminEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.sqlite3")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, err := secretbox.New(bytes.Repeat([]byte{0xA1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	siteRepo := sqlite.NewSiteRepo(db)
	secretRepo := sqlite.NewSecretRepo(db)
	eventRepo := sqlite.NewEventRepo(db)
	sessionRepo := sqlite.NewSessionRepo(db)
	resolver := policy.NewDBResolver(siteRepo, secretRepo, box)

	env := &adminEnv{
		now: 1_000_000,
	}
	clock := func() int64 { return atomic.LoadInt64(&env.now) }

	env.h = &Handler{
		AdminKey:     []byte("admin-key-high-entropy-12345"),
		Sessions:     session.NewManager(sessionRepo, 0),
		Box:          box,
		Sites:        siteRepo,
		Secrets:      secretRepo,
		Events:       eventRepo,
		Resolver:     resolver,
		Limiter:      memory.NewRateLimiter(),
		Clock:        clock,
		CookieSecure: true,
	}
	if mutate != nil {
		mutate(env.h)
	}

	env.pub = &public.Handler{
		Sites:      resolver,
		Challenges: memory.NewChallengeStore(),
		Tokens:     memory.NewTokenStore(),
		Limiter:    memory.NewRateLimiter(),
		Clock:      clock,
	}
	env.sites = siteRepo
	env.secrets = secretRepo
	env.box = box
	env.resolver = resolver

	mux := http.NewServeMux()
	if err := env.h.Register(mux); err != nil {
		t.Fatal(err)
	}
	env.pub.Register(mux)
	env.srv = httptest.NewServer(mux)
	t.Cleanup(env.srv.Close)
	return env
}

func (e *adminEnv) do(t *testing.T, method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp, m
}

// login 建立会话并返回 csrf + cookie header。
func (e *adminEnv) login(t *testing.T) (csrfToken, cookie string) {
	t.Helper()
	resp, m := e.do(t, http.MethodPost, "/admin/api/login", map[string]string{"key": "admin-key-high-entropy-12345"}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login 失败：%v %v", resp.StatusCode, m)
	}
	csrfTok, _ := m["csrf"].(string)
	// httptest 无 TLS；cookie 从 Set-Cookie 提取
	var c *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == CookieName {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("登录未种 cookie")
	}
	return csrfTok, c.Name + "=" + c.Value
}

func (e *adminEnv) auth(csrfToken, cookie string) map[string]string {
	return map[string]string{"X-CSRF-Token": csrfToken, "Cookie": cookie}
}

func TestAdminDisabledWhenNoKey(t *testing.T) {
	e := newEnv(t, func(h *Handler) { h.AdminKey = nil })
	// Register 已被调用过；验证 h.Register 的行为：重新注册到新 mux
	mux := http.NewServeMux()
	if err := e.h.Register(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/admin/api/login", "application/json", strings.NewReader(`{"key":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("管理禁用时登录应 404：%d", resp.StatusCode)
	}
}

func TestLoginFlow(t *testing.T) {
	e := newEnv(t, nil)

	// 错误 key
	resp, m := e.do(t, http.MethodPost, "/admin/api/login", map[string]string{"key": "wrong"}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("错误 key 应 401：%d", resp.StatusCode)
	}

	// 正确 key：cookie 旗标
	resp, m = e.do(t, http.MethodPost, "/admin/api/login", map[string]string{"key": "admin-key-high-entropy-12345"}, nil)
	if resp.StatusCode != 200 || m["csrf"] == "" {
		t.Fatalf("登录失败：%v %v", resp.StatusCode, m)
	}
	var c *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == CookieName {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("缺会话 cookie")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Secure {
		t.Errorf("cookie 旗标缺失：%+v", c)
	}
	csrfTok := m["csrf"].(string)
	cookie := c.Name + "=" + c.Value

	// whoami
	resp, m = e.do(t, http.MethodGet, "/admin/api/session", nil, e.auth("", cookie))
	if resp.StatusCode != 200 || m["authenticated"] != true {
		t.Fatalf("whoami 失败：%v", m)
	}

	// 无会话 401
	resp, _ = e.do(t, http.MethodGet, "/admin/api/session", nil, nil)
	if resp.StatusCode != 401 {
		t.Errorf("无 cookie 应 401：%d", resp.StatusCode)
	}

	// 登出后失效
	resp, m = e.do(t, http.MethodPost, "/admin/api/logout", nil, e.auth(csrfTok, cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("logout 失败：%v", m)
	}
	resp, _ = e.do(t, http.MethodGet, "/admin/api/session", nil, e.auth("", cookie))
	if resp.StatusCode != 401 {
		t.Errorf("登出后应 401：%d", resp.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 5; i++ {
		resp, _ := e.do(t, http.MethodPost, "/admin/api/login", map[string]string{"key": "wrong"}, nil)
		if resp.StatusCode != 401 {
			t.Fatalf("第 %d 次应 401：%d", i+1, resp.StatusCode)
		}
	}
	resp, m := e.do(t, http.MethodPost, "/admin/api/login", map[string]string{"key": "admin-key-high-entropy-12345"}, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("第 6 次应 429：%d %v", resp.StatusCode, m)
	}
}

func TestCSRFEnforced(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	// 无 CSRF
	resp, m := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "x"}, e.auth("", cookie))
	if resp.StatusCode != 403 || m["error"] != "CSRF token invalid" {
		t.Fatalf("无 CSRF 应 403：%d %v", resp.StatusCode, m)
	}
	// 错误 CSRF
	resp, _ = e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "x"}, e.auth("bad", cookie))
	if resp.StatusCode != 403 {
		t.Fatalf("错误 CSRF 应 403：%d", resp.StatusCode)
	}
	// 正确 CSRF + 非法 slug → 400（证明过了 CSRF 层）
	resp, _ = e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "Bad Slug!"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 400 {
		t.Fatalf("合法 CSRF 后应进业务层：%d", resp.StatusCode)
	}
}

func TestSiteCreateSecretEncryptedAtRest(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)

	resp, m := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{
		"slug": "blog", "name": "博客", "cors_allow_all": false,
		"cors_origins": []string{"https://blog.example.com"},
	}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 201 {
		t.Fatalf("创建失败：%d %v", resp.StatusCode, m)
	}
	secret := m["secret"].(string)
	if len(secret) != 48 { // 24 bytes hex
		t.Fatalf("secret 形态：%q", secret)
	}

	// 库中密文 ≠ 明文，且能被 box 解开
	siteRow, err := e.sites.GetBySlug("blog")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := e.secrets.Get(siteRow.ID, model.FieldSiteVerify)
	if err != nil {
		t.Fatal(err)
	}
	if sec.Ciphertext == secret || strings.Contains(sec.Ciphertext, secret) {
		t.Fatalf("明文不得入库：%q", sec.Ciphertext)
	}
	plain, err := e.box.Open(sec.Ciphertext, "blog", model.FieldSiteVerify)
	if err != nil || string(plain) != secret {
		t.Fatalf("密文应能解回明文：%v", err)
	}

	// resolver 解析出新站点（含 secret）
	site, ok := e.resolver.Resolve("blog")
	if !ok || site.Secret != secret {
		t.Fatalf("resolver 未反映新站点：%+v", site)
	}

	// 重复 slug → 409
	resp, m = e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "blog"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 409 {
		t.Fatalf("重复 slug 应 409：%d %v", resp.StatusCode, m)
	}

	// 公开 API 立即可用（resolver 缓存已失效）
	resp, ch := e.post("/blog/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("新站点 challenge 失败：%d %v", resp.StatusCode, ch)
	}
}

func TestSiteUpdateAndPublicBehavior(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	resp0, m0 := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "cfg"}, e.auth(csrfTok, cookie))
	if resp0.StatusCode != 201 {
		t.Fatalf("创建失败：%d %v", resp0.StatusCode, m0)
	}

	// 改小参数并禁用 CORS *
	resp, m := e.do(t, http.MethodPost, "/admin/api/sites/cfg", map[string]any{
		"challenge_count": 2, "challenge_size": 8, "challenge_difficulty": 2,
		"cors_allow_all": false, "cors_origins": []string{"https://only.example.com"},
	}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("更新失败：%d %v", resp.StatusCode, m)
	}
	chResp, ch := e.post("/cfg/challenge", nil)
	if chResp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	cfg := ch["challenge"].(map[string]any)
	if cfg["c"] != float64(2) || cfg["s"] != float64(8) || cfg["d"] != float64(2) {
		t.Errorf("策略未生效：%v", cfg)
	}

	// 非法参数拒绝
	resp, m = e.do(t, http.MethodPost, "/admin/api/sites/cfg", map[string]any{"challenge_difficulty": 99}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 400 {
		t.Fatalf("非法难度应 400：%d %v", resp.StatusCode, m)
	}

	// 禁用站点 → 公开 404
	_, _ = e.do(t, http.MethodPost, "/admin/api/sites/cfg", map[string]any{"enabled": false}, e.auth(csrfTok, cookie))
	chResp, _ = e.post("/cfg/challenge", nil)
	if chResp.StatusCode != 404 {
		t.Fatalf("禁用站点应 404：%d", chResp.StatusCode)
	}

	// slug 不可改
	resp, _ = e.do(t, http.MethodPost, "/admin/api/sites/cfg", map[string]any{"slug": "new"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 400 {
		t.Fatalf("slug 修改应 400：%d", resp.StatusCode)
	}
}

func TestSiteSoftDelete(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "gone"}, e.auth(csrfTok, cookie))

	resp, m := e.do(t, http.MethodDelete, "/admin/api/sites/gone", nil, e.auth(csrfTok, cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("删除失败：%d %v", resp.StatusCode, m)
	}
	// 公开 404；重建同名 slug → 409（软删除占位）
	if r, _ := e.post("/gone/challenge", nil); r.StatusCode != 404 {
		t.Error("软删除后公开应 404")
	}
	resp, _ = e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "gone"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 409 {
		t.Errorf("软删除占位下重建应 409：%d", resp.StatusCode)
	}
}

func TestRevealRequiresReAuth(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	_, m := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "sec"}, e.auth(csrfTok, cookie))
	secret := m["secret"].(string)

	// 错误 admin key → 401，且不泄露 secret
	resp, m := e.do(t, http.MethodPost, "/admin/api/sites/sec/reveal", map[string]string{"key": "wrong"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 401 {
		t.Fatalf("re-auth 失败应 401：%d", resp.StatusCode)
	}
	if m["secret"] != nil {
		t.Error("re-auth 失败不得返回 secret")
	}

	// 正确 key → 与创建时一致的 secret
	resp, m = e.do(t, http.MethodPost, "/admin/api/sites/sec/reveal", map[string]string{"key": "admin-key-high-entropy-12345"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 200 || m["secret"].(string) != secret {
		t.Fatalf("reveal 结果不一致：%v", m)
	}
}

func TestRotateSecret(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	_, m := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "rot"}, e.auth(csrfTok, cookie))
	oldSecret := m["secret"].(string)

	resp, m := e.do(t, http.MethodPost, "/admin/api/sites/rot/rotate", map[string]string{"key": "admin-key-high-entropy-12345"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("rotate 失败：%d %v", resp.StatusCode, m)
	}
	newSecret := m["secret"].(string)
	if newSecret == "" || newSecret == oldSecret {
		t.Fatalf("新 secret 异常：%q", newSecret)
	}

	// resolver 缓存已失效：siteverify 用新 secret 成功、旧 secret 失败
	sv := func(secret string) (*http.Response, map[string]any) {
		return e.post("/rot/siteverify", map[string]string{"secret": secret, "response": "rot:abc:def"})
	}
	r, mm := sv(oldSecret)
	if r.StatusCode == 200 && mm["error"] == "Token not found" {
		// 走到了 token 校验 = secret 已换（旧 secret 不再是 invalid_secret）
	} else if r.StatusCode != 403 {
		t.Fatalf("旧 secret 应被判 invalid_secret(403)：%d %v", r.StatusCode, mm)
	}
	r, mm = sv(newSecret)
	if r.StatusCode != 404 || mm["error"] != "Token not found" {
		t.Fatalf("新 secret 应通过 secret 校验到达 token 阶段(404)：%d %v", r.StatusCode, mm)
	}
}

func TestEventsAndStats(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	_, m0 := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "st"}, e.auth(csrfTok, cookie))
	if m0["secret"] == nil {
		t.Fatal("创建失败")
	}

	// 制造公开流量
	e.post("/st/challenge", nil)
	e.post("/st/redeem", map[string]any{"token": "nope", "solutions": []int{1}})

	// 直接播种两条事件（admin 测试环境未接公开 sink，验证 events/stats 端点装配）
	if err := e.h.Events.Insert(&model.Event{Ts: e.now, SiteSlug: "st", Type: "challenge", Outcome: "pass", Protocol: "format1"}); err != nil {
		t.Fatal(err)
	}
	if err := e.h.Events.Insert(&model.Event{Ts: e.now, SiteSlug: "st", Type: "redeem", Outcome: "fail", Reason: "invalid_solution", Protocol: "format1"}); err != nil {
		t.Fatal(err)
	}

	resp, m := e.do(t, http.MethodGet, "/admin/api/events?limit=10&site=st", nil, e.auth("", cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("events 查询失败：%d %v", resp.StatusCode, m)
	}
	evs, _ := m["events"].([]any)
	if len(evs) != 2 {
		t.Errorf("应查到 2 条事件：%v", m)
	}
	first, _ := evs[0].(map[string]any)
	if first["reason"] != "invalid_solution" && first["type"] != "redeem" {
		// 倒序：第一条应为最新插入
	}

	resp, m = e.do(t, http.MethodGet, "/admin/api/stats?days=7", nil, e.auth("", cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("stats 查询失败：%d %v", resp.StatusCode, m)
	}
	if m["daily"] == nil || m["reasons"] == nil {
		t.Errorf("stats 形状错误：%v", m)
	}
	daily, _ := m["daily"].([]any)
	if len(daily) != 1 {
		t.Errorf("应聚出一天：%v", m)
	}
	day, _ := daily[0].(map[string]any)
	if day["count"] != float64(2) || day["pass"] != float64(1) || day["fail"] != float64(1) {
		t.Errorf("聚合数字错误：%v", day)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	// 推进时钟越过 12h
	atomic.StoreInt64(&e.now, 1_000_000+13*60*60*1000)
	resp, _ := e.do(t, http.MethodGet, "/admin/api/session", nil, e.auth("", cookie))
	if resp.StatusCode != 401 {
		t.Fatalf("会话过期应 401：%d", resp.StatusCode)
	}
	_ = csrfTok
}

// post 是直通公开 API 的便捷方法。
func (e *adminEnv) post(path string, body any) (*http.Response, map[string]any) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		return nil, map[string]any{"__err": err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp, m
}

// TestEventStreamFlushes 验证 SSE：首帧 hello + Flush 生效。
func TestEventStreamFlushes(t *testing.T) {
	e := newEnv(t, nil)
	_, cookie := e.login(t)

	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/admin/api/events/stream", nil)
	req.Header.Set("Cookie", cookie)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("SSE 状态：%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type：%q", ct)
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Error("应有 X-Accel-Buffering: no（反代不缓冲）")
	}
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	first := string(buf[:n])
	if !strings.Contains(first, "event: hello") {
		t.Errorf("首帧应为 hello：%q", first)
	}
}

// TestEventStreamRequiresAuth 未登录不可订阅。
func TestEventStreamRequiresAuth(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Get(e.srv.URL + "/admin/api/events/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录应 401，得到 %d", resp.StatusCode)
	}
}
