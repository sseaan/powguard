package public

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"capgo/internal/policy"
	"capgo/internal/protocol/format1"
	"capgo/internal/protocol/sha256pow"
	"capgo/internal/store/memory"
)

// testEnv 组装一个可控时钟的 handler + test server。
type testEnv struct {
	h    *Handler
	srv  *httptest.Server
	now  int64
	site *policy.Site
}

func newEnv(t *testing.T, mutate func(*policy.Site)) *testEnv {
	t.Helper()
	site, err := policy.NewSite("twikoo", "test-secret-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	site.Challenge = format1.ChallengeConfig{Count: 4, Size: 16, Difficulty: 3}
	if mutate != nil {
		mutate(site)
	}
	env := &testEnv{now: 1_000_000, site: site}
	env.h = &Handler{
		Sites:      &policy.StaticResolver{Site: site},
		Challenges: memory.NewChallengeStore(),
		Tokens:     memory.NewTokenStore(),
		Limiter:    memory.NewRateLimiter(),
		Clock:      func() int64 { return atomicNow(env) },
	}
	mux := http.NewServeMux()
	env.h.Register(mux)
	env.srv = httptest.NewServer(mux)
	t.Cleanup(env.srv.Close)
	return env
}

func atomicNow(e *testEnv) int64 { return e.now }

func (e *testEnv) post(path string, body any) (*http.Response, map[string]any) {
	return e.postFullURL(e.srv.URL+path, body)
}

func (e *testEnv) postFullURL(url string, body any) (*http.Response, map[string]any) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(http.MethodPost, url, reader)
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

// solveChallenge 用被测端点返回的挑战本地求解（等价 widget 行为）。
func solveChallenge(t *testing.T, body map[string]any) []int64 {
	t.Helper()
	token, _ := body["token"].(string)
	ch, _ := body["challenge"].(map[string]any)
	c := int(ch["c"].(float64))
	s := int(ch["s"].(float64))
	d := int(ch["d"].(float64))
	out := make([]int64, c)
	for i := 1; i <= c; i++ {
		salt, target := format1.SaltAndTarget(token, i, s, d)
		n := sha256pow.Solve(salt, target)
		if n > 1<<31 {
			t.Fatalf("测试难度设置过高（nonce=%d）", n)
		}
		out[i-1] = n
	}
	return out
}

// fullFlow 走完 challenge → redeem，返回 redeem 响应。
func fullFlow(t *testing.T, e *testEnv) map[string]any {
	t.Helper()
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("challenge 失败：%v %v", resp, ch)
	}
	solutions := solveChallenge(t, ch)
	resp, rd := e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": solutions})
	if resp == nil || resp.StatusCode != 200 || rd["success"] != true {
		t.Fatalf("redeem 失败：%v %v", resp, rd)
	}
	return map[string]any{"challenge": ch, "redeem": rd}
}

func TestFullFlowAndReplay(t *testing.T) {
	e := newEnv(t, nil)
	flow := fullFlow(t, e)
	rd := flow["redeem"].(map[string]any)
	token, _ := rd["token"].(string)

	if strings.Count(token, ":") != 2 || !strings.HasPrefix(token, "twikoo:") {
		t.Fatalf("redeem token 应为三段式 site:id:vertoken：%q", token)
	}

	// siteverify 成功
	resp, sv := e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": token})
	if resp.StatusCode != 200 || sv["success"] != true {
		t.Fatalf("siteverify 失败：%v %v", resp, sv)
	}
	// 重放 → 404 Token not found
	resp, rp := e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": token})
	if resp.StatusCode != 404 || rp["success"] != false {
		t.Fatalf("重放应失败：%v %v", resp, rp)
	}
	if rp["error"] != "Token not found" {
		t.Errorf("重放错误信息：%v", rp["error"])
	}
}

func TestTwikooExactCallShape(t *testing.T) {
	// 复刻 Twikoo 2.0.17 spam.ts checkCapCaptcha 的调用方式：
	// endpoint 去尾斜杠 + "/siteverify"，body {secret, response}，只看 data.success
	e := newEnv(t, nil)
	flow := fullFlow(t, e)
	token := flow["redeem"].(map[string]any)["token"].(string)

	endpoint := e.srv.URL + "/twikoo/" // Twikoo 配置里的 CAP_API_ENDPOINT
	url := strings.TrimSuffix(endpoint, "/") + "/siteverify"
	resp, sv := e.postFullURL(url, map[string]string{"secret": "test-secret-0123456789abcdef", "response": token})
	if resp == nil || resp.StatusCode != 200 || sv["success"] != true {
		t.Fatalf("Twikoo 形状的 siteverify 失败：%v %v", resp, sv)
	}
}

func TestUnknownAndInvalidSite(t *testing.T) {
	e := newEnv(t, nil)
	for _, path := range []string{"/nosuch/challenge", "/nosuch/redeem", "/nosuch/siteverify"} {
		resp, m := e.post(path, map[string]string{"secret": "x", "response": "y"})
		if resp == nil || resp.StatusCode != 404 {
			t.Fatalf("[%s] 未知站点应 404：%v", path, resp)
		}
		if m["error"] != "Invalid site key or secret" {
			t.Errorf("[%s] 错误形状：%v", path, m)
		}
	}
	// 非法 slug（大写/过长/特殊字符）
	for _, slug := range []string{"Twikoo", "x", "a-b_c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z-1234", "a b"} {
		resp, _ := e.post("/"+slug+"/challenge", nil)
		if resp == nil || resp.StatusCode != 404 {
			t.Errorf("非法 slug %q 应 404", slug)
		}
	}
	// 超长 slug → mux 直接 404
	resp, _ := e.post("/"+strings.Repeat("a", 33)+"/challenge", nil)
	if resp == nil || resp.StatusCode != 404 {
		t.Error("33 字符 slug 应 404")
	}
}

func TestDisabledSite(t *testing.T) {
	e := newEnv(t, func(s *policy.Site) { s.Enabled = false })
	resp, _ := e.post("/twikoo/challenge", nil)
	if resp == nil || resp.StatusCode != 404 {
		t.Fatal("禁用站点应 404")
	}
}

func TestRedeemShapes(t *testing.T) {
	e := newEnv(t, nil)

	cases := []struct {
		name string
		body any
		code int
		err  string
	}{
		{"missing all", map[string]any{}, 400, "Missing required fields"},
		{"missing solutions", map[string]any{"token": "x"}, 400, "Missing required fields"},
		{"missing token", map[string]any{"solutions": []int{1}}, 400, "Missing required fields"},
		{"solutions string", map[string]any{"token": "x", "solutions": "1"}, 400, "Missing required fields"},
		{"solution string element", map[string]any{"token": "x", "solutions": []string{"1"}}, 400, "Invalid solutions"},
		{"solution float", map[string]any{"token": "x", "solutions": []float64{1.5}}, 400, "Invalid solutions"},
		{"solution exp", map[string]any{"token": "x", "solutions": []json.Number{json.Number("1e3")}}, 400, "Invalid solutions"},
		{"unknown token", map[string]any{"token": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "solutions": []int{1}}, 403, "Challenge invalid or expired"},
	}
	for _, tc := range cases {
		resp, m := e.post("/twikoo/redeem", tc.body)
		if resp == nil || resp.StatusCode != tc.code {
			t.Errorf("[%s] 状态码 %d != %d：%v", tc.name, resp.StatusCode, tc.code, m)
			continue
		}
		if m["error"] != tc.err {
			t.Errorf("[%s] 错误 %v != %q", tc.name, m["error"], tc.err)
		}
		if m["success"] != false {
			t.Errorf("[%s] success 应为 false", tc.name)
		}
	}

	// 非法 JSON
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/twikoo/redeem", strings.NewReader("{bad"))
	resp, err := e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 400 {
		t.Errorf("非法 JSON 应 400：%v", resp)
	}

	// 空白 body（widget 在极端网络下可能发空 body）→ 400
	req, _ = http.NewRequest(http.MethodPost, e.srv.URL+"/twikoo/redeem", nil)
	resp, err = e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 400 {
		t.Errorf("空 body 应 400：%v", resp)
	}
}

func TestWrongSolutionBurnsChallenge(t *testing.T) {
	e := newEnv(t, nil)
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	good := solveChallenge(t, ch)
	// 错误解（每个 +1）
	wrong := make([]int64, len(good))
	for i, n := range good {
		wrong[i] = n + 1
	}
	resp, m := e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": wrong})
	if resp.StatusCode != 403 || m["error"] != "Invalid solution" {
		t.Fatalf("错误解应 403 Invalid solution：%v %v", resp, m)
	}
	// 正确解重试 → 挑战已被烧
	resp, m = e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": good})
	if resp.StatusCode != 403 || m["error"] != "Challenge invalid or expired" {
		t.Fatalf("先删后验：正确解重试应失效：%v %v", resp, m)
	}
}

func TestExpiredChallenge(t *testing.T) {
	e := newEnv(t, nil)
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	solutions := solveChallenge(t, ch)
	// 推进时钟越过 TTL（默认 10 分钟）
	e.now += 11 * 60 * 1000
	resp, m := e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": solutions})
	if resp.StatusCode != 403 || m["error"] != "Challenge invalid or expired" {
		t.Fatalf("过期挑战应 403：%v %v", resp, m)
	}
}

func TestSolutionCountMismatch(t *testing.T) {
	e := newEnv(t, nil)
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	solutions := solveChallenge(t, ch)
	resp, m := e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": solutions[:len(solutions)-1]})
	if resp.StatusCode != 403 || m["error"] != "Invalid solution" {
		t.Fatalf("解数量不符应 403 Invalid solution：%v %v", resp, m)
	}
}

func TestConcurrentRedeemSingleUse(t *testing.T) {
	e := newEnv(t, nil)
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	solutions := solveChallenge(t, ch)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, m := e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": solutions})
			if resp != nil && resp.StatusCode == 200 && m["success"] == true {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("并发 redeem 应恰好一次成功，实际 %d", w)
	}
}

func TestConcurrentSiteVerifySingleUse(t *testing.T) {
	e := newEnv(t, nil)
	flow := fullFlow(t, e)
	token := flow["redeem"].(map[string]any)["token"].(string)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, m := e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": token})
			if resp != nil && resp.StatusCode == 200 && m["success"] == true {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("并发 siteverify 应恰好一次成功，实际 %d", w)
	}
}

func TestSiteVerifySecretsAndShapes(t *testing.T) {
	e := newEnv(t, nil)
	flow := fullFlow(t, e)
	token := flow["redeem"].(map[string]any)["token"].(string)

	// 错误 secret → 403
	resp, m := e.post("/twikoo/siteverify", map[string]string{"secret": "wrong-secret-wrong-secret", "response": token})
	if resp.StatusCode != 403 || m["error"] != "Invalid site key or secret" || m["success"] != false {
		t.Fatalf("错误 secret 应 403：%v %v", resp, m)
	}
	// 缺参 → 400
	resp, m = e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef"})
	if resp.StatusCode != 400 || m["error"] != "Missing required parameters" {
		t.Fatalf("缺 response 应 400：%v %v", resp, m)
	}
	// 畸形 token → 400
	resp, m = e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": "abc"})
	if resp.StatusCode != 400 || m["error"] != "Missing required parameters" {
		t.Fatalf("畸形 token 应 400：%v %v", resp, m)
	}
	// 三段式 site 不匹配 → 404
	badSite := "other:" + strings.SplitN(token, ":", 2)[1]
	resp, m = e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": badSite})
	if resp.StatusCode != 404 || m["error"] != "Invalid site key or secret" {
		t.Fatalf("site 不匹配应 404：%v %v", resp, m)
	}
	// token 在此期间未被消费（错误 secret 不烧 token）
	resp, m = e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": token})
	if resp.StatusCode != 200 || m["success"] != true {
		t.Fatalf("正确 secret 应消费成功：%v %v", resp, m)
	}
}

func TestLegacyTwoPartTokenSiteVerify(t *testing.T) {
	// 官方 @cap.js/server 两段式通行 token（无 site 段）也能被验证
	e := newEnv(t, nil)
	vt, err := format1.NewVerificationToken(e.now, 20*60*1000)
	if err != nil {
		t.Fatal(err)
	}
	e.h.Tokens.Put(vt.Key, vt.Expires)
	resp, m := e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": vt.Token})
	if resp.StatusCode != 200 || m["success"] != true {
		t.Fatalf("两段式 token 应可验证：%v %v", resp, m)
	}
}

func TestGlobalSiteVerify(t *testing.T) {
	e := newEnv(t, nil)
	flow := fullFlow(t, e)
	token := flow["redeem"].(map[string]any)["token"].(string)

	// 三段式 + 全局端点
	resp, m := e.post("/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": token})
	if resp.StatusCode != 200 || m["success"] != true {
		t.Fatalf("全局 siteverify 应成功：%v %v", resp, m)
	}

	// 两段式在全局端点 → 400（capd 语义：必须三段）
	vt, _ := format1.NewVerificationToken(e.now, 20*60*1000)
	e.h.Tokens.Put(vt.Key, vt.Expires)
	resp, m = e.post("/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": vt.Token})
	if resp.StatusCode != 400 || m["error"] != "Missing required parameters" {
		t.Fatalf("两段式全局应 400：%v %v", resp, m)
	}
}

func TestTokenExpiry(t *testing.T) {
	e := newEnv(t, nil)
	vt, err := format1.NewVerificationToken(e.now, 20*60*1000)
	if err != nil {
		t.Fatal(err)
	}
	e.h.Tokens.Put(vt.Key, vt.Expires)
	e.now += 21 * 60 * 1000
	resp, m := e.post("/twikoo/siteverify", map[string]string{"secret": "test-secret-0123456789abcdef", "response": vt.Token})
	if resp.StatusCode != 403 || m["error"] != "Token expired" {
		t.Fatalf("过期 token 应 403 Token expired：%v %v", resp, m)
	}
}

func TestCORS(t *testing.T) {
	e := newEnv(t, func(s *policy.Site) {
		s.CORSAllowAll = false
		s.CORSOrigins = []string{"https://blog.example.com"}
	})
	// 预检：允许的 Origin
	req, _ := http.NewRequest(http.MethodOptions, e.srv.URL+"/twikoo/challenge", nil)
	req.Header.Set("Origin", "https://blog.example.com")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("预检应 204：%v", resp)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://blog.example.com" {
		t.Errorf("应回显 Origin：%q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	if resp.Header.Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Error("Allow-Methods 应为 GET, POST")
	}
	if resp.Header.Get("Access-Control-Allow-Headers") != "content-type" {
		t.Error("应回显请求头")
	}
	if resp.Header.Get("Access-Control-Max-Age") != "600" {
		t.Error("Max-Age 应 600")
	}
	if resp.Header.Get("Vary") != "Origin" {
		t.Error("应有 Vary: Origin")
	}

	// 预检：不允许的 Origin → 不带 ACAO
	req, _ = http.NewRequest(http.MethodOptions, e.srv.URL+"/twikoo/challenge", nil)
	req.Header.Set("Origin", "https://evil.example.net")
	resp, err = e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("预检应仍 204：%v", resp)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("不允许的 Origin 不应回 ACAO：%q", resp.Header.Get("Access-Control-Allow-Origin"))
	}

	// 实际请求也带 CORS 头
	req, _ = http.NewRequest(http.MethodPost, e.srv.URL+"/twikoo/challenge", nil)
	req.Header.Set("Origin", "https://blog.example.com")
	resp, err = e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://blog.example.com" {
		t.Error("challenge 应带允许的 Origin")
	}

	// AllowAll=true → *
	e2 := newEnv(t, nil)
	req, _ = http.NewRequest(http.MethodPost, e2.srv.URL+"/twikoo/challenge", nil)
	req.Header.Set("Origin", "https://anything.example.org")
	resp, err = e2.srv.Client().Do(req)
	if err != nil || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("AllowAll 应回 *：%q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestWasmParamIgnored(t *testing.T) {
	e := newEnv(t, nil)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/twikoo/challenge?wasm=0", nil)
	resp, err := e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("?wasm=0 应被容忍：%v", resp)
	}
	// 未知参数同样容忍
	req, _ = http.NewRequest(http.MethodPost, e.srv.URL+"/twikoo/challenge?foo=bar", nil)
	resp, err = e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("未知参数应容忍：%v", resp)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(s *policy.Site) { s.RateLimitPerWindow = 3 })
	// siteverify 不限流（capd 语义），challenge/redeem 每 IP 每窗口 3 次
	for i := 0; i < 3; i++ {
		resp, _ := e.post("/twikoo/challenge", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("第 %d 次应放行：%d", i+1, resp.StatusCode)
		}
	}
	resp, m := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 429 {
		t.Fatalf("第 4 次应 429：%d %v", resp.StatusCode, m)
	}
	if m["error"] != "Too many requests" {
		t.Errorf("429 错误形状：%v", m)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 应带 Retry-After")
	}
	// 推进窗口
	e.now += 5000
	resp, _ = e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("窗口翻页后应放行")
	}
}

func TestBodyTooLarge(t *testing.T) {
	e := newEnv(t, nil)
	huge := make([]byte, 300*1024)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/twikoo/redeem", bytes.NewReader(huge))
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("请求发送失败：%v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大 body 应 413，得到 %d", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Get(e.srv.URL + "/twikoo/challenge")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应 405，得到 %d", resp.StatusCode)
	}
}

func TestChallengeResponseShape(t *testing.T) {
	e := newEnv(t, nil)
	resp, m := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	ch, _ := m["challenge"].(map[string]any)
	if ch == nil || ch["c"] != float64(4) || ch["s"] != float64(16) || ch["d"] != float64(3) {
		t.Errorf("challenge 参数形状：%v", ch)
	}
	if tok, _ := m["token"].(string); len(tok) != 50 {
		t.Errorf("token 应为 50 hex 字符：%q", tok)
	}
	if exp, _ := m["expires"].(float64); int64(exp) != e.now+10*60*1000 {
		t.Errorf("expires 应为 now+10min：%v", exp)
	}
}

func TestSolveTimingSanity(t *testing.T) {
	// 保证测试套件整体耗时可接受：默认 4/16/3 的求解成本
	e := newEnv(t, nil)
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	sol := solveChallenge(t, ch)
	if len(sol) != 4 {
		t.Fatalf("解数量：%d", len(sol))
	}
}
