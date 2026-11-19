package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sseaan/powguard/internal/policy"
	"github.com/sseaan/powguard/internal/protocol/format1"
	"github.com/sseaan/powguard/internal/protocol/sha256pow"
	"github.com/sseaan/powguard/internal/store/memory"
)

func newServer(mux *http.ServeMux) *httptest.Server { return httptest.NewServer(mux) }

func format1Cfg() format1.ChallengeConfig {
	return format1.ChallengeConfig{Count: 4, Size: 16, Difficulty: 3}
}

// newEnvV2 构造 format-2 站点环境。
func newEnvV2(t *testing.T, mutate func(*policy.Site)) *testEnv {
	t.Helper()
	site, err := policy.NewSite("fmt2", "fmt2-secret-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	site.Protocol = policy.ProtocolFormat2
	site.SigningKey = "signing-key-high-entropy-0123456789abcdef"
	site.Challenge = format1Cfg()
	if mutate != nil {
		mutate(site)
	}
	env := &testEnv{now: 1_000_000, site: site}
	env.h = &Handler{
		Sites:      &policy.StaticResolver{Site: site},
		Challenges: memory.NewChallengeStore(),
		Tokens:     memory.NewTokenStore(),
		Nonces:     memory.NewTokenStore(),
		Limiter:    memory.NewRateLimiter(),
		Clock:      func() int64 { return env.now },
	}
	mux := http.NewServeMux()
	env.h.Register(mux)
	env.srv = newServer(mux)
	t.Cleanup(env.srv.Close)
	return env
}

// challengeV2 解析 format-2 challenge 响应。
func challengeV2(t *testing.T, m map[string]any) (token string, challenges []map[string]string) {
	t.Helper()
	if m["format"] != float64(2) {
		t.Fatalf("format 应为 2：%v", m)
	}
	token, _ = m["token"].(string)
	raw, _ := json.Marshal(m["challenges"])
	var arr []struct {
		Protocol string `json:"protocol"`
		Payload  struct {
			Salt   string `json:"salt"`
			Target string `json:"target"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("challenges 解析：%v", err)
	}
	challenges = make([]map[string]string, len(arr))
	for i, c := range arr {
		if c.Protocol != "sha256-pow" {
			t.Fatalf("协议应为 sha256-pow：%q", c.Protocol)
		}
		challenges[i] = map[string]string{"salt": c.Payload.Salt, "target": c.Payload.Target}
	}
	return token, challenges
}

// solveV2 求解并返回 [{nonce:N}] 形态的 solutions。
func solveV2(t *testing.T, challenges []map[string]string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, len(challenges))
	for i, c := range challenges {
		n := sha256pow.Solve(c["salt"], c["target"])
		if n > 1<<31 {
			t.Fatalf("测试难度设置过高（nonce=%d）", n)
		}
		out[i] = map[string]any{"nonce": n}
	}
	return out
}

func TestFormat2FullFlowAndReplay(t *testing.T) {
	e := newEnvV2(t, nil)
	resp, m := e.post("/fmt2/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("challenge 失败：%v %v", resp, m)
	}
	token, challenges := challengeV2(t, m)
	solutions := solveV2(t, challenges)

	resp, rd := e.post("/fmt2/redeem", map[string]any{"token": token, "solutions": solutions})
	if resp.StatusCode != 200 || rd["success"] != true {
		t.Fatalf("redeem 失败：%v %v", resp, rd)
	}
	vt, _ := rd["token"].(string)
	if !strings.HasPrefix(vt, "fmt2:") || strings.Count(vt, ":") != 2 {
		t.Fatalf("通行 token 形态：%q", vt)
	}

	// siteverify 成功 + 重放失败
	resp, sv := e.post("/fmt2/siteverify", map[string]string{"secret": "fmt2-secret-0123456789", "response": vt})
	if resp.StatusCode != 200 || sv["success"] != true {
		t.Fatalf("siteverify 失败：%v %v", resp, sv)
	}
	resp, rp := e.post("/fmt2/siteverify", map[string]string{"secret": "fmt2-secret-0123456789", "response": vt})
	if resp.StatusCode != 404 || rp["success"] != false {
		t.Fatalf("重放应失败：%v %v", resp, rp)
	}
}

func TestFormat2RedeemReasons(t *testing.T) {
	e := newEnvV2(t, nil)

	// 错误解
	_, m := e.post("/fmt2/challenge", nil)
	token, challenges := challengeV2(t, m)
	solutions := solveV2(t, challenges)
	solutions[0] = map[string]any{"nonce": solutions[0]["nonce"].(int64) + 1}
	resp, rd := e.post("/fmt2/redeem", map[string]any{"token": token, "solutions": solutions})
	if resp.StatusCode != 403 || rd["error"] != "Invalid solution" {
		t.Fatalf("错误解应 403 Invalid solution：%v %v", resp, rd)
	}

	// 重放（正确解提交两次）→ Challenge already redeemed
	solutions2 := solveV2(t, challenges)
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": token, "solutions": solutions2})
	if resp.StatusCode != 200 || rd["success"] != true {
		t.Fatalf("首次应成功：%v %v", resp, rd)
	}
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": token, "solutions": solutions2})
	if resp.StatusCode != 403 || rd["error"] != "Challenge already redeemed" {
		t.Fatalf("重放应 403 already redeemed：%v %v", resp, rd)
	}

	// format-1 形状的解发给 format-2 token：
	// 数量不符 → invalid_solutions → 400（官方语义）；
	// 数量匹配但元素非对象 → invalid_solution → 403
	_, m = e.post("/fmt2/challenge", nil)
	token2, _ := challengeV2(t, m)
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": token2, "solutions": []int{1, 2, 3}})
	if resp.StatusCode != 400 || rd["error"] != "Invalid solutions" {
		t.Fatalf("数量不符应 400 invalid_solutions：%v %v", resp, rd)
	}
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": token2, "solutions": []int{1, 2, 3, 4}})
	if resp.StatusCode != 403 || rd["error"] != "Invalid solution" {
		t.Fatalf("元素非对象应 403 invalid_solution：%v %v", resp, rd)
	}

	// 跨站点 token（用另一个站的 secret 签发）→ scope_mismatch
	eOther := newEnvV2(t, func(s *policy.Site) { s.Slug = "othersite" })
	// StaticResolver 比对 Slug——构造跨站 token：把 token 拿到别的 slug 校验
	otherToken, _ := func() (string, []map[string]string) {
		resp, m := eOther.post("/othersite/challenge", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("other challenge：%v", resp)
		}
		return challengeV2(t, m)
	}()
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": otherToken, "solutions": []map[string]any{}})
	if resp.StatusCode != 403 || rd["error"] != "Challenge token does not match site key" {
		t.Fatalf("跨站 token 应 403 scope：%v %v", resp, rd)
	}

	// 错误 secret 站点（同 slug 不同 key）→ invalid_token
	eBadKey := newEnvV2(t, func(s *policy.Site) { s.SigningKey = "different-signing-key-0123456789a" })
	resp, m = eBadKey.post("/fmt2/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	badToken, badChallenges := challengeV2(t, m)
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": badToken, "solutions": solveV2(t, badChallenges)})
	if resp.StatusCode != 403 || rd["error"] != "Invalid challenge token" {
		t.Fatalf("异 key token 应 403 invalid_token：%v %v", resp, rd)
	}

	// 过期
	eOld := newEnvV2(t, nil)
	resp, m = eOld.post("/fmt2/challenge", nil)
	tokenOld, oldChallenges := challengeV2(t, m)
	eOld.now += 11 * 60 * 1000
	resp, rd = eOld.post("/fmt2/redeem", map[string]any{"token": tokenOld, "solutions": solveV2(t, oldChallenges)})
	if resp.StatusCode != 403 || rd["error"] != "Challenge expired" {
		t.Fatalf("过期应 403 Challenge expired：%v %v", resp, rd)
	}

	// 非法 JWT 结构
	resp, rd = e.post("/fmt2/redeem", map[string]any{"token": "not.a.jwt", "solutions": []map[string]any{}})
	if resp.StatusCode != 403 || rd["error"] != "Invalid challenge token" {
		t.Fatalf("畸形 JWT 应 403：%v %v", resp, rd)
	}
}

func TestFormat2ConcurrentRedeemSingleUse(t *testing.T) {
	e := newEnvV2(t, nil)
	_, m := e.post("/fmt2/challenge", nil)
	token, challenges := challengeV2(t, m)
	solutions := solveV2(t, challenges)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, rd := e.post("/fmt2/redeem", map[string]any{"token": token, "solutions": solutions})
			if resp != nil && resp.StatusCode == 200 && rd["success"] == true {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("并发 redeem 应恰好一次成功，实际 %d", w)
	}
}

func TestFormat2NoSigningKey(t *testing.T) {
	e := newEnvV2(t, func(s *policy.Site) { s.SigningKey = "" })
	resp, m := e.post("/fmt2/challenge", nil)
	if resp.StatusCode != 500 || m["error"] != "Site key is not configured for JWT challenges" {
		t.Fatalf("缺签名密钥应 500（capd 语义）：%v %v", resp, m)
	}
}

func TestFormat1UnaffectedByNonces(t *testing.T) {
	// 回归：format-1 路径不碰 Nonces 存储；混合 token 检测按「含点号」分流
	e := newEnv(t, nil)
	flow := fullFlow(t, e)
	rd := flow["redeem"].(map[string]any)
	if _, ok := rd["token"]; !ok {
		t.Fatal("format-1 回归失败")
	}
	// format-1 token 提交到 format-2 redeem 端点（同实例）：hex token 不含点 →
	// 走 format-1 分支 → challenge 不存在 → 403 invalid or expired
	e2 := newEnvV2(t, nil)
	resp, m := e2.post("/fmt2/redeem", map[string]any{"token": rd["token"], "solutions": []int{1}})
	if resp.StatusCode != 403 || m["error"] != "Challenge invalid or expired" {
		t.Fatalf("format-1 token 在 format-2 站点应回落 format-1 分支：%v %v", resp, m)
	}
}

func TestTryClaimSemantics(t *testing.T) {
	s := memory.NewTokenStore()
	now := int64(1000)
	if !s.TryClaim("k", now, now+5000) {
		t.Fatal("首次占位应成功")
	}
	if s.TryClaim("k", now, now+5000) {
		t.Fatal("重复占位应失败")
	}
	// 过期后可重新占位
	if !s.TryClaim("k", now+6000, now+11000) {
		t.Fatal("占位过期后应可重新占位")
	}
	// 并发恰好一个成功
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.TryClaim("race", 1000, 5000) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("并发占位应恰好一次成功，实际 %d", w)
	}
}

// 混合站点切换协议后旧 format-1 挑战仍可兑换（token 分流正确性）
func TestProtocolSwitchKeepsFormat1State(t *testing.T) {
	e := newEnv(t, nil)
	// format-1 下发挑战
	resp, ch := e.post("/twikoo/challenge", nil)
	if resp.StatusCode != 200 {
		t.Fatal("challenge 失败")
	}
	solutions := solveChallenge(t, ch)
	// 切到 format-2 后旧 format-1 token 仍走 format-1 分支
	e.site.Protocol = policy.ProtocolFormat2
	resp, rd := e.post("/twikoo/redeem", map[string]any{"token": ch["token"], "solutions": solutions})
	if resp.StatusCode != 200 || rd["success"] != true {
		t.Fatalf("旧 format-1 挑战应仍可兑换：%v %v", resp, rd)
	}
}
