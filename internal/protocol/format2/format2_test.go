package format2

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"capgo/internal/protocol/sha256pow"
)

type caseEntry2 struct {
	Name      string          `json:"name"`
	Opts      json.RawMessage `json:"opts"`
	Challenge struct {
		Token      string          `json:"token"`
		Format     int             `json:"format"`
		Challenges json.RawMessage `json:"challenges"`
		Expires    int64           `json:"expires"`
	} `json:"challenge"`
	Solutions          []map[string]any `json:"solutions"`
	GoodSolutions      []map[string]any `json:"goodSolutions"`
	WrongSolutions     []map[string]any `json:"wrongSolutions"`
	Validate           map[string]any   `json:"validate"`
	First              map[string]any   `json:"first"`
	Replay             map[string]any   `json:"replay"`
	WrongSecret        map[string]any   `json:"wrongSecret"`
	ScopeMismatch      map[string]any   `json:"scopeMismatch"`
	ShortSolutions     map[string]any   `json:"shortSolutions"`
	NonObjectSolutions map[string]any   `json:"nonObjectSolutions"`
	StringNonceFirst   map[string]any   `json:"stringNonceFirst"`
	EmptySolutions     map[string]any   `json:"emptySolutions"`
	Claims             map[string]any   `json:"claims"`
	ExpectedDecrypted  map[string]any   `json:"expectedDecrypted"`
}

type casesFile struct {
	Source string       `json:"source"`
	Secret string       `json:"secret"`
	Cases  []caseEntry2 `json:"cases"`
}

type cryptoFile struct {
	JWT struct {
		Secret           string         `json:"secret"`
		Payload          map[string]any `json:"payload"`
		Token            string         `json:"token"`
		Header           string         `json:"header"`
		TamperedLastChar string         `json:"tamperedLastChar"`
		VerifyGood       map[string]any `json:"verifyGood"`
		VerifyBad        any            `json:"verifyBad"`
		NotJwt           any            `json:"notJwt"`
		TwoDots          any            `json:"twoDots"`
		FourDots         any            `json:"fourDots"`
	} `json:"jwt"`
	GCM struct {
		Info         string         `json:"info"`
		Secret       string         `json:"secret"`
		Data         map[string]any `json:"data"`
		BlobFromCore string         `json:"blobFromCore"`
		Roundtrip    map[string]any `json:"roundtrip"`
	} `json:"gcm"`
}

func loadCases(t *testing.T) casesFile {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/format2/cases.json")
	if err != nil {
		t.Fatalf("读取 fixture 失败：%v", err)
	}
	var f casesFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("解析 fixture：%v", err)
	}
	if f.Source != "capjs-core@0.1.18" {
		t.Fatalf("fixture 来源变化：%q", f.Source)
	}
	return f
}

func loadCrypto(t *testing.T) cryptoFile {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/format2/crypto.json")
	if err != nil {
		t.Fatalf("读取 fixture 失败：%v", err)
	}
	var f cryptoFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("解析 fixture：%v", err)
	}
	return f
}

func solutionsRaw(t *testing.T, arr []map[string]any) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, len(arr))
	for i, s := range arr {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func reasonOf(m map[string]any) string {
	if m == nil {
		return ""
	}
	r, _ := m["reason"].(string)
	return r
}

// TestOfficialLifecycle 官方 capjs-core 生成的 format-2 挑战由 Go 校验（官方 → capgo）。
func TestOfficialLifecycle(t *testing.T) {
	f := loadCases(t)
	var c *caseEntry2
	for i := range f.Cases {
		if f.Cases[i].Name == "sha256_lifecycle" {
			c = &f.Cases[i]
		}
	}
	if c == nil {
		t.Fatal("缺少 sha256_lifecycle")
	}

	res := Validate(RedeemBody{Token: c.Challenge.Token, Solutions: solutionsRaw(t, c.Solutions)},
		ValidateOptions{Secret: []byte(f.Secret), Scope: "twikoo"})
	if !res.Success {
		t.Fatalf("Go 校验官方挑战失败：%s", res.Reason)
	}
	// scope 透传
	if res.Scope != "twikoo" {
		t.Errorf("scope 透传错误：%q", res.Scope)
	}
	// token 结构与过期时间
	if res.Token == "" || res.TokenKey == "" {
		t.Error("通行 token 未签发")
	}

	// Go 解开官方 ev 密文，与官方 expectedDecrypted 一致
	claimsJSON, ok := VerifyHS256(c.Challenge.Token, []byte(f.Secret))
	if !ok {
		t.Fatal("Go 无法验签官方 token")
	}
	var claims struct {
		Ev string `json:"ev"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptGcm(claims.Ev, []byte(f.Secret), GCMInfoExpected)
	if err != nil {
		t.Fatalf("Go 解密官方 ev 失败：%v", err)
	}
	var got, want map[string]any
	json.Unmarshal(plaintext, &got)
	wantBytes, _ := json.Marshal(c.ExpectedDecrypted)
	json.Unmarshal(wantBytes, &want)
	gotB, _ := json.Marshal(got)
	wantB, _ := json.Marshal(want)
	if string(gotB) != string(wantB) {
		t.Errorf("ev 解密不一致：\n got %s\nwant %s", gotB, wantB)
	}

	// 官方自己的校验也应成功（fixture 断言）
	if c.Validate["success"] != true {
		t.Error("fixture 官方断言失败")
	}
}

// TestFailureReasons 官方失败语义与 Go reason 一一对应。
func TestFailureReasons(t *testing.T) {
	f := loadCases(t)
	byName := map[string]*caseEntry2{}
	for i := range f.Cases {
		byName[f.Cases[i].Name] = &f.Cases[i]
	}

	type tc struct {
		name    string
		scope   string
		sol     []map[string]any
		wantGo  string
		wantOff map[string]any
	}
	tests := []tc{
		{"expired", "twikoo", nil, ReasonExpired, byName["expired"].Validate},
		{"wrong_solution", "", byName["wrong_solution"].WrongSolutions, ReasonBadSolution, byName["wrong_solution"].Validate},
	}
	for _, tt := range tests {
		c := byName[tt.name]
		body := RedeemBody{Token: c.Challenge.Token}
		if tt.sol != nil {
			body.Solutions = solutionsRaw(t, tt.sol)
		} else {
			body.Solutions = solutionsRaw(t, c.Solutions)
		}
		res := Validate(body, ValidateOptions{Secret: []byte(f.Secret), Scope: tt.scope})
		if res.Success || res.Reason != tt.wantGo {
			t.Errorf("[%s] Go reason %q != 官方 %q", tt.name, res.Reason, reasonOf(tt.wantOff))
		}
		if tt.wantOff["success"] != false || reasonOf(tt.wantOff) != tt.wantGo {
			t.Errorf("[%s] fixture 官方 reason 变化：%v", tt.name, tt.wantOff)
		}
	}

	// malformed_solutions
	m := byName["malformed_solutions"]
	if m.ShortSolutions["success"] != false || reasonOf(m.ShortSolutions) != ReasonBadSolutions {
		t.Error("官方 shortSolutions 语义变化")
	}
	if m.NonObjectSolutions["success"] != false || reasonOf(m.NonObjectSolutions) != ReasonBadSolution {
		t.Error("官方 nonObjectSolutions 语义变化")
	}
	if m.StringNonceFirst["success"] != false || reasonOf(m.StringNonceFirst) != ReasonBadSolution {
		t.Error("官方 stringNonceFirst 语义变化")
	}
	if m.EmptySolutions["success"] != false || reasonOf(m.EmptySolutions) != ReasonBadSolutions {
		t.Error("官方 emptySolutions 语义变化")
	}

	// Go 复现：数量不符 / 非对象 / 字符串 nonce 不匹配 / 空
	good := m.Challenge.Token
	cases := []struct {
		label string
		body  RedeemBody
		want  string
	}{
		{"short", RedeemBody{Token: good, Solutions: solutionsRaw(t, []map[string]any{{"nonce": json.Number("1")}})}, ReasonBadSolutions},
		{"nonObject", RedeemBody{Token: good, Solutions: []json.RawMessage{json.RawMessage("1"), json.RawMessage("2")}}, ReasonBadSolution},
		{"stringNonce", RedeemBody{Token: good, Solutions: solutionsRaw(t, []map[string]any{{"nonce": "x"}, {"nonce": json.Number("1")}})}, ReasonBadSolution},
		{"empty", RedeemBody{Token: good, Solutions: []json.RawMessage{}}, ReasonBadSolutions},
	}
	for _, tc := range cases {
		res := Validate(tc.body, ValidateOptions{Secret: []byte(f.Secret)})
		if res.Success || res.Reason != tc.want {
			t.Errorf("[%s] Go reason %q != %q", tc.label, res.Reason, tc.want)
		}
	}

	// 错误 secret / scope 不匹配
	ss := byName["secret_and_scope"]
	res := Validate(RedeemBody{Token: ss.Challenge.Token, Solutions: solutionsRaw(t, ss.Solutions)},
		ValidateOptions{Secret: []byte("another-secret-value-16bytes!!")})
	if res.Success || res.Reason != ReasonInvalidToken {
		t.Errorf("错误 secret：Go %q", res.Reason)
	}
	if ss.WrongSecret["success"] != false || reasonOf(ss.WrongSecret) != ReasonInvalidToken {
		t.Errorf("官方错误 secret 语义变化：%v", ss.WrongSecret)
	}
	res = Validate(RedeemBody{Token: ss.Challenge.Token, Solutions: solutionsRaw(t, ss.Solutions)},
		ValidateOptions{Secret: []byte(f.Secret), Scope: "othersite"})
	if res.Success || res.Reason != ReasonScopeMismatch {
		t.Errorf("scope 错配（token 无 sk 但期望 othersite）：Go %q", res.Reason)
	}
	if ss.ScopeMismatch["success"] != false || reasonOf(ss.ScopeMismatch) != ReasonScopeMismatch {
		t.Errorf("官方 scope_mismatch 语义变化：%v", ss.ScopeMismatch)
	}

	// consumeNonce 一次性
	cn := byName["consume_nonce"]
	seen := map[string]bool{}
	consume := func(sig string, _ int64) bool {
		if seen[sig] {
			return false
		}
		seen[sig] = true
		return true
	}
	r1 := Validate(RedeemBody{Token: cn.Challenge.Token, Solutions: solutionsRaw(t, cn.Solutions)},
		ValidateOptions{Secret: []byte(f.Secret), ConsumeNonce: consume})
	r2 := Validate(RedeemBody{Token: cn.Challenge.Token, Solutions: solutionsRaw(t, cn.Solutions)},
		ValidateOptions{Secret: []byte(f.Secret), ConsumeNonce: consume})
	if !r1.Success {
		t.Errorf("首次消费应成功，得到 %q", r1.Reason)
	}
	if r2.Success || r2.Reason != ReasonAlreadyRedeemed {
		t.Errorf("重放应 already_redeemed，得到 %q", r2.Reason)
	}
	if cn.First["success"] != true || reasonOf(cn.Replay) != ReasonAlreadyRedeemed {
		t.Errorf("官方 consumeNonce 语义变化：%v / %v", cn.First, cn.Replay)
	}
}

// TestJWTExact 官方 jwtSign 的逐字节输出。
func TestJWTExact(t *testing.T) {
	cf := loadCrypto(t)
	j := cf.JWT

	// 官方 payload 的 JSON.stringify 键序 = 插入序；fixture 记录了原始 token，
	// Go 侧用官方 token 的 body 部分重签名对比签名段即可（header 段独立断言）。
	parts := split3(j.Token)
	if len(parts) != 3 {
		t.Fatalf("fixture token 结构错误")
	}
	if parts[0] != j.Header {
		t.Errorf("header 段 %q != %q", parts[0], j.Header)
	}
	if jwtHeaderB64 != parts[0] {
		t.Errorf("Go jwtHeaderB64 %q != 官方 %q", jwtHeaderB64, parts[0])
	}
	// Go 对官方 body 重新签名 → 逐字节一致
	body, err := b64urlDecode(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	got := SignHS256(body, []byte(j.Secret))
	if got != j.Token {
		t.Errorf("Go 重签名与官方不一致：\n got %s\nwant %s", got, j.Token)
	}

	// 验签与畸形 token
	if _, ok := VerifyHS256(j.Token, []byte(j.Secret)); !ok {
		t.Error("Go 应验签通过")
	}
	if _, ok := VerifyHS256(j.TamperedLastChar, []byte(j.Secret)); ok {
		t.Error("篡改签名应失败")
	}
	if _, ok := VerifyHS256(j.Token, []byte("wrong-secret-wrong-secret")); ok {
		t.Error("错误 secret 应失败")
	}
	for _, bad := range []string{"no-dots-here", "a.b", "a.b.c.d", ""} {
		if _, ok := VerifyHS256(bad, []byte(j.Secret)); ok {
			t.Errorf("畸形 token %q 应失败", bad)
		}
	}
	if j.VerifyBad != nil || j.NotJwt != nil || j.TwoDots != nil || j.FourDots != nil {
		t.Error("官方畸形 token 语义变化（应返回 null）")
	}
}

// TestGCMInterop 官方 GCM blob 由 Go 解密 + Go 编码 blob 双向兼容。
func TestGCMInterop(t *testing.T) {
	cf := loadCrypto(t)
	g := cf.GCM

	// 官方 blob → Go 解密
	plaintext, err := DecryptGcm(g.BlobFromCore, []byte(g.Secret), g.Info)
	if err != nil {
		t.Fatalf("Go 解密官方 blob：%v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(plaintext, &got); err != nil {
		t.Fatal(err)
	}
	wantB, _ := json.Marshal(g.Data)
	gotB, _ := json.Marshal(got)
	if string(gotB) != string(wantB) {
		t.Errorf("解密结果不一致：\n got %s\nwant %s", gotB, wantB)
	}

	// Go 加密 → Go 解密 roundtrip
	blob, err := EncryptGcm(g.Data, []byte(g.Secret), g.Info)
	if err != nil {
		t.Fatal(err)
	}
	round, err := DecryptGcm(blob, []byte(g.Secret), g.Info)
	if err != nil {
		t.Fatal(err)
	}
	if string(round) != string(wantB) {
		t.Errorf("roundtrip 不一致：%s", round)
	}
	// 每次加密随机 IV：两次 blob 不同
	blob2, _ := EncryptGcm(g.Data, []byte(g.Secret), g.Info)
	if blob == blob2 {
		t.Error("IV 应随机")
	}
	// 错误 info 派生不同 key → 解密失败
	if _, err := DecryptGcm(blob, []byte(g.Secret), "cap:enc-v1"); err == nil {
		t.Error("错误 info 应解密失败")
	}
}

// TestGoToOfficialDirection 「Go 生成 → 官方验证」互操作（依赖 node；无 node 跳过）。
func TestGoToOfficialDirection(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 node，跳过官方 oracle 互操作")
	}

	// Go 生成 format-2 挑战并求解
	secret := []byte("interop-secret-16bytes-ok!!!")
	ch, err := Generate(GenerateOptions{
		Secret:     secret,
		Protocols:  []string{"sha256-pow"},
		Count:      3,
		Size:       24,
		Difficulty: 3,
		ExpiresMs:  600000,
		Scope:      "twikoo",
	})
	if err != nil {
		t.Fatal(err)
	}
	solutions := make([]map[string]any, len(ch.Challenges))
	for i, c := range ch.Challenges {
		var p Sha256Payload
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			t.Fatal(err)
		}
		n := solveInt(p.Salt, p.Target)
		solutions[i] = map[string]any{"nonce": json.Number(strconv.FormatInt(n, 10))}
	}

	input := map[string]any{
		"mode":      "format2",
		"secret":    string(secret),
		"scope":     "twikoo",
		"challenge": ch,
		"solutions": solutions,
	}
	dir, script := runOracle(t, node, input)
	t.Cleanup(func() { os.RemoveAll(dir) })

	var out struct {
		OK     bool           `json:"ok"`
		Result map[string]any `json:"result"`
		Error  string         `json:"error"`
	}
	if err := json.Unmarshal([]byte(script), &out); err != nil {
		t.Fatalf("oracle 输出解析：%v\n%s", err, script)
	}
	if !out.OK {
		t.Errorf("官方拒绝 Go 生成的挑战：%s / %v", out.Error, out.Result)
	}
}

// solveInt 是 sha256-pow 暴力求解（测试用）。
func solveInt(salt, target string) int64 {
	n := int64(0)
	for {
		if sha256pow.Matches(salt, strconv.FormatInt(n, 10), target) {
			return n
		}
		n++
	}
}

func runOracle(t *testing.T, node string, input any) (dir, stdout string) {
	t.Helper()
	tmp, err := os.MkdirTemp("", "capgo-interop-*")
	if err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(tmp, "input.json")
	b, _ := json.Marshal(input)
	if err := os.WriteFile(inPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "verify-go.mjs", inPath)
	cmd.Dir = "../../../tools/oracle"
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("oracle 执行失败：%v\nstdout: %s", err, out.String())
	}
	return tmp, out.String()
}

func split3(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
