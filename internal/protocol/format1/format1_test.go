package format1

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type caseConfig struct {
	ChallengeCount      int   `json:"challengeCount"`
	ChallengeSize       int   `json:"challengeSize"`
	ChallengeDifficulty int   `json:"challengeDifficulty"`
	ExpiresMs           int64 `json:"expiresMs"`
}

type challengeSpec struct {
	Challenge struct {
		C int `json:"c"`
		S int `json:"s"`
		D int `json:"d"`
	} `json:"challenge"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

type challengeStateSpec struct {
	Expires   int64 `json:"expires"`
	Challenge struct {
		C int `json:"c"`
		S int `json:"s"`
		D int `json:"d"`
	} `json:"challenge"`
}

type caseEntry struct {
	Name           string              `json:"name"`
	Config         caseConfig          `json:"config"`
	Challenge      challengeSpec       `json:"challenge"`
	ChallengeState *challengeStateSpec `json:"challengeState"`
	Solutions      []int64             `json:"solutions"`
	GoodSolutions  []int64             `json:"goodSolutions"`
	WrongSolutions []int64             `json:"wrongSolutions"`
	Redeem         map[string]any      `json:"redeem"`
	RedeemWrong    map[string]any      `json:"redeemWrong"`
	RedeemAgain    map[string]any      `json:"redeemAgain"`
	Validate       map[string]any      `json:"validate"`
	FirstValidate  map[string]any      `json:"firstValidate"`
	ReplayValidate map[string]any      `json:"replayValidate"`
	TokenStateKey  string              `json:"tokenStateKey"`
	// verification_token_structure
	RedeemToken     string                    `json:"redeemToken"`
	IdPart          string                    `json:"idPart"`
	VerPart         string                    `json:"verPart"`
	VerPartIsHex30  bool                      `json:"verPartIsHex30"`
	StoredKey       string                    `json:"storedKeyDerived"`
	ValidateFresh   map[string]map[string]any `json:"validateFresh"`
	ValidateOneShot map[string]map[string]any `json:"validateOneShot"`
	MalformedTokens map[string]map[string]any `json:"malformedTokens"`
	// invalid_bodies
	MissingToken        map[string]any `json:"missingToken"`
	MissingSolutions    map[string]any `json:"missingSolutions"`
	SolutionsNotArray   map[string]any `json:"solutionsNotArray"`
	SolutionsNotNumbers map[string]any `json:"solutionsNotNumbers"`
	UnknownToken        map[string]any `json:"unknownToken"`
}

type casesFile struct {
	Source string      `json:"source"`
	Cases  []caseEntry `json:"cases"`
}

func loadCases(t *testing.T) casesFile {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/format1/cases.json")
	if err != nil {
		t.Fatalf("读取 fixture 失败（先运行 tools/oracle/gen-fixtures.mjs）：%v", err)
	}
	var f casesFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("解析 fixture：%v", err)
	}
	if f.Source != "@cap.js/server@4.0.5" {
		t.Fatalf("fixture 来源变化：%q", f.Source)
	}
	return f
}

func (f casesFile) caseByName(t *testing.T, name string) *caseEntry {
	t.Helper()
	for i := range f.Cases {
		if f.Cases[i].Name == name {
			return &f.Cases[i]
		}
	}
	t.Fatalf("缺少 case %q", name)
	return nil
}

func stateOf(c *caseEntry) ChallengeData {
	cs := c.ChallengeState
	return ChallengeData{
		Config: ChallengeConfig{
			Count:      cs.Challenge.C,
			Size:       cs.Challenge.S,
			Difficulty: cs.Challenge.D,
		},
		Expires: cs.Expires,
	}
}

func solutionsStrings(nums []int64) []string {
	out := make([]string, len(nums))
	for i, n := range nums {
		b, _ := json.Marshal(n)
		out[i] = string(b)
	}
	return out
}

func sub(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("fixture 结构变化：缺 %q", key)
	}
	return v
}

// TestOfficialLifecycle 官方签发的挑战由 Go 校验解（官方 → capgo 方向），
// 并验证 Go 推导的通行 token 存储键与官方存储键一致。
func TestOfficialLifecycle(t *testing.T) {
	f := loadCases(t)

	for _, name := range []string{"default_lifecycle", "small_params"} {
		c := f.caseByName(t, name)
		if err := VerifySolutions(c.Challenge.Token, stateOf(c), solutionsStrings(c.Solutions)); err != nil {
			t.Errorf("[%s] Go 校验官方解失败：%v", name, err)
		}
		if c.Redeem["success"] != true {
			t.Errorf("[%s] fixture 的官方 redeem 未成功", name)
		}
		key, err := SplitVerificationToken(c.Redeem["token"].(string), "")
		if err != nil {
			t.Fatalf("[%s] 解析官方 token：%v", name, err)
		}
		if key != c.TokenStateKey {
			t.Errorf("[%s] Go 存储键 %q != 官方 %q", name, key, c.TokenStateKey)
		}
		// 官方一次性消费：firstValidate 成功、replayValidate 失败
		if c.FirstValidate["success"] != true || c.ReplayValidate["success"] != false {
			t.Errorf("[%s] 官方一次性消费语义变化", name)
		}
	}
}

// TestWrongSolutionBurnsChallenge 错误解失败 + fixture 记录官方先删后验语义。
func TestWrongSolutionBurnsChallenge(t *testing.T) {
	f := loadCases(t)
	c := f.caseByName(t, "wrong_solution_burns_challenge")
	if err := VerifySolutions(c.Challenge.Token, stateOf(c), solutionsStrings(c.WrongSolutions)); err == nil {
		t.Error("错误解不应通过")
	} else if err != ErrInvalidSolution {
		t.Errorf("错误解应返回 ErrInvalidSolution，得到 %v", err)
	}
	if err := VerifySolutions(c.Challenge.Token, stateOf(c), solutionsStrings(c.GoodSolutions)); err != nil {
		t.Errorf("正确解应通过：%v", err)
	}
	if c.RedeemWrong["success"] != false || c.RedeemAgain["success"] != false {
		t.Error("fixture 官方断言变化（先删后验）")
	}
}

// TestExpiredChallenge 官方对生成即过期的挑战失败；Go 的解校验与过期判定分离。
func TestExpiredChallenge(t *testing.T) {
	f := loadCases(t)
	c := f.caseByName(t, "expired_challenge")
	if c.Redeem["success"] != false {
		t.Error("官方对过期挑战应失败")
	}
	if stateOf(c).Expires >= time.Now().UnixMilli() {
		t.Fatal("fixture 过期挑战的 expires 已在未来（重跑 gen-fixtures）")
	}
	// 解本身正确（过期判定属于存储/HTTP 层）
	if err := VerifySolutions(c.Challenge.Token, stateOf(c), solutionsStrings(c.Solutions)); err != nil {
		t.Errorf("解校验不应受过期影响：%v", err)
	}
}

// TestInvalidBodies 官方对非法请求体的判定（fixture 固定语义）。
func TestInvalidBodies(t *testing.T) {
	f := loadCases(t)
	c := f.caseByName(t, "invalid_bodies")
	for name, want := range map[string]map[string]any{
		"missingToken":        c.MissingToken,
		"missingSolutions":    c.MissingSolutions,
		"solutionsNotArray":   c.SolutionsNotArray,
		"solutionsNotNumbers": c.SolutionsNotNumbers,
		"unknownToken":        c.UnknownToken,
	} {
		if want["success"] != false {
			t.Errorf("[%s] 官方应失败", name)
		}
		if msg, _ := want["message"].(string); msg == "" {
			t.Errorf("[%s] 官方失败应带 message", name)
		}
	}
}

// TestVerificationTokenStructure 官方通行 token 结构与一次性消费语义。
func TestVerificationTokenStructure(t *testing.T) {
	f := loadCases(t)
	c := f.caseByName(t, "verification_token_structure")

	if c.VerPartIsHex30 != true {
		t.Fatal("fixture 断言变化")
	}
	if len(c.IdPart) != 16 || len(c.VerPart) != 30 {
		t.Fatalf("官方 token 分段长度变化：id=%d ver=%d", len(c.IdPart), len(c.VerPart))
	}
	key, err := SplitVerificationToken(c.RedeemToken, "")
	if err != nil {
		t.Fatalf("解析官方 token：%v", err)
	}
	if key != c.StoredKey {
		t.Errorf("Go 存储键 %q != 官方 %q", key, c.StoredKey)
	}

	fresh := c.ValidateFresh
	if fresh["keep1"]["success"] != true || fresh["keep2"]["success"] != true || fresh["consumeAfterKeep"]["success"] != true {
		t.Error("官方 keepToken 语义变化")
	}
	oneShot := c.ValidateOneShot
	if oneShot["first"]["success"] != true || oneShot["second"]["success"] != false {
		t.Error("官方一次性消费语义变化")
	}

	// 畸形 token 在 Go 与官方同样失败（a:b:c 三段式由 TestThreePartToken 覆盖）
	for _, bad := range []string{"", "abc", ":abc", "abc:"} {
		if _, err := SplitVerificationToken(bad, ""); err == nil {
			t.Errorf("畸形 token %q 应失败", bad)
		}
	}
	mf := c.MalformedTokens
	if mf["empty"]["success"] != false || mf["onePart"]["success"] != false ||
		mf["threeParts"]["success"] != false || mf["emptyPart"]["success"] != false {
		t.Error("官方畸形 token 语义变化")
	}
}

// TestThreePartToken capd 风格三段式 token 的 site 校验。
func TestThreePartToken(t *testing.T) {
	vt, err := NewVerificationToken(1000, 20000)
	if err != nil {
		t.Fatal(err)
	}
	capdStyle := "twikoo:" + vt.Token
	key, err := SplitVerificationToken(capdStyle, "twikoo")
	if err != nil {
		t.Fatalf("三段式 token 应被接受：%v", err)
	}
	if key != vt.Key {
		t.Errorf("三段式存储键 %q != %q", key, vt.Key)
	}
	if _, err := SplitVerificationToken(capdStyle, "othersite"); err == nil {
		t.Error("site 不匹配应失败")
	}
	if _, err := SplitVerificationToken(capdStyle, ""); err != nil {
		t.Errorf("未指定 site 时应接受：%v", err)
	}
}

// TestConfigBounds 参数边界与默认值。
func TestConfigBounds(t *testing.T) {
	bad := []ChallengeConfig{
		{Count: 0, Size: 32, Difficulty: 4},
		{Count: 1001, Size: 32, Difficulty: 4},
		{Count: 50, Size: 0, Difficulty: 4},
		{Count: 50, Size: 257, Difficulty: 4},
		{Count: 50, Size: 32, Difficulty: 0},
		{Count: 50, Size: 32, Difficulty: 17},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("配置 %+v 应非法", c)
		}
	}
	if err := (ChallengeConfig{Count: 1, Size: 1, Difficulty: 1}).Validate(); err != nil {
		t.Error("最小合法配置被拒")
	}
	if DefaultChallengeCount != 50 || DefaultChallengeSize != 32 || DefaultChallengeDifficulty != 4 {
		t.Error("默认值与官方不一致")
	}
}

// TestNewVerificationTokenFormat Go 签发 token 的官方结构。
func TestNewVerificationTokenFormat(t *testing.T) {
	vt, err := NewVerificationToken(1000, DefaultTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	if len(vt.Token) != 47 { // 16 hex + ':' + 30 hex
		t.Errorf("token 长度 %d != 47", len(vt.Token))
	}
	if vt.Expires != 1000+DefaultTokenTTL {
		t.Error("过期计算错误")
	}
	key, err := SplitVerificationToken(vt.Token, "")
	if err != nil {
		t.Fatal(err)
	}
	if key != vt.Key {
		t.Errorf("Key %q != SplitVerificationToken %q", vt.Key, key)
	}
}

// TestSaltAndTarget 推导逻辑与官方内联实现一致性（通过 fixture 解校验覆盖）。
func TestSaltAndTarget(t *testing.T) {
	f := loadCases(t)
	c := f.caseByName(t, "small_params")
	ch := c.Challenge.Challenge
	salt, target := SaltAndTarget(c.Challenge.Token, 1, ch.S, ch.D)
	if len(salt) != ch.S || len(target) != ch.D {
		t.Errorf("盐/目标长度错误：%d/%d", len(salt), len(target))
	}
	// 索引从 1 开始：第 c 个也存在
	saltC, _ := SaltAndTarget(c.Challenge.Token, ch.C, ch.S, ch.D)
	if len(saltC) != ch.S {
		t.Error("最后一个挑战索引推导失败")
	}
}
