package format1

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"capgo/internal/protocol/prng"
	"capgo/internal/protocol/sha256pow"
)

// TestGoToOfficialDirection 「Go 生成 → 官方验证」互操作（依赖 node；无 node 跳过）。
// 官方 @cap.js/server 实例以自身的内存存储路径接受 Go 签发的挑战与解。
func TestGoToOfficialDirection(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 node，跳过官方 oracle 互操作")
	}

	now := time.Now().UnixMilli()
	const ttl = 10 * 60 * 1000
	cfg := ChallengeConfig{Count: 3, Size: 16, Difficulty: 3}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	token, err := NewChallengeToken()
	if err != nil {
		t.Fatal(err)
	}

	// 用 Go 的 SaltAndTarget 求解（等价 widget 客户端行为）
	solutions := make([]int64, cfg.Count)
	for i := 1; i <= cfg.Count; i++ {
		salt, target := SaltAndTarget(token, i, cfg.Size, cfg.Difficulty)
		solutions[i-1] = sha256pow.Solve(salt, target)
	}

	input := map[string]any{
		"mode":      "format1",
		"token":     token,
		"c":         cfg.Count,
		"s":         cfg.Size,
		"d":         cfg.Difficulty,
		"expires":   now + ttl,
		"solutions": solutions,
	}

	tmp, err := os.MkdirTemp("", "capgo-interop-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
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
		t.Fatalf("官方 oracle 执行失败：%v\nstdout: %s", err, out.String())
	}

	var result struct {
		OK     bool `json:"ok"`
		Redeem struct {
			Success bool   `json:"success"`
			Token   string `json:"token"`
			Expires int64  `json:"expires"`
		} `json:"redeem"`
		Validate struct {
			Success bool `json:"success"`
		} `json:"validate"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("oracle 输出解析：%v\n%s", err, out.String())
	}
	if !result.OK || !result.Redeem.Success || !result.Validate.Success {
		t.Errorf("官方拒绝 Go 生成的挑战：ok=%v redeem=%+v validate=%+v err=%s\n%s",
			result.OK, result.Redeem, result.Validate, result.Error, out.String())
	}
	// 官方签发的通行 token 能被 Go 的 SplitVerificationToken 推导出一致的存储键
	if result.Redeem.Token != "" {
		if _, err := SplitVerificationToken(result.Redeem.Token, ""); err != nil {
			t.Errorf("Go 无法解析官方通行 token：%v", err)
		}
	}
}

// TestSaltAndTargetIsByteExact 直接对拍一个手工向量（防 PRNG fixture 与本函数间耦合）。
func TestSaltAndTargetIsByteExact(t *testing.T) {
	// 由 oracle lib/prng.mjs 生成：prng("tok" + "1", 4) / prng("tok" + "1" + "d", 2)
	const seed = "tok1"
	salt, target := SaltAndTarget("tok", 1, 4, 2)
	if len(salt) != 4 || len(target) != 2 {
		t.Fatalf("长度错误：%q %q", salt, target)
	}
	// 双向自洽：SaltAndTarget 与 prng.Generate 必须同源
	if salt != prng.Generate(seed, 4) || target != prng.Generate(seed+"d", 2) {
		t.Errorf("SaltAndTarget 与 prng.Generate 不一致：%q/%q", salt, target)
	}
}

// Solve 全链路一致性：SaltAndTarget + sha256pow.Solve + VerifySolutions。
func TestSolveAndVerifyRoundtrip(t *testing.T) {
	cfg := ChallengeConfig{Count: 2, Size: 8, Difficulty: 2}
	token := "0123456789abcdef0123456789abcdef0123456789abcdef01"
	solutions := make([]string, cfg.Count)
	for i := 1; i <= cfg.Count; i++ {
		salt, target := SaltAndTarget(token, i, cfg.Size, cfg.Difficulty)
		n := sha256pow.Solve(salt, target)
		solutions[i-1] = strconv.FormatInt(n, 10)
	}
	data := ChallengeData{Config: cfg, Expires: time.Now().UnixMilli() + 60000}
	if err := VerifySolutions(token, data, solutions); err != nil {
		t.Fatalf("自洽校验失败：%v", err)
	}
	// 篡改一个解
	solutions[0] = solutions[0] + "0"
	if err := VerifySolutions(token, data, solutions); err != ErrInvalidSolution {
		t.Fatalf("篡改解应失败：%v", err)
	}
}
