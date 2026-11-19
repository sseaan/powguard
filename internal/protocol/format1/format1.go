// Package format1 实现 legacy @cap.js/server@4.0.5 线协议：
// 有状态挑战（不透明 hex token + 内存状态）、redeem 校验、一次性通行 token。
//
// 本包只做纯协议运算；存储与 HTTP 由 internal/store 和 internal/api 负责。
package format1

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sseaan/powguard/internal/protocol/prng"
	"github.com/sseaan/powguard/internal/protocol/sha256pow"
)

// 参数边界沿用 capjs-core 0.1.18 的校验（防 DoS，见 docs/protocol-notes.md §3.1）。
const (
	MaxChallengeCount      = 1000
	MaxChallengeSize       = 256
	MaxChallengeDifficulty = 16
)

// 官方默认值（@cap.js/server createChallenge 缺省 + Twikoo CHALLENGE_OPTS）。
const (
	DefaultChallengeCount      = 50
	DefaultChallengeSize       = 32
	DefaultChallengeDifficulty = 4
	DefaultChallengeTTL        = 10 * 60 * 1000 // 毫秒
	DefaultTokenTTL            = 20 * 60 * 1000 // 毫秒
)

// ChallengeConfig 是站点策略中的 format-1 参数。
// 字段名即线协议字段（官方 challenge 响应 {c,s,d}）。
type ChallengeConfig struct {
	Count      int `json:"c"` // c：挑战数量
	Size       int `json:"s"` // s：盐 hex 长度
	Difficulty int `json:"d"` // d：难度（hex 前缀位数）
}

func (c ChallengeConfig) Validate() error {
	switch {
	case c.Count < 1 || c.Count > MaxChallengeCount,
		c.Size < 1 || c.Size > MaxChallengeSize,
		c.Difficulty < 1 || c.Difficulty > MaxChallengeDifficulty:
		return fmt.Errorf("format1: invalid params c=%d s=%d d=%d", c.Count, c.Size, c.Difficulty)
	}
	return nil
}

// ChallengeData 是内存中的挑战状态（等价官方 challengesList[token] 的值）。
type ChallengeData struct {
	Config  ChallengeConfig
	Expires int64 // Unix 毫秒
}

// ChallengeResponse 是 POST /challenge 的响应。
type ChallengeResponse struct {
	Challenge ChallengeConfig `json:"challenge"`
	Token     string          `json:"token"`
	Expires   int64           `json:"expires"`
}

// SaltAndTarget 推导第 index 个（1 ≤ index ≤ c）挑战的盐与目标。
// 与官方 redeemChallenge 内联逻辑 bit-exact：
//
//	salt   = prng(`${token}${index}`,   s)
//	target = prng(`${token}${index}d`,  d)
func SaltAndTarget(token string, index, size, difficulty int) (salt, target string) {
	base := strconv.Itoa(index)
	salt = prng.Generate(token+base, size)
	target = prng.Generate(token+base+"d", difficulty)
	return salt, target
}

// ErrInvalidSolution / ErrChallengeExpired 表达官方 redeem 的失败语义。
var (
	ErrInvalidBody         = errors.New("Invalid body")
	ErrChallengeInvalid    = errors.New("Challenge invalid or expired")
	ErrInvalidSolution     = errors.New("Invalid solution")
	ErrInvalidVerification = errors.New("invalid verification token")
)

// VerifySolutions 校验 redeem body 的解是否匹配挑战状态。
// 调用方负责先取出并删除挑战状态（官方先删后验）。
// solutions 元素必须是十进制整数字符串（JSON number 已由解码层规范化）。
func VerifySolutions(token string, data ChallengeData, solutions []string) error {
	if len(solutions) != data.Config.Count {
		return ErrInvalidSolution
	}
	for i := 1; i <= data.Config.Count; i++ {
		salt, target := SaltAndTarget(token, i, data.Config.Size, data.Config.Difficulty)
		if !sha256pow.Matches(salt, solutions[i-1], target) {
			return ErrInvalidSolution
		}
	}
	return nil
}

// VerificationToken 是 redeem 成功后签发的一次性通行 token。
// 结构等价官方："id:vertoken"（id 16 hex、vertoken 30 hex），
// 存储键为 "id:sha256hex(vertoken)"，值是过期毫秒时间戳。
type VerificationToken struct {
	Token   string // "id:vertoken"
	Key     string // "id:sha256(vertoken)"
	Expires int64  // Unix 毫秒
}

// NewVerificationToken 签发通行 token（随机 id/vertoken 与官方长度一致）。
func NewVerificationToken(nowMs, ttlMs int64) (VerificationToken, error) {
	id, err := RandomHex(8)
	if err != nil {
		return VerificationToken{}, err
	}
	ver, err := RandomHex(15)
	if err != nil {
		return VerificationToken{}, err
	}
	return VerificationToken{
		Token:   id + ":" + ver,
		Key:     id + ":" + sha256pow.Hex(ver),
		Expires: nowMs + ttlMs,
	}, nil
}

// SplitVerificationToken 解析通行 token 为存储键；格式非法返回错误。
// 同时接受 legacy 两段式（powguard / @cap.js/server）与 capd 三段式
// （"siteKey:id:vertoken"，siteKey 必须与 expectedSite 匹配）。
func SplitVerificationToken(token, expectedSite string) (key string, err error) {
	parts := strings.Split(token, ":")
	switch len(parts) {
	case 2:
		id, ver := parts[0], parts[1]
		if id == "" || ver == "" {
			return "", ErrInvalidVerification
		}
		return id + ":" + sha256pow.Hex(ver), nil
	case 3:
		site, id, ver := parts[0], parts[1], parts[2]
		if expectedSite != "" && site != expectedSite {
			return "", ErrInvalidVerification
		}
		if id == "" || ver == "" {
			return "", ErrInvalidVerification
		}
		return id + ":" + sha256pow.Hex(ver), nil
	default:
		return "", ErrInvalidVerification
	}
}

// RandomHex 生成 nBytes 随机字节的 hex（官方 randomHex）。
func RandomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// NewChallengeToken 生成挑战 token（官方 randomHex(25) → 50 hex 字符）。
func NewChallengeToken() (string, error) { return RandomHex(25) }
