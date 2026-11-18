// Package format2 实现 capjs-core@0.1.18 的 format-2 envelope（stateless JWT）。
//
// capgo 当前只开放 "sha256-pow" 协议；hashwx / rsw / instrumentation 是
// 明确的后续扩展（PLAN.md §2.1），遇到时返回 invalid 语义。
package format2

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"capgo/internal/protocol/format1"
	"capgo/internal/protocol/sha256pow"
)

const (
	DefaultChallengeTTL = 10 * 60 * 1000 // 毫秒，同 format-1
	DefaultTokenTTL     = 20 * 60 * 1000

	// GCMInfoExpected 是 format-2 expected 数组的 AEAD info（官方 "cap:fmt2-v1"）。
	GCMInfoExpected = "cap:fmt2-v1"
)

// Challenge 是 envelope 中的单个挑战条目。
type Challenge struct {
	Protocol string          `json:"protocol"`
	Payload  json.RawMessage `json:"payload"`
}

// Sha256Payload 是 protocol=="sha256-pow" 的 payload。
type Sha256Payload struct {
	Salt   string `json:"salt"`
	Target string `json:"target"`
}

// Sha256Solution 是 sha256-pow 的解；nonce 可为 number 或 string（官方语义）。
type Sha256Solution struct {
	Nonce json.RawMessage `json:"nonce"`
}

// ChallengeResponse 是 POST /challenge 的 format-2 响应。
type ChallengeResponse struct {
	Token      string      `json:"token"`
	Format     int         `json:"format"`
	Challenges []Challenge `json:"challenges"`
	Expires    int64       `json:"expires"`
}

// tokenClaims 是 format-2 JWT payload 的字段（官方生成顺序无关，verify 宽松）。
type tokenClaims struct {
	Format int             `json:"f"`
	Nonce  string          `json:"n"`
	Exp    int64           `json:"exp"`
	Iat    int64           `json:"iat"`
	Ev     string          `json:"ev"`
	Scope  string          `json:"sk,omitempty"`
	Extra  json.RawMessage `json:"x,omitempty"`
}

// expectedEntry 是 ev 密文内 expected 数组的条目。
type expectedEntry struct {
	Protocol string `json:"protocol"`
	Salt     string `json:"salt"`
	Target   string `json:"target"`
}

type expectedBlob struct {
	Expected []expectedEntry `json:"expected"`
}

// GenerateOptions 控制 format-2 挑战生成。
type GenerateOptions struct {
	Secret     []byte
	Protocols  []string // 当前仅 ["sha256-pow"]
	Count      int
	Size       int
	Difficulty int
	ExpiresMs  int64
	Scope      string
	NowMs      int64
}

// 失败 reason 与官方 validateChallenge 的字符串一致。
const (
	ReasonInvalidBody     = "invalid_body"
	ReasonMissingToken    = "missing_token"
	ReasonMissingSolution = "missing_solutions"
	ReasonInvalidToken    = "invalid_token"
	ReasonExpired         = "expired"
	ReasonScopeMismatch   = "scope_mismatch"
	ReasonBadSolutions    = "invalid_solutions"
	ReasonBadSolution     = "invalid_solution"
	ReasonAlreadyRedeemed = "already_redeemed"
)

var ErrUnknownProtocol = errors.New("format2: unknown protocol")

// Generate 生成 format-2 sha256-pow 挑战。
func Generate(opts GenerateOptions) (*ChallengeResponse, error) {
	if len(opts.Protocols) == 0 {
		opts.Protocols = []string{"sha256-pow"}
	}
	for _, p := range opts.Protocols {
		if p != "sha256-pow" {
			return nil, fmt.Errorf("%w: %q", ErrUnknownProtocol, p)
		}
	}
	cfg := format1.ChallengeConfig{Count: opts.Count, Size: opts.Size, Difficulty: opts.Difficulty}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.ExpiresMs <= 0 {
		opts.ExpiresMs = DefaultChallengeTTL
	}
	if opts.NowMs == 0 {
		opts.NowMs = time.Now().UnixMilli()
	}
	exp := opts.NowMs + opts.ExpiresMs

	challenges := make([]Challenge, 0, opts.Count)
	expected := make([]expectedEntry, 0, opts.Count)
	for i := 0; i < opts.Count; i++ {
		salt, err := format1.RandomHex(opts.Size)
		if err != nil {
			return nil, err
		}
		target := ""
		for j := 0; j < opts.Difficulty; j++ {
			target += "0"
		}
		payload, _ := json.Marshal(Sha256Payload{Salt: salt, Target: target})
		challenges = append(challenges, Challenge{Protocol: "sha256-pow", Payload: payload})
		expected = append(expected, expectedEntry{Protocol: "sha256-pow", Salt: salt, Target: target})
	}

	nonce, err := format1.RandomHex(16)
	if err != nil {
		return nil, err
	}
	ev, err := EncryptGcm(expectedBlob{Expected: expected}, opts.Secret, GCMInfoExpected)
	if err != nil {
		return nil, err
	}
	claims := tokenClaims{
		Format: 2,
		Nonce:  nonce,
		Exp:    exp,
		Iat:    opts.NowMs,
		Ev:     ev,
		Scope:  opts.Scope,
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return &ChallengeResponse{
		Token:      SignHS256(claimsJSON, opts.Secret),
		Format:     2,
		Challenges: challenges,
		Expires:    exp,
	}, nil
}

// NonceConsumer 是一次性消费回调（对应官方 consumeNonce）。
// 返回 false 表示已被消费过（already_redeemed）。
type NonceConsumer func(sigHex string, ttlMs int64) bool

// ValidateOptions 控制 format-2 校验。
type ValidateOptions struct {
	Secret       []byte
	Scope        string // 期望 scope；空 = 不校验
	TokenTtlMs   int64
	NowMs        int64
	ConsumeNonce NonceConsumer
}

// ValidateResult 是校验结果；Success=false 时 Reason 为官方 reason。
type ValidateResult struct {
	Success  bool
	Reason   string
	Token    string // 成功时签发的通行 token（"id:vertoken"）
	TokenKey string
	Expires  int64
	Scope    string
}

// RedeemBody 是 POST /redeem 的请求体（format-2）。
type RedeemBody struct {
	Token     string            `json:"token"`
	Solutions []json.RawMessage `json:"solutions"`
}

// Validate 校验 format-2 redeem。
func Validate(body RedeemBody, opts ValidateOptions) ValidateResult {
	if opts.TokenTtlMs == 0 {
		opts.TokenTtlMs = DefaultTokenTTL
	}
	if opts.NowMs == 0 {
		opts.NowMs = time.Now().UnixMilli()
	}
	fail := func(reason string) ValidateResult {
		return ValidateResult{Success: false, Reason: reason}
	}

	if body.Token == "" {
		return fail(ReasonMissingToken)
	}
	payloadJSON, ok := VerifyHS256(body.Token, opts.Secret)
	if !ok {
		return fail(ReasonInvalidToken)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil || claims.Format != 2 || claims.Ev == "" {
		return fail(ReasonInvalidToken)
	}
	if opts.Scope != "" && claims.Scope != opts.Scope {
		return fail(ReasonScopeMismatch)
	}
	if claims.Exp < opts.NowMs {
		return fail(ReasonExpired)
	}

	plaintext, err := DecryptGcm(claims.Ev, opts.Secret, GCMInfoExpected)
	if err != nil {
		return fail(ReasonInvalidToken)
	}
	var blob expectedBlob
	if err := json.Unmarshal(plaintext, &blob); err != nil || len(blob.Expected) == 0 {
		return fail(ReasonInvalidToken)
	}
	expected := blob.Expected

	if len(body.Solutions) != len(expected) {
		return fail(ReasonBadSolutions)
	}

	for i, e := range expected {
		if e.Protocol != "sha256-pow" {
			return fail(ReasonBadSolution) // 未知协议：官方语义为 invalid_solution
		}
		var sol Sha256Solution
		if err := json.Unmarshal(body.Solutions[i], &sol); err != nil {
			return fail(ReasonBadSolution) // 非对象解（官方 typeof s !== "object"）
		}
		nonce, valid := nonceString(sol.Nonce)
		if !valid {
			return fail(ReasonBadSolution)
		}
		if !sha256pow.MatchesBytes(e.Salt, nonce, e.Target) {
			return fail(ReasonBadSolution)
		}
	}

	if opts.ConsumeNonce != nil {
		sig, ok := SigHex(body.Token)
		if !ok {
			return fail(ReasonInvalidToken)
		}
		ttl := claims.Exp - opts.NowMs
		if ttl < 1 {
			ttl = 1
		}
		if !opts.ConsumeNonce(sig, ttl) {
			return fail(ReasonAlreadyRedeemed)
		}
	}

	vt, err := format1.NewVerificationToken(opts.NowMs, opts.TokenTtlMs)
	if err != nil {
		return fail("nonce_store_error")
	}
	return ValidateResult{
		Success:  true,
		Token:    vt.Token,
		TokenKey: vt.Key,
		Expires:  vt.Expires,
		Scope:    claims.Scope,
	}
}

// nonceString 把官方允许的 nonce（JSON number 的十进制整数，或任意 string）
// 转为参与哈希的字符串。非整数 number 拒绝（docs/protocol-notes.md §9.1 已知偏差）。
func nonceString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	}
	// JSON number：仅接受十进制整数语法（无小数点/指数/前导 +）。
	s := string(raw)
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		// 官方接受大整数；超出 int64 的整数用 big 解析判别
		if !isBigInteger(s) {
			return "", false
		}
	}
	return s, true
}

func isBigInteger(s string) bool {
	t := s
	if t == "" {
		return false
	}
	if t[0] == '-' || t[0] == '+' {
		t = t[1:]
	}
	if t == "" {
		return false
	}
	for _, c := range t {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
