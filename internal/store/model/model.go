// Package model 定义 SQLite 持久化的数据结构（PLAN.md §6.1）。
package model

import "time"

// Site 是站点行（策略字段与 format-1 参数；format-2 接入时复用同表扩展）。
type Site struct {
	ID                  int64
	Slug                string
	Name                string
	Enabled             bool
	Deleted             bool   // 软删除：保留审计上下文（PLAN.md §3.2）
	Protocol            string // format1 | format2（sha256-pow）
	ChallengeCount      int
	ChallengeSize       int
	ChallengeDifficulty int
	ChallengeTTL        int64 // 毫秒
	TokenTTL            int64 // 毫秒
	CORSAllowAll        bool
	CORSOrigins         []string
	RateLimitPerWindow  int
	RateLimitWindowMs   int64
	CreatedAt           int64 // Unix 毫秒
	UpdatedAt           int64
}

const (
	ProtocolFormat1 = "format1"
	ProtocolFormat2 = "format2"
)

// ProtocolOrDefault 归一化站点协议取值。
func ProtocolOrDefault(p string) string {
	if p == "" {
		return ProtocolFormat1
	}
	return p
}

// Secret 字段名（AEAD AAD 的一部分）。
const (
	FieldSiteVerify = "siteverify" // Twikoo CAP_SECRET_KEY
	FieldSigning    = "signing"    // format-2 JWT 签名密钥（P3 接入）
)

// SiteSecret 是加密存储的站点密钥行。
type SiteSecret struct {
	SiteID        int64
	Field         string
	Ciphertext    string // secretbox Seal 产物
	SchemaVersion int
	RotatedAt     int64
}

// AdminSession 是管理会话行（只存 token 哈希，PLAN.md §6.1）。
type AdminSession struct {
	ID        int64
	TokenHash string // sha256(token) hex
	CreatedAt int64
	ExpiresAt int64
	Revoked   bool
}

// Event 是审计事件（白名单字段，禁止敏感内容，PLAN.md §6.3）。
type Event struct {
	ID       int64
	Ts       int64
	SiteSlug string
	Type     string // challenge | redeem | siteverify | admin
	Outcome  string // pass | fail | blocked | limit
	Reason   string
	Protocol string // format1 | format2
	IPDigest string // keyed digest，非明文 IP
	TokenID  string // 通行/挑战 token 的 id 段
	DurMs    *int64
	Meta     string // JSON（白名单字段）
}

// Settings 键。
const (
	SettingEventRetentionDays = "event_retention_days"
	SettingPublicURL          = "public_url"
)

// DefaultEventRetentionDays 是事件保留期默认值（PLAN.md §6.3：30 天）。
const DefaultEventRetentionDays = 30

// 纪元辅助。
func NowMs() int64 { return time.Now().UnixMilli() }
