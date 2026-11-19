// Package policy 定义站点策略模型。P1 提供进程内单站点实现；
// M2 起 SiteResolver 由 SQLite 站点表驱动，接口保持不变。
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"capgo/internal/protocol/format1"
)

// SlugRe 是站点 slug 的合法形态（PLAN.md §3.2：小写字母/数字/-/_，1–32）。
var SlugRe = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// ValidSlug 校验 slug。
func ValidSlug(s string) bool { return SlugRe.MatchString(s) }

// CORSOrigin 是规范化后的 Origin（scheme://host[:port]，小写）。
type CORSOrigin = string

// Site 是一个站点的完整运行时策略。
type Site struct {
	Slug         string
	Secret       string // siteverify 密钥（M2 起 AES-GCM 加密入库，运行时解密）
	Name         string // 展示名（不入线协议）
	Enabled      bool
	Challenge    format1.ChallengeConfig
	ChallengeTTL int64 // 毫秒
	TokenTTL     int64 // 毫秒
	// CORS：AllowAll 显式开启 "*"；否则只允许 Origins 白名单
	CORSAllowAll bool
	CORSOrigins  []CORSOrigin
	// RateLimitPerWindow 是每 IP 每 Window 的请求上限（challenge/redeem/siteverify）
	RateLimitPerWindow int
	RateLimitWindowMs  int64
}

// NewSite 用官方默认值构造站点。
func NewSite(slug, secret string) (*Site, error) {
	if !ValidSlug(slug) {
		return nil, fmt.Errorf("policy: 非法 slug %q", slug)
	}
	return &Site{
		Slug:               slug,
		Secret:             secret,
		Enabled:            true,
		Challenge:          format1.ChallengeConfig{Count: format1.DefaultChallengeCount, Size: format1.DefaultChallengeSize, Difficulty: format1.DefaultChallengeDifficulty},
		ChallengeTTL:       format1.DefaultChallengeTTL,
		TokenTTL:           format1.DefaultTokenTTL,
		CORSAllowAll:       true, // P1 默认放开；管理面板上线后按站点白名单
		RateLimitPerWindow: 30,   // capd 默认：30 次 / 5 秒
		RateLimitWindowMs:  5000,
	}, nil
}

// CORSAllowed 判断 Origin 是否被该站点允许。
func (s *Site) CORSAllowed(origin string) bool {
	if origin == "" {
		return true // 非浏览器请求（无 Origin 头）不参与 CORS
	}
	if s.CORSAllowAll {
		return true
	}
	for _, o := range s.CORSOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// SiteResolver 把 slug 解析为站点策略。
type SiteResolver interface {
	// Resolve 返回站点；未知/禁用站点返回 false。
	Resolve(slug string) (*Site, bool)
}

// StaticResolver 是 P1 的单站点解析器（环境变量装配）。
type StaticResolver struct{ Site *Site }

func (r *StaticResolver) Resolve(slug string) (*Site, bool) {
	if r.Site != nil && r.Site.Enabled && r.Site.Slug == slug {
		return r.Site, true
	}
	return nil, false
}
