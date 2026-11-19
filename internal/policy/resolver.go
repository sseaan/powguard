package policy

import (
	"strings"
	"sync"
	"time"

	"capgo/internal/protocol/format1"
	"capgo/internal/security/secretbox"
	"capgo/internal/store/model"
	"capgo/internal/store/sqlite"
)

// ResolveCacheTTL 是站点解析缓存时长（对齐 capd KEY_CACHE_TTL=5s）。
const ResolveCacheTTL = 5 * time.Second

// DBResolver 用 SQLite 站点表解析策略（M2 起的生产实现）。
type DBResolver struct {
	sites   *sqlite.SiteRepo
	secrets *sqlite.SecretRepo
	box     *secretbox.Box

	mu    sync.RWMutex
	cache map[string]dbCacheEntry
}

type dbCacheEntry struct {
	site *Site
	at   time.Time
}

func NewDBResolver(sites *sqlite.SiteRepo, secrets *sqlite.SecretRepo, box *secretbox.Box) *DBResolver {
	return &DBResolver{
		sites:   sites,
		secrets: secrets,
		box:     box,
		cache:   make(map[string]dbCacheEntry),
	}
}

// Resolve 返回站点的运行时策略；未知/禁用/软删除站点返回 false。
func (r *DBResolver) Resolve(slug string) (*Site, bool) {
	r.mu.RLock()
	if e, ok := r.cache[slug]; ok && time.Since(e.at) < ResolveCacheTTL {
		r.mu.RUnlock()
		return e.site, e.site.Enabled
	}
	r.mu.RUnlock()

	m, err := r.sites.GetBySlug(slug)
	if err != nil || m == nil {
		return nil, false
	}
	site, ok := r.build(m)
	if !ok {
		return nil, false
	}

	r.mu.Lock()
	r.cache[slug] = dbCacheEntry{site: site, at: time.Now()}
	r.mu.Unlock()
	return site, site.Enabled
}

// build 把站点行 + 解密后的 siteverify secret 组装为运行时策略。
func (r *DBResolver) build(m *model.Site) (*Site, bool) {
	site := &Site{
		Slug:               m.Slug,
		Name:               m.Name,
		Enabled:            m.Enabled,
		Secret:             "", // 未配置密钥时保持空（siteverify 将拒绝所有请求）
		ChallengeTTL:       m.ChallengeTTL,
		TokenTTL:           m.TokenTTL,
		CORSAllowAll:       m.CORSAllowAll,
		CORSOrigins:        normalizeOrigins(m.CORSOrigins),
		RateLimitPerWindow: m.RateLimitPerWindow,
		RateLimitWindowMs:  m.RateLimitWindowMs,
	}
	site.Challenge = format1.ChallengeConfig{Count: m.ChallengeCount, Size: m.ChallengeSize, Difficulty: m.ChallengeDifficulty}

	if r.box != nil {
		if sec, err := r.secrets.Get(m.ID, model.FieldSiteVerify); err == nil && sec != nil {
			if plaintext, err := r.box.Open(sec.Ciphertext, m.Slug, model.FieldSiteVerify); err == nil {
				site.Secret = string(plaintext)
			}
			// 解密失败：保持空 secret。siteverify 只会拒绝，不放大错误。
		}
	}
	return site, true
}

// Invalidate 失效单站点缓存（admin 修改后调用）。
func (r *DBResolver) Invalidate(slug string) {
	r.mu.Lock()
	delete(r.cache, slug)
	r.mu.Unlock()
}

// InvalidateAll 失效全部缓存。
func (r *DBResolver) InvalidateAll() {
	r.mu.Lock()
	r.cache = make(map[string]dbCacheEntry)
	r.mu.Unlock()
}

func normalizeOrigins(origins []string) []string {
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}
