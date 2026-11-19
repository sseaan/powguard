package policy

import (
	"path/filepath"
	"testing"
	"time"

	"capgo/internal/security/secretbox"
	"capgo/internal/store/model"
	"capgo/internal/store/sqlite"
)

func newResolver(t *testing.T) (*DBResolver, *sqlite.SiteRepo, *sqlite.SecretRepo, *secretbox.Box) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r.sqlite3")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, err := secretbox.New([]byte("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"))
	if err != nil {
		t.Fatal(err)
	}
	return NewDBResolver(sqlite.NewSiteRepo(db), sqlite.NewSecretRepo(db), box),
		sqlite.NewSiteRepo(db), sqlite.NewSecretRepo(db), box
}

func seedSite(t *testing.T, sites *sqlite.SiteRepo, secrets *sqlite.SecretRepo, box *secretbox.Box, slug, secret string) *model.Site {
	t.Helper()
	m := &model.Site{
		Slug: slug, Name: slug, Enabled: true,
		ChallengeCount: 4, ChallengeSize: 16, ChallengeDifficulty: 3,
		ChallengeTTL: 600000, TokenTTL: 1200000,
		CORSAllowAll: false, CORSOrigins: []string{"https://blog.example.com"},
		RateLimitPerWindow: 7, RateLimitWindowMs: 5000,
	}
	if err := sites.Create(m); err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		ct, err := box.Seal([]byte(secret), slug, model.FieldSiteVerify)
		if err != nil {
			t.Fatal(err)
		}
		if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: model.FieldSiteVerify, Ciphertext: ct, SchemaVersion: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestResolveDecryptsSecret(t *testing.T) {
	r, sites, secrets, box := newResolver(t)
	seedSite(t, sites, secrets, box, "twikoo", "the-site-secret")

	site, ok := r.Resolve("twikoo")
	if !ok {
		t.Fatal("站点应可解析")
	}
	if site.Secret != "the-site-secret" {
		t.Fatalf("secret 解密失败：%q", site.Secret)
	}
	if site.Challenge.Count != 4 || site.RateLimitPerWindow != 7 {
		t.Errorf("策略字段不一致：%+v", site)
	}
	if !site.CORSAllowed("https://blog.example.com") || site.CORSAllowed("https://evil.example.net") {
		t.Error("CORS 白名单语义错误")
	}

	// 未知/禁用站点
	if _, ok := r.Resolve("nosuch"); ok {
		t.Error("未知站点应失败")
	}
}

func TestResolveDisabled(t *testing.T) {
	r, sites, secrets, box := newResolver(t)
	m := seedSite(t, sites, secrets, box, "off", "s")
	m.Enabled = false
	if err := sites.Update(m); err != nil {
		t.Fatal(err)
	}
	// 缓存里的旧条目仍会命中 —— Invalidate 后应消失
	r.Invalidate("off")
	if _, ok := r.Resolve("off"); ok {
		t.Error("禁用站点 Resolve 应返回 false")
	}
}

func TestResolveCachingAndInvalidate(t *testing.T) {
	r, sites, secrets, box := newResolver(t)
	m := seedSite(t, sites, secrets, box, "cache", "v1")

	if _, ok := r.Resolve("cache"); !ok {
		t.Fatal("初始解析失败")
	}
	// 密钥更换但不失效缓存 → 仍读到 v1
	v2, err := box.Seal([]byte("v2"), "cache", model.FieldSiteVerify)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: model.FieldSiteVerify, Ciphertext: v2, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if site, _ := r.Resolve("cache"); site.Secret != "v1" {
		t.Errorf("TTL 内应命中缓存：%q", site.Secret)
	}
	// Invalidate 后读到新密文
	r.Invalidate("cache")
	if site, _ := r.Resolve("cache"); site.Secret != "v2" {
		t.Errorf("失效后应读到新值：%q", site.Secret)
	}
}

func TestResolveMissingSecret(t *testing.T) {
	r, sites, secrets, box := newResolver(t)
	seedSite(t, sites, secrets, box, "nosecret", "")

	site, ok := r.Resolve("nosecret")
	if !ok {
		t.Fatal("站点应可解析")
	}
	if site.Secret != "" {
		t.Fatalf("无密钥应保持空：%q", site.Secret)
	}
}

func TestResolveCacheTTL(t *testing.T) {
	r, sites, secrets, box := newResolver(t)
	seedSite(t, sites, secrets, box, "ttl", "x")
	if _, ok := r.Resolve("ttl"); !ok {
		t.Fatal("解析失败")
	}
	// 强制缓存条目过期（不 sleep 5s：直接改内部 at）
	r.mu.Lock()
	if e, hit := r.cache["ttl"]; hit {
		e.at = time.Now().Add(-ResolveCacheTTL - time.Second)
		r.cache["ttl"] = e
	}
	r.mu.Unlock()
	m, _ := sites.GetBySlug("ttl")
	m.Name = "renamed"
	if err := sites.Update(m); err != nil {
		t.Fatal(err)
	}
	site, _ := r.Resolve("ttl")
	if site == nil || site.Name != "renamed" {
		t.Errorf("过期缓存应重新加载：%+v", site)
	}
}
