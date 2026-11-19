package sqlite

import (
	"path/filepath"
	"testing"

	"capgo/internal/store/model"
)

func openTestDB(t *testing.T) (*SiteRepo, *SecretRepo, *SessionRepo, *EventRepo, *SettingsRepo, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capgo-test.sqlite3")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSiteRepo(db), NewSecretRepo(db), NewSessionRepo(db),
		NewEventRepo(db), NewSettingsRepo(db), func() {}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.sqlite3")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	// 二次打开应跳过已应用迁移
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var v int
	if err := db2.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil || v < 1 {
		t.Fatalf("迁移记录异常：v=%d err=%v", v, err)
	}
}

func TestSiteCRUD(t *testing.T) {
	sites, _, _, _, _, _ := openTestDB(t)

	m := &model.Site{
		Slug: "twikoo", Name: "博客评论", Enabled: true,
		ChallengeCount: 50, ChallengeSize: 32, ChallengeDifficulty: 4,
		ChallengeTTL: 600000, TokenTTL: 1200000,
		CORSAllowAll: false, CORSOrigins: []string{"https://a.example.com", "https://b.example.com"},
		RateLimitPerWindow: 30, RateLimitWindowMs: 5000,
	}
	if err := sites.Create(m); err != nil {
		t.Fatal(err)
	}
	if m.ID == 0 {
		t.Fatal("ID 未回填")
	}

	got, err := sites.GetBySlug("twikoo")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "博客评论" || got.Enabled != true || got.CORSAllowAll != false {
		t.Errorf("读回不一致：%+v", got)
	}
	if len(got.CORSOrigins) != 2 || got.CORSOrigins[0] != "https://a.example.com" {
		t.Errorf("CORS 白名单不一致：%v", got.CORSOrigins)
	}

	// 更新
	got.Name = "新名字"
	got.Enabled = false
	if err := sites.Update(got); err != nil {
		t.Fatal(err)
	}
	got2, _ := sites.GetBySlug("twikoo")
	if got2.Name != "新名字" || got2.Enabled {
		t.Errorf("更新不一致：%+v", got2)
	}
	if got2.UpdatedAt < got2.CreatedAt {
		t.Error("updatedAt 应推进")
	}

	// 重复 slug 拒绝
	if err := sites.Create(&model.Site{Slug: "twikoo"}); err == nil {
		t.Error("重复 slug 应失败")
	}

	// 软删除：GetBySlug 消失、GetBySlugAny 仍在、List 不含
	if err := sites.SoftDelete("twikoo"); err != nil {
		t.Fatal(err)
	}
	if _, err := sites.GetBySlug("twikoo"); err == nil {
		t.Error("软删除后 GetBySlug 应失败")
	}
	if _, err := sites.GetBySlugAny("twikoo"); err != nil {
		t.Errorf("软删除后 GetBySlugAny 应仍在：%v", err)
	}
	// 重建同名 slug 被拒（软删除占位）
	if err := sites.Create(&model.Site{Slug: "twikoo"}); err == nil {
		t.Error("软删除占位下重建同 slug 应失败")
	}
}

func TestSecrets(t *testing.T) {
	sites, secrets, _, _, _, _ := openTestDB(t)
	m := &model.Site{Slug: "s", Enabled: true}
	if err := sites.Create(m); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: model.FieldSiteVerify, Ciphertext: "blob1", SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := secrets.Get(m.ID, model.FieldSiteVerify)
	if err != nil || got.Ciphertext != "blob1" {
		t.Fatalf("读回不一致：%+v err=%v", got, err)
	}
	// 覆盖
	if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: model.FieldSiteVerify, Ciphertext: "blob2", SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	got, _ = secrets.Get(m.ID, model.FieldSiteVerify)
	if got.Ciphertext != "blob2" {
		t.Error("覆盖失败")
	}
	// 第二字段独立
	if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: model.FieldSigning, Ciphertext: "sign", SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	got, _ = secrets.Get(m.ID, model.FieldSigning)
	if got.Ciphertext != "sign" {
		t.Error("signing 字段失败")
	}
	if has, _ := secrets.HasAnySecrets(); !has {
		t.Error("HasAnySecrets 应为 true")
	}
	all, err := secrets.All()
	if err != nil || len(all) != 2 {
		t.Errorf("All 应返回 2 条：%v err=%v", len(all), err)
	}
}

func TestSessions(t *testing.T) {
	_, _, sessions, _, _, _ := openTestDB(t)
	now := int64(1000)
	if err := sessions.Create("hash-a", now, now+60000); err != nil {
		t.Fatal(err)
	}
	if ok, _ := sessions.Valid("hash-a", now+59999); !ok {
		t.Error("未过期应有效")
	}
	if ok, _ := sessions.Valid("hash-a", now+60001); ok {
		t.Error("过期应无效")
	}
	if ok, _ := sessions.Valid("hash-b", now); ok {
		t.Error("未知哈希应无效")
	}
	if err := sessions.Revoke("hash-a"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := sessions.Valid("hash-a", now+1); ok {
		t.Error("撤销后应无效")
	}
	// 过期清理：撤销/过期的行在一天后被清
	if n, err := sessions.DeleteExpired(now + 25*60*60*1000); err != nil || n == 0 {
		t.Errorf("清理应有产出：n=%d err=%v", n, err)
	}
}

func TestEvents(t *testing.T) {
	_, _, _, events, _, _ := openTestDB(t)
	base := int64(1_700_000_000_000) // 固定基准，避免依赖当前时间
	dur := int64(42)
	for i := 0; i < 10; i++ {
		e := &model.Event{
			Ts: base + int64(i*1000), SiteSlug: "twikoo", Type: "redeem",
			Outcome: "pass", Protocol: "format1", IPDigest: "d1", TokenID: "t",
			DurMs: &dur, Meta: `{"k":"v"}`,
		}
		if err := events.Insert(e); err != nil {
			t.Fatal(err)
		}
	}
	// 失败样本
	if err := events.Insert(&model.Event{Ts: base + 11000, SiteSlug: "twikoo", Type: "redeem", Outcome: "fail", Reason: "invalid_solution", Protocol: "format1"}); err != nil {
		t.Fatal(err)
	}
	if err := events.Insert(&model.Event{Ts: base + 12000, SiteSlug: "twikoo", Type: "challenge", Outcome: "limit", Reason: "rate_limited", Protocol: "format1"}); err != nil {
		t.Fatal(err)
	}

	list, err := events.List(EventFilter{Site: "twikoo", Type: "redeem", Limit: 5})
	if err != nil || len(list) != 5 {
		t.Fatalf("List：%d err=%v", len(list), err)
	}
	if list[0].Ts < list[4].Ts {
		t.Error("应按 ts 倒序")
	}
	list, _ = events.List(EventFilter{Type: "challenge"})
	if len(list) != 1 || list[0].Outcome != "limit" {
		t.Errorf("type 过滤：%+v", list)
	}
	list, _ = events.List(EventFilter{Since: base + 11000, Limit: 100})
	if len(list) != 2 {
		t.Errorf("since 过滤：%d", len(list))
	}

	stats, err := events.DailyStats(base+12000, 1, "redeem")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Count != 11 || stats[0].Pass != 10 || stats[0].Fail != 1 {
		t.Errorf("聚合不一致：%+v", stats)
	}
	reasons, err := events.TopReasons("redeem", base+12000, 1, 10)
	if err != nil || reasons["invalid_solution"] != 1 {
		t.Errorf("TopReasons：%v err=%v", reasons, err)
	}

	// 保留期清理：以 31 天后的 now 视角，所有 base 时间的事件都超过 30 天保留期
	dayMs := int64(24 * 60 * 60 * 1000)
	if n, err := events.DeleteOlderThan(base+31*dayMs, 30); err != nil || n != 12 {
		t.Errorf("应清理全部 12 条：n=%d err=%v", n, err)
	}
	if n, _ := events.Count(); n != 0 {
		t.Errorf("清理后应剩 0：%d", n)
	}
}

func TestSettings(t *testing.T) {
	_, _, _, _, settings, _ := openTestDB(t)
	if _, ok, _ := settings.Get("k"); ok {
		t.Fatal("初始应为空")
	}
	if err := settings.Put("k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := settings.Put("k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := settings.Get("k"); !ok || v != "v2" {
		t.Errorf("upsert 失败：%q %v", v, ok)
	}
}
