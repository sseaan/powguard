package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sseaan/powguard/internal/security/secretbox"
	"github.com/sseaan/powguard/internal/store/model"
	"github.com/sseaan/powguard/internal/store/sqlite"
)

// 验证运维子命令参数解析与 key 解析（不含进程级 os.Exit 路径）。
func TestParseFlags(t *testing.T) {
	f := parseFlags([]string{"--db", "/tmp/x.db", "--out", "/tmp/b.sqlite3"})
	if f["db"] != "/tmp/x.db" || f["out"] != "/tmp/b.sqlite3" {
		t.Fatalf("解析结果：%v", f)
	}
	if _, ok := need(f, "db", "out"); !ok {
		t.Error("必需参数应齐全")
	}
	if _, ok := need(f, "db", "missing"); ok {
		t.Error("缺参应失败")
	}
}

func TestBoxFromKeyFormats(t *testing.T) {
	hexKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	if _, err := boxFrom(hexKey); err != nil {
		t.Errorf("hex key 应接受：%v", err)
	}
	// base64（32 字节）
	b64Key := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	if _, err := boxFrom(b64Key); err != nil {
		t.Errorf("base64 key 应接受：%v", err)
	}
	if _, err := boxFrom("too-short"); err == nil {
		t.Error("短 key 应拒绝")
	}
	if _, err := boxFrom(""); err == nil {
		t.Error("空 key 应拒绝")
	}
}

// TestOpsRoundTrip 在真实 DB 上跑备份 → 校验 → 轮换 的完整运维链路。
func TestOpsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "powguard.sqlite3")
	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	oldBox, _ := secretbox.New(mustKey(0x11))
	newBox, _ := secretbox.New(mustKey(0x22))

	sites := sqlite.NewSiteRepo(db)
	secrets := sqlite.NewSecretRepo(db)
	m := &model.Site{
		Slug: "twikoo", Protocol: "format1", Enabled: true,
		ChallengeCount: 50, ChallengeSize: 32, ChallengeDifficulty: 4,
		ChallengeTTL: 600000, TokenTTL: 1200000,
		CORSAllowAll: true, RateLimitPerWindow: 30, RateLimitWindowMs: 5000,
	}
	if err := sites.Create(m); err != nil {
		t.Fatal(err)
	}
	ct, _ := oldBox.Seal([]byte("site-secret"), "twikoo", model.FieldSiteVerify)
	if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: model.FieldSiteVerify, Ciphertext: ct, SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}

	// backup
	backupPath := filepath.Join(dir, "backup.sqlite3")
	if err := sqlite.Backup(db, backupPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatal(err)
	}

	// 备份可用旧 key 校验
	bdb, err := sqlite.Open(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	if err := sqlite.VerifyAllSecrets(bdb, oldBox); err != nil {
		t.Errorf("备份应用旧 key 可解：%v", err)
	}

	// rotate
	res, err := sqlite.RotateMasterKey(db, oldBox, newBox)
	if err != nil {
		t.Fatal(err)
	}
	if res.Secrets != 1 {
		t.Errorf("轮换条数：%d", res.Secrets)
	}
	if err := sqlite.VerifyAllSecrets(db, newBox); err != nil {
		t.Errorf("轮换后新 key 应可解：%v", err)
	}
	// 明文不变
	sec, _ := secrets.Get(m.ID, model.FieldSiteVerify)
	plain, err := newBox.Open(sec.Ciphertext, "twikoo", model.FieldSiteVerify)
	if err != nil || string(plain) != "site-secret" {
		t.Fatalf("轮换后明文应不变：%v %q", err, plain)
	}
	db.Close()
}

func mustKey(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
