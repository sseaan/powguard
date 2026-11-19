package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/sseaan/powguard/internal/security/secretbox"
	"github.com/sseaan/powguard/internal/store/model"
)

func newMasterBox(t *testing.T, fill byte) *secretbox.Box {
	t.Helper()
	box, err := secretbox.New([]byte{
		fill, fill, fill, fill, fill, fill, fill, fill,
		fill, fill, fill, fill, fill, fill, fill, fill,
		fill, fill, fill, fill, fill, fill, fill, fill,
		fill, fill, fill, fill, fill, fill, fill, fill,
	})
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// seedEncryptedSite 建站点并写入加密的 siteverify + signing 密钥。
func seedEncryptedSite(t *testing.T, sites *SiteRepo, secrets *SecretRepo, box *secretbox.Box, slug string) int64 {
	t.Helper()
	m := &model.Site{
		Slug: slug, Protocol: "format1", Enabled: true,
		ChallengeCount: 4, ChallengeSize: 16, ChallengeDifficulty: 3,
		ChallengeTTL: 600000, TokenTTL: 1200000,
		CORSAllowAll: true, RateLimitPerWindow: 30, RateLimitWindowMs: 5000,
	}
	if err := sites.Create(m); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{model.FieldSiteVerify, model.FieldSigning} {
		ct, err := box.Seal([]byte("plain-"+slug+"-"+field), slug, field)
		if err != nil {
			t.Fatal(err)
		}
		if err := secrets.Put(&model.SiteSecret{SiteID: m.ID, Field: field, Ciphertext: ct, SchemaVersion: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return m.ID
}

func TestBackupAndRestore(t *testing.T) {
	sites, secrets, _, events, _, _ := openTestDB(t)
	box := newMasterBox(t, 0x11)
	seedEncryptedSite(t, sites, secrets, box, "twikoo")

	// 备份到临时文件
	dir := t.TempDir()
	dst := filepath.Join(dir, "powguard-backup.sqlite3")
	db := r2db(sites)
	if err := Backup(db, dst); err != nil {
		t.Fatalf("Backup：%v", err)
	}
	if st, err := os.Stat(dst); err != nil || st.Size() == 0 {
		t.Fatalf("备份文件无效：%v", err)
	}

	// 目标已存在时应拒绝覆盖
	if err := Backup(db, dst); err == nil {
		t.Error("已存在的目标应拒绝")
	}

	// 从备份打开：站点、密文、可解密
	restored, err := Open(dst)
	if err != nil {
		t.Fatalf("打开备份：%v", err)
	}
	defer restored.Close()
	rs := NewSiteRepo(restored)
	rsSecret := NewSecretRepo(restored)
	site, err := rs.GetBySlug("twikoo")
	if err != nil {
		t.Fatalf("备份中缺站点：%v", err)
	}
	sec, err := rsSecret.Get(site.ID, model.FieldSiteVerify)
	if err != nil {
		t.Fatalf("备份中缺密文：%v", err)
	}
	plain, err := box.Open(sec.Ciphertext, site.Slug, model.FieldSiteVerify)
	if err != nil || string(plain) != "plain-twikoo-siteverify" {
		t.Fatalf("备份中的密文不可解：%v %q", err, plain)
	}
	// 备份是独立副本：原库继续写入不影响备份
	if err := events.Insert(&model.Event{SiteSlug: "twikoo", Type: "challenge", Outcome: "pass"}); err != nil {
		t.Fatal(err)
	}
	rev := NewEventRepo(restored)
	if n, _ := rev.Count(); n != 0 {
		t.Errorf("备份不应包含后续写入：%d", n)
	}
}

// r2db 取回 SiteRepo 持有的 *sql.DB（测试辅助）。
func r2db(r *SiteRepo) *sql.DB { return r.db }

func TestRotateMasterKey(t *testing.T) {
	sites, secrets, _, _, _, _ := openTestDB(t)
	oldBox := newMasterBox(t, 0x22)
	newBox := newMasterBox(t, 0x33)
	seedEncryptedSite(t, sites, secrets, oldBox, "site-a")
	seedEncryptedSite(t, sites, secrets, oldBox, "site-b")

	db := r2db(sites)
	res, err := RotateMasterKey(db, oldBox, newBox)
	if err != nil {
		t.Fatalf("RotateMasterKey：%v", err)
	}
	if res.Sites != 2 || res.Secrets != 4 {
		t.Errorf("轮换统计：%+v", res)
	}

	// 新 key 可解，旧 key 不可解
	if err := VerifyAllSecrets(db, newBox); err != nil {
		t.Errorf("新 key 校验失败：%v", err)
	}
	if err := VerifyAllSecrets(db, oldBox); err == nil {
		t.Error("旧 key 不应还能解密")
	}
}

func TestRotateMasterKeyWrongOldKey(t *testing.T) {
	sites, secrets, _, _, _, _ := openTestDB(t)
	realBox := newMasterBox(t, 0x44)
	wrongBox := newMasterBox(t, 0x55)
	newBox := newMasterBox(t, 0x66)
	seedEncryptedSite(t, sites, secrets, realBox, "site")

	db := r2db(sites)
	if _, err := RotateMasterKey(db, wrongBox, newBox); err == nil {
		t.Fatal("错误旧 key 应失败")
	}
	// 失败后数据未被破坏：真实旧 key 仍可解
	if err := VerifyAllSecrets(db, realBox); err != nil {
		t.Errorf("失败回滚后旧 key 应仍可用：%v", err)
	}
}

func TestVerifyAllSecretsEmpty(t *testing.T) {
	sites, _, _, _, _, _ := openTestDB(t)
	if err := VerifyAllSecrets(r2db(sites), newMasterBox(t, 0x77)); err != nil {
		t.Errorf("空库校验应通过：%v", err)
	}
}
