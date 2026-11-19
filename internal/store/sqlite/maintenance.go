package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"capgo/internal/security/secretbox"
	"capgo/internal/store/model"
)

// Backup 用 VACUUM INTO 生成一致性快照（WAL 下安全，不需要停止服务）。
// 目标文件必须不存在；返回后可用 Restore 恢复到新位置。
func Backup(db *sql.DB, destPath string) error {
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("sqlite: 备份目标已存在：%s", destPath)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return fmt.Errorf("sqlite: 创建备份目录：%w", err)
	}
	// VACUUM INTO 不接受参数化路径以外的东西；用单引号转义防御畸形路径
	quoted := "'" + escapeSQLString(destPath) + "'"
	if _, err := db.Exec("VACUUM INTO " + quoted); err != nil {
		return fmt.Errorf("sqlite: VACUUM INTO 失败：%w", err)
	}
	return nil
}

func escapeSQLString(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// RotationResult 描述 master key 轮换结果。
type RotationResult struct {
	Sites   int // 处理的站点数
	Secrets int // 重新加密的密文条数
}

// RotateMasterKey 用新 key 重新加密全部站点密钥（secretbox.Reencrypt）。
// 全程在单事务内完成：任一条失败则整体回滚，不会留下半新半旧的状态。
//
// 使用流程（部署文档 deploy/README.md）：
//  1. capgo keyrotate --old ... --new ...（本函数）
//  2. 更新 systemd EnvironmentFile 中的 CAPGO_MASTER_KEY
//  3. 重启服务
//  4. 用新 key 验证 reveal 成功
func RotateMasterKey(db *sql.DB, oldBox, newBox *secretbox.Box) (RotationResult, error) {
	var res RotationResult
	secrets := NewSecretRepo(db)
	sites := NewSiteRepo(db)

	all, err := secrets.All()
	if err != nil {
		return res, err
	}

	tx, err := db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	touched := map[int64]bool{}
	for _, sec := range all {
		site, err := sites.GetByIDTx(tx, sec.SiteID)
		if err != nil {
			return res, fmt.Errorf("sqlite: 读取站点 %d：%w", sec.SiteID, err)
		}
		plaintext, err := oldBox.Open(sec.Ciphertext, site.Slug, sec.Field)
		if err != nil {
			return res, fmt.Errorf("sqlite: 站点 %s 字段 %s 无法用旧 key 解密（旧 key 错误或数据损坏）", site.Slug, sec.Field)
		}
		newCT, err := newBox.Seal(plaintext, site.Slug, sec.Field)
		if err != nil {
			return res, err
		}
		if _, err := tx.Exec(`UPDATE site_secrets SET ciphertext=?, rotated_at=? WHERE site_id=? AND field=?`,
			newCT, model.NowMs(), sec.SiteID, sec.Field); err != nil {
			return res, err
		}
		touched[sec.SiteID] = true
		res.Secrets++
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	res.Sites = len(touched)
	return res, nil
}

// GetByIDTx 在事务内按 ID 读取站点（轮换用；含软删除站点以覆盖全部密文）。
func (r *SiteRepo) GetByIDTx(tx *sql.Tx, id int64) (*model.Site, error) {
	row := tx.QueryRow(`SELECT `+siteColumns+` FROM sites WHERE id = ?`, id)
	return scanSite(row)
}

// VerifyAllSecrets 用给定 key 校验库中全部密文都可解密（部署后的健康检查）。
func VerifyAllSecrets(db *sql.DB, box *secretbox.Box) error {
	secrets := NewSecretRepo(db)
	sites := NewSiteRepo(db)
	all, err := secrets.All()
	if err != nil {
		return err
	}
	for _, sec := range all {
		site, err := sites.GetByID(sec.SiteID)
		if err != nil {
			return fmt.Errorf("sqlite: 站点 %d 缺失：%w", sec.SiteID, err)
		}
		if _, err := box.Open(sec.Ciphertext, site.Slug, sec.Field); err != nil {
			return fmt.Errorf("sqlite: 站点 %s 字段 %s 无法解密：%w", site.Slug, sec.Field, err)
		}
	}
	return nil
}

// GetByID 按 ID 读取站点（含软删除）。
func (r *SiteRepo) GetByID(id int64) (*model.Site, error) {
	row := r.db.QueryRow(`SELECT `+siteColumns+` FROM sites WHERE id = ?`, id)
	return scanSite(row)
}
