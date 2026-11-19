package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"capgo/internal/store/model"
)

var ErrNotFound = errors.New("sqlite: record not found")

// SiteRepo 管理站点行。
type SiteRepo struct{ db *sql.DB }

func NewSiteRepo(db *sql.DB) *SiteRepo { return &SiteRepo{db: db} }

const siteColumns = `id, slug, protocol, name, enabled, deleted, challenge_count, challenge_size,
	challenge_difficulty, challenge_ttl_ms, token_ttl_ms, cors_allow_all, cors_origins,
	rate_limit_per_window, rate_limit_window_ms, created_at, updated_at`

func scanSite(row interface{ Scan(...any) error }) (*model.Site, error) {
	s := &model.Site{}
	var enabled, deleted, allowAll int
	var origins string
	err := row.Scan(&s.ID, &s.Slug, &s.Protocol, &s.Name, &enabled, &deleted,
		&s.ChallengeCount, &s.ChallengeSize, &s.ChallengeDifficulty,
		&s.ChallengeTTL, &s.TokenTTL, &allowAll, &origins,
		&s.RateLimitPerWindow, &s.RateLimitWindowMs, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.Enabled = enabled == 1
	s.Deleted = deleted == 1
	s.CORSAllowAll = allowAll == 1
	s.CORSOrigins = splitOrigins(origins)
	return s, nil
}

// Create 插入站点。
func (r *SiteRepo) Create(s *model.Site) error {
	now := model.NowMs()
	if s.CreatedAt == 0 {
		s.CreatedAt = now
	}
	s.UpdatedAt = now
	res, err := r.db.Exec(`INSERT INTO sites (slug, protocol, name, enabled, challenge_count,
		challenge_size, challenge_difficulty, challenge_ttl_ms, token_ttl_ms,
		cors_allow_all, cors_origins, rate_limit_per_window, rate_limit_window_ms, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.Slug, model.ProtocolOrDefault(s.Protocol), s.Name, b2i(s.Enabled), s.ChallengeCount, s.ChallengeSize,
		s.ChallengeDifficulty, s.ChallengeTTL, s.TokenTTL, b2i(s.CORSAllowAll), joinOrigins(s.CORSOrigins),
		s.RateLimitPerWindow, s.RateLimitWindowMs, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("sqlite: create site %s: %w", s.Slug, err)
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

// GetBySlug 返回未软删除的站点。
func (r *SiteRepo) GetBySlug(slug string) (*model.Site, error) {
	row := r.db.QueryRow(`SELECT `+siteColumns+` FROM sites WHERE slug = ? AND deleted = 0`, slug)
	return scanSite(row)
}

// GetBySlugAny 返回任意（含软删除）站点。
func (r *SiteRepo) GetBySlugAny(slug string) (*model.Site, error) {
	row := r.db.QueryRow(`SELECT `+siteColumns+` FROM sites WHERE slug = ?`, slug)
	return scanSite(row)
}

// List 返回未软删除的站点。
func (r *SiteRepo) List() ([]*model.Site, error) {
	rows, err := r.db.Query(`SELECT ` + siteColumns + ` FROM sites WHERE deleted = 0 ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Site
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Update 保存策略字段的修改。
func (r *SiteRepo) Update(s *model.Site) error {
	s.UpdatedAt = model.NowMs()
	res, err := r.db.Exec(`UPDATE sites SET protocol=?, name=?, enabled=?,
		challenge_count=?, challenge_size=?, challenge_difficulty=?,
		challenge_ttl_ms=?, token_ttl_ms=?, cors_allow_all=?, cors_origins=?,
		rate_limit_per_window=?, rate_limit_window_ms=?, updated_at=?
		WHERE id=? AND deleted=0`,
		model.ProtocolOrDefault(s.Protocol), s.Name, b2i(s.Enabled), s.ChallengeCount, s.ChallengeSize, s.ChallengeDifficulty,
		s.ChallengeTTL, s.TokenTTL, b2i(s.CORSAllowAll), joinOrigins(s.CORSOrigins),
		s.RateLimitPerWindow, s.RateLimitWindowMs, s.UpdatedAt, s.ID)
	if err != nil {
		return fmt.Errorf("sqlite: update site %d: %w", s.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete 软删除站点（保留事件审计上下文）。
func (r *SiteRepo) SoftDelete(slug string) error {
	res, err := r.db.Exec(`UPDATE sites SET deleted=1, enabled=0, updated_at=? WHERE slug=? AND deleted=0`,
		model.NowMs(), slug)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Count 返回未软删除站点数（启动 bootstrap 判定用）。
func (r *SiteRepo) Count() (int, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM sites WHERE deleted = 0`).Scan(&n)
	return n, err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func joinOrigins(origins []string) string {
	return strings.Join(origins, ",")
}

func splitOrigins(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------- secrets

// SecretRepo 管理加密后的站点密钥。
type SecretRepo struct{ db *sql.DB }

func NewSecretRepo(db *sql.DB) *SecretRepo { return &SecretRepo{db: db} }

// Put 写入（覆盖）一条密文。
func (r *SecretRepo) Put(sec *model.SiteSecret) error {
	if sec.RotatedAt == 0 {
		sec.RotatedAt = model.NowMs()
	}
	_, err := r.db.Exec(`INSERT INTO site_secrets (site_id, field, ciphertext, schema_version, rotated_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(site_id, field) DO UPDATE SET
			ciphertext=excluded.ciphertext, schema_version=excluded.schema_version, rotated_at=excluded.rotated_at`,
		sec.SiteID, sec.Field, sec.Ciphertext, sec.SchemaVersion, sec.RotatedAt)
	if err != nil {
		return fmt.Errorf("sqlite: put secret site=%d field=%s: %w", sec.SiteID, sec.Field, err)
	}
	return nil
}

// Get 读取密文行。
func (r *SecretRepo) Get(siteID int64, field string) (*model.SiteSecret, error) {
	sec := &model.SiteSecret{}
	err := r.db.QueryRow(`SELECT site_id, field, ciphertext, schema_version, rotated_at
		FROM site_secrets WHERE site_id=? AND field=?`, siteID, field).
		Scan(&sec.SiteID, &sec.Field, &sec.Ciphertext, &sec.SchemaVersion, &sec.RotatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return sec, nil
}

// HasAnySecrets 判断库中是否已有密文（master key 缺失时的启动保护）。
func (r *SecretRepo) HasAnySecrets() (bool, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM site_secrets`).Scan(&n)
	return n > 0, err
}

// All 以 (site_id, field) 遍历全部密文（master key re-encrypt 演练用）。
func (r *SecretRepo) All() ([]*model.SiteSecret, error) {
	rows, err := r.db.Query(`SELECT site_id, field, ciphertext, schema_version, rotated_at FROM site_secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.SiteSecret
	for rows.Next() {
		sec := &model.SiteSecret{}
		if err := rows.Scan(&sec.SiteID, &sec.Field, &sec.Ciphertext, &sec.SchemaVersion, &sec.RotatedAt); err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- sessions

// SessionRepo 管理管理面板会话（只存 token 哈希）。
type SessionRepo struct{ db *sql.DB }

func NewSessionRepo(db *sql.DB) *SessionRepo { return &SessionRepo{db: db} }

func (r *SessionRepo) Create(tokenHash string, nowMs, expiresAt int64) error {
	_, err := r.db.Exec(`INSERT INTO admin_sessions (token_hash, created_at, expires_at) VALUES (?,?,?)`,
		tokenHash, nowMs, expiresAt)
	return err
}

// Valid 校验 token 哈希是否对应未撤销未过期会话。
func (r *SessionRepo) Valid(tokenHash string, nowMs int64) (bool, error) {
	ok, _, err := r.ValidWithExpiry(tokenHash, nowMs)
	return ok, err
}

// ValidWithExpiry 返回会话是否有效及其过期毫秒。
func (r *SessionRepo) ValidWithExpiry(tokenHash string, nowMs int64) (bool, int64, error) {
	var revoked int
	var expires int64
	err := r.db.QueryRow(`SELECT revoked, expires_at FROM admin_sessions WHERE token_hash=?`, tokenHash).
		Scan(&revoked, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, 0, nil
		}
		return false, 0, err
	}
	ok := revoked == 0 && expires > nowMs
	return ok, expires, nil
}

// Revoke 撤销会话。
func (r *SessionRepo) Revoke(tokenHash string) error {
	_, err := r.db.Exec(`UPDATE admin_sessions SET revoked=1 WHERE token_hash=?`, tokenHash)
	return err
}

// DeleteExpired 清理过期/撤销会话。
func (r *SessionRepo) DeleteExpired(nowMs int64) (int64, error) {
	res, err := r.db.Exec(`DELETE FROM admin_sessions WHERE expires_at < ? OR revoked = 1`, nowMs-24*60*60*1000)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- settings

// SettingsRepo 是实例级键值设置。
type SettingsRepo struct{ db *sql.DB }

func NewSettingsRepo(db *sql.DB) *SettingsRepo { return &SettingsRepo{db: db} }

func (r *SettingsRepo) Get(key string) (string, bool, error) {
	var v string
	err := r.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

func (r *SettingsRepo) Put(key, value string) error {
	_, err := r.db.Exec(`INSERT INTO settings (key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
