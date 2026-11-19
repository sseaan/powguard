// Package session 管理管理面板会话：随机不透明 token、只落库其 sha256 哈希、
// 过期与撤销（PLAN.md §6.3）。Cookie 由 API 层装配（HttpOnly/Secure/SameSite=Lax）。
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"capgo/internal/store/sqlite"
)

// DefaultTTL 是会话有效期（12 小时）。
const DefaultTTL int64 = 12 * 60 * 60 * 1000

// Manager 创建/校验/撤销会话。
type Manager struct {
	repo *sqlite.SessionRepo
	ttl  int64
}

func NewManager(repo *sqlite.SessionRepo, ttlMs int64) *Manager {
	if ttlMs <= 0 {
		ttlMs = DefaultTTL
	}
	return &Manager{repo: repo, ttl: ttlMs}
}

// Hash 返回 token 的存储形态（sha256 hex）。
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Create 签发一个新会话，返回不透明 token 与过期毫秒。
func (m *Manager) Create(nowMs int64) (token string, expiresAt int64, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", 0, err
	}
	token = hex.EncodeToString(buf)
	expiresAt = nowMs + m.ttl
	if err = m.repo.Create(Hash(token), nowMs, expiresAt); err != nil {
		return "", 0, err
	}
	return token, expiresAt, nil
}

// Valid 校验 token，有效时返回过期毫秒。
func (m *Manager) Valid(token string, nowMs int64) (bool, int64, error) {
	if token == "" {
		return false, 0, nil
	}
	return m.repo.ValidWithExpiry(Hash(token), nowMs)
}

// Revoke 撤销会话。
func (m *Manager) Revoke(token string) error {
	return m.repo.Revoke(Hash(token))
}

// Cleanup 清理过期/撤销超过一天的会话。
func (m *Manager) Cleanup(nowMs int64) (int64, error) {
	return m.repo.DeleteExpired(nowMs)
}
