// Package secretbox 用 POWGUARD_MASTER_KEY 派生的 AES-256-GCM 加密站点 secret。
//
// 密文布局与 capjs-core 的 GCM blob 一致：base64url(nonce[12] ‖ tag[16] ‖ ct)。
// 每条密文绑定 AAD = "powguard:secret:v1|" + siteSlug + "|" + field + "|" + schemaVersion，
// 防止跨字段/跨站点/跨版本的密文挪用。master key 丢失即无法恢复（PLAN.md §6.2）。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// AADSchema 是当前密文格式版本；升级格式时递增并把旧密文迁移。
	AADSchema = 1
	aadPrefix = "powguard:secret"
)

var b64 = base64.RawURLEncoding

var (
	ErrBadKey    = errors.New("secretbox: master key 必须是 32 字节")
	ErrCorrupted = errors.New("secretbox: 密文损坏或 AAD 不匹配")
)

// Box 持有派生后的加密能力。
type Box struct{ key []byte }

// New 从 32 字节 master key 构造。
func New(masterKey []byte) (*Box, error) {
	if len(masterKey) != 32 {
		return nil, ErrBadKey
	}
	return &Box{key: append([]byte(nil), masterKey...)}, nil
}

// DeriveIPDigestKey 从 master key 派生事件 IP 摘要密钥（HMAC，PLAN.md §6.3：
// 事件中保存 keyed digest，不保存明文 IP）。
func (b *Box) DeriveIPDigestKey() []byte {
	return b.derive("ip-digest")
}

// DeriveCSRFKey 从 master key 派生 CSRF 签名密钥。
func (b *Box) DeriveCSRFKey() []byte {
	return b.derive("csrf")
}

func (b *Box) derive(purpose string) []byte {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(aadPrefix + ":derive:" + purpose))
	return m.Sum(nil)
}

func aad(siteSlug, field string, schemaVersion int) []byte {
	return []byte(fmt.Sprintf("%s:v%d|%s|%s|%d", aadPrefix, AADSchema, siteSlug, field, schemaVersion))
}

// Seal 加密 plaintext，输出 base64url(nonce ‖ tag ‖ ct)。
func (b *Box) Seal(plaintext []byte, siteSlug, field string) (string, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, aad(siteSlug, field, AADSchema))
	return b64.EncodeToString(sealed), nil
}

// Open 解密 Seal 的产物；slug/field/schema 任一不匹配都会失败。
func (b *Box) Open(blob, siteSlug, field string) ([]byte, error) {
	raw, err := b64.DecodeString(blob)
	if err != nil || len(raw) < 12+16 {
		return nil, ErrCorrupted
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, sealed := raw[:12], raw[12:]
	plaintext, err := gcm.Open(nil, nonce, sealed, aad(siteSlug, field, AADSchema))
	if err != nil {
		return nil, ErrCorrupted
	}
	return plaintext, nil
}

// Reencrypt 用新 master key 重新加密（master key 轮换演练，PLAN.md §9）。
func Reencrypt(oldBox, newBox *Box, blob, siteSlug, field string) (string, error) {
	plaintext, err := oldBox.Open(blob, siteSlug, field)
	if err != nil {
		return "", err
	}
	return newBox.Seal(plaintext, siteSlug, field)
}
