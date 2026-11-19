// Package csrf 提供管理面板修改操作的 CSRF 防护。
//
// 方案：per-session 确定性 token = HMAC-SHA256(csrfKey, sessionTokenHash)。
// 服务端无需额外存储；token 绑定会话，随会话撤销即失效。
// csrfKey 从 master key 派生（secretbox.DeriveCSRFKey），重启后保持稳定。
package csrf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Token 生成绑定到会话哈希的 CSRF token（hex）。
func Token(csrfKey []byte, sessionTokenHash string) string {
	m := hmac.New(sha256.New, csrfKey)
	m.Write([]byte("powguard:csrf:v1|"))
	m.Write([]byte(sessionTokenHash))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify 常数时间校验客户端提交的 token。
func Verify(csrfKey []byte, sessionTokenHash, presented string) bool {
	if presented == "" {
		return false
	}
	want := Token(csrfKey, sessionTokenHash)
	return subtle.ConstantTimeCompare([]byte(want), []byte(presented)) == 1
}
