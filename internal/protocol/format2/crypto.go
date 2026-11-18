// format2 包内的 JWT(HS256) 与 AES-GCM 辅助，与 capjs-core@0.1.18
// src/crypto.js bit-exact。JSON 字段顺序无关紧要（官方 JSON.stringify，
// Go json.Marshal 字段排序不同 —— 仅在需要与官方逐字节一致的 token 上
// 由调用方直接传入已序列化的 JSON）。
package format2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

var b64url = base64.RawURLEncoding // JS base64url，无填充

// jwtHeaderB64 是官方固定的 JWT header：{"alg":"HS256","typ":"JWT"}。
// 硬编码逐字节对齐官方（不依赖 Go map 序列化顺序）。
var jwtHeaderB64 = b64url.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

func b64urlDecode(s string) ([]byte, error) { return b64url.DecodeString(s) }

// SignHS256 对已序列化的 payload JSON 签名，返回完整 JWT。
// payloadJSON 必须与官方 JSON.stringify 输出逐字节一致时 token 才逐字节一致
// （仅 fixture 对拍需要；运行时只要可 verify）。
func SignHS256(payloadJSON []byte, secret []byte) string {
	body := b64url.EncodeToString(payloadJSON)
	signing := jwtHeaderB64 + "." + body
	return signing + "." + b64url.EncodeToString(HMACSHA256(secret, []byte(signing)))
}

// VerifyHS256 校验 JWT 签名（常数时间），返回 payload JSON；任何格式错误都失败。
func VerifyHS256(token string, secret []byte) ([]byte, bool) {
	firstDot := -1
	lastDot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if firstDot < 0 {
				firstDot = i
			}
			lastDot = i
		}
	}
	if firstDot < 1 || lastDot == firstDot || firstDot+1 == lastDot {
		return nil, false
	}
	// 官方要求恰好 3 段：中间不允许再有第三个点
	if stringsCount(token, '.') != 2 {
		return nil, false
	}
	signing := token[:lastDot]
	actual, err := b64urlDecode(token[lastDot+1:])
	if err != nil {
		return nil, false
	}
	expected := HMACSHA256(secret, []byte(signing))
	if !hmac.Equal(expected, actual) {
		return nil, false
	}
	payload, err := b64urlDecode(token[firstDot+1 : lastDot])
	if err != nil {
		return nil, false
	}
	return payload, true
}

func stringsCount(s string, c byte) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			n++
		}
	}
	return n
}

// HMACSHA256 = crypto.createHmac("sha256", key).update(data).digest()。
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// SigHex 复刻官方 jwtSigHex：token 最后一段 b64url 解码后的 hex。
// 用作一次性消费（consumeNonce）的 key。
func SigHex(token string) (string, bool) {
	last := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			last = i
		}
	}
	if last < 0 {
		return "", false
	}
	raw, err := b64urlDecode(token[last+1:])
	if err != nil {
		return "", false
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0xf]
	}
	return string(out), true
}

// deriveKey 复刻官方 deriveKey(secret, info) = HMAC-SHA256(secret, info)。
func deriveKey(secret, info []byte) []byte { return HMACSHA256(secret, info) }

// EncryptGcm 复刻官方 encryptGcm(data, secret, info)：
// key=HMAC(secret,info)；随机 12 字节 IV；blob=b64url(iv ‖ tag ‖ ciphertext)。
func EncryptGcm(data any, secret []byte, info string) (string, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	key := deriveKey(secret, []byte(info))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize()) // 12
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil) // sealed = ciphertext ‖ tag(16)
	// 官方 blob 布局：iv ‖ tag ‖ ciphertext
	ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	blob := make([]byte, 0, len(iv)+len(tag)+len(ct))
	blob = append(blob, iv...)
	blob = append(blob, tag...)
	blob = append(blob, ct...)
	return b64url.EncodeToString(blob), nil
}

// DecryptGcm 复刻官方 decryptGcm：blob 布局为 iv(12) ‖ tag(16) ‖ ciphertext
// （官方 encryptGcm 的 Buffer.concat([iv, tag, encrypted])，注意 tag 在密文之前）。
func DecryptGcm(blob string, secret []byte, info string) ([]byte, error) {
	buf, err := b64urlDecode(blob)
	if err != nil || len(buf) < 28 { // iv(12)+tag(16)
		return nil, errors.New("format2: bad gcm blob")
	}
	iv, tag, ciphertext := buf[:12], buf[12:28], buf[28:]
	key := deriveKey(secret, []byte(info))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Go GCM.Open 期望 ciphertext ‖ tag，重新拼装
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
