package csrf

import (
	"bytes"
	"testing"
)

func TestTokenPerSession(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a := Token(key, "session-hash-a")
	b := Token(key, "session-hash-b")
	if a == b {
		t.Fatal("不同会话应得到不同 CSRF token")
	}
	if !Verify(key, "session-hash-a", a) {
		t.Fatal("正确 token 应通过")
	}
	if Verify(key, "session-hash-a", b) {
		t.Fatal("跨会话 token 应失败")
	}
	if Verify(key, "session-hash-b", b) {
		// 同会话重放同一 token 合法（CSRF token 可复用，不是 one-time）
		t.Log("同会话校验通过（符合预期）")
	}
}

func TestVerifyRejects(t *testing.T) {
	key := bytes.Repeat([]byte{8}, 32)
	tok := Token(key, "h")
	if Verify(key, "h", "") {
		t.Error("空 token 应失败")
	}
	if Verify(key, "h", tok+"x") {
		t.Error("篡改 token 应失败")
	}
	if Verify(bytes.Repeat([]byte{9}, 32), "h", tok) {
		t.Error("错误 key 应失败")
	}
}
