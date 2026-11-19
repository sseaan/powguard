package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(t *testing.T, remote, xff string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/x/challenge", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// 直连模式：RemoteAddr 不可信 → XFF 完全忽略。
func TestDirectModeIgnoresXFF(t *testing.T) {
	e, err := NewIPExtractor("")
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "203.0.113.9:5555", "1.2.3.4, 5.6.7.8")
	if got := e.Client(r); got != "203.0.113.9" {
		t.Errorf("直连应取 RemoteAddr：%q", got)
	}
	// 非法 RemoteAddr 也原样返回（防御式）
	r2 := req(t, "garbage", "")
	if got := e.Client(r2); got != "garbage" {
		t.Errorf("非法 RemoteAddr：%q", got)
	}
}

// 可信反代模式：RemoteAddr 可信 → 从 XFF 右侧回溯取第一个不可信地址。
func TestTrustedProxyMode(t *testing.T) {
	e, err := NewIPExtractor("127.0.0.0/8, 10.0.0.0/8, ::1/128")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"单层代理", "127.0.0.1:9000", "203.0.113.7", "203.0.113.7"},
		{"多层代理（左客户端右代理链）", "127.0.0.1:9000", "203.0.113.7, 10.0.0.2, 127.0.0.1", "203.0.113.7"},
		{"代理直连（无 XFF）", "127.0.0.1:9000", "", "127.0.0.1"},
		{"XFF 全为可信网段", "127.0.0.1:9000", "10.0.0.2", "10.0.0.2"},
		{"RemoteAddr 不可信（直连伪造 XFF）", "203.0.113.9:5555", "1.2.3.4", "203.0.113.9"},
		{"XFF 含噪声", "127.0.0.1:9000", "not-an-ip, 203.0.113.8", "203.0.113.8"},
		{"IPv6 客户端", "127.0.0.1:9000", "2001:db8::1", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := e.Client(req(t, c.remote, c.xff)); got != c.want {
			t.Errorf("[%s] got %q want %q", c.name, got, c.want)
		}
	}
}

// 单个 IP 不带 / 也应接受。
func TestSingleIPCIDR(t *testing.T) {
	e, err := NewIPExtractor("10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "10.1.2.3:443", "198.51.100.1")
	if got := e.Client(r); got != "198.51.100.1" {
		t.Errorf("单 IP 信任失败：%q", got)
	}
}

func TestBadCIDR(t *testing.T) {
	if _, err := NewIPExtractor("not-a-cidr/xx"); err == nil {
		t.Error("非法 CIDR 应报错")
	}
}

// 伪造测试：不可信直连伪造 XFF 必须无效（安全边界）。
func TestUntrustedCannotSpoof(t *testing.T) {
	e, err := NewIPExtractor("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "45.45.45.45:1234", "127.0.0.1, 1.2.3.4")
	if got := e.Client(r); got != "45.45.45.45" {
		t.Errorf("不可信来源的 XFF 应被忽略：%q", got)
	}
}
