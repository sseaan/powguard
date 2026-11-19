package admin

import (
	"net/http"
	"strings"
	"testing"

	"capgo/internal/store/model"
)

func TestSiteProtocolFormat2(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)

	// 建站即选 format-2
	resp, m := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{
		"slug": "v2", "protocol": "format2",
	}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 201 {
		t.Fatalf("创建失败：%d %v", resp.StatusCode, m)
	}

	// 签名密钥落库且非明文可解（不外发）
	siteRow, err := e.sites.GetBySlug("v2")
	if err != nil {
		t.Fatal(err)
	}
	sign, err := e.secrets.Get(siteRow.ID, model.FieldSigning)
	if err != nil {
		t.Fatalf("签名密钥未落库：%v", err)
	}
	plain, err := e.box.Open(sign.Ciphertext, "v2", model.FieldSigning)
	if err != nil || len(plain) != 64 { // RandomHex(32)
		t.Fatalf("签名密钥解密异常：err=%v len=%d", err, len(plain))
	}
	if strings.Contains(sign.Ciphertext, string(plain)) {
		t.Fatal("密文不得包含明文")
	}

	// resolver 提供 SigningKey → 公开 challenge 是 format-2 envelope
	site, ok := e.resolver.Resolve("v2")
	if !ok || site.SigningKey == "" || site.Protocol != "format2" {
		t.Fatalf("resolver 未生效：%+v", site)
	}
	pubResp, pubM := e.post("/v2/challenge", nil)
	if pubResp.StatusCode != 200 || pubM["format"] != float64(2) {
		t.Fatalf("challenge 应为 format-2：%d %v", pubResp.StatusCode, pubM)
	}

	// 切回 format-1 → 立即恢复 format-1 形态（缓存已失效）
	resp, m = e.do(t, http.MethodPost, "/admin/api/sites/v2", map[string]any{"protocol": "format1"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 200 {
		t.Fatalf("切换失败：%d %v", resp.StatusCode, m)
	}
	pubResp, pubM = e.post("/v2/challenge", nil)
	if pubResp.StatusCode != 200 || pubM["format"] != nil {
		t.Fatalf("challenge 应回到 format-1：%v", pubM)
	}
	if _, ok := pubM["challenge"].(map[string]any); !ok {
		t.Fatalf("format-1 响应缺 challenge 字段：%v", pubM)
	}

	// 非法协议拒绝
	resp, m = e.do(t, http.MethodPost, "/admin/api/sites/v2", map[string]any{"protocol": "hashwx"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 400 {
		t.Fatalf("非法协议应 400（HashWX 未实现不开放）：%d %v", resp.StatusCode, m)
	}
}

func TestSiteJSONIncludesProtocol(t *testing.T) {
	e := newEnv(t, nil)
	csrfTok, cookie := e.login(t)
	resp, m := e.do(t, http.MethodPost, "/admin/api/sites", map[string]any{"slug": "p1"}, e.auth(csrfTok, cookie))
	if resp.StatusCode != 201 {
		t.Fatalf("创建失败：%v", m)
	}
	site, _ := m["site"].(map[string]any)
	if site["protocol"] != "format1" {
		t.Errorf("默认协议应 format1：%v", site["protocol"])
	}
}
