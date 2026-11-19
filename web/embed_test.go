package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sseaan/powguard/internal/security/secretbox"
	"github.com/sseaan/powguard/internal/security/session"
	"github.com/sseaan/powguard/internal/store/sqlite"
)

func newAssets(t *testing.T, adminEnabled bool) (*Assets, *sqlite.SessionRepo) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "w.sqlite3")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	sessionRepo := sqlite.NewSessionRepo(db)
	return &Assets{
		Sessions:     session.NewManager(sessionRepo, 0),
		Box:          box,
		Sites:        sqlite.NewSiteRepo(db),
		FirstSlug:    "twikoo",
		AdminEnabled: adminEnabled,
	}, sessionRepo
}

func TestTemplatesParse(t *testing.T) {
	if _, err := parseTemplates(); err != nil {
		t.Fatalf("模板解析失败：%v", err)
	}
}

func TestStaticAssets(t *testing.T) {
	a, _ := newAssets(t, true)
	mux := http.NewServeMux()
	if err := a.Register(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		path        string
		status      int
		contentType string
		cachePrefix string
	}{
		{"/static/app.css", 200, "text/css", "no-store"},
		{"/static/app.js", 200, "javascript", "no-store"},
		{"/static/vendor/cap.min.js", 200, "javascript", "public, max-age"},
		{"/static/vendor/cap_wasm_bg.wasm", 200, "application/wasm", "public, max-age"},
		{"/", 200, "text/html", "no-store"},
	}
	for _, c := range cases {
		resp, err := http.Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Errorf("%s 状态 %d != %d", c.path, resp.StatusCode, c.status)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, c.contentType) {
			t.Errorf("%s Content-Type %q 应含 %q", c.path, ct, c.contentType)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.HasPrefix(cc, c.cachePrefix) {
			t.Errorf("%s Cache-Control %q 应以 %q 开头", c.path, cc, c.cachePrefix)
		}
	}
}

func TestDemoPageRenders(t *testing.T) {
	a, _ := newAssets(t, true)
	mux := http.NewServeMux()
	if err := a.Register(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	for _, want := range []string{"cap-widget", "CAP_CUSTOM_WASM_URL", "/static/vendor/cap_wasm_bg.wasm", "twikoo"} {
		if !strings.Contains(body, want) {
			t.Errorf("demo 页缺少 %q", want)
		}
	}
}

func TestAdminGuards(t *testing.T) {
	a, sessionRepo := newAssets(t, true)
	mux := http.NewServeMux()
	if err := a.Register(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // 不跟随，检查 302 本身
	}}

	// 未登录：页面重定向到登录页
	for _, path := range []string{"/admin", "/admin/sites", "/admin/sites/twikoo", "/admin/events", "/admin/settings"} {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("%s 未登录应 302，得到 %d", path, resp.StatusCode)
			continue
		}
		if loc := resp.Header.Get("Location"); loc != "/admin/login" {
			t.Errorf("%s 重定向目标 %q", path, loc)
		}
	}

	// 登录页可访问
	resp, err := client.Get(srv.URL + "/admin/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("登录页应 200，得到 %d", resp.StatusCode)
	}

	// 已登录：正常渲染
	mgr := session.NewManager(sessionRepo, 0)
	tok, _, err := mgr.Create(nowMs())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin", nil)
	req.AddCookie(&http.Cookie{Name: "powguard_admin", Value: tok})
	plain := &http.Client{}
	resp, err = plain.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("已登录概览应 200，得到 %d", resp.StatusCode)
	}
	buf := make([]byte, 128*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	for _, want := range []string{"概览", "data-nav=\"sites\"", "logout-btn"} {
		if !strings.Contains(body, want) {
			t.Errorf("概览页缺少 %q", want)
		}
	}
	// 未登录时不应出现导航
	if strings.Contains(body, "data-nav=\"overview\"") == false {
		t.Error("概览页应有导航")
	}
}

func TestAdminDisabled(t *testing.T) {
	a, _ := newAssets(t, false)
	mux := http.NewServeMux()
	if err := a.Register(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("管理禁用时 /admin 应 404，得到 %d", resp.StatusCode)
	}
	// demo 页仍可用
	resp, err = http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("demo 页应 200，得到 %d", resp.StatusCode)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	a, _ := newAssets(t, true)
	mux := http.NewServeMux()
	if err := a.Register(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, p := range []string{"/static/../go.mod", "/static/vendor/../../go.mod"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+p, nil)
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			continue // 客户端已拒绝
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Errorf("%s 不应返回 200", p)
		}
	}
}
