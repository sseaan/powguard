// Package web 通过 go:embed 把模板与静态资产打进单二进制，并提供管理面板页面。
package web

import (
	"bytes"
	"embed"
	"html/template"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"capgo/internal/security/secretbox"
	"capgo/internal/security/session"
	"capgo/internal/store/sqlite"
)

//go:embed templates static
var files embed.FS

// Assets 暴露给 main 装配（登录态判定依赖 session 仓库）。
type Assets struct {
	Sessions *session.Manager
	Box      *secretbox.Box
	Sites    *sqlite.SiteRepo
	// FirstSlug 是演示页默认站点。
	FirstSlug string
	// AdminEnabled 为 false 时不注册 /admin 页面（整体禁用）。
	AdminEnabled bool
	// CookieSecure 由公开 URL 判定（与 admin API 保持一致）。
	CookieSecure bool
}

var (
	tmplOnce sync.Once
	tmpl     *template.Template
	tmplErr  error
)

func parseTemplates() (*template.Template, error) {
	tmplOnce.Do(func() {
		tmpl, tmplErr = template.ParseFS(files,
			"templates/layout.html",
			"templates/login.html",
			"templates/overview.html",
			"templates/sites.html",
			"templates/site_detail.html",
			"templates/events.html",
			"templates/settings.html",
			"templates/demo.html",
		)
	})
	return tmpl, tmplErr
}

func init() {
	// .wasm 必须是 application/wasm，否则 WebAssembly.compile 拒绝
	_ = mime.AddExtensionType(".wasm", "application/wasm")
}

// Register 挂载静态资产、演示页与管理面板页面。
func (a *Assets) Register(mux *http.ServeMux) error {
	t, err := parseTemplates()
	if err != nil {
		return err
	}
	fileServer := http.FileServerFS(files)
	mux.Handle("GET /static/", withCachePolicy(fileServer))

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		// demo.html 是完整文档（无 layout），单独执行
		_ = t.ExecuteTemplate(w, "demo.html", map[string]string{"Slug": a.FirstSlug})
	})

	if !a.AdminEnabled {
		return nil
	}
	page := func(name, title string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data := map[string]any{
				"Title":   title,
				"Authed":  a.authed(r),
				"Content": name,
			}
			var buf bytes.Buffer
			if err := t.ExecuteTemplate(&buf, "layout.html", data); err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = buf.WriteTo(w)
		}
	}

	// 登录页：已登录则跳到概览
	mux.HandleFunc("GET /admin/login", func(w http.ResponseWriter, r *http.Request) {
		if a.authed(r) {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		page("login.html", "登录")(w, r)
	})
	mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		// GET /admin/ 重定向到 /admin，避免与 /admin/sites 等冲突
		if r.URL.Path == "/admin/" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /admin", a.guard(page("overview.html", "概览")))
	mux.HandleFunc("GET /admin/sites", a.guard(page("sites.html", "站点")))
	mux.HandleFunc("GET /admin/sites/{slug}", a.guard(page("site_detail.html", "站点详情")))
	mux.HandleFunc("GET /admin/events", a.guard(page("events.html", "事件")))
	mux.HandleFunc("GET /admin/settings", a.guard(page("settings.html", "实例设置")))
	return nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

// authed 用与 admin API 相同的会话判定。
func (a *Assets) authed(r *http.Request) bool {
	if a.Sessions == nil {
		return false
	}
	c, err := r.Cookie("capgo_admin")
	if err != nil {
		return false
	}
	ok, _, err := a.Sessions.Valid(c.Value, nowMs())
	return err == nil && ok
}

// guard 未登录时跳转登录页。
func (a *Assets) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// withCachePolicy：vendor 资产钉版本、内容寻址稳定 → 长缓存；其余不缓存。
func withCachePolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/vendor/") && !strings.HasSuffix(r.URL.Path, ".md") {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
