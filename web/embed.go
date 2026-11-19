// web 包通过 go:embed 把模板与静态资产打进单二进制。
package web

import (
	"embed"
	"html/template"
	"mime"
	"net/http"
	"strings"
)

//go:embed templates static
var files embed.FS

var demoTmpl = template.Must(template.ParseFS(files, "templates/demo.html"))

func init() {
	// .wasm 必须是 application/wasm，否则 WebAssembly.compile 拒绝
	_ = mime.AddExtensionType(".wasm", "application/wasm")
}

// RegisterStatic 挂载静态资产与演示页路由（P1 版根路径；M4 由 dashboard 取代）。
func RegisterStatic(mux *http.ServeMux, siteSlug string) {
	fileServer := http.FileServerFS(files)
	mux.Handle("GET /static/", withCachePolicy(fileServer))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = demoTmpl.Execute(w, map[string]string{"Slug": siteSlug})
	})
}

// withCachePolicy：vendor 资产钉版本、内容寻址稳定 → 长缓存；
// 其余（NOTICE 等）不缓存，方便核查。
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
