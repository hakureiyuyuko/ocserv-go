package panel

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:webdist
var webFS embed.FS

// newWebHandler 提供前端静态资源；找不到的路径回落到 index.html（SPA 路由）。
func newWebHandler() http.Handler {
	sub, err := fs.Sub(webFS, "webdist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		if clean == "/" {
			serveIndex(w, r, sub)
			return
		}
		if f, err := sub.Open(strings.TrimPrefix(clean, "/")); err == nil {
			_ = f.Close()
			// 静态资源带长缓存（文件名含 hash），index.html 不缓存
			if strings.HasPrefix(clean, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			files.ServeHTTP(w, r)
			return
		}
		serveIndex(w, r, sub)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "前端未构建", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}
