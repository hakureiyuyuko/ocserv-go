// Package assets 管理「用户自己上传的 Cisco 登录页资源」。
//
// 套件本身**不自带**任何 Cisco 的图片/CSS（那是厂商版权素材）：想还原某台设备
// 的外观，用户可以自己从设备上抓取 /+CSCOT+/、/+CSCOU+/、/+CSCOE+/ 下的静态文件，
// 打成一个 tar.gz 上传。这里负责安全解包、查找与清理。
package assets

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 限制：防止恶意的超大包/超多文件
const (
	MaxTotalSize = 32 << 20 // 32MB
	MaxFileSize  = 8 << 20  // 单文件 8MB
	MaxFiles     = 500
)

// File 是一个已上传的资源。
type File struct {
	Path  string    `json:"path"` // 相对路径，形如 +CSCOU+/csco_logo.gif
	Size  int64     `json:"size"`
	Mtime time.Time `json:"mtime"`
}

// CleanName 把 URL 或包内路径规范成 "段/段" 形式，拒绝越界与非法前缀。
//
// 兼容用户把整个上层目录打进来的情况：例如包内路径 "iframe/+CSCOU+/x.gif"
// 会被规范化成 "+CSCOU+/x.gif"。
func CleanName(p string) (string, error) {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimPrefix(p, "./")
	if p == "" {
		return "", errors.New("空路径")
	}
	c := path.Clean(p)
	if c == "." || path.IsAbs(c) || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") {
		return "", fmt.Errorf("非法路径: %q", p)
	}
	segs := strings.Split(c, "/")
	for i, seg := range segs {
		low := strings.ToLower(seg)
		if low == "+cscot+" || low == "+cscou+" || low == "+cscoe+" {
			return path.Join(segs[i:]...), nil
		}
	}
	if c == "index.html" {
		return c, nil
	}
	return "", fmt.Errorf("不允许的路径: %q（只接受 +CSCOT+ / +CSCOU+ / +CSCOE+ 下的文件）", c)
}

func allowedTop(p string) bool {
	top := strings.ToLower(strings.SplitN(p, "/", 2)[0])
	switch top {
	case "+cscot+", "+cscou+", "+cscoe+":
		return true
	}
	return false
}

// Extract 把 gzip 压缩的 tar 解到 dir（安全解包：拒绝绝对路径/越界/软链/设备文件）。
func Extract(r io.Reader, dir string) ([]File, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("不是 gzip/tar.gz: %v", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	tr := tar.NewReader(gz)
	var total int64
	var out []File
	count := 0

	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取 tar 失败: %v", err)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue // 目录/软链/设备一律跳过
		}
		// 包内条目不允许绝对路径或 ..（正常打包不会出现）
		if strings.HasPrefix(h.Name, "/") || strings.Contains(strings.ReplaceAll(h.Name, "\\", "/"), "../") {
			return nil, fmt.Errorf("包内路径不合法: %q", h.Name)
		}
		name, err := CleanName(h.Name)
		if err != nil {
			// 非官方目录的文件（README、.DS_Store、__MACOSX/…）直接忽略，
			// 不要因为包里多带了几个杂项就让整个上传失败。
			continue
		}
		if !allowedTop(name) && name != "index.html" {
			continue
		}
		if h.Size > MaxFileSize {
			return nil, fmt.Errorf("%s 超过单文件上限 (%d MB)", name, MaxFileSize>>20)
		}
		total += h.Size
		if total > MaxTotalSize {
			return nil, fmt.Errorf("包内文件总量超过 %d MB", MaxTotalSize>>20)
		}
		if count++; count > MaxFiles {
			return nil, fmt.Errorf("包内文件数超过 %d", MaxFiles)
		}

		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		var n int64
		if needsSanitize(name) {
			raw, rerr := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
			if rerr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("读取 %s 失败: %v", name, rerr)
			}
			clean := SanitizeLogonHTML(raw)
			if _, werr := f.Write(clean); werr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("写入 %s 失败: %v", name, werr)
			}
			n = int64(len(clean))
		} else {
			var cerr error
			n, cerr = io.Copy(f, io.LimitReader(tr, MaxFileSize+1))
			if cerr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("写入 %s 失败: %v", name, cerr)
			}
		}
		if cerr := f.Close(); cerr != nil {
			return nil, cerr
		}
		if n > MaxFileSize {
			_ = os.Remove(dst)
			return nil, fmt.Errorf("%s 超过单文件上限", name)
		}
		out = append(out, File{Path: name, Size: n, Mtime: time.Now()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Lookup 在 dir 下找 urlPath 对应的文件（只允许官方目录树），返回绝对路径。
func Lookup(dir, urlPath string) (string, bool) {
	if dir == "" {
		return "", false
	}
	name, err := CleanName(urlPath)
	if err != nil || !allowedTop(name) {
		return "", false
	}
	p := filepath.Join(dir, filepath.FromSlash(name))
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return "", false
	}
	return p, true
}

// List 列出 dir 下已上传的文件。
func List(dir string) []File {
	var out []File
	if dir == "" {
		return out
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return out
	}
	defer root.Close()
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return nil
		}
		name := filepath.ToSlash(rel)
		if !allowedTop(name) && name != "index.html" {
			return nil
		}
		out = append(out, File{Path: name, Size: info.Size(), Mtime: info.ModTime()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Clear 删除所有已上传资源（回到内置占位图）。
func Clear(dir string) error {
	if dir == "" {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// ContentType 按扩展名猜 Content-Type（未识别时按二进制返回）。
func ContentType(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".gif":
		return "image/gif"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".xml":
		return "text/xml; charset=utf-8"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	}
	return "application/octet-stream"
}

// ---- 脱敏：登录页里的组名 ----

// GroupName 是登录页里统一展示的连接组名：
// 上传页面里的真实组名会被替换成它（服务端本来就忽略 tgroup）。
const GroupName = "HetraVPN_Group"

var (
	reSelectGroup = regexp.MustCompile(`(?is)<select\b[^>]*\bname\s*=\s*["']?(?:tgroup|group_list)["']?[^>]*>`)
	reOption      = regexp.MustCompile(`(?is)<option\b[^>]*>(.*?)</option>`)
	reOptionVal   = regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	reGroupInput  = regexp.MustCompile(`(?is)<input\b[^>]*name\s*=\s*["']?group_list["']?[^>]*>`)
)

// SanitizeLogonHTML 把页面里暴露的「组名」统一替换成 GroupName。
//
// Cisco 登录页会把设备上配置的连接组（group）以 <option> 形式写进页面，
// 传上来就等于把对方（或自己）的内部组名公开到登录页。这里：
//   - 删除所有原有 <option>…</option>，只留一个固定的 HetraVPN_Group；
//   - 删除 group_list 隐藏域；
//   - 再把从 option 里提取到的组名，在全文其它位置一并清掉（含 URL 转义形式）。
func SanitizeLogonHTML(b []byte) []byte {
	s := string(b)

	// 先收集组名，后面全文清理
	var names []string
	for _, m := range reOption.FindAllStringSubmatch(s, -1) {
		if v := strings.TrimSpace(html.UnescapeString(m[1])); v != "" && v != GroupName {
			names = append(names, v)
		}
		if vm := reOptionVal.FindStringSubmatch(m[0]); vm != nil {
			if v := strings.TrimSpace(html.UnescapeString(vm[1])); v != "" && v != GroupName {
				names = append(names, v)
			}
		}
	}

	s = reOption.ReplaceAllString(s, "")
	s = reGroupInput.ReplaceAllString(s, "")

	for _, n := range names {
		if len(n) < 3 { // 太短的不替换，避免误伤
			continue
		}
		s = strings.ReplaceAll(s, html.EscapeString(n), "")
		s = strings.ReplaceAll(s, n, "")
		s = strings.ReplaceAll(s, url.PathEscape(n), "")
	}
	// 清理完再放固定选项，避免它自己被当成组名清掉
	s = reSelectGroup.ReplaceAllStringFunc(s, func(m string) string {
		return m + `<option value="` + GroupName + `" selected>` + GroupName + `</option>`
	})
	return []byte(s)
}

// needsSanitize 判断某个包内文件是否需要脱敏（+CSCOE+ 下的 HTML）。
func needsSanitize(name string) bool {
	if !strings.HasPrefix(strings.ToLower(name), "+cscoe+/") {
		return false
	}
	low := strings.ToLower(name)
	return strings.HasSuffix(low, ".html") || strings.HasSuffix(low, ".htm")
}
