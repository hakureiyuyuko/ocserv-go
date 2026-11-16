package assets

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// makeTarGz 构造测试用的 tar.gz。
func makeTarGz(t *testing.T, files map[string]string, symlink string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if symlink != "" {
		_ = tw.WriteHeader(&tar.Header{Name: symlink, Linkname: "/etc/passwd", Mode: 0o777, Typeflag: tar.TypeSymlink})
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestExtractAndLookup(t *testing.T) {
	dir := t.TempDir()
	buf := makeTarGz(t, map[string]string{
		"+CSCOU+/csco_logo.gif":        "GIF89a-fake",
		"dir/+CSCOE+/logon_custom.css": "body{color:red}",
	}, "")
	got, err := Extract(buf, dir)
	if err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应解出 2 个文件，得到 %d: %+v", len(got), got)
	}

	p, ok := Lookup(dir, "/+CSCOU+/csco_logo.gif")
	if !ok {
		t.Fatal("应能查到 +CSCOU+/csco_logo.gif")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "GIF89a-fake" {
		t.Fatalf("内容不符: %q", b)
	}
	if _, ok := Lookup(dir, "/+CSCOU+/nope.gif"); ok {
		t.Fatal("不存在的文件不应命中")
	}
	if _, ok := Lookup(dir, "/etc/passwd"); ok {
		t.Fatal("非官方目录不应命中")
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../evil.sh", "+CSCOU+/../../../etc/evil", "/abs/+CSCOU+/x.gif"} {
		dir := t.TempDir()
		buf := makeTarGz(t, map[string]string{name: "x"}, "")
		if _, err := Extract(buf, dir); err == nil {
			t.Fatalf("应拒绝路径 %q", name)
		}
	}
}

func TestExtractSkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	buf := makeTarGz(t, map[string]string{"+CSCOU+/ok.gif": "x"}, "+CSCOU+/link")
	files, err := Extract(buf, dir)
	if err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("软链应被跳过，得到 %d 个文件", len(files))
	}
	if _, err := os.Lstat(filepath.Join(dir, "+CSCOU+", "link")); err == nil {
		t.Fatal("软链不应被创建")
	}
}

func TestExtractRejectsOversized(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("x"), MaxFileSize+10)
	buf := makeTarGz(t, map[string]string{"+CSCOU+/big.gif": string(big)}, "")
	if _, err := Extract(buf, dir); err == nil {
		t.Fatal("超过单文件上限应报错")
	}
}

func TestExtractRejectsNonGzip(t *testing.T) {
	if _, err := Extract(bytes.NewReader([]byte("not gzip")), t.TempDir()); err == nil {
		t.Fatal("非 gzip 内容应报错")
	}
}

func TestListAndClear(t *testing.T) {
	dir := t.TempDir()
	buf := makeTarGz(t, map[string]string{
		"+CSCOU+/a.gif": "a",
		"+CSCOE+/b.css": "b",
	}, "")
	if _, err := Extract(buf, dir); err != nil {
		t.Fatal(err)
	}
	list := List(dir)
	if len(list) != 2 {
		t.Fatalf("应列出 2 个文件，得到 %d", len(list))
	}
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if n := len(List(dir)); n != 0 {
		t.Fatalf("清理后应为空，得到 %d", n)
	}
}

func TestContentType(t *testing.T) {
	cases := map[string]string{
		"x.gif":  "image/gif",
		"x.css":  "text/css; charset=utf-8",
		"x.html": "text/html; charset=utf-8",
		"x.bin":  "application/octet-stream",
	}
	for name, want := range cases {
		if got := ContentType(name); got != want {
			t.Fatalf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestCleanName(t *testing.T) {
	ok := []string{"+CSCOU+/a.gif", "/+CSCOE+/logon.html", "dir/+CSCOT+/x.js"}
	for _, n := range ok {
		if _, err := CleanName(n); err != nil {
			t.Fatalf("%q 应被接受: %v", n, err)
		}
	}
	bad := []string{"../a", "+CSCOU+/../../x", "/etc/passwd", "a/b"}
	for _, n := range bad {
		if _, err := CleanName(n); err == nil {
			t.Fatalf("%q 应被拒绝", n)
		}
	}
}
