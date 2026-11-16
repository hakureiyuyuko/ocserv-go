package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hakureiyuyuko/ocserv-go/internal/assets"
	"github.com/hakureiyuyuko/ocserv-go/panel"
)

// runPanel 是 `ocserv-go panel` 子命令：内置管理面板（API + 内嵌 Vue 前端）。
func runPanel() int {
	fs := flag.NewFlagSet("panel", flag.ExitOnError)
	confPath := fs.String("config", "/etc/ocserv-go/panel.json", "面板配置文件")
	listen := fs.String("listen", "", "监听地址（覆盖配置文件，如 :19999）")
	importOld := fs.String("import", "", "从旧 Node 面板的 config.json 迁移")
	setPw := fs.String("set-password", "", "重置面板账号密码，格式 用户名:新密码")
	initOnly := fs.Bool("init", false, "只生成/保存配置文件后退出（安装脚本用）")
	resanitize := fs.Bool("resanitize", false, "对已上传的 +CSCOE+/*.html 重新脱敏（替换组名）后退出")
	_ = fs.Parse(os.Args[2:])

	cfg, err := panel.LoadConfig(*confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取面板配置失败: %v\n", err)
		return 1
	}
	if *importOld != "" {
		if err := cfg.ImportNodePanel(*importOld); err != nil {
			fmt.Fprintf(os.Stderr, "迁移旧配置失败: %v\n", err)
			return 1
		}
		fmt.Printf("已从 %s 迁移配置\n", *importOld)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	if *setPw != "" {
		parts := strings.SplitN(*setPw, ":", 2)
		if len(parts) != 2 || parts[0] == "" || len(parts[1]) < 6 {
			fmt.Fprintln(os.Stderr, "格式应为 用户名:新密码（密码至少 6 位）")
			return 1
		}
		cfg.PanelUsers[parts[0]] = panel.HashPassword(parts[1])
		fmt.Printf("已设置 %s 的面板密码\n", parts[0])
	}
	// 首次运行：建一个 admin 账号并打印密码
	if len(cfg.PanelUsers) == 0 {
		pw := randomPassword(12)
		cfg.PanelUsers["admin"] = panel.HashPassword(pw)
		fmt.Printf("已创建面板管理员账号: admin / %s\n", pw)
	}
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "保存配置失败: %v\n", err)
		return 1
	}

	if *resanitize {
		n, err := assets.ReSanitizeDir(cfg.AssetsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "重新脱敏失败: %v\n", err)
			return 1
		}
		fmt.Printf("已重新脱敏 %d 个文件（目录 %s）\n", n, cfg.AssetsDir)
		return 0
	}
	if *initOnly {
		fmt.Printf("配置已写入 %s\n", *confPath)
		return 0
	}

	p := panel.New(cfg, version)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("面板: http://%s/ （账号 %s，配置 %s）", strings.Replace(cfg.Listen, "0.0.0.0", "127.0.0.1", 1), strings.Join(cfg.PanelUsersNames(), " / "), *confPath)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("面板退出: %v", err)
		return 1
	}
	return 0
}

func randomPassword(n int) string {
	const cs = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "admin123456"
	}
	for i := range b {
		b[i] = cs[int(b[i])%len(cs)]
	}
	return string(b)
}
