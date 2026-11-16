package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	supervise := fs.Bool("supervise", false, "容器模式：面板托管 VPN 子进程（不依赖 systemd / journalctl）")
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
	var sup *panel.Supervisor
	var stopSupervisor func()
	supMode := *supervise
	if !supMode && p.InitKind() == panel.InitNone {
		// 既没有 systemd 也没有 OpenRC（比如精简容器里直接跑 panel）：
		// 面板自己托管 VPN 子进程，否则「服务控制」无从谈起
		log.Printf("未检测到 systemd / OpenRC：自动进入托管模式（面板自己拉起 VPN 子进程）")
		supMode = true
	}
	if supMode {
		// 容器模式：面板即 PID 1，VPN 作为子进程被托管
		sup = panel.NewSupervisorFor(cfg)
		p.Supervise(sup)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		stopSupervisor = stop
		go sup.Run(ctx)
		log.Printf("容器模式: 面板托管 VPN 进程 %s %s", cfg.Bin, strings.Join(sup.Args(), " "))
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("面板: http://%s/ （账号 %s，配置 %s）", strings.Replace(cfg.Listen, "0.0.0.0", "127.0.0.1", 1), strings.Join(cfg.PanelUsersNames(), " / "), *confPath)
	if sup != nil {
		// 子进程停掉（收到 SIGTERM）后，面板自己也退出
		go func() {
			<-sup.Done()
			_ = srv.Shutdown(context.Background())
		}()
	}
	err = srv.ListenAndServe()
	if sup != nil {
		stopSupervisor()
		<-sup.Done()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// runSelfSigned 是 `ocserv-go self-signed` 子命令：生成自签 RSA 证书。
// 容器首次启动没有证书时由入口脚本调用（不必依赖 openssl）。
func runSelfSigned() int {
	fs := flag.NewFlagSet("self-signed", flag.ExitOnError)
	domain := fs.String("domain", "ocserv-go.local", "证书域名（CN / SAN）")
	cert := fs.String("cert", "", "证书输出路径（默认 /etc/ssl/securev/<domain>/fullchain.pem）")
	key := fs.String("key", "", "私钥输出路径（默认同目录 privkey.pem）")
	_ = fs.Parse(os.Args[2:])

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "域名不能为空")
		return 1
	}
	dir := filepath.Join("/etc/ssl/securev", *domain)
	cf, kf := *cert, *key
	if cf == "" {
		cf = filepath.Join(dir, "fullchain.pem")
	}
	if kf == "" {
		kf = filepath.Join(dir, "privkey.pem")
	}
	if err := panel.SelfSigned(*domain, cf, kf); err != nil {
		fmt.Fprintf(os.Stderr, "生成自签证书失败: %v\n", err)
		return 1
	}
	fmt.Printf("已生成自签证书: %s（CN=%s，有效期 365 天，客户端会提示不受信任）\n", cf, *domain)
	return 0
}
