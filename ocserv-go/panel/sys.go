package panel

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---- 服务管理（systemd / OpenRC / 面板托管）----

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// InitKind 返回面板实际使用的服务管理方式（托管模式不依赖 init）。
func (p *Panel) InitKind() InitKind {
	if p.sup != nil {
		return InitNone
	}
	if p.init == "" {
		return InitSystemd
	}
	return p.init
}

// ModeName 给前端用：container / openrc / systemd。
func (p *Panel) ModeName() string {
	if p.sup != nil {
		return "container"
	}
	if k := p.InitKind(); k != "" {
		return string(k)
	}
	return string(InitSystemd)
}

// ServiceState 返回 (active, enabled)。
func (p *Panel) ServiceState() (string, string) {
	if p.sup != nil {
		return p.sup.State()
	}
	switch p.InitKind() {
	case InitOpenRC:
		active := "inactive"
		if out, err := runCmd("rc-service", p.cfg.Service, "status"); err == nil &&
			strings.Contains(strings.ToLower(out), "started") {
			active = "active"
		}
		enabled := "disabled"
		if out, _ := runCmd("rc-update", "show", "default"); strings.Contains(out, p.cfg.Service) {
			enabled = "enabled"
		}
		return active, enabled
	case InitNone:
		return "inactive", "none"
	}
	active, _ := runCmd("systemctl", "is-active", p.cfg.Service)
	enabled, _ := runCmd("systemctl", "is-enabled", p.cfg.Service)
	if active == "" {
		active = "inactive"
	}
	if enabled == "" || strings.Contains(enabled, "No such file") {
		enabled = "not-found"
	}
	return active, enabled
}

// ServiceAction 执行 start/stop/restart。
func (p *Panel) ServiceAction(action string) error {
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("不支持的动作: %s", action)
	}
	if p.sup != nil {
		return p.sup.Do(action)
	}
	switch p.InitKind() {
	case InitOpenRC:
		if out, err := runCmd("rc-service", p.cfg.Service, action); err != nil {
			return fmt.Errorf("%s 失败: %s %v", action, out, err)
		}
		return nil
	case InitNone:
		return fmt.Errorf("这个环境里没有 systemd / OpenRC，无法控制系统服务；请用 `ocserv-go panel -supervise` 启动面板，让它托管 VPN 进程（容器镜像默认就是这样）")
	}
	if out, err := runCmd("systemctl", action, p.cfg.Service); err != nil {
		return fmt.Errorf("%s 失败: %s %v", action, out, err)
	}
	return nil
}

// Logs 取最近 n 行服务日志：托管模式读子进程输出，OpenRC 读 /var/log/<服务>.log，
// 否则读 journal。
func (p *Panel) Logs(lines int) string {
	if lines <= 0 || lines > 2000 {
		lines = 200
	}
	if p.sup != nil {
		return p.sup.Logs(lines)
	}
	if p.InitKind() == InitOpenRC {
		logPath := filepath.Join("/var/log", p.cfg.Service+".log")
		out, err := tailLines(logPath, lines)
		if err != nil {
			return "读取 " + logPath + " 失败: " + err.Error()
		}
		return out
	}
	out, err := runCmd("journalctl", "-u", p.cfg.Service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	if err != nil && out == "" {
		return "读取日志失败: " + err.Error()
	}
	return out
}

// tailLines 读文件末尾 n 行（最多回看 1MB，避免日志大了把内存吃掉）。
func tailLines(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	const maxRead = 1 << 20
	off := int64(0)
	if st.Size() > maxRead {
		off = st.Size() - maxRead
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(b), "\n")
	if text == "" {
		return "", nil
	}
	ls := strings.Split(text, "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n") + "\n", nil
}

// ---- 证书 ----

// CertInfo 是证书摘要（给面板展示用）。
type CertInfo struct {
	Exists   bool     `json:"exists"`
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	NotAfter string   `json:"notAfter"`
	DaysLeft int      `json:"daysLeft"`
	SAN      []string `json:"san"`
	IsRSA    bool     `json:"isRsa"`
}

// CertInfo 解析当前证书。
func (p *Panel) CertInfo() CertInfo {
	return certInfoOf(p.cfg.CertFile)
}

func certInfoOf(path string) CertInfo {
	b, err := os.ReadFile(path)
	if err != nil {
		return CertInfo{}
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return CertInfo{}
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertInfo{}
	}
	days := int(time.Until(crt.NotAfter).Hours() / 24)
	ci := CertInfo{
		Exists:   true,
		Subject:  crt.Subject.CommonName,
		Issuer:   crt.Issuer.CommonName,
		NotAfter: crt.NotAfter.Format("2006-01-02"),
		DaysLeft: days,
		SAN:      crt.DNSNames,
		IsRSA:    crt.PublicKeyAlgorithm == x509.RSA,
	}
	return ci
}

// ---- 单元文件 ----

// RenderUnit 生成 ocserv-go 的 systemd 单元内容。
func (c *Config) RenderUnit() string {
	args := append([]string{c.Bin}, VPNArgs(c)...)
	return "[Unit]\n" +
		"Description=ocserv-go (userspace AnyConnect VPN)\n" +
		"After=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\n" +
		"ExecStart=" + strings.Join(args, " ") + "\n" +
		"Restart=always\nRestartSec=3\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

// WriteUnit 写单元文件（不重启服务）。
func (c *Config) WriteUnit() error {
	p := filepath.Join("/etc/systemd/system", c.Service+".service")
	if err := os.WriteFile(p, []byte(c.RenderUnit()), 0o644); err != nil {
		return err
	}
	_, _ = runCmd("systemctl", "daemon-reload")
	return nil
}

// RenderOpenRC 生成 OpenRC（Alpine）服务脚本，字段与 install.sh 写的一致。
func (c *Config) RenderOpenRC() string {
	args := strings.Join(VPNArgs(c), " ")
	return "#!/sbin/openrc-run\n" +
		"description=\"ocserv-go (userspace AnyConnect VPN)\"\n\n" +
		"command=\"" + c.Bin + "\"\n" +
		"command_args=\"" + args + "\"\n" +
		"command_background=true\n" +
		"pidfile=\"/run/" + c.Service + ".pid\"\n" +
		"output_log=\"/var/log/" + c.Service + ".log\"\n" +
		"error_log=\"/var/log/" + c.Service + ".log\"\n\n" +
		"depend() {\n    need net\n}\n"
}

// WriteService 按当前环境重写服务脚本/单元（不重启服务）。
func (p *Panel) WriteService() error {
	switch p.InitKind() {
	case InitOpenRC:
		path := filepath.Join("/etc/init.d", p.cfg.Service)
		if err := os.WriteFile(path, []byte(p.cfg.RenderOpenRC()), 0o755); err != nil {
			return err
		}
		_, _ = runCmd("rc-update", "add", p.cfg.Service, "default")
		return nil
	case InitSystemd:
		return p.cfg.WriteUnit()
	}
	return nil // 托管模式：参数在 panel.json 里，没有服务脚本
}

// ServiceScript 返回当前环境对应的服务脚本文本（面板「设置」页展示用）。
func (p *Panel) ServiceScript() string {
	switch p.InitKind() {
	case InitOpenRC:
		return p.cfg.RenderOpenRC()
	case InitSystemd:
		return p.cfg.RenderUnit()
	}
	return ""
}

// serverIPOf 取网段的第一个可用地址（10.66.66.0/24 → 10.66.66.1）。
func serverIPOf(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("只支持 IPv4 网段")
	}
	_ = ipnet
	v4[3]++
	return v4.String(), nil
}
