package panel

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---- systemd ----

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ServiceState 返回 (active, enabled)。
func (p *Panel) ServiceState() (string, string) {
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
	out, err := runCmd("systemctl", action, p.cfg.Service)
	if err != nil {
		return fmt.Errorf("%s 失败: %s %v", action, out, err)
	}
	return nil
}

// Logs 取最近 n 行 journal 日志。
func (p *Panel) Logs(lines int) string {
	if lines <= 0 || lines > 2000 {
		lines = 200
	}
	out, err := runCmd("journalctl", "-u", p.cfg.Service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	if err != nil && out == "" {
		return "读取日志失败: " + err.Error()
	}
	return out
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
	ip, err := serverIPOf(c.VPNNet)
	if err != nil {
		ip = "10.66.66.1"
	}
	args := []string{
		c.Bin,
		"-addr", ":" + strconv.Itoa(c.VPNPort),
		"-users", c.UsersFile,
		"-cert", c.CertFile,
		"-key", c.KeyFile,
		"-net", c.VPNNet,
		"-ip", ip,
		"-dns", strings.Join(c.VPNDNS, ","),
		"-mtu", strconv.Itoa(c.VPNMTU),
	}
	if c.Domain != "" {
		args = append(args, "-domain", c.Domain)
	}
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
