package panel

// 服务管理器探测：面板要能在 systemd、OpenRC（Alpine）以及两者都没有的环境里工作。
//
//   · systemd  —— 有 systemctl 且 /run/systemd/system 存在（容器里不等于有 systemd）
//   · openrc   —— 有 rc-service、/run/openrc 存在（OpenRC 在跑）、且 /etc/init.d/<服务名> 存在
//   · none     —— 都没有：面板自动转为托管模式（自己拉起 VPN 子进程），否则服务控制无从谈起

import (
	"os"
	"os/exec"
	"path/filepath"
)

// InitKind 是服务管理器类型。
type InitKind string

const (
	InitSystemd InitKind = "systemd"
	InitOpenRC  InitKind = "openrc"
	InitNone    InitKind = "none"
)

// DetectInit 判断当前环境用哪个服务管理器来管 service。
func DetectInit(service string) InitKind {
	hasSystemctl := lookPathOK("systemctl")
	isSystemdRunning := false
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		isSystemdRunning = true
	}
	hasRC := lookPathOK("rc-service")
	isOpenRCRunning := false
	if st, err := os.Stat("/run/openrc"); err == nil && st.IsDir() {
		isOpenRCRunning = true
	}
	hasRCUnit := false
	if service != "" {
		if st, err := os.Stat(filepath.Join("/etc/init.d", service)); err == nil && !st.IsDir() {
			hasRCUnit = true
		}
	}
	return classifyInit(hasSystemctl && isSystemdRunning, hasRC && isOpenRCRunning, hasRCUnit)
}

// classifyInit 是纯逻辑（便于单测）：systemd 优先，其次 OpenRC（真的在跑且真有服务脚本），否则 none。
func classifyInit(systemdReady, openrcReady, hasRCUnit bool) InitKind {
	switch {
	case systemdReady:
		return InitSystemd
	case openrcReady && hasRCUnit:
		return InitOpenRC
	default:
		return InitNone
	}
}

func lookPathOK(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
