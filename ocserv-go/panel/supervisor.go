package panel

// 容器模式：把 VPN 子进程托管在面板进程里（没有 systemd 的环境，比如 Docker）。
//
// 行为尽量与 install.sh 写的 systemd 单元一致：
//   · 子进程意外退出 3 秒后自动拉起（等价 Restart=always / RestartSec=3）
//   · 面板「启动 / 停止 / 重启」直接作用于子进程
//   · 面板「服务日志」读子进程输出（最近 2000 行环形缓冲），同时照常写 stdout，
//     所以 `docker logs` 里也看得到
//
// 非容器部署不用这段逻辑：面板照旧调 systemctl / journalctl。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Supervisor 托管一个 VPN 子进程。
type Supervisor struct {
	bin  string
	args []string

	mu    sync.Mutex
	cond  *sync.Cond
	cmd   *exec.Cmd
	since time.Time
	hold  bool // 面板点了「停止」：不要自动拉起
	fast  bool // 本次退出是面板主动重启：短延迟拉起

	buf  *logRing
	done chan struct{}
}

// NewSupervisor 构造托管器（bin 一般是 /usr/local/bin/ocserv-go）。
func NewSupervisor(bin string, args []string) *Supervisor {
	s := &Supervisor{bin: bin, args: args, buf: newLogRing(2000), done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// NewSupervisorFor 按面板配置构造托管器（参数与 systemd 单元一致）。
func NewSupervisorFor(c *Config) *Supervisor {
	return NewSupervisor(c.Bin, VPNArgs(c))
}

// Args 返回子进程参数（日志里打出来方便排错）。
func (s *Supervisor) Args() []string { return s.args }

// Done 在 Run 返回后关闭。
func (s *Supervisor) Done() <-chan struct{} { return s.done }

// VPNArgs 由面板配置生成 VPN 进程参数。
func VPNArgs(c *Config) []string {
	ip, err := serverIPOf(c.VPNNet)
	if err != nil {
		ip = "10.66.66.1"
	}
	args := []string{
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
	if c.AssetsDir != "" {
		args = append(args, "-assets", c.AssetsDir)
	}
	if c.ConnLog != "" {
		args = append(args, "-conn-log", c.ConnLog)
	}
	if c.AcmeState != "" {
		args = append(args, "-acme-state", c.AcmeState)
	}
	if c.AcmeEnv != "" {
		args = append(args, "-acme-env", c.AcmeEnv)
	}
	return args
}

// Run 常驻循环：拉起子进程 → 等退出 → 视情况重启。ctx 取消时先停子进程再返回。
func (s *Supervisor) Run(ctx context.Context) {
	defer close(s.done)
	go func() {
		<-ctx.Done()
		_ = s.Stop()
	}()

	for {
		s.mu.Lock()
		for s.hold && ctx.Err() == nil {
			s.cond.Wait()
		}
		fast := s.fast
		s.fast = false
		s.mu.Unlock()
		if ctx.Err() != nil {
			return
		}

		started, waitfn, err := s.spawn()
		if err != nil {
			s.logf("! 启动 VPN 子进程失败: %v", err)
			if !sleepCtx(3*time.Second, ctx) {
				return
			}
			continue
		}
		s.mu.Lock()
		s.since = started
		s.mu.Unlock()
		s.logf("VPN 进程已启动: %s %s", s.bin, strings.Join(s.args, " "))

		werr := waitfn()
		s.mu.Lock()
		s.cmd = nil
		s.mu.Unlock()
		s.logf("VPN 进程退出: %v", werr)

		if ctx.Err() != nil {
			return
		}
		d := 3 * time.Second
		if fast {
			d = 300 * time.Millisecond
		}
		if !sleepCtx(d, ctx) {
			return
		}
	}
}

// logf 记一条托管器自己的日志：既进面板「服务日志」，也写 docker logs。
func (s *Supervisor) logf(format string, a ...any) {
	line := fmt.Sprintf("[supervisor] "+format, a...)
	s.buf.add(line)
	fmt.Fprintln(os.Stdout, line)
}

// spawn 启动子进程，把 stdout/stderr 同时写到本进程 stdout 和环形缓冲。
func (s *Supervisor) spawn() (time.Time, func() error, error) {
	cmd := exec.Command(s.bin, s.args...)
	// 独立进程组：停止/重启时连同它派生的子进程一起收掉；父进程被强杀时子进程收到 SIGTERM
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}

	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw

	started := time.Now()
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return started, nil, err
	}

	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()

	go s.readOutput(pr)

	return started, func() error {
		err := cmd.Wait()
		_ = pw.Close() // 触发 reader 退出（子进程的管道已关闭）
		return err
	}, nil
}

func (s *Supervisor) readOutput(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		s.buf.add(line)
		fmt.Fprintln(os.Stdout, line)
	}
	for {
		var rest [4096]byte
		n, err := r.Read(rest[:])
		if n > 0 {
			s.buf.add(string(rest[:n]))
			_, _ = os.Stdout.Write(rest[:n])
		}
		if err != nil {
			return
		}
	}
}

// State 返回 (active, enabled)，与 systemd 版本同形。
func (s *Supervisor) State() (string, string) {
	s.mu.Lock()
	running := s.cmd != nil
	s.mu.Unlock()
	if running {
		return "active", "container"
	}
	return "inactive", "container"
}

// Do 执行 start / stop / restart（供面板「服务控制」调用）。
func (s *Supervisor) Do(action string) error {
	switch action {
	case "start":
		return s.Start()
	case "stop":
		return s.Stop()
	case "restart":
		return s.Restart()
	}
	return fmt.Errorf("不支持的动作: %s", action)
}

// Start 取消停止状态并等子进程起来。
func (s *Supervisor) Start() error {
	s.mu.Lock()
	s.hold = false
	s.cond.Broadcast()
	running := s.cmd != nil
	s.mu.Unlock()
	if running {
		return nil
	}
	if err := s.waitState(true, 15*time.Second); err != nil {
		return errors.New("启动失败：子进程没有起来（看服务日志）")
	}
	return nil
}

// Stop 停止子进程并保持停止（面板「停止」）。
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	s.hold = true
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil {
		return nil
	}
	signalGroup(cmd, syscall.SIGTERM)
	if err := s.waitState(false, 15*time.Second); err != nil {
		signalGroup(cmd, syscall.SIGKILL)
		return errors.New("停止超时：已强制结束")
	}
	return nil
}

// Restart 重启子进程（面板「重启」）。
func (s *Supervisor) Restart() error {
	s.mu.Lock()
	s.hold = false
	s.fast = true
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil {
		return s.Start()
	}
	signalGroup(cmd, syscall.SIGTERM)
	if err := s.waitState(false, 15*time.Second); err != nil {
		signalGroup(cmd, syscall.SIGKILL)
		if err := s.waitState(false, 5*time.Second); err != nil {
			return errors.New("重启失败：旧进程停不下来")
		}
	}
	if err := s.waitState(true, 15*time.Second); err != nil {
		return errors.New("重启失败：子进程没有起来（看服务日志）")
	}
	return nil
}

// Since 返回当前子进程的启动时间（没在跑则为零值）。
func (s *Supervisor) Since() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.since
}

// Logs 返回最近 n 行子进程输出。
func (s *Supervisor) Logs(n int) string {
	if n <= 0 || n > s.buf.cap() {
		n = 200
	}
	return s.buf.tail(n)
}

// signalGroup 向子进程所在的整个进程组发信号（拿不到进程组时退回单进程）。
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, sig); err != nil {
		_ = cmd.Process.Signal(sig)
	}
}

func (s *Supervisor) waitState(active bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		now := s.cmd != nil
		s.mu.Unlock()
		if now == active {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("超时")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sleepCtx(d time.Duration, ctx context.Context) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---- 日志环形缓冲 ----

type logRing struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newLogRing(max int) *logRing { return &logRing{max: max} }

func (r *logRing) cap() int { return r.max }

func (r *logRing) add(line string) {
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
	r.mu.Unlock()
}

func (r *logRing) tail(n int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	if n == 0 {
		return ""
	}
	return strings.Join(r.lines[len(r.lines)-n:], "\n") + "\n"
}
