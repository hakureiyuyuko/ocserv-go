package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/hakureiyuyuko/ocserv-go/internal/acme"
)

const (
	renewThresholdDays = 30            // 剩余不足这么多天就续期
	renewCheckInterval = 6 * time.Hour // 检查间隔
)

// shouldRenew 是纯函数，方便测试：剩余天数 <= 阈值就需要续期。
// daysLeft < 0 表示读不到/无法解析证书，此时不动（避免误写）。
func shouldRenew(daysLeft, threshold int) bool {
	if daysLeft < 0 {
		return false
	}
	return daysLeft <= threshold
}

// runAutoRenew 周期性检查证书，快到期时用面板留下的参数自动续期。
// 续期只是改写磁盘上的证书文件，certStore 会在下一次握手时热加载，无需重启。
func runAutoRenew(ctx context.Context, statePath string, store *certStore, logf func(string, ...any)) {
	if logf == nil {
		logf = log.Printf
	}
	checkAndRenew(ctx, statePath, store, logf)
	tk := time.NewTicker(renewCheckInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			checkAndRenew(ctx, statePath, store, logf)
		}
	}
}

func checkAndRenew(ctx context.Context, statePath string, store *certStore, logf func(string, ...any)) {
	st, err := acme.LoadState(statePath)
	if err != nil {
		logf("! 读取自动续期配置 %s 失败: %v", statePath, err)
		return
	}
	if st == nil {
		return // 没有配置（没用面板签发过），不自动续期
	}
	days := store.DaysLeft()
	if !shouldRenew(days, renewThresholdDays) {
		logf("证书剩余 %d 天，暂不续期（阈值 %d 天）", days, renewThresholdDays)
		return
	}
	logf("证书剩余 %d 天，开始自动续期: 域名=%s 服务商=%s", days, st.Domain, st.Provider)
	if err := acme.LoadEnvFile(st.EnvFile); err != nil {
		logf("! 读取凭据文件 %s 失败，无法续期: %v", st.EnvFile, err)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	certPEM, keyPEM, err := acme.Obtain(rctx, acme.Config{
		Domain:   st.Domain,
		Email:    st.Email,
		Provider: st.Provider,
		CacheDir: st.CacheDir,
		Staging:  st.Staging,
		KeyType:  "rsa2048",
	}, func(f string, a ...any) { logf(f, a...) })
	if err != nil {
		logf("! 自动续期失败（%s 后重试）: %v", renewCheckInterval, err)
		return
	}
	if err := writeFileAtomic(store.certFile, certPEM, 0o644); err != nil {
		logf("! 写入证书失败: %v", err)
		return
	}
	if err := writeFileAtomic(store.keyFile, keyPEM, 0o600); err != nil {
		logf("! 写入私钥失败: %v", err)
		return
	}
	if _, err := store.Get(); err == nil {
		logf("证书已续期完成，热加载生效（剩余 %d 天）", store.DaysLeft())
	}
}

// writeFileAtomic 先写临时文件再 rename，避免写到一半被读到。
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
