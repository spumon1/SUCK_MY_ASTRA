package main

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
)

// FC 灌池:后台循环用 probe_accounts 里的账号定期调 FC(cloud_mint.url)打票,把打到的
// 满血 __cflb/__oailb 灌进全局路由 cookie 池(和响应侧 harvest 同一个池)。业务侧在
// 池模式(cloud_mint.enabled=false)下靠池引导,让每个账号都复用池里的满血 cookie。
//
// 账号的 access_token 经只读管理 API 取得(复用 probe 的 probeClient/probeDownloadCreds),
// 不写账号文件、不刷新 OAuth。整个循环随插件配置变更与关闭而干净取消。
var poolFiller = struct {
	sync.Mutex
	cancel context.CancelFunc
}{}

// poolFillStatus is the dashboard view of the灌池 loop: whether it is running,
// its cadence and scope, and the outcome of the last completed round. Updated
// on reconfigure/stop and at the end of every round.
var poolFillStatus = struct {
	sync.Mutex
	running     bool
	intervalMS  int
	accounts    int
	models      int
	gateway     string
	lastRoundAt time.Time
	lastPooled  int
	lastAttempt int
}{}

type poolFillSnap struct {
	Running     bool   `json:"running"`
	IntervalMS  int    `json:"interval_ms"`
	Accounts    int    `json:"accounts"`
	Models      int    `json:"models"`
	Gateway     string `json:"gateway"`
	LastRoundAt string `json:"last_round_at,omitempty"`
	LastPooled  int    `json:"last_pooled"`
	LastAttempt int    `json:"last_attempt"`
}

func poolFillSnapshot() poolFillSnap {
	poolFillStatus.Lock()
	defer poolFillStatus.Unlock()
	snap := poolFillSnap{
		Running: poolFillStatus.running, IntervalMS: poolFillStatus.intervalMS,
		Accounts: poolFillStatus.accounts, Models: poolFillStatus.models, Gateway: poolFillStatus.gateway,
		LastPooled: poolFillStatus.lastPooled, LastAttempt: poolFillStatus.lastAttempt,
	}
	if !poolFillStatus.lastRoundAt.IsZero() {
		snap.LastRoundAt = poolFillStatus.lastRoundAt.UTC().Format(time.RFC3339)
	}
	return snap
}

// 按新配置重启灌池循环:先停旧的,若 cloud_mint.pool_fill 开启则起新的。
func cloudPoolFillerReconfigure(cfg pluginConfig) {
	poolFiller.Lock()
	defer poolFiller.Unlock()
	if poolFiller.cancel != nil {
		poolFiller.cancel()
		poolFiller.cancel = nil
	}
	if !cfg.CloudMint.PoolFill {
		poolFillStatus.Lock()
		poolFillStatus.running = false
		poolFillStatus.Unlock()
		return
	}
	poolFillStatus.Lock()
	poolFillStatus.running = true
	poolFillStatus.intervalMS = cfg.CloudMint.poolFillIntervalMS()
	poolFillStatus.accounts = len(cfg.ProbeAccounts)
	poolFillStatus.models = len(cfg.Models)
	poolFillStatus.gateway = cfg.CloudMint.Gateway
	poolFillStatus.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	poolFiller.cancel = cancel
	go cloudPoolFillLoop(ctx, cfg)
	log.Printf(logPrefix+"FC 灌池循环启动:accounts=%d models=%d interval=%dms gateway=%s url=%q",
		len(cfg.ProbeAccounts), len(cfg.Models), cfg.CloudMint.poolFillIntervalMS(), cfg.CloudMint.Gateway, cfg.CloudMint.URL)
}

func cloudPoolFillerStop() {
	poolFiller.Lock()
	defer poolFiller.Unlock()
	if poolFiller.cancel != nil {
		poolFiller.cancel()
		poolFiller.cancel = nil
	}
	poolFillStatus.Lock()
	poolFillStatus.running = false
	poolFillStatus.Unlock()
}

func cloudPoolFillLoop(ctx context.Context, cfg pluginConfig) {
	interval := time.Duration(cfg.CloudMint.poolFillIntervalMS()) * time.Millisecond
	for {
		cloudPoolFillOnce(ctx, cfg)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// 一轮:读账号 token,逐账号逐模型调 FC 打票,成功则把 pair 灌进全局池。
func cloudPoolFillOnce(ctx context.Context, cfg pluginConfig) {
	if len(cfg.ProbeAccounts) == 0 || len(cfg.Models) == 0 {
		return
	}
	key := os.Getenv(cfg.CloudMint.KeyEnv)
	if key == "" {
		cloudRecordLog("FC 灌池跳过", "relay key 环境变量未设")
		return
	}
	proxyURL, err := cfg.CloudMint.resolvedProxy()
	if err != nil {
		cloudRecordLog("FC 灌池跳过", "%s", err)
		return
	}
	client := newProbeClient(cfg)
	creds := probeDownloadCreds(ctx, client, cfg.ProbeAccounts, time.Now())
	pooled := 0
	attempt := 0
	for _, cred := range creds {
		for _, model := range cfg.Models {
			select {
			case <-ctx.Done():
				return
			default:
			}
			attempt++
			work := cloudMintWork{
				cfg:      cfg.CloudMint,
				creds:    cloudMintCredentials{AuthID: cred.name, AccessToken: cred.accessToken, AccountID: cred.accountID},
				model:    model,
				key:      key,
				proxyURL: proxyURL,
			}
			mctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.CloudMint.TimeoutMS)*time.Millisecond)
			entry, mErr := requestCloudMint(mctx, work)
			cancel()
			if mErr != nil {
				cloudRecordLog("FC 灌池失败", "账号 #%s · %s · %s", cloudFingerprint(cred.name), cloudSafeLabel(model), mErr)
				continue
			}
			if len(entry.Cookies) == 0 {
				cloudRecordLog("FC 灌池失败", "账号 #%s · %s · 无 cookie", cloudFingerprint(cred.name), cloudSafeLabel(model))
				continue
			}
			now := time.Now()
			state.mu.Lock()
			state.noteRouteCookiesLocked(routeCookieSet{pairs: entry.Cookies, seenAt: now, expireAt: entry.ExpiresAt}, "cloud-fill")
			state.mu.Unlock()
			pooled++
			cloudRecordLog("FC 灌池", "账号 #%s · %s · 网关 %s · 票长 %d",
				cloudFingerprint(cred.name), cloudSafeLabel(model), entry.Gateway, len(entry.Ticket))
		}
	}
	poolFillStatus.Lock()
	poolFillStatus.lastRoundAt = time.Now()
	poolFillStatus.lastPooled = pooled
	poolFillStatus.lastAttempt = attempt
	poolFillStatus.Unlock()
	if pooled > 0 {
		log.Printf(logPrefix+"FC 灌池一轮:入池 %d 个满血 pair", pooled)
	}
}
