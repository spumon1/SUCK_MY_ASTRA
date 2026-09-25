package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// 灌池:后台循环用 probe_accounts 里的账号定期向每个启用的灌池源打票,把打到的
// 满血 __cflb/__oailb 灌进同一个全局路由 cookie 池(和响应侧 harvest 同一个池)。
// 两个源(fc = 公网阿里云函数;relay = 本机住宅代理 relay)各自开关、各自地址与
// 前置代理,可并行灌池,打到的 pair 都进同一个池。业务侧在池模式下靠池引导复用。
//
// 账号的 access_token 经只读管理 API 取得(复用 probe 的 probeClient/probeDownloadCreds),
// 不写账号文件、不刷新 OAuth。整个循环随插件配置变更与关闭而干净取消。
var poolFiller = struct {
	sync.Mutex
	cancel context.CancelFunc
}{}

// fillSourceStat 记录单个灌池源上一轮的结果。
type fillSourceStat struct {
	enabled     bool
	lastRoundAt time.Time
	lastPooled  int
	lastAttempt int
}

// poolFillStatus 是灌池循环的面板视图:是否运行、节奏与范围,以及每个源上一轮
// 的结果。在配置变更/关闭与每轮结束时更新。
var poolFillStatus = struct {
	sync.Mutex
	running    bool
	intervalMS int
	accounts   int
	models     int
	gateway    string
	sources    map[string]*fillSourceStat
}{sources: map[string]*fillSourceStat{}}

type fillSourceSnap struct {
	Enabled     bool   `json:"enabled"`
	LastRoundAt string `json:"last_round_at,omitempty"`
	LastPooled  int    `json:"last_pooled"`
	LastAttempt int    `json:"last_attempt"`
}

type poolFillSnap struct {
	Running     bool                      `json:"running"`
	IntervalMS  int                       `json:"interval_ms"`
	Accounts    int                       `json:"accounts"`
	Models      int                       `json:"models"`
	Gateway     string                    `json:"gateway"`
	LastPooled  int                       `json:"last_pooled"`
	LastAttempt int                       `json:"last_attempt"`
	LastRoundAt string                    `json:"last_round_at,omitempty"`
	Sources     map[string]fillSourceSnap `json:"sources"`
}

func poolFillSnapshot() poolFillSnap {
	poolFillStatus.Lock()
	defer poolFillStatus.Unlock()
	snap := poolFillSnap{
		Running: poolFillStatus.running, IntervalMS: poolFillStatus.intervalMS,
		Accounts: poolFillStatus.accounts, Models: poolFillStatus.models, Gateway: poolFillStatus.gateway,
		Sources: map[string]fillSourceSnap{},
	}
	var last time.Time
	for name, st := range poolFillStatus.sources {
		s := fillSourceSnap{Enabled: st.enabled, LastPooled: st.lastPooled, LastAttempt: st.lastAttempt}
		if !st.lastRoundAt.IsZero() {
			s.LastRoundAt = st.lastRoundAt.UTC().Format(time.RFC3339)
			if st.lastRoundAt.After(last) {
				last = st.lastRoundAt
			}
		}
		snap.Sources[name] = s
		snap.LastPooled += st.lastPooled
		snap.LastAttempt += st.lastAttempt
	}
	if !last.IsZero() {
		snap.LastRoundAt = last.UTC().Format(time.RFC3339)
	}
	return snap
}

// 按新配置重启灌池循环:先停旧的,若任一灌池源启用(或旧 pool_fill)则起新的。
func cloudPoolFillerReconfigure(cfg pluginConfig) {
	poolFiller.Lock()
	defer poolFiller.Unlock()
	if poolFiller.cancel != nil {
		poolFiller.cancel()
		poolFiller.cancel = nil
	}
	targets := cfg.CloudMint.fillTargets()
	if !cfg.CloudMint.poolFillActive() || len(targets) == 0 {
		poolFillStatus.Lock()
		poolFillStatus.running = false
		poolFillStatus.sources = map[string]*fillSourceStat{}
		poolFillStatus.Unlock()
		return
	}
	poolFillStatus.Lock()
	poolFillStatus.running = true
	poolFillStatus.intervalMS = cfg.CloudMint.poolFillIntervalMS()
	poolFillStatus.accounts = len(cfg.ProbeAccounts)
	poolFillStatus.models = len(cfg.Models)
	poolFillStatus.gateway = cfg.CloudMint.Gateway
	next := map[string]*fillSourceStat{}
	for _, t := range targets {
		if old := poolFillStatus.sources[t.Name]; old != nil {
			old.enabled = true
			next[t.Name] = old
		} else {
			next[t.Name] = &fillSourceStat{enabled: true}
		}
	}
	poolFillStatus.sources = next
	poolFillStatus.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	poolFiller.cancel = cancel
	go cloudPoolFillLoop(ctx, cfg)
	log.Printf(logPrefix+"灌池循环启动:accounts=%d models=%d interval=%dms gateway=%s 源=[%s]",
		len(cfg.ProbeAccounts), len(cfg.Models), cfg.CloudMint.poolFillIntervalMS(), cfg.CloudMint.Gateway, fillTargetsSummary(targets))
}

// fillTargetsSummary 给日志用:源名 + 脱敏端点,不打印代理凭据。
func fillTargetsSummary(targets []cloudFillTarget) string {
	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		parts = append(parts, fmt.Sprintf("%s→%s", t.Name, maskProxyURL(t.URL)))
	}
	return strings.Join(parts, ", ")
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

// 一轮:读一次账号 token,再对每个启用的灌池源各跑一遍(逐账号逐模型打票,
// 成功则把 pair 灌进同一个全局池)。
func cloudPoolFillOnce(ctx context.Context, cfg pluginConfig) {
	targets := cfg.CloudMint.fillTargets()
	if len(cfg.ProbeAccounts) == 0 || len(cfg.Models) == 0 || len(targets) == 0 {
		return
	}
	key := os.Getenv(cfg.CloudMint.KeyEnv)
	if key == "" {
		cloudRecordLog("灌池跳过", "relay key 环境变量未设")
		return
	}
	client := newProbeClient(cfg)
	creds := probeDownloadCreds(ctx, client, cfg.ProbeAccounts, time.Now())
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		cloudPoolFillSource(ctx, cfg, t, creds, key)
	}
}

// cloudPoolFillSource 用一个灌池源打一轮,并记录该源的本轮结果。
func cloudPoolFillSource(ctx context.Context, cfg pluginConfig, t cloudFillTarget, creds map[string]probeCredential, key string) {
	proxyURL, err := t.resolvedProxy()
	if err != nil {
		cloudRecordLog(t.Name+" 灌池跳过", "%s", err)
		return
	}
	scfg := cfg.CloudMint
	scfg.URL = t.URL
	pooled, attempt := 0, 0
	for _, cred := range creds {
		for _, model := range cfg.Models {
			select {
			case <-ctx.Done():
				return
			default:
			}
			attempt++
			work := cloudMintWork{
				cfg:      scfg,
				creds:    cloudMintCredentials{AuthID: cred.name, AccessToken: cred.accessToken, AccountID: cred.accountID},
				model:    model,
				key:      key,
				proxyURL: proxyURL,
			}
			mctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.CloudMint.TimeoutMS)*time.Millisecond)
			entry, mErr := requestCloudMint(mctx, work)
			cancel()
			if mErr != nil {
				cloudRecordLog(t.Name+" 灌池失败", "账号 #%s · %s · %s", cloudFingerprint(cred.name), cloudSafeLabel(model), mErr)
				continue
			}
			if len(entry.Cookies) == 0 {
				cloudRecordLog(t.Name+" 灌池失败", "账号 #%s · %s · 无 cookie", cloudFingerprint(cred.name), cloudSafeLabel(model))
				continue
			}
			now := time.Now()
			state.mu.Lock()
			state.noteRouteCookiesLocked(routeCookieSet{pairs: entry.Cookies, seenAt: now, expireAt: entry.ExpiresAt}, "cloud-fill:"+t.Name)
			state.mu.Unlock()
			pooled++
			cloudRecordLog(t.Name+" 灌池", "账号 #%s · %s · 网关 %s · 票长 %d",
				cloudFingerprint(cred.name), cloudSafeLabel(model), entry.Gateway, len(entry.Ticket))
		}
	}
	poolFillStatus.Lock()
	st := poolFillStatus.sources[t.Name]
	if st == nil {
		st = &fillSourceStat{}
		poolFillStatus.sources[t.Name] = st
	}
	st.enabled = true
	st.lastRoundAt = time.Now()
	st.lastPooled = pooled
	st.lastAttempt = attempt
	poolFillStatus.Unlock()
	if pooled > 0 {
		log.Printf(logPrefix+"%s 灌池一轮:入池 %d 个满血 pair", t.Name, pooled)
	}
}
