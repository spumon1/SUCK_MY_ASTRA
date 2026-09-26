// 插件里的离线采集员直接向上游收 __cflb/__oailb 路由 pair；
// 不借 CPA 的柜台过账，也不碰它的状态。
//
// # 为什么自己跑腿，而不是把整间店翻过来
//
// 旧方案为让 CPA 响应钩子认出账号，先禁用其余 Codex 账号，
// 再 PATCH 代理到凭据、POST CPA 的 /v1/responses，最后逐项恢复。
// 曾有一次中途散场，凭据留在禁用状态，真把营业掀了桌；也无法与业务并行。
//
// 现在只用只读管理调用，从账号自己的凭据文件读取 access_token，
// 经该账号出口直连 https://chatgpt.com/backend-api/codex/responses。
// CPA 看不到这次请求。响应给的是 GLOBAL 路由凭据：pair 可供任意账号使用，
// 哪个账号铸出来不影响入池，所有账号照常营业。
//
// 拿着真实凭据，也得守三条柜台规矩：
//   - 绝不写 CPA；只发两个 GET：auth-files 取名单，auth-files/download 取 token。
//   - 绝不刷新 token；过期就跳过，留给 CPA 在正常业务中刷新。
//     这里刷新可能轮换 refresh token，把线上客人的凳子抽走。
//     access token 实测能活数天，这点克制代价很小。
//   - 采集与引导同进程各做各的：business 请求钩子读池，本 goroutine 往池里补货。
//
// # 续期不是等锅冷了再找柴
//
// pair 的 HTTP 声明为一小时：oailb Max-Age=3600、cflb Expires=+1h，
// oailb JWT 自己签的是 iat+3900s；实测可用时间远超旧票的 ~240s 窗口。
// 首轮补满不收摊：池中最长寿条目的余量低于 probeRenewThreshold 就后台补 pair，
// 只要 CPA 还营业就保持池子有货，这才是“到期前自动续一遍”。
//
// # 这些东西不能拿到台前当道具
//
// probeRunState.Lines 会显示在无需密钥的页面上。
// token、turn-state、cookie 原值和代理 userinfo 都不能登台：代理经
// probeShowProxy/maskProxyURL，含客户邮箱的账号名经 maskAuthLabel，
// 所有写入 Lines 的文字再过 probeRedact 这道门。读到的管理密钥也绝不记日志。
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 采集员只认这两条只读管理路由，集中挂牌便于不同 CPA 构建改一处就换门牌。
// 不调用其他 CPA 路由，尤其没有写路由；跑堂不能顺手改账本。
const (
	probeRouteAuthFiles    = "/v0/management/auth-files"
	probeRouteAuthDownload = "/v0/management/auth-files/download"
)

// 上游端点与探针身份用 var 留给测试换成 httptest 的假柜台，生产不改。
// probeUserAgent 对齐真实 codex-tui 构建；同机器、同 CPA 账号发请求，
// 上游看到的仍是普通 Codex 流量这身衣服，不另戴一顶神秘帽子。
var (
	probeUpstreamURL = "https://chatgpt.com/backend-api/codex/responses"
	probeUserAgent   = "codex-tui/0.154.0 (Ubuntu 24.04; x86_64) OVH (codex-tui; 0.154.0)"
)

const (
	// probeMaxLines 给流水账封顶，只留最近四十行交代进度与缘由。
	// 进程要开张数周，不能让账本胖到把柜台压塌。
	probeMaxLines = 40

	// probeFireTimeout 管住单次上游调用，只等先于 SSE 正文到达的响应头。
	// 时间给得宽，仍得有闹钟，免得故障出口把 goroutine 留作人质。
	probeFireTimeout = 60 * time.Second
	probeMgmtTimeout = 30 * time.Second

	// probeMaxAccountsInFlight 数的是同时工作的凭据，不是随意放飞的请求。
	// 每账号只派一个 goroutine，逐桶办理，因此也是同时在途请求的上限，
	// 尤其保证同一账号不会两路同时敲门。
	//
	// 上游限速认账号，不认我们嗓门：2026-09-18 曾把六桶 × 十出口连着打，
	// 四秒发 60 请求，两个账号各约 ~7.5/s，结果 21 次 429。
	// 本来正常营业的凭据，被探针自己敲成了关门谢客。
	probeMaxAccountsInFlight = 4

	// probeMaxBodyBytes 只允许少量排空正文，照顾 socket 复用。
	// 要的是响应头，不是把整条 SSE 长卷搬进堆内存当桌布。
	probeMaxBodyBytes = 1 << 10

	// probeMgmtMaxBodyBytes 限制 auth-files 与 token 下载的响应大小。
	// CPA 名单带配额、冷却、近期请求，几个凭据就有数十 KB；旧 64KB 上限
	// 曾把 JSON 拦腰切断，报成 “unexpected end of JSON”，切菜刀背了语法锅。
	// 正文来自自家 CPA，上限主要防错配 base_url 把无底洞灌进内存。
	probeMgmtMaxBodyBytes = 4 << 20
)

// 续期节奏用 var 让测试拨快时钟，生产不动这口钟。
// 每隔 probeRenewInterval 检查最长寿 pair，余量低于 probeRenewThreshold 就补货。
// 在 T+(ttl-threshold) 动身，与声明的一小时窗口重叠，不能等最后一秒才借梯子。
// 续期失败先消耗重叠余量，不立即变成空池；每个续期窗口每出口一次调用。
var (
	probeRenewInterval  = 20 * time.Second
	probeRenewThreshold = 120 * time.Second

	// probeExitCooldown 管未产出 pair 的 (exit, account, model) 三人小队。
	// 同一组合两次上游调用至少隔这段时间，不能每 tick 去敲同一扇空门。
	// 2026-09-18 实测旧逻辑每小时打 540 次，全是 312，凭据本就在限流，
	// 还不断上门问为什么不接客，正是限速器要挡的动静。
	//
	// 成功铸票则缩短为 probeSuccessRest：续期还要请这位有货的老伙计。
	// 下面 55 分钟只让耗尽或限流的组合坐冷板凳；刚回 312 的 IP 保守歇近一小时。
	probeExitCooldown = 55 * time.Minute

	// probeExitPause 让同一目标的出口依次留出空拍。
	// 十个出口若一秒内轮流敲同一凭据，便重演 2026-09-18 的 429；
	// 池子越大锣鼓越急，本想扩大覆盖，反把突发越敲越响。
	//
	// 间隔两秒不伤筋骨：同一组合最多每 probeExitCooldown 重试一次，
	// 一轮走一分钟还是四秒影响很小，消掉那阵突发才有用。
	probeExitPause = 2 * time.Second

	// probeRotatingAttempts 是每次访问轮换池的调用预算，
	// 全未产出 pair 时按 probeRotatingCooldown 歇场。
	//
	// 静态代理一 URL 一 IP，312 后每 55 分钟一次才有意义；轮换门牌却不一样。
	// 2026-09-19 实测同一入口连续二十次请求拿到二十个住宅地址，
	// 下一次重拨才有机会离开返回 312 的地址。套静态冷却只用到轮换能力的 1/N。
	//
	// 用户选定十次尝试后等十分钟，即每目标每小时最多 60 次，账要明白记。
	// 这不提高瞬时速率：仍每账号一个 goroutine，每次隔 probeExitPause，
	// 单凭据大约两秒一次，不重演 2026-09-18 的突发 429。
	//
	// 没有递增退避是明确取舍，不是藏着灵药：账号级限流若一直回 312 而非 429，
	// 这里不会自动察觉并减速；自动刹车只认 429 路径。
	probeRotatingAttempts = 10
	probeRotatingCooldown = 10 * time.Minute

	// probeAccountBackoff 让收到账号级拒绝（429 或 token 被拒）的凭据歇场。
	// 它不等于 probeExitCooldown：312 指向这个账号、模型下的出口 IP，
	// 另一个出口可能可用；429 是账号被嫌问得太勤，换门牌继续敲只会更吵。
	probeAccountBackoff = 10 * time.Minute
)

// probeRunState 是面板轮询的场记快照，只带进度与说明，不带任何凭据。
// Lines 不是保险柜，脱敏规矩见文件开头。
type probeRunState struct {
	Running    bool     `json:"running"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Done       int      `json:"done"`
	Total      int      `json:"total"`
	Current    string   `json:"current,omitempty"`
	Lines      []string `json:"lines,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// probeRunner 只容纳一个进程内任务；续期循环由它独占，
// 另开一队只会拿同一凭据重复铸同样的 pair，忙得热闹却不添菜。
// 采集直连上游，不再改 CPA 状态，所以停止只需取消，没有账要回填。
var probeRunner struct {
	mu     sync.Mutex
	run    probeRunState
	cancel context.CancelFunc
}

// probeTarget 是准备出门的 (account, payload-model) 搭档。
// pair 不绑模型，模型只给上游载荷填名牌，因此各目标使用首个已配模型。
type probeTarget struct {
	account string
	model   string
}

// probeCredential 从账号文件读一次可用状态，口袋里有 accessToken 秘密。
// 这位不能登日志公告栏。
type probeCredential struct {
	name        string
	accessToken string
	accountID   string
	proxyURL    string
	expiresAt   time.Time
}

// probeRunStart 先验入场手续再启动后台 goroutine，动身后返回 nil。
// 不准开场就返回拒绝原因，柜台原状不动一笔。
func probeRunStart() error {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	accounts := append([]string(nil), cfg.ProbeAccounts...)
	models := append([]string(nil), cfg.Models...)
	proxies := append([]string(nil), cfg.ProbeProxies...)
	rotating := append([]string(nil), cfg.ProbeProxiesRotating...)

	switch {
	case len(accounts) == 0:
		// 没选账号不能翻译成“全店都请”：每账号、每次续期都花一个上游请求。
		// 把空名单当全名单，会悄悄替用户没点名的凭据付配额账。
		return fmt.Errorf("probe_accounts is empty, so there is nothing to probe; refusing to widen an empty selection to every credential")
	case len(models) == 0:
		return fmt.Errorf("models is empty, so there is no payload to mint with")
	case strings.TrimSpace(cfg.ProbeManagementKey) == "":
		return fmt.Errorf("probe_management_key is not set; it is the Bearer for GET %s and %s, the two read-only calls that fetch the account list and each credential's token", probeRouteAuthFiles, probeRouteAuthDownload)
	case strings.TrimSpace(cfg.StoreDir) == "":
		return fmt.Errorf("store_dir is empty, so a minted pair has nowhere to be pooled for the business role to read")
	}

	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if probeRunner.run.Running {
		return fmt.Errorf("a probe is already running; stop it before starting another")
	}

	ctx, cancel := context.WithCancel(context.Background())
	probeRunner.cancel = cancel
	probeRunner.run = probeRunState{
		Running:   true,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	go probeSweep(ctx, cfg, accounts, models, proxies, rotating)
	return nil
}

// probeRunCancel 通知初始扫描与续期循环收摊，无任务时返回 false。
// 离线采集没改过凭据，停场无需再把别人的椅子搬回原位。
func probeRunCancel() bool {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if !probeRunner.run.Running || probeRunner.cancel == nil {
		return false
	}
	probeRunner.cancel()
	probeRunner.run.Lines = probeAppendLine(probeRunner.run.Lines, "stop requested; the probe will finish the current harvest and exit")
	return true
}

// probeRunSnapshot 连 Lines 一起复制快照再交给 JSON 编码器。
// 任务继续添账时，编码器读自己的那本，不抢同一支笔。
func probeRunSnapshot() probeRunState {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	out := probeRunner.run
	out.Lines = append([]string(nil), probeRunner.run.Lines...)
	return out
}

// probeRunUpdate 拿到守护状态的那把互斥锁才改账，别两位掌柜同时涂数字。
func probeRunUpdate(mutate func(run *probeRunState)) {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	mutate(&probeRunner.run)
}

// probeRunLog 向流水账添一行，并同步到进程日志。
//
// 每行先过 probeRedact；调用方仍应先用 maskProxyURL 与 maskAuthLabel
// 遮好代理和账号。这是第二道门，不是第一道：Lines 的读者没有出示密钥。
func probeRunLog(format string, args ...any) {
	line := probeRedact(fmt.Sprintf(format, args...))
	probeRunUpdate(func(run *probeRunState) {
		run.Lines = probeAppendLine(run.Lines, line)
	})
	log.Printf("%sprobe %s", logPrefix, line)
}

// probeRunFail 只记最早把任务绊倒的原因，后来摔倒的杯碟别抢主因的座位。
func probeRunFail(errRun error) {
	if errRun == nil {
		return
	}
	message := probeRedact(errRun.Error())
	probeRunUpdate(func(run *probeRunState) {
		if run.Error == "" {
			run.Error = message
		}
		run.Lines = probeAppendLine(run.Lines, "error: "+message)
	})
	log.Printf("%sprobe error: %s", logPrefix, message)
}

// probeRunFinish 在 probeSweep 最外层 defer 收尾。
// 续期循环取消并返回才算散场，不能演员还在后台就先熄灯。
func probeRunFinish() {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	probeRunner.run.Running = false
	probeRunner.run.Current = ""
	probeRunner.run.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if probeRunner.cancel != nil {
		probeRunner.cancel()
		probeRunner.cancel = nil
	}
}

// probeAppendLine 给新行盖时间戳并限制流水账长度，不把收据养成无底长卷。
func probeAppendLine(lines []string, line string) []string {
	lines = append(lines, time.Now().UTC().Format("15:04:05")+" "+line)
	if len(lines) > probeMaxLines {
		// 真复制，不只改切片边界；后者仍吊着整块底层数组，像说搬家却把旧楼背走。
		lines = append([]string(nil), lines[len(lines)-probeMaxLines:]...)
	}
	return lines
}

// probeSweep 总管这场戏：读凭据、每账号首轮铸 pair，再留守续期。
// 这是本文件启动整场任务的 goroutine，别把首轮上菜误认成关门。
func probeSweep(ctx context.Context, cfg pluginConfig, accounts, models, proxies, rotating []string) {
	// 先登记的 defer 最后走；下面续期循环没返回，收工锣就不能响。
	defer probeRunFinish()
	// 原生插件的 panic 会掀翻整个 CPA 进程，这个 goroutine 得自己接住飞来的盘子。
	defer func() {
		if recovered := recover(); recovered != nil {
			probeRunFail(fmt.Errorf("probe panicked: %v", recovered))
		}
	}()

	pool := newProbeClientPool()
	defer pool.closeIdle()
	client := newProbeClient(cfg)
	defer client.http.CloseIdleConnections()

	auths, errList := client.listCodexAuths(ctx)
	if errList != nil {
		probeRunFail(fmt.Errorf("could not list Codex credentials: %w", errList))
		return
	}
	// 选中名单里若有 CPA 不认识的账号就停场，不能少请一位却假装全员到齐。
	known := make(map[string]bool, len(auths))
	for _, auth := range auths {
		known[auth.Name] = true
	}
	for _, account := range accounts {
		if !known[account] {
			probeRunFail(fmt.Errorf("selected account %q is not among CPA's Codex credentials; fix the selection rather than probing something CPA cannot serve", account))
			return
		}
	}

	now := time.Now()
	creds := probeDownloadCreds(ctx, client, accounts, now)
	if len(creds) == 0 {
		probeRunFail(fmt.Errorf("no usable credentials: every selected account's token was unreadable or already expired"))
		return
	}

	idxOf := probeAccountIndex(accounts)
	targets := probePendingTargets(cfg, accounts, models)
	probeRunUpdate(func(run *probeRunState) { run.Total = len(targets) })
	probeRunLog("offline harvest: %d account(s) to mint a pair each, %d static exit(s) + %d rotating entr(ies)", len(targets), len(proxies), len(rotating))
	if len(targets) > 0 {
		if cooling := probeFireBatch(ctx, cfg, pool, creds, targets, idxOf, proxies, rotating, true); cooling > 0 {
			// 每轮只解释一次，不按目标、tick 反复报幕。
			// 刚扫描完多数出口仍在冷却，用户按了按钮要知道为何没动静，不需要听复读戏。
			probeRunLog("%d target(s) skipped: every exit already tried within the %s cooldown", cooling, probeExitCooldown)
		}
	} else {
		probeRunLog("no accounts in scope to mint with")
	}

	if ctx.Err() != nil {
		probeRunLog("stopped on request")
		return
	}

	// 首轮结束不等于散席；CPA 仍营业，引导就仍需活 pair。
	// 池中最长寿条目快到期前自动补一遍，直到任务取消或插件重载才收摊。
	probeRunLog("initial fill done; renewal active — the pool re-mints automatically within %s of the best entry's expiry", probeRenewThreshold)
	probeRunUpdate(func(run *probeRunState) { run.Current = "renewal active" })
	probeRenewLoop(ctx, pool)
}

// probeAccountIndex 给选中账号排座次，probeExits 按此顺序分配代理入口。
func probeAccountIndex(accounts []string) map[string]int {
	idx := make(map[string]int, len(accounts))
	for i, name := range accounts {
		idx[name] = i
	}
	return idx
}

// probeFireBatch 统一并发出场口，受 probeMaxAccountsInFlight 约束。
// 首轮 countDone 推进进度条；续期没有固定 Total，就不拿它虚报进度。
// 两边共走这一扇门，免得各自给并发上限开后门。
func probeFireBatch(ctx context.Context, cfg pluginConfig, pool *probeClientPool, creds map[string]probeCredential, targets []probeTarget, idxOf map[string]int, proxies, rotating []string, countDone bool) int {
	// 按凭据分组，每个只派一个 goroutine 依次办目标，不能按目标乱放队伍。
	// 旧方式让同账号同时出门，曾达到 ~7.5 请求/秒而收到 429。
	// 现在同账号同刻一请求，再用 probeExitPause 留空拍，队伍不挤成一团。
	byAccount := make(map[string][]probeTarget, len(creds))
	var order []string
	for _, target := range targets {
		if _, seen := byAccount[target.account]; !seen {
			order = append(order, target.account)
		}
		byAccount[target.account] = append(byAccount[target.account], target)
	}

	var cooling atomic.Int64
	sem := make(chan struct{}, probeMaxAccountsInFlight)
	var wg sync.WaitGroup
	for _, account := range order {
		cred, ok := creds[account]
		if !ok {
			// 凭据不可读或已过期的原因已记账；目标仍计入 done。
			// 失败也要点名退场，进度条才到 Total，不会永远欠一把椅子。
			if countDone {
				missing := len(byAccount[account])
				probeRunUpdate(func(run *probeRunState) { run.Done += missing })
			}
			continue
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(list []probeTarget, cred probeCredential, accountIdx int) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, target := range list {
				if ctx.Err() != nil {
					return
				}
				if !probeHarvestBucket(ctx, cfg, pool, cred, target.model, proxies, rotating, accountIdx) {
					cooling.Add(1)
				}
				if countDone {
					probeRunUpdate(func(run *probeRunState) { run.Done++ })
				}
			}
		}(byAccount[account], cred, idxOf[account])
	}
	wg.Wait()
	return int(cooling.Load())
}

// probeHarvestBucket 沿账号出口队列取 pair：冷却已过的出口各试一次，
// 首个成功入池即收队。初始补池与续期共用这条路，claim 防止彼此抢同一桌。
//
// 返回是否真发过上游请求；全部出口还在 probeExitCooldown 就安静返回 false，
// 免得续期循环每分钟朗诵同一份“今日歇业”。
func probeHarvestBucket(ctx context.Context, cfg pluginConfig, pool *probeClientPool, cred probeCredential, model string, proxies, rotating []string, accountIdx int) bool {
	key := bucketKey(cred.name, model)
	if !probeClaim(key) {
		// 同一目标已经有人跑腿，可能是另一个循环或先到的续期 tick。
		// 再发一次只会花配额拿近乎相同的值互相覆盖，不叫双倍勤快。
		return false
	}
	defer probeRelease(key)

	short := maskAuthLabel(cred.name)
	if !probeAccountReady(cred.name, time.Now()) {
		// 上游已请此凭据休息，就静默跳过；别让续期每分钟逐桶喊它起床。
		return false
	}

	// 静态出口先上桌：每 IP 每窗口一次预算，过窗未用便作废；
	// 轮换池随时能领新地址，留它接剩下的活，不先浪费易过期的那份。
	//
	// 有轮换池时，空静态池绝不能偷偷变成直连。
	// probe_proxies 为空原指本机出口，仅在没有其他配置时合理；
	// 用户把池全挪去 probe_proxies_rotating 后，不能背着他又从服务器地址出门。
	staticExits := probeExits(proxies, accountIdx)
	if len(proxies) == 0 && len(rotating) > 0 {
		staticExits = nil
	}

	fired := false
	for _, exit := range staticExits {
		if ctx.Err() != nil {
			return fired
		}
		// 只给真正发出的尝试留空拍；跳过冷却出口不花请求，别空站着数拍子。
		if fired && !probeSleep(ctx, probeExitPause) {
			return fired
		}
		now := time.Now()
		if !probeCooldownReady(exit, cred.name, model, now) {
			// 这个窗口已花过预算，安静略过；否则四十行流水账很快被逐桶逐 tick 的唠叨挤满。
			continue
		}
		client, errClient := pool.get(exit)
		if errClient != nil {
			probeRunLog("%s %s: exit %s unusable, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errClient.Error()))
			continue
		}

		// 调用前先记预算，不能吃完才记账。
		// 请求超时或 goroutine 中途退场也已经花了一次，保证同组合每窗口至多一次上游调用。
		probeCooldownMark(exit, cred.name, model, now)
		fired = true

		res, errFire := probeFireUpstream(ctx, client, cred, model)
		if errFire != nil {
			// 传输没走通说明这条出口没把请求送到；换下一位跑堂还有机会。
			probeRunLog("%s %s: exit %s failed at transport, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errFire.Error()))
			continue
		}
		switch probeConsume(cfg, cred.name, short, model, res, exit) {
		case probeOutcomeStored:
			// 刚铸成功的出口到 T+(ttl-threshold) 还得回来续期，休息应对齐该时刻。
			// 若仍罚坐满 55 分钟，pair 按声明到期时就没人接班了。
			probeCooldownSet(exit, cred.name, model, time.Now().Add(probeSuccessRest(cfg)))
			return true
		case probeOutcomeAccountLimited:
			// 账号级拒绝不是门牌故障；剩下出口带的仍是同一凭据，再走只会添乱。
			probeAccountSetBackoff(cred.name, time.Now())
			return fired
		}
		// 没记成功而回 312，指向这个账号与模型下的当前出口 IP，不代表整桶没救。
		// 下一出口换 IP 后仍应轮到它；旧逻辑见 312 就收摊，整池其他门都没敲过。
	}

	if len(rotating) > 0 {
		stored, rotFired := probeHarvestRotating(ctx, cfg, pool, cred, short, model, rotating, accountIdx)
		fired = fired || rotFired
		if stored {
			return true
		}
	}
	return fired
}

// probeHarvestRotating 每桶最多花 probeRotatingAttempts 次，轮流用配置入口。
// 常见入口是同一网关的不同凭据，轮用分担负载，每次调用仍拿新地址；
// 起点取账号索引，让并行账号别齐步冲向同一柜台。
//
// 先按失败窗口占预算，实际存入模板后才调整成功窗口。
// 取消或中途退场也算花过尝试，与静态路径一样先记账，不能回来再点一份免单。
func probeHarvestRotating(ctx context.Context, cfg pluginConfig, pool *probeClientPool, cred probeCredential, short, model string, rotating []string, accountIdx int) (stored, fired bool) {
	now := time.Now()
	if !probeCooldownReady(probeRotatingExit, cred.name, model, now) {
		return false, false
	}
	probeCooldownSet(probeRotatingExit, cred.name, model, now.Add(probeRotatingCooldown))

	for attempt := 0; attempt < probeRotatingAttempts; attempt++ {
		if ctx.Err() != nil {
			return false, fired
		}
		if fired && !probeSleep(ctx, probeExitPause) {
			return false, fired
		}
		exit := rotating[(accountIdx+attempt)%len(rotating)]
		client, errClient := pool.get(exit)
		if errClient != nil {
			probeRunLog("%s %s: rotating exit %s unusable, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errClient.Error()))
			continue
		}
		fired = true

		res, errFire := probeFireUpstream(ctx, client, cred, model)
		if errFire != nil {
			probeRunLog("%s %s: rotating exit %s failed at transport, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errFire.Error()))
			continue
		}
		switch probeConsume(cfg, cred.name, short, model, res, exit) {
		case probeOutcomeStored:
			// 与静态队伍同一张续期钟表：刚铸成的网关在 T+(ttl-threshold) 再来，不必等一小时。
			probeCooldownSet(probeRotatingExit, cred.name, model, time.Now().Add(probeSuccessRest(cfg)))
			return true, fired
		case probeOutcomeAccountLimited:
			// 429 是让凭据慢点说话，不是让它换地址换口音；剩余尝试继续只会加重拒绝。
			probeAccountSetBackoff(cred.name, time.Now())
			return false, fired
		}
		// 312 说明这次地址在该桶受限；轮换入口下次能换地址，值得继续。
		// 静态门牌与轮换柜台分开记账，就是为了不把两位跑堂认成同一个人。
	}
	if fired {
		probeRunLog("%s %s: rotating pool gave %d address(es), none of them a %d; resting this bucket for %s",
			short, model, probeRotatingAttempts, cfg.TemplateLength, probeRotatingCooldown)
	}
	return false, fired
}

// probeConsume 判定响应该让出口队伍继续还是收场。
// 要收的是 __cflb/__oailb pair：200 带 pair 可记成功；降级或失败带的 pair 也入池，
// 因为 pair 是边缘铸的，不靠本轮服务状态吃饭。
//
// pair 始终按自身值进入 GLOBAL 池，不绑铸造账号。
// 但入池与出口记成功是两本账：返回结果决定是否停止换出口，别把收据当奖状。
func probeConsume(cfg pluginConfig, name, short, model string, res probeFireResult, exit string) probeOutcome {
	if len(res.cookies.pairs) > 0 {
		state.mu.Lock()
		state.noteRouteCookiesLocked(res.cookies, exit)
		state.mu.Unlock()
	}
	switch res.status {
	case http.StatusTooManyRequests:
		// 凭据被要求降速，所有剩余出口仍拿同一凭据；到此收队让账号休息。
		// 继续硬敲曾把零星 312 敲成整墙 429，不是勤奋，是添堵。
		probeRunLog("%s %s: http=429 — upstream is rate limiting this credential, not this exit; stopping the walk and resting the account for %s",
			short, model, probeAccountBackoff)
		return probeOutcomeAccountLimited
	case http.StatusUnauthorized, http.StatusForbidden:
		// token 被拒也不是出口的错，换辆轿子不能换掉乘客的身份。
		probeRunLog("%s %s: http=%d — the credential was refused, no exit can change that; resting the account for %s",
			short, model, res.status, probeAccountBackoff)
		return probeOutcomeAccountLimited
	}
	if res.status != http.StatusOK {
		probeRunLog("%s %s: http=%d via %s, no pair", short, model, res.status, probeShowProxy(exit))
		return probeOutcomeTryNext
	}
	stateLen := len(res.stateValue)
	if stateLen == cfg.ReplaceLength {
		// 当前 IP 回了降级；响应里的 pair 已在上面入池，边缘照样会铸它。
		// 出口本身不记成功，下一出口换节点继续试，别把收下房卡误算成赢了比赛。
		probeRunLog("%s %s: http=200 via %s answered degraded (len=%d)%s — this exit's IP is throttled, trying next",
			short, model, probeShowProxy(exit), stateLen, pooledSuffix(res.cookies.pairs))
		return probeOutcomeTryNext
	}
	if len(res.cookies.pairs) == 0 {
		// 200 却无 Set-Cookie pair，通常是已引导请求的样子。
		// 这里故意裸发求新节点和 pair，裸发仍空手回来，就表示边缘没给新房卡。
		probeRunLog("%s %s: http=200 via %s but no __cflb/__oailb was set", short, model, probeShowProxy(exit))
		return probeOutcomeTryNext
	}
	switch stateLen {
	case cfg.TemplateLength, 0:
		probeRunLog("%s %s: pooled a %s pair via %s", short, model, orDash(gatewayLabel(res.cookies.pairs)), probeShowProxy(exit))
	default:
		probeRunLog("%s %s: pooled a %s pair via %s (turn-state len=%d)", short, model, orDash(gatewayLabel(res.cookies.pairs)), probeShowProxy(exit), stateLen)
	}
	return probeOutcomeStored
}

// pooledSuffix 给降级响应补一张小收据：pair 已收进池。
// 不能让流水账误报“312 把 cookie 也一起扔了”。
func pooledSuffix(pairs map[string]string) string {
	if len(pairs) == 0 {
		return ""
	}
	return fmt.Sprintf(" (pair still pooled: %s)", orDash(gatewayLabel(pairs)))
}

// probeSuccessRest 让成功组合休息到 ttl - probeRenewThreshold，正好接上续期。
// 上限仍是 probeExitCooldown；ttl 配得再长，成功者也不能比失败者罚坐更久。
func probeSuccessRest(cfg pluginConfig) time.Duration {
	rest := cfg.ttl() - probeRenewThreshold
	if rest < probeExitPause {
		return probeExitPause
	}
	if rest > probeExitCooldown {
		return probeExitCooldown
	}
	return rest
}

// probeDownloadCreds 每个选中账号读一次可用状态。
// token 不可读或过期就退队并记脱敏原因，不把带 token 的堆栈当公告贴。
func probeDownloadCreds(ctx context.Context, client *probeClient, accounts []string, now time.Time) map[string]probeCredential {
	creds := make(map[string]probeCredential, len(accounts))
	for _, name := range accounts {
		if ctx.Err() != nil {
			return creds
		}
		short := maskAuthLabel(name)
		blob, errDownload := client.downloadAuth(ctx, name)
		if errDownload != nil {
			probeRunLog("%s: could not read credential: %s", short, probeRedact(errDownload.Error()))
			continue
		}
		cred, errParse := probeParseCredential(name, blob)
		if errParse != nil {
			probeRunLog("%s: credential unusable: %s", short, probeRedact(errParse.Error()))
			continue
		}
		// 这里绝不刷新。access token 过期交给 CPA 在正常业务中刷新，下轮再读新值。
		// 擅自刷新可能轮换 refresh token，把线上凭据从客人手里抽走；
		// 离线采集整套规矩就是不掀别人正在吃的桌子。
		if !cred.expiresAt.IsZero() && !cred.expiresAt.After(now) {
			probeRunLog("%s: access token expired; skipping (not refreshed here — CPA refreshes it, next cycle harvests)", short)
			continue
		}
		creds[name] = cred
	}
	return creds
}

// probeRenewLoop 每 probeRenewInterval 重读有效 scope，面板改动无需重启便能入戏。
// 找出范围内缺货或余量低于 probeRenewThreshold 的桶补货，取消就退场。
// 柜台保持热乎，不能只照开张时那份名单办事。
func probeRenewLoop(ctx context.Context, pool *probeClientPool) {
	ticker := time.NewTicker(probeRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}

		state.mu.Lock()
		cfg := state.config
		state.mu.Unlock()
		accounts := append([]string(nil), cfg.ProbeAccounts...)
		models := append([]string(nil), cfg.Models...)
		proxies := append([]string(nil), cfg.ProbeProxies...)
		rotating := append([]string(nil), cfg.ProbeProxiesRotating...)
		if len(accounts) == 0 || len(models) == 0 {
			probeRunUpdate(func(run *probeRunState) { run.Current = "scope is empty; nothing to keep fresh" })
			continue
		}

		now := time.Now()
		left, poolLive := probePoolSecondsLeft(cfg, now)
		if poolLive && left >= probeRenewThreshold {
			probeRunUpdate(func(run *probeRunState) {
				run.Current = fmt.Sprintf("pool fresh (%s left on best pair); next check in %s", left.Round(time.Second), probeRenewInterval)
			})
			continue
		}
		idxOf := probeAccountIndex(accounts)
		var due []probeTarget
		involved := make(map[string]bool)
		for _, account := range accounts {
			// 上游已点名让该凭据歇场，整位跳过，不拉它换张桌继续演。
			if !probeAccountReady(account, now) {
				continue
			}
			// pair 不绑模型，桶维度收成“每个可用凭据铸一次”；模型只给载荷报个名。
			model := models[0]
			// 真有出口能出门才排队，否则每分钟下载凭据，最后却发现全在冷却，白搬账本。
			if !probeBucketHasEligibleExit(proxies, rotating, idxOf[account], account, model, now) {
				continue
			}
			due = append(due, probeTarget{account: account, model: model})
			involved[account] = true
		}
		if len(due) == 0 {
			probeRunUpdate(func(run *probeRunState) {
				run.Current = fmt.Sprintf("pool needs pairs but every exit is cooling or every account resting; next check in %s", probeRenewInterval)
			})
			continue
		}

		probeRunUpdate(func(run *probeRunState) {
			run.Current = fmt.Sprintf("minting fresh pair(s), best entry has %s left", left.Round(time.Second))
		})
		// 只下载确有到期工作的账号，仍按 scope 座次取，免得代理分配认错人。
		var accountList []string
		for _, account := range accounts {
			if involved[account] {
				accountList = append(accountList, account)
			}
		}
		client := newProbeClient(cfg)
		creds := probeDownloadCreds(ctx, client, accountList, now)
		probeFireBatch(ctx, cfg, pool, creds, due, idxOf, proxies, rotating, false)
		client.http.CloseIdleConnections()
	}
}

// probePoolSecondsLeft 报池中最长剩余寿命及是否有可用 pair。
// 全局池只需一只续期钟，不是每桶一只；最佳条目低于 probeRenewThreshold 才敲补货锣。
func probePoolSecondsLeft(cfg pluginConfig, now time.Time) (time.Duration, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	var best int64
	for _, e := range state.cookies {
		if l := entrySecondsLeft(*e, now, cfg.ttl()); l > best {
			best = l
		}
	}
	return time.Duration(best) * time.Second, best > 0
}

// probePendingTargets 列手动任务的目标。pair 不绑账号，一个可用凭据就能铸，
// 但逐个走选中账号仍有用：边缘可能分配不同节点，让池子多几扇门。
// 模型只是载荷名牌，pair 不绑它，因此每目标取首个配置模型，不另排模型大戏。
func probePendingTargets(cfg pluginConfig, accounts, models []string) []probeTarget {
	model := ""
	if len(models) > 0 {
		model = models[0]
	}
	out := make([]probeTarget, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, probeTarget{account: account, model: model})
	}
	return out
}

// probeExits 先走账号分配出口（索引 i % N），再顺序绕一圈尝遍其他出口。
// 账号 i 从出口 i 起步，首门不通还有整队备选；不是只给名牌不给后路。
// 空池给一个空字符串的直连尝试，客户端池会用无代理 transport 接待。
func probeExits(proxies []string, accountIdx int) []string {
	if len(proxies) == 0 {
		return []string{""}
	}
	n := len(proxies)
	out := make([]string, 0, n)
	for k := 0; k < n; k++ {
		out = append(out, proxies[(accountIdx+k)%n])
	}
	return out
}

// probeActive 不让初始补池与续期同时采同桶，慢上游也不能让后个 tick 插队。
// 守门键是 bucketKey，即 (account, model)，不是全店大锁；不同桶仍能并行出门。
var probeActive = struct {
	mu  sync.Mutex
	set map[string]bool
}{set: map[string]bool{}}

func probeClaim(key string) bool {
	probeActive.mu.Lock()
	defer probeActive.mu.Unlock()
	if probeActive.set[key] {
		return false
	}
	probeActive.set[key] = true
	return true
}

func probeRelease(key string) {
	probeActive.mu.Lock()
	defer probeActive.mu.Unlock()
	delete(probeActive.set, key)
}

// probeCooldown 记录 (exit, account, model) 组合何时能再次出门。
// 312 指向该账号、模型下当前 IP，不能替其他出口判歇业；全试完才算本窗口无路。
//
// 出口 URL 入键还有用：修正代理拼写就成新组合，可立即重试，不让改好的门牌罚站。
// 表中存准许重试的截止时刻，不是上次敲门时刻，才能容纳不同休息窗口。
// 静态路径先按 probeExitCooldown 记账，成功再对齐 probeSuccessRest；
// 轮换池耗完预算仍没拿到 292 时只等 probeRotatingCooldown，细节见 probeHarvestRotating。
var probeCooldown = struct {
	mu    sync.Mutex
	until map[string]time.Time
}{until: map[string]time.Time{}}

// probeRotatingExit 是轮换池冷却账上的虚拟出口。
// URL 不含 NUL，键分隔符却是 NUL，因此不会与真入口撞名。
//
// 冷却按 (account, model) 共记，不按 URL 分桌：轮换 URL 是发新 IP 的柜台，
// “试过这门牌”不代表下次还是那地址；要省的是账号耐受，不是门牌油漆。
const probeRotatingExit = "\x00rotating"

func probeCooldownKey(exit, account, model string) string {
	return exit + "\x00" + account + "\x00" + model
}

// probeCooldownReady 看这组现在能否出门；没打过的一律就绪。
// 新出口一入池就能排上，不必先坐一轮冷板凳。
func probeCooldownReady(exit, account, model string, now time.Time) bool {
	probeCooldown.mu.Lock()
	defer probeCooldown.mu.Unlock()
	until, seen := probeCooldown.until[probeCooldownKey(exit, account, model)]
	return !seen || !now.Before(until)
}

// probeCooldownMark 给组合记标准休息窗口。
// 静态路线上一出口、一 IP、每窗口一次，账本不认二次领号。
func probeCooldownMark(exit, account, model string, now time.Time) {
	probeCooldownSet(exit, account, model, now.Add(probeExitCooldown))
}

// probeCooldownSet 按明确截止时刻休息；轮换路径成功与失败各有钟点，不能齐喊散场。
func probeCooldownSet(exit, account, model string, until time.Time) {
	probeCooldown.mu.Lock()
	defer probeCooldown.mu.Unlock()
	probeCooldown.until[probeCooldownKey(exit, account, model)] = until
}

// probeAccountRest 收下被上游点名休息的凭据，只按账号记。
// 429 不认它从哪扇出口进来，因此该账号所有桶、所有出口一起歇场，不能换桌逃点名。
var probeAccountRest = struct {
	mu    sync.Mutex
	until map[string]time.Time
}{until: make(map[string]time.Time)}

func probeAccountReady(account string, now time.Time) bool {
	probeAccountRest.mu.Lock()
	defer probeAccountRest.mu.Unlock()
	until, seen := probeAccountRest.until[account]
	return !seen || now.After(until)
}

func probeAccountSetBackoff(account string, now time.Time) {
	probeAccountRest.mu.Lock()
	defer probeAccountRest.mu.Unlock()
	probeAccountRest.until[account] = now.Add(probeAccountBackoff)
}

// probeOutcome 是响应给出口队伍的口令：收队、换门，还是整位账号休息。
type probeOutcome int

const (
	// probeOutcomeStored：模板到柜台了，这桶收工，不再四处敲门。
	probeOutcomeStored probeOutcome = iota
	// probeOutcomeTryNext：此门没办成，下一扇门仍可请教。
	probeOutcomeTryNext
	// probeOutcomeAccountLimited：凭据本身被拒，收队并让账号歇场。
	// 硬换出口曾把几次 312 堆成 21 次 429，不再重演这场砸锅戏。
	probeOutcomeAccountLimited
)

// probeBucketHasEligibleExit 先看桶有没有可出门的出口，再让续期排队。
// 若所有组合都冷却，就别每分钟下载凭据、占桶，然后宣布“今天没活”。
func probeBucketHasEligibleExit(proxies, rotating []string, accountIdx int, account, model string, now time.Time) bool {
	// 轮换池每 (account, model) 共用一把键，只多问一次，不挨个入口重复点名。
	if len(rotating) > 0 && probeCooldownReady(probeRotatingExit, account, model, now) {
		return true
	}
	// 与 probeHarvestBucket 同规矩：有轮换池而静态名单空，不表示允许从本机后门直连。
	if len(proxies) == 0 && len(rotating) > 0 {
		return false
	}
	for _, exit := range probeExits(proxies, accountIdx) {
		if probeCooldownReady(exit, account, model, now) {
			return true
		}
	}
	return false
}

// probeSleep 等指定时长并报告任务是否还要演；收到取消立即返回 false，不等锣敲完。
func probeSleep(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// --- 上游柜台：请求出门，响应交账 -------------------------------------------

// probeFireResult 收上游状态、可能为空的 turn-state 与路由 pair。
// 所有状态都采 pair，不只 200；__cflb/__oailb 的轮换不以本轮铸 state 为前提，
// 别因票没出场就把房卡一起挡在门外。
type probeFireResult struct {
	status     int
	stateValue string
	cookies    routeCookieSet
}

// probeFireUpstream 用账号身份直连一次，只取响应头里的 turn-state 与 Set-Cookie pair。
// SSE 正文少量排空帮助 socket 复用后丢弃，不生成无用 completion 浪费配额。
// 传输失败返回 error，让调用方换出口；HTTP 状态则作为响应交账，不混为 error。
//
// 请求故意 BARE，不带池里 pair：有效 pair 会钉住节点，边缘不再发新 cookie。
// 2026-09-22 实测 steered 请求没有 Set-Cookie pair；这趟为铸新卡而来，
// 得让边缘自己分配节点，不能带旧房卡又要求门卫假装没见过。
func probeFireUpstream(ctx context.Context, client *http.Client, cred probeCredential, model string) (probeFireResult, error) {
	payload := map[string]any{
		"model":  model,
		"stream": true,
		"store":  false,
		"input": []map[string]any{{
			"type": "message",
			"role": "user",
			"content": []map[string]any{{
				"type": "input_text",
				"text": "ping",
			}},
		}},
		"reasoning":           map[string]any{"effort": "low"},
		"tool_choice":         "auto",
		"parallel_tool_calls": false,
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return probeFireResult{}, errMarshal
	}

	callCtx, cancel := context.WithTimeout(ctx, probeFireTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodPost, probeUpstreamURL, bytes.NewReader(raw))
	if errNew != nil {
		return probeFireResult{}, errNew
	}
	request.Header.Set("Authorization", "Bearer "+cred.accessToken)
	if cred.accountID != "" {
		request.Header.Set("Chatgpt-Account-Id", cred.accountID)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Originator", "codex-tui")
	request.Header.Set("Session-Id", probeUUID())
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return probeFireResult{}, errDo
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, probeMaxBodyBytes))
	return probeFireResult{
		status:     response.StatusCode,
		stateValue: response.Header.Get(turnStateHeader),
		cookies:    routeCookiesFromResponseHeaders(response.Header, time.Now()),
	}, nil
}

// probeUUID 用已链接的 crypto/rand 为 Session-Id 造随机 v4 UUID。
// 随机读取几乎不会失败；兜底避免这条冷门分支把整场探针喊停。
func probeUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// --- 凭据拆封：读得清，秘密不登台 -------------------------------------------

// probeParseCredential 从下载文件取 access token、账号出口、到期时间，
// 以及 token claims 内的账号 id，供上游 Chatgpt-Account-Id 使用。
// 柜台只拆封办事，这些内容不拿去记日志。
func probeParseCredential(name string, blob map[string]any) (probeCredential, error) {
	token := strings.TrimSpace(stringField(blob, "access_token"))
	if token == "" {
		return probeCredential{}, fmt.Errorf("no access_token in credential file")
	}
	claims := probeJWTClaims(token)
	cred := probeCredential{
		name:        name,
		accessToken: token,
		accountID:   probeAccountID(claims, blob),
		proxyURL:    strings.TrimSpace(stringField(blob, "proxy_url")),
	}
	if exp, ok := probeTokenExpiry(claims); ok {
		cred.expiresAt = exp
	}
	return cred, nil
}

// probeJWTClaims 解 JWT 中段，读 exp 与账号 id；这些 claims 不是秘密。
// 整张 token 才是钥匙，不能因为看懂门牌就把钥匙登报。
func probeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	data, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
	if errDecode != nil {
		return nil
	}
	var claims map[string]any
	if errUnmarshal := json.Unmarshal(data, &claims); errUnmarshal != nil {
		return nil
	}
	return claims
}

// probeAccountID 取上游要求的 chatgpt_account_id。
// 先认 token 自己的 auth claim，缺了才看文件顶层 account_id，不让替身抢主演名牌。
func probeAccountID(claims, blob map[string]any) string {
	if claims != nil {
		if auth, ok := claims["https://api.openai.com/auth"].(map[string]any); ok {
			if id, ok := auth["chatgpt_account_id"].(string); ok && strings.TrimSpace(id) != "" {
				return strings.TrimSpace(id)
			}
		}
	}
	return strings.TrimSpace(stringField(blob, "account_id"))
}

// probeTokenExpiry 读 exp；读不到就 ok=false，暂按可用送上游裁定。
// 本地没看清钟表不等于宣布过期；上游 401 仍按非 200 路径处理。
func probeTokenExpiry(claims map[string]any) (time.Time, bool) {
	if claims == nil {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// stringField 从 JSON 对象拿字符串；字段缺席或穿错类型就回 ""，不硬把它拉上台。
func stringField(blob map[string]any, key string) string {
	if value, ok := blob[key].(string); ok {
		return value
	}
	return ""
}

// --- CPA 只读柜台：查账，不改账 ---------------------------------------------

type probeAuthFile struct {
	Name      string          `json:"name"`
	AuthIndex json.RawMessage `json:"auth_index,omitempty"`
	Disabled  bool            `json:"disabled"`
	Provider  string          `json:"provider"`
	Type      string          `json:"type"`
}

type probeHTTPResult struct {
	status int
	body   []byte
}

// probeClient 只读 CPA 管理 API，取账号名单与各凭据 token。
// 借看账本，不顺手改账。
type probeClient struct {
	baseURL string
	mgmtKey string
	http    *http.Client
}

func newProbeClient(cfg pluginConfig) *probeClient {
	// configure 已把空 probe_base_url 补成 defaultProbeBaseURL。
	// 这里只兜测试或未来绕过 configure 的进程内配置，仍复用 main.go 常量。
	// 默认端口别抄两份各唱各的，免得探针敲到隔壁店。
	base := strings.TrimRight(strings.TrimSpace(cfg.ProbeBaseURL), "/")
	if base == "" {
		base = defaultProbeBaseURL
	}
	return &probeClient{
		baseURL: base,
		mgmtKey: strings.TrimSpace(cfg.ProbeManagementKey),
		// Proxy 故意为 nil：只访问 CPA 回环监听，不跟本机 http_proxy/all_proxy 出远门。
		// 把回环请求送进外部出口会够不到目标，反报假 502。
		// 上游的逐出口客户端在 probeClientPool，也按同样原则明确构建，不借错轿子。
		http: &http.Client{Transport: &http.Transport{Proxy: nil}},
	}
}

// call 发一次请求，把状态与正文一起交账。
//
// 非 2xx 是结果，不是 error：401 是管理钥匙不对，404 是该 CPA 构建没这扇路由门。
// 两者若都报“调用失败”，查案就会跑错街；只有传输故障才返回 error。
func (c *probeClient) call(ctx context.Context, method, path, token string, payload any, timeout time.Duration) (probeHTTPResult, error) {
	var body io.Reader
	if payload != nil {
		raw, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			return probeHTTPResult{}, errMarshal
		}
		body = bytes.NewReader(raw)
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, errNew := http.NewRequestWithContext(callCtx, method, c.baseURL+path, body)
	if errNew != nil {
		return probeHTTPResult{}, errNew
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, errDo := c.http.Do(request)
	if errDo != nil {
		return probeHTTPResult{}, errDo
	}
	defer func() { _ = response.Body.Close() }()

	// 读取有上限，但别用小碟装整桌菜：v7.3.4 的 auth-files 条目有
	// recent_requests、quota、model_quotas、cooldowns，少量账号也能撑破小上限。
	// 额外读一字节识别超限，明确报“太大”，别把自己切断的正文诬成 JSON 语法错。
	raw, errRead := io.ReadAll(io.LimitReader(response.Body, probeMgmtMaxBodyBytes+1))
	if errRead != nil {
		return probeHTTPResult{status: response.StatusCode}, errRead
	}
	if len(raw) > probeMgmtMaxBodyBytes {
		return probeHTTPResult{status: response.StatusCode},
			fmt.Errorf("%s %s response exceeds %d bytes", method, path, probeMgmtMaxBodyBytes)
	}
	return probeHTTPResult{status: response.StatusCode, body: raw}, nil
}

// probeExplainStatus 分清三类故障再报原因，修门、换钥匙、找路由不能同喊一声“坏了”。
func probeExplainStatus(result probeHTTPResult, what string) error {
	switch result.status {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s: 401 unauthorized -- probe_management_key is wrong or not accepted; this is an auth failure, not a bad path", what)
	case http.StatusForbidden:
		return fmt.Errorf("%s: 403 forbidden -- the key was accepted but lacks access", what)
	case http.StatusNotFound:
		return fmt.Errorf("%s: 404 not found -- this CPA build does not serve that path (a bad key would have answered 401)", what)
	}
	return fmt.Errorf("%s: HTTP %d %s", what, result.status, probeTruncate(probeRedact(string(result.body)), 200))
}

// listCodexAuths 取 CPA 的 Codex 凭据，有 provider 先认它，没有才认命名约定。
// .bak 是用户留的替身备份，永不拉来探测跑龙套。
func (c *probeClient) listCodexAuths(ctx context.Context) ([]probeAuthFile, error) {
	result, errCall := c.call(ctx, http.MethodGet, probeRouteAuthFiles, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return nil, errCall
	}
	if result.status != http.StatusOK {
		return nil, probeExplainStatus(result, "GET "+probeRouteAuthFiles)
	}
	var doc struct {
		Files []probeAuthFile `json:"files"`
	}
	if errUnmarshal := json.Unmarshal(result.body, &doc); errUnmarshal != nil {
		return nil, fmt.Errorf("GET %s returned a body that is not the expected {\"files\":[...]} document: %w", probeRouteAuthFiles, errUnmarshal)
	}
	out := make([]probeAuthFile, 0, len(doc.Files))
	for _, file := range doc.Files {
		name := strings.TrimSpace(file.Name)
		if name == "" || strings.Contains(name, ".bak") {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(file.Provider))
		kind := strings.ToLower(strings.TrimSpace(file.Type))
		lower := strings.ToLower(name)
		if provider != "codex" && kind != "codex" &&
			!(strings.HasPrefix(lower, "codex-") && strings.HasSuffix(lower, ".json")) {
			continue
		}
		file.Name = name
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// downloadAuth 整份取回凭据文件，这是唯一把 token 带回进程的调用。
// 正文绝不写日志；调用方经 probeParseCredential 只取所需，余下收起，不摊开示众。
func (c *probeClient) downloadAuth(ctx context.Context, name string) (map[string]any, error) {
	path := probeRouteAuthDownload + "?name=" + url.QueryEscape(name)
	result, errCall := c.call(ctx, http.MethodGet, path, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return nil, errCall
	}
	if result.status != http.StatusOK {
		return nil, probeExplainStatus(result, "GET "+probeRouteAuthDownload)
	}
	var blob map[string]any
	if errUnmarshal := json.Unmarshal(result.body, &blob); errUnmarshal != nil {
		return nil, fmt.Errorf("GET %s returned a body that is not a JSON object: %w", probeRouteAuthDownload, errUnmarshal)
	}
	return blob, nil
}

// --- 逐出口客户端：一扇门配一位熟路跑堂 -------------------------------------

// probeClientPool 每出口建一个 http.Client，所有走该出口的请求复用。
// 四账号共用两出口只开两套 transport，不是八套；别给每位客人另盖厨房。
type probeClientPool struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

func newProbeClientPool() *probeClientPool {
	return &probeClientPool{clients: map[string]*http.Client{}}
}

// get 每出口只建一次客户端；proxyURL 为空就是明确直连。
// 与 newProbeClient 一样不继承 http_proxy/all_proxy：那是 CPA 转发业务的出口，
// 独立探针不偷偷借用别人订的轿子。
func (p *probeClientPool) get(proxyURL string) (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.clients[proxyURL]; ok {
		return client, nil
	}
	transport := &http.Transport{Proxy: nil}
	if proxyURL != "" {
		parsed, errParse := url.Parse(proxyURL)
		if errParse != nil {
			return nil, fmt.Errorf("exit is not a valid URL: %w", errParse)
		}
		// net/http 认 socks5，不认 socks5h；未知 scheme 会被当 HTTP 代理，
		// SOCKS 服务因此报协议错，看起来像出口永久关门，其实只是叫错了接头暗号。
		// 两种写法区别仅在域名由谁解析；Go socks5 已把主机名交给代理，
		// 正好符合 socks5h，因此规范化是语义等价，不是蒙混过关。用户池内两种写法都有。
		if strings.EqualFold(parsed.Scheme, "socks5h") {
			parsed.Scheme = "socks5"
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	client := &http.Client{Transport: transport}
	p.clients[proxyURL] = client
	return client, nil
}

func (p *probeClientPool) closeIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, client := range p.clients {
		client.CloseIdleConnections()
	}
}

// --- 脱敏柜台：能讲笑话，不能晒钥匙 -----------------------------------------

var (
	// 按 scheme://...@ 找所有 URL 的 userinfo，也就是此处代理凭据。
	// 不只查配置名单：上游错误里可能回显陌生 URL，那位也得蒙好脸再上日志。
	probeURLAuthRE = regexp.MustCompile(`(?i)\b([a-z0-9+.\-]+://)[^/\s@]+@`)
	// Fernet 的 0x80 版本字节经 base64url 后露出 gAAAAA 前缀，见 FINDINGS.md。
	// 认这截衣角就能筛 turn-state，不必先解码整件外套。
	probeTokenRE = regexp.MustCompile(`gAAAAA[A-Za-z0-9_\-=]{16,}`)
	// 回显的所有 Bearer 凭据都拦住，包括自家的；熟人也不能举钥匙登台。
	probeBearerRE = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._\-]{16,}`)
)

// probeRedact 把送往 Lines、任务错误与进程日志的疑似凭据抹去。
// 这几张公告栏都不是保险柜。
func probeRedact(text string) string {
	text = probeTokenRE.ReplaceAllString(text, "<turn-state redacted>")
	text = probeBearerRE.ReplaceAllString(text, "${1}<redacted>")
	return probeURLAuthRE.ReplaceAllString(text, "${1}***@")
}

// probeShowProxy 把出口遮好再展示；未设置出口与脱敏后恰好为空要分清，
// 不能把没来的演员和戴面具的演员写成同一个人。
func probeShowProxy(raw string) string {
	if masked := maskProxyURL(raw); masked != "" {
		return masked
	}
	return "(direct)"
}

// probeTruncate 限制引用正文长度并说明删去多少。
// 截短是账本装不下，不要让读者误认上游交来一张天生破损的 JSON。
func probeTruncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + fmt.Sprintf(" ...[+%d chars]", len(text)-limit)
}
