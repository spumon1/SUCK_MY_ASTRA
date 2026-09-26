// 出口体检一次问遍全池：这些出口到底能不能到 OpenAI，不必等探测整轮结束才猜谁瘸腿。
// 探测按序跳过失败出口，半池坏了也可能继续采集，只是更慢；这里让每条出口单独交体检表。
// 可达性请求不带 Authorization 或 Chatgpt-Account-Id。实测未认证 Codex POST 回 401，
// 这里反而算抵达证据：请求经出口到 OpenAI 边缘完成 TLS，由 API 回答，不是代理或拦截页唱戏。
// 不碰凭据、不花账号额度，能与业务和探测并行，也不会凭空给账号添限流请求。
// 出口地址查同一 chatgpt.com 的 /cdn-cgi/trace，拿上游实际所见 IP、国家和边缘机房；
// 不问第三方 ipinfo.io，免得多依赖还问到另一条路的落点。trace 尽力而为，失败只缺地址，不改 API 判定。
// 结果页无需 key：代理经 probeShowProxy 整体遮 userinfo，错误经 probeRedact；
// IP 本身明文显示，用来识破“二十顶帽子其实只戴在三个出口头上”。当前状态页按操作者要求已明文展示代理，
// 但这不等于日志也能裸奔，日志仍严格脱敏。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// proxyCheckTraceURL 是探测同一主机的 Cloudflare trace 入口，不找第三方代问。
// 用变量便于测试换假端点，和 probeUpstreamURL 一样，替身只在排练时上场。
var proxyCheckTraceURL = "https://chatgpt.com/cdn-cgi/trace"

const (
	// 单请求预算刻意短：体检都答得拖拖拉拉的出口，不值得再花一桶探测机会等它系鞋带。
	proxyCheckRequestTimeout = 8 * time.Second

	// 整批预算要装进合理管理超时，因为宿主同步等结果。
	// 配合下面并行度，二十个健康出口几秒答完，全黑洞也要按时交完整答卷。
	proxyCheckBudget = 45 * time.Second

	// 并行度既要快，也别让二十条出口同时撞共享网关像集体敲锣。
	// 不花账号额度，所以不受探测的账号节奏约束，但网关承受力仍得顾。
	proxyCheckParallel = 6

	// 只要状态行和少量 trace 字段；响应体排空供连接复用后丢弃，不把餐盘都搬回家。
	proxyCheckMaxBody = 4 << 10

	// 未认证请求体的模型只为格式完整；上游先因缺凭据拒绝，模型名只是坐在门外的道具。
	proxyCheckFallbackModel = "gpt-5.5"
)

// 结果不止成功失败两色：连不上应查代理商，连上却被拒应查出口信誉。
// 混叫失败就像把没点火和烧糊都叫“饭不好”，操作者无从下手。
const (
	// 标记条目来自哪个池；这些线上值是面板标签依据，来路不能靠闻味道猜。
	proxyPoolStatic   = "static"
	proxyPoolRotating = "rotating"

	proxyVerdictOK          = "ok"
	proxyVerdictBlocked     = "blocked"
	proxyVerdictRateLimited = "ratelimited"
	proxyVerdictUnexpected  = "unexpected"
	proxyVerdictDead        = "dead"
)

type proxyCheckResult struct {
	// Index 从 1 起，对齐出口在自己池里的位置，也是探测尝试顺序。
	// 二十份同网关凭据脱敏后可能一个模样，只能靠座号认人，别把排序当装饰。
	Index int    `json:"index"`
	Pool  string `json:"pool"`
	Proxy string `json:"proxy"`
	// Rotated 表示两次采样 IP 不同；Mismatch 只在证据反驳声明时点亮。
	// 不同 IP 足以打脸“静态”；相同 IP 却不能反驳“轮换”，小池会重抽，网关也可能短暂黏住地址。
	// 证据只能单向用，不能看两次同一辆车就宣布全城只有一辆车。
	Rotated    bool   `json:"rotated"`
	Mismatch   string `json:"mismatch,omitempty"`
	Verdict    string `json:"verdict"`
	StatusCode int    `json:"status_code,omitempty"`
	MS         int64  `json:"ms"`
	ExitIP     string `json:"exit_ip,omitempty"`
	Country    string `json:"country,omitempty"`
	Colo       string `json:"colo,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type proxyCheckResponse struct {
	Checked    int `json:"checked"`
	OK         int `json:"ok"`
	Blocked    int `json:"blocked"`
	Dead       int `json:"dead"`
	Other      int `json:"other"`
	Mismatches int `json:"mismatches"`
	// DistinctIPs 只数静态池地址，回答几个静态条目是否其实共用一个出口。
	// 轮换池本就应变地址，混进来只会把车牌抽签次数误当固定车位数。
	StaticChecked int                `json:"static_checked"`
	DistinctIPs   int                `json:"distinct_ips"`
	MS            int64              `json:"ms"`
	TimedOut      bool               `json:"timed_out,omitempty"`
	Direct        bool               `json:"direct,omitempty"`
	Note          string             `json:"note,omitempty"`
	Results       []proxyCheckResult `json:"results"`
}

// runProxyCheck 测插件当前配置的出口，每个一行，绝不收调用方临时名单。
// 这是无 key GET，代理 URL 带密码，放查询参数就会落宿主访问日志和浏览器历史；
// 请先在面板保存配置，别把钥匙刻到路边指示牌上。
func runProxyCheck() pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	model := proxyCheckFallbackModel
	if len(cfg.Models) > 0 {
		model = cfg.Models[0]
	}

	// 两池铺成同一列表，但留来源标签，共用一个有界 worker 队列，别各自开无数灶。
	type target struct {
		pool  string
		index int
		url   string
	}
	var targets []target
	for i, raw := range cfg.ProbeProxies {
		targets = append(targets, target{pool: proxyPoolStatic, index: i + 1, url: raw})
	}
	for i, raw := range cfg.ProbeProxiesRotating {
		targets = append(targets, target{pool: proxyPoolRotating, index: i + 1, url: raw})
	}

	out := proxyCheckResponse{Results: []proxyCheckResult{}}
	if len(targets) == 0 {
		// 只有两池都空才测一次直连，对齐 probeHarvestBucket 的真实动作，不回“无可检查”。
		// 仅静态池空而轮换池有条目不回退直连，不能看一口锅空就宣布全店没菜。
		targets = append(targets, target{pool: proxyPoolStatic, index: 1, url: ""})
		out.Direct = true
		out.Note = "两个代理池都是空的 —— 探测会走本机直连，所以这里测的就是直连出口。"
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyCheckBudget)
	defer cancel()

	// 自建客户端池，结束就收摊；不借正在探测的连接，免得体检把营业的脉搏也搅乱。
	pool := newProbeClientPool()
	defer pool.closeIdle()

	results := make([]proxyCheckResult, len(targets))
	gate := make(chan struct{}, proxyCheckParallel)
	var wg sync.WaitGroup
	started := time.Now()
	for slot, tgt := range targets {
		wg.Add(1)
		// 每个 goroutine 只写固定 slice 自己那格，slice 不扩容，所以不需要另派互斥门卫。
		go func(slot int, t target) {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			results[slot] = proxyCheckOne(ctx, pool, t.pool, t.index, t.url, model)
		}(slot, tgt)
	}
	wg.Wait()

	out.MS = time.Since(started).Milliseconds()
	out.Results = results
	out.Checked = len(results)
	out.TimedOut = ctx.Err() != nil

	seen := map[string]bool{}
	for _, row := range results {
		switch row.Verdict {
		case proxyVerdictOK:
			out.OK++
		case proxyVerdictDead:
			out.Dead++
		case proxyVerdictBlocked, proxyVerdictRateLimited:
			out.Blocked++
		default:
			out.Other++
		}
		if row.Mismatch != "" {
			out.Mismatches++
		}
		if row.Pool == proxyPoolStatic {
			out.StaticChecked++
			if row.ExitIP != "" {
				seen[row.ExitIP] = true
			}
		}
	}
	out.DistinctIPs = len(seen)

	// 日志只报数量，不报出口；响应都已脱敏，更不能在会被复制进工单和聊天的日志里露钥匙。
	log.Printf(logPrefix+"proxy check: %d entr(ies) -> %d ok, %d refused, %d unreachable, %d other; %d misdeclared; %d distinct static address(es) in %dms",
		out.Checked, out.OK, out.Blocked, out.Dead, out.Other, out.Mismatches, out.DistinctIPs, out.MS)

	return jsonResponse(http.StatusOK, out)
}

// proxyCheckOne 给单出口跑 trace 和可达性请求，先 trace，坏出口也尽量带回线索。
// 计时只量决定结论的 API 请求，不把拍证件照时间算进跑步成绩。
func proxyCheckOne(ctx context.Context, pool *probeClientPool, poolName string, index int, raw, model string) proxyCheckResult {
	out := proxyCheckResult{Index: index, Pool: poolName, Proxy: probeShowProxy(raw), Verdict: proxyVerdictDead}

	client, errClient := pool.get(raw)
	if errClient != nil {
		// 出口格式错就不联网，明确报配置问题；打错门牌不能怪房东失踪。
		out.Detail = "这条代理地址本身有问题：" + probeRedact(errClient.Error())
		return out
	}

	// 取两次 trace 样本核对声明，均为尽力；trace 停摆只缺 IP 和轮换验证，不推翻 API 通行证。
	if trace := proxyCheckTrace(ctx, client); trace != nil {
		out.ExitIP, out.Country, out.Colo = trace["ip"], trace["loc"], trace["colo"]
		if second := proxyCheckTrace(ctx, client); second != nil && second["ip"] != "" && out.ExitIP != "" {
			out.Rotated = second["ip"] != out.ExitIP
		}
	}
	// 只按能证明的方向判矛盾，见 proxyCheckResult.Rotated；证据没到，锤子别先落。
	if out.Rotated && poolName == proxyPoolStatic && raw != "" {
		out.Mismatch = "这条在静态池里，但两次采样给了不同地址 —— 它其实是轮换的，应该移到轮换池。"
	}

	started := time.Now()
	status, errReach := proxyCheckReach(ctx, client, model)
	out.MS = time.Since(started).Milliseconds()
	if errReach != nil {
		out.Detail = "连不上：" + probeRedact(errReach.Error())
		return out
	}

	out.StatusCode = status
	switch status {
	case http.StatusUnauthorized:
		out.Verdict = proxyVerdictOK
		out.Detail = "通。401 正是不带凭据时该有的答复，说明请求确实走到了 OpenAI。"
	case http.StatusForbidden:
		out.Verdict = proxyVerdictBlocked
		out.Detail = "连得上，但上游拒绝（403）—— 多半是这个出口地址被挡了。"
	case http.StatusTooManyRequests:
		out.Verdict = proxyVerdictRateLimited
		out.Detail = "连得上，但被限速（429）—— 这个出口短期内请求太多。"
	default:
		out.Verdict = proxyVerdictUnexpected
		out.Detail = fmt.Sprintf("连得上，上游回了 %d（不带凭据时预期是 401）。", status)
	}
	return out
}

// proxyCheckReach 用探测自己的端点与头，但故意不带凭据。
// 401 在这里证明抵达，问路被要求出示证件，说明至少找对了门。
func proxyCheckReach(ctx context.Context, client *http.Client, model string) (int, error) {
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
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return 0, errMarshal
	}

	callCtx, cancel := context.WithTimeout(ctx, proxyCheckRequestTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodPost, probeUpstreamURL, bytes.NewReader(raw))
	if errNew != nil {
		return 0, errNew
	}
	// 除了 Authorization、Chatgpt-Account-Id，其余头与探测一致。
	// 边缘若拒 User-Agent 或 Originator，这里也应失败，不让体检穿礼服、正式上班换假胡子。
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Originator", "codex-tui")
	request.Header.Set("Session-Id", probeUUID())
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return 0, errDo
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, proxyCheckMaxBody))
	return response.StatusCode, nil
}

// proxyCheckTrace 通过出口读 Cloudflare trace，任意失败回 nil。
// 这是补充线索，不是主判官，没拿到地址不能宣布出口有罪。
func proxyCheckTrace(ctx context.Context, client *http.Client) map[string]string {
	callCtx, cancel := context.WithTimeout(ctx, proxyCheckRequestTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodGet, proxyCheckTraceURL, nil)
	if errNew != nil {
		return nil
	}
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return nil
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, proxyCheckMaxBody))
		return nil
	}

	// 每行 key=value，只拿要展示的三个字段；Cloudflare 新添的菜别未经点单端上面板。
	out := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, proxyCheckMaxBody))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		switch key {
		case "ip", "loc", "colo":
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
