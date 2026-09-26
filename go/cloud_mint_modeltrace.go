package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// modeltraceSid 生成不超过 32 位的字母数字 sid，给本轮住宅出口钉座号，别半场换包间。
func modeltraceSid() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "mtprobe0"
	}
	return fmt.Sprintf("%x", b[:])
}

// modeltrace 主动探针用池账号经指定灌池源（默认 fc），以 WS 对目标模型连问 N 轮，报实际 served。
// served 等于请求模型记满血，不同则为 fallback（如 gpt-6-luna）；只审计，不写池、不改业务。
// 每轮由上游独立决定，不能凭上一盘菜替下一盘打包票；会烧额度，所以走带 key 的 POST。
const (
	modeltraceDefaultModel = "gpt-6-astra"
	modeltraceDefaultTurns = 3
	modeltraceMaxTurns     = 10
)

type modeltraceTurn struct {
	DeclaredServed string `json:"declared_served"` // 本轮 response.created 自报的模型，先记名牌再验手艺
	OutputLen      int    `json:"output_len"`      // 收到的输出文本长度，账房量尺不猜篇幅
	ParsedNumbers  int    `json:"parsed_numbers"`  // 真解析到的数字数，不能把标点也算进米粒
	Error          string `json:"error,omitempty"`
}

type modeltraceCandidate struct {
	Model       string  `json:"model"`
	DisplayName string  `json:"display_name"`
	Probability float64 `json:"probability"`
}

// 行为指纹汇总全部有效输出做归因，不只看声明标签；认厨师看出菜手势，不看胸前名牌。
type modeltraceFingerprint struct {
	Predicted     string                `json:"predicted"`
	DisplayName   string                `json:"display_name"`
	Confidence    float64               `json:"confidence"`
	Match         bool                  `json:"match"` // 指纹与点单模型是否一致，手艺和招牌对不对得上
	ValidOutputs  int                   `json:"valid_outputs"`
	TopCandidates []modeltraceCandidate `json:"top_candidates"`
}

type modeltraceReport struct {
	Model             string                 `json:"model"`
	Source            string                 `json:"source"`
	Path              string                 `json:"path"` // fc 经 FC 验票；client 经 CPA 出口验真实路径，分清考试走哪扇门
	Account           string                 `json:"account"`
	Transport         string                 `json:"transport"`
	DeclaredServed    string                 `json:"declared_served"`    // 铸票轮自报模型，先留声明不替它担保
	MintGateway       string                 `json:"mint_gateway"`       // 票落到哪个 unified-N，座位牌认清包间
	TicketFingerprint string                 `json:"ticket_fingerprint"` // 被验票的脱敏指纹，认票不晒票
	Turns             []modeltraceTurn       `json:"turns"`
	Fingerprint       *modeltraceFingerprint `json:"fingerprint,omitempty"`
	Note              string                 `json:"note,omitempty"`
}

type gradeResult struct {
	Served     string `json:"served"`
	OutputText string `json:"output_text"`
	Status     int    `json:"status"`
	Reason     string `json:"reason"`
}

// cloudGradeTurn 让 FC 回放票，跑一轮带挑战的真实 WS，交回输出文本。
// 这是两轮制第二场：先铸 token+pair，再拿它们走真实客户端式请求，票买到了还得真进场。
func cloudGradeTurn(ctx context.Context, cfgURL, key string, creds cloudMintCredentials, model, token, pairCookie, prompt, proxyURL, sid string) (gradeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfgURL, nil)
	if err != nil {
		return gradeResult{}, errors.New("invalid cloud endpoint")
	}
	req.Header.Set("X-Relay-Key", key)
	req.Header.Set("X-Relay-Grade", "1")
	req.Header.Set("X-Mint-Model", model)
	req.Header.Set("X-Mint-Replay-State", token)
	req.Header.Set("X-Mint-Prompt", base64.StdEncoding.EncodeToString([]byte(prompt)))
	req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
	if creds.AccountID != "" {
		req.Header.Set("Chatgpt-Account-Id", creds.AccountID)
	}
	if pairCookie != "" {
		req.Header.Set("Cookie", pairCookie)
	}
	if sid != "" {
		req.Header.Set("X-Mint-Sid", sid)
	}
	transport, err := newCloudMintTransport(proxyURL)
	if err != nil {
		return gradeResult{}, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return gradeResult{}, errors.New("grade turn 连接失败或超时")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, cloudResponseLimit+1))
	if err != nil || len(raw) > cloudResponseLimit {
		return gradeResult{}, errors.New("grade 响应无效或过大")
	}
	var out gradeResult
	if json.Unmarshal(raw, &out) != nil {
		return gradeResult{}, errors.New("grade 响应不是 JSON")
	}
	if res.StatusCode != http.StatusOK {
		if out.Reason != "" {
			return out, fmt.Errorf("grade 被拒: %s", out.Reason)
		}
		return out, fmt.Errorf("grade HTTP %d", res.StatusCode)
	}
	return out, nil
}

// runClientPathProbe 是 Test B：不铸票、不碰 FC，只经本机 CPA 回环发 turns 条业务挑战。
// 让真实客户端链路出菜，收输出做指纹，不另开考试专用小灶。
func runClientPathProbe(ctx context.Context, cfg pluginConfig, model, apiKey, cpaURL string, turns int) (modeltraceReport, error) {
	report := modeltraceReport{Model: model, Source: "cpa", Path: "client", Transport: "websocket", Turns: []modeltraceTurn{}}
	if apiKey == "" {
		return report, errors.New("client 路径需要 api_key(业务鉴权)")
	}
	if cpaURL == "" {
		// 本机 CPA 的业务 WS 地址由 http(s):// 换成 ws(s)://，换交通工具不换目的地。
		base := strings.TrimRight(cfg.ProbeBaseURL, "/")
		base = strings.Replace(base, "http://", "ws://", 1)
		base = strings.Replace(base, "https://", "wss://", 1)
		cpaURL = base + "/backend-api/codex/responses"
	}
	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 90 * time.Second
	}
	challenges := generateChallenges(turns)
	var outputs []string
	for _, ch := range challenges {
		select {
		case <-ctx.Done():
			report.Turns = append(report.Turns, modeltraceTurn{Error: "cancelled"})
			return report, nil
		default:
		}
		cctx, ccancel := context.WithTimeout(ctx, perTurn)
		served, outText, cErr := clientTurnWS(cctx, cpaURL, apiKey, "", model, ch.Prompt)
		ccancel()
		turn := modeltraceTurn{DeclaredServed: served, OutputLen: len(outText)}
		if cErr != nil {
			turn.Error = cErr.Error()
		}
		if outText != "" {
			turn.ParsedNumbers = len(parseNumbers(outText))
			outputs = append(outputs, outText)
		}
		report.Turns = append(report.Turns, turn)
	}
	report.applyFingerprint(outputs, model)
	return report, nil
}

// runBridgePathProbe 给方案 B 做灰度：连 wss://<fc>/k/<relaykey>/backend-api/codex/responses，
// 带所选账号真 access_token 与 account_id 发 turns 条挑战。FC 同连接住宅铸票，
// 把 turn-state 注入 response.create，再双向中继；收输出做指纹，astra 归因作为桥接满血证据，
// 但仍是本轮行为判定，不是给未来所有轮次颁终身厨神证。
func runBridgePathProbe(ctx context.Context, cfg pluginConfig, model, source, urlOverride, account string, turns int) (modeltraceReport, error) {
	report := modeltraceReport{Model: model, Source: source, Path: "bridge", Transport: "websocket", Turns: []modeltraceTurn{}}
	target, err := modeltraceTarget(cfg.CloudMint, source, urlOverride)
	if err != nil {
		return report, err
	}
	key := os.Getenv(cfg.CloudMint.KeyEnv)
	if key == "" {
		return report, errors.New("relay key 环境变量未设")
	}
	accounts := cfg.ProbeAccounts
	if account != "" {
		accounts = []string{account}
	}
	var cred probeCredential
	for _, c := range probeDownloadCreds(ctx, newProbeClient(cfg), accounts, time.Now()) {
		if c.accessToken == "" {
			continue
		}
		if account == "" || c.name == account {
			cred = c
			break
		}
	}
	if cred.accessToken == "" {
		return report, errors.New("无可用账号凭据(检查 probe_accounts / 账号 access_token)")
	}
	report.Account = cred.name
	bridgeURL, err := bridgeWSURL(target.URL, key)
	if err != nil {
		return report, err
	}
	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 120 * time.Second
	}
	var outputs []string
	for _, ch := range generateChallenges(turns) {
		select {
		case <-ctx.Done():
			report.Turns = append(report.Turns, modeltraceTurn{Error: "cancelled"})
			return report, nil
		default:
		}
		cctx, ccancel := context.WithTimeout(ctx, perTurn)
		served, outText, cErr := clientTurnWS(cctx, bridgeURL, cred.accessToken, cred.accountID, model, ch.Prompt)
		ccancel()
		turn := modeltraceTurn{DeclaredServed: served, OutputLen: len(outText)}
		if cErr != nil {
			turn.Error = cErr.Error()
		}
		if outText != "" {
			turn.ParsedNumbers = len(parseNumbers(outText))
			outputs = append(outputs, outText)
		}
		report.Turns = append(report.Turns, turn)
	}
	report.applyFingerprint(outputs, model)
	return report, nil
}

// bridgeWSURL 把 FC https 基址拼为桥接 WS，relay key 编码在路径段。
// CPA 账号 base_url 指到 FC 时带不了 X-Relay-Key 头，故走这条门；门牌含钥匙，不能乱晒。
func bridgeWSURL(fcURL, key string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(fcURL))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("FC 地址无效: %q", fcURL)
	}
	scheme := "wss"
	if u.Scheme == "http" {
		scheme = "ws"
	}
	return fmt.Sprintf("%s://%s/k/%s/backend-api/codex/responses", scheme, u.Host, url.PathEscape(key)), nil
}

// applyFingerprint 给汇总输出做行为归因并填报告，演员报了名，手艺还得另验。
func (report *modeltraceReport) applyFingerprint(outputs []string, model string) {
	if len(outputs) == 0 {
		if report.Note == "" {
			report.Note = "未收集到任何模型输出,无法做指纹"
		}
		return
	}
	bank, bErr := loadBank()
	if bErr != nil {
		report.Note = "指纹基准加载失败: " + bErr.Error()
		return
	}
	att, aErr := analyzeOutputs(outputs, bank)
	if aErr != nil {
		report.Note = "指纹归因失败: " + aErr.Error()
		return
	}
	fp := &modeltraceFingerprint{
		Predicted: att.PredictedModel, DisplayName: att.DisplayName,
		Confidence: att.Confidence, Match: att.PredictedModel == model, ValidOutputs: att.ValidOutputs,
	}
	for i, r := range att.Results {
		if i >= 5 {
			break
		}
		fp.TopCandidates = append(fp.TopCandidates, modeltraceCandidate{Model: r.Model, DisplayName: r.DisplayName, Probability: r.Probability})
	}
	report.Fingerprint = fp
}

// cloudPairCookie 把 __cflb/__oailb 拼成 Cookie 头，座位牌只拼这两张，不乱夹名片。
func cloudPairCookie(cookies map[string]string) string {
	var parts []string
	for _, name := range []string{"__cflb", "__oailb"} {
		if v := cookies[name]; v != "" {
			parts = append(parts, name+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// modeltraceTarget 按源名找打票目标，不像 fillTargets 要求 enabled。
// 测试可以先验源再开生产灌池；urlOverride 可临时指新 FC 地址，试灶不必先办全店开业。
func modeltraceTarget(c cloudMintConfig, source, urlOverride string) (cloudFillTarget, error) {
	var t cloudFillTarget
	switch source {
	case "fc":
		t = cloudFillTarget{Name: "fc", URL: c.FC.URL, ProxyURL: c.FC.ProxyURL, ProxyEnv: c.FC.ProxyEnv}
	case "relay":
		t = cloudFillTarget{Name: "relay", URL: c.Relay.URL, ProxyURL: c.Relay.ProxyURL, ProxyEnv: c.Relay.ProxyEnv}
	case "legacy", "":
		t = cloudFillTarget{Name: "legacy", URL: c.URL, ProxyURL: c.ProxyURL, ProxyEnv: c.ProxyEnv}
	default:
		return cloudFillTarget{}, fmt.Errorf("未知源 %q(可用:fc / relay / legacy)", source)
	}
	if urlOverride != "" {
		t.URL = urlOverride
	}
	if t.URL == "" {
		return cloudFillTarget{}, fmt.Errorf("源 %q 无地址(配置 cloud_mint.%s.url 或在请求体给 url)", t.Name, t.Name)
	}
	return t, nil
}

// runModeltraceProbe 两轮制先验票再看戏：
// 1. 经所选源（默认 FC）用 WS 铸 token + __cflb/__oailb pair。
// 2. 回放该票，经 FC 住宅出口发 turns 条真实客户端式挑战，收数字输出。
// 3. 全部有效输出交 bank 行为分类器归因，不凭声明胸牌认演员。
// account 空取第一个可用 probe 账号，否则按 auth_id 精确点名，不随手抓客人替考。
func runModeltraceProbe(ctx context.Context, cfg pluginConfig, model, source, urlOverride, account, path, apiKey, cpaURL, gateway string, turns int) (modeltraceReport, error) {
	if path == "client" {
		// Test B 走本机 CPA 回环真实客户端链路，不铸票、不碰 FC，考试不能临时换专用厨房。
		return runClientPathProbe(ctx, cfg, model, apiKey, cpaURL, turns)
	}
	if path == "bridge" {
		// 方案 B 带所选账号真 access_token 连 FC 桥接挑战，FC 在同一连接住宅铸票、注入、中继。
		// 验证的是客户端经桥接这一盘菜，不能只验厨房门口的招牌。
		return runBridgePathProbe(ctx, cfg, model, source, urlOverride, account, turns)
	}
	report := modeltraceReport{Model: model, Source: source, Path: path, Transport: "websocket", Turns: []modeltraceTurn{}}

	target, err := modeltraceTarget(cfg.CloudMint, source, urlOverride)
	if err != nil {
		return report, err
	}
	key := os.Getenv(cfg.CloudMint.KeyEnv)
	if key == "" {
		return report, errors.New("relay key 环境变量未设")
	}
	proxyURL, err := target.resolvedProxy()
	if err != nil {
		return report, err
	}
	accounts := cfg.ProbeAccounts
	if account != "" {
		accounts = []string{account}
	}
	creds := probeDownloadCreds(ctx, newProbeClient(cfg), accounts, time.Now())
	var cred probeCredential
	for _, c := range creds {
		if c.accessToken == "" {
			continue
		}
		if account == "" || c.name == account {
			cred = c
			break
		}
	}
	if cred.accessToken == "" {
		if account != "" {
			return report, fmt.Errorf("账号 %q 无可用凭据", account)
		}
		return report, errors.New("没有可用的 probe 账号凭据")
	}
	report.Account = cred.name
	creds2 := cloudMintCredentials{AuthID: cred.name, AccessToken: cred.accessToken, AccountID: cred.accountID}

	scfg := cfg.CloudMint
	scfg.URL = target.URL
	scfg.Transport = "websocket"
	if gateway != "" {
		scfg.Gateway = gateway // #2 固定网关试铸票，空则沿配置（通常 any），不另猜门牌
	}
	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 90 * time.Second
	}

	// 本次验证固定住宅 sid，让铸票与后续 grade 尽量同出口 IP。
	// 票从出生的出口使用，免得换出口把指纹实验搅成认亲大会。
	sid := modeltraceSid()

	// 第一轮先铸票；requestCloudMint 已验 served 等于请求模型，拿合格 token+pair 才开第二场。
	mctx, cancel := context.WithTimeout(ctx, perTurn)
	entry, mErr := requestCloudMint(mctx, cloudMintWork{cfg: scfg, creds: creds2, model: model, key: key, proxyURL: proxyURL, sid: sid})
	cancel()
	if mErr != nil {
		report.Note = "铸票失败(无票可验证): " + mErr.Error()
		return report, nil
	}
	report.DeclaredServed = model
	report.MintGateway = entry.Gateway
	report.TicketFingerprint = cloudFingerprint(entry.Ticket)
	pairCookie := cloudPairCookie(entry.Cookies)

	// 接着回放同张票，逐条挑战收输出，不能买完票就宣布整场戏演得好。
	challenges := generateChallenges(turns)
	var outputs []string
	for _, ch := range challenges {
		select {
		case <-ctx.Done():
			report.Turns = append(report.Turns, modeltraceTurn{Error: "cancelled"})
			return report, nil
		default:
		}
		// grade 首次沿用铸票出口；遇坏 IP、SSL 或掉线等传输失败，后续重试才换新住宅出口。
		// 最多 4 次，以可用出口取得结果；换道只是传输兜底，不把断线当模型答卷。
		var gr gradeResult
		var gErr error
		for attempt := 0; attempt < 4; attempt++ {
			if ctx.Err() != nil {
				break
			}
			gsid := sid
			if attempt > 0 {
				gsid = modeltraceSid() // 重试换新出口，每次固定一个新粘性会话，别一轮内换三辆车
			}
			gctx, gcancel := context.WithTimeout(ctx, perTurn)
			gr, gErr = cloudGradeTurn(gctx, target.URL, key, creds2, model, entry.Ticket, pairCookie, ch.Prompt, proxyURL, gsid)
			gcancel()
			if gErr == nil && gr.OutputText != "" {
				break
			}
		}
		turn := modeltraceTurn{DeclaredServed: gr.Served, OutputLen: len(gr.OutputText)}
		if gErr != nil {
			turn.Error = gErr.Error()
		}
		if gr.OutputText != "" {
			turn.ParsedNumbers = len(parseNumbers(gr.OutputText))
			outputs = append(outputs, gr.OutputText)
		}
		report.Turns = append(report.Turns, turn)
	}

	// 最后做行为指纹归因，账本齐了再认厨师，不靠一声自报家门。
	report.applyFingerprint(outputs, model)
	return report, nil
}

// handleModeltrace 接 POST /codex-turn-state/modeltrace，验票柜台只按这扇门接单。
// 可选 JSON 请求体示例，菜单键名不改艺名：
// {"model":"gpt-6-astra","turns":3,"source":"fc"}。
func handleModeltrace(body []byte) pluginapi.ManagementResponse {
	var params struct {
		Model    string   `json:"model"`
		Turns    int      `json:"turns"`
		Source   string   `json:"source"`
		URL      string   `json:"url"`
		Account  string   `json:"account"`
		Accounts []string `json:"accounts"`
		Path     string   `json:"path"`
		APIKey   string   `json:"api_key"`
		CpaURL   string   `json:"cpa_url"`
		Gateway  string   `json:"gateway"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &params); err != nil {
			return managementError(http.StatusBadRequest, "请求体不是合法 JSON")
		}
	}
	model := params.Model
	if model == "" {
		model = modeltraceDefaultModel
	}
	source := params.Source
	if source == "" {
		source = "fc"
	}
	path := params.Path
	if path == "" {
		path = "fc"
	}
	if path != "fc" && path != "client" && path != "bridge" {
		return managementError(http.StatusBadRequest, "path 只能是 fc / client / bridge")
	}
	turns := params.Turns
	if turns <= 0 {
		turns = modeltraceDefaultTurns
	}
	if turns > modeltraceMaxTurns {
		turns = modeltraceMaxTurns
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// 账号支持 accounts 多选与 account 单选，都传真账号名或指纹；空则取首个可用。
	// 面板多选时各账号并发独立跑报告，多桌同开也不能串账。
	resolveAcct := func(sel string) string {
		for _, a := range cfg.ProbeAccounts {
			if a == sel || cloudFingerprint(a) == sel {
				return a
			}
		}
		return ""
	}
	var accounts []string
	seen := map[string]bool{}
	for _, sel := range params.Accounts {
		if strings.TrimSpace(sel) == "" {
			continue
		}
		a := resolveAcct(sel)
		if a == "" {
			return managementError(http.StatusBadRequest, "未知账号选择: "+sel)
		}
		if !seen[a] {
			seen[a] = true
			accounts = append(accounts, a)
		}
	}
	if len(accounts) == 0 && params.Account != "" {
		a := resolveAcct(params.Account)
		if a == "" {
			return managementError(http.StatusBadRequest, "未知账号选择")
		}
		accounts = append(accounts, a)
	}

	// 总时限按每轮 TimeoutMS 加余量，别让管理请求先掀桌，而单轮探针还在上菜。
	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 90 * time.Second
	}
	// 给一轮铸票和 turns 轮 grade 留足总时限；多账号并发墙钟近似，不把并行当逐桌排队算。
	ctx, cancel := context.WithTimeout(context.Background(), perTurn*time.Duration(turns+1)+60*time.Second)
	defer cancel()

	// 单账号或自动选择仍回原单份报告结构，老面板照吃老碗，不突然换成托盘。
	if len(accounts) <= 1 {
		acct := ""
		if len(accounts) == 1 {
			acct = accounts[0]
		}
		report, err := runModeltraceProbe(ctx, cfg, model, source, params.URL, acct, path, params.APIKey, params.CpaURL, params.Gateway, turns)
		if err != nil {
			return managementError(http.StatusBadGateway, err.Error())
		}
		logModeltrace(model, path, &report)
		return jsonResponse(http.StatusOK, report)
	}

	// 多账号各跑一份再汇总，席可并开，账仍分人。
	type acctResult struct {
		Account string            `json:"account"`
		Report  *modeltraceReport `json:"report,omitempty"`
		Error   string            `json:"error,omitempty"`
	}
	results := make([]acctResult, len(accounts))
	var wg sync.WaitGroup
	for i, acct := range accounts {
		wg.Add(1)
		go func(i int, acct string) {
			defer wg.Done()
			rep, err := runModeltraceProbe(ctx, cfg, model, source, params.URL, acct, path, params.APIKey, params.CpaURL, params.Gateway, turns)
			if err != nil {
				results[i] = acctResult{Account: acct, Error: err.Error()}
				return
			}
			rep.Account = acct
			logModeltrace(model, path, &rep)
			results[i] = acctResult{Account: acct, Report: &rep}
		}(i, acct)
	}
	wg.Wait()
	return jsonResponse(http.StatusOK, map[string]any{"multi": true, "count": len(results), "results": results})
}

// logModeltrace 统一记录单或多账号探测结果，一位账房管多桌，不各自乱写账本。
func logModeltrace(model, path string, report *modeltraceReport) {
	if report.Fingerprint != nil {
		cloudRecordLog("modeltrace", "%s · %s · 路径 %s · 指纹=%s 置信 %.0f%% 匹配=%v",
			cloudSafeLabel(model), cloudSafeLabel(report.Account), path, cloudSafeLabel(report.Fingerprint.Predicted), report.Fingerprint.Confidence*100, report.Fingerprint.Match)
	} else {
		cloudRecordLog("modeltrace", "%s · %s · 路径 %s · %s", cloudSafeLabel(model), cloudSafeLabel(report.Account), path, report.Note)
	}
}
