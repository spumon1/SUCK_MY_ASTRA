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
	"os"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// modeltraceSid 生成一个字母数字 sid(≤32),用于钉住本次验证的住宅出口。
func modeltraceSid() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "mtprobe0"
	}
	return fmt.Sprintf("%x", b[:])
}

// modeltrace 主动探针:用池账号对某个灌池源(默认 fc)以 WS 对目标模型连打 N 轮,
// 报出每轮上游实际执行(served)的模型。满血 = served == 请求模型;降级则 served
// 是 fallback(如 gpt-6-luna)。它不写池、不改业务,只做审计式验证 —— 满血是上游
// 每轮决策,只有真跑一轮才知道那一轮的结果。烧额度,故走带 key 的 POST 路由。
const (
	modeltraceDefaultModel = "gpt-6-astra"
	modeltraceDefaultTurns = 3
	modeltraceMaxTurns     = 10
)

type modeltraceTurn struct {
	DeclaredServed string `json:"declared_served"` // 该轮 response.created 声明的模型
	OutputLen      int    `json:"output_len"`      // 收到的输出文本长度
	ParsedNumbers  int    `json:"parsed_numbers"`  // 解析出的数字个数
	Error          string `json:"error,omitempty"`
}

type modeltraceCandidate struct {
	Model       string  `json:"model"`
	DisplayName string  `json:"display_name"`
	Probability float64 `json:"probability"`
}

// 行为指纹结论:对全部有效输出统计归因,得出上游"实际是哪个模型",不看声明标签。
type modeltraceFingerprint struct {
	Predicted    string                `json:"predicted"`
	DisplayName  string                `json:"display_name"`
	Confidence   float64               `json:"confidence"`
	Match        bool                  `json:"match"` // 指纹判定 == 请求模型?
	ValidOutputs int                   `json:"valid_outputs"`
	TopCandidates []modeltraceCandidate `json:"top_candidates"`
}

type modeltraceReport struct {
	Model             string                 `json:"model"`
	Source            string                 `json:"source"`
	Path              string                 `json:"path"` // fc = 经 FC 验票;client = 经 CPA 出口验客户端真实路径
	Account           string                 `json:"account"`
	Transport         string                 `json:"transport"`
	DeclaredServed    string                 `json:"declared_served"`    // 铸票那轮声明的模型
	MintGateway       string                 `json:"mint_gateway"`       // 这张票落在哪个网关(unified-N)
	TicketFingerprint string                 `json:"ticket_fingerprint"` // 被验证的那张票(脱敏)
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

// cloudGradeTurn 让 FC 回放一张票发一轮真实 WS 请求(带挑战),回传模型输出文本。
// 这是"两轮制"的第二轮:第一轮铸票拿到 token+pair,这里用它们发真实客户端式请求。
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

// runClientPathProbe 是 Test B:不铸票、不碰 FC,只从 CPA 本机回环发 turns 条正常业务
// 请求(内容为挑战),让 CPA 用真实客户端路径执行,收集输出做指纹。
func runClientPathProbe(ctx context.Context, cfg pluginConfig, model, apiKey, cpaURL string, turns int) (modeltraceReport, error) {
	report := modeltraceReport{Model: model, Source: "cpa", Path: "client", Transport: "websocket", Turns: []modeltraceTurn{}}
	if apiKey == "" {
		return report, errors.New("client 路径需要 api_key(业务鉴权)")
	}
	if cpaURL == "" {
		// CPA 本机业务 WS 端点:把 http(s):// 基址转成 ws(s)://。
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
		served, outText, cErr := clientTurnWS(cctx, cpaURL, apiKey, model, ch.Prompt)
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

// applyFingerprint 对收集到的输出做行为指纹归因,填进报告。
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

// cloudPairCookie 把 __cflb/__oailb 拼成 Cookie 头值。
func cloudPairCookie(cookies map[string]string) string {
	var parts []string
	for _, name := range []string{"__cflb", "__oailb"} {
		if v := cookies[name]; v != "" {
			parts = append(parts, name+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// modeltraceTarget 按源名解析打票目标。与 fillTargets 不同,它不要求源 enabled ——
// 测试路径要能在不开启生产灌池的前提下单测某个源;urlOverride 可临时指向某个地址
// (如刚部署、还没写进配置的 FC)。
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

// runModeltraceProbe 两轮制指纹验证:
//  1) 经所选源(默认 FC)以 WS 铸一张票(拿到 token + __cflb/__oailb pair);
//  2) 用这张票回放,发 turns 条挑战(真实客户端式 WS 请求,经 FC 住宅出口),收集
//     模型输出的数字;
//  3) 把全部有效输出交给行为指纹分类器(bank),判定"实际是哪个模型",不看声明标签。
// account 为空则取第一个可用 probe 账号,否则按 auth_id 精确选。
func runModeltraceProbe(ctx context.Context, cfg pluginConfig, model, source, urlOverride, account, path, apiKey, cpaURL, gateway string, turns int) (modeltraceReport, error) {
	if path == "client" {
		// Test B:走 CPA 本机回环的真实客户端路径,不铸票、不碰 FC。
		return runClientPathProbe(ctx, cfg, model, apiKey, cpaURL, turns)
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
		scfg.Gateway = gateway // #2:测试固定网关铸票(留空沿用配置,通常 any)
	}
	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 90 * time.Second
	}

	// 本次验证钉一个住宅出口 sid:铸票与后续 grade 走同一个出口 IP,票才是"从它出生
	// 的出口去用",指纹结果才不被出口不一致污染。
	sid := modeltraceSid()

	// 第一轮:铸票(requestCloudMint 已校验 served==请求模型,拿到合格 token + pair)。
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

	// 第二轮起:用这张票回放,逐条挑战收集输出。
	challenges := generateChallenges(turns)
	var outputs []string
	for _, ch := range challenges {
		select {
		case <-ctx.Done():
			report.Turns = append(report.Turns, modeltraceTurn{Error: "cancelled"})
			return report, nil
		default:
		}
		// grade 轮偶发传输/上游错误(旋转出口坏 IP、ws_closed、ws_error_event),
		// 重试最多 3 次,拿到输出即止 —— 让单次测试更可靠。
		var gr gradeResult
		var gErr error
		for attempt := 0; attempt < 3; attempt++ {
			if ctx.Err() != nil {
				break
			}
			gctx, gcancel := context.WithTimeout(ctx, perTurn)
			gr, gErr = cloudGradeTurn(gctx, target.URL, key, creds2, model, entry.Ticket, pairCookie, ch.Prompt, proxyURL, sid)
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

	// 第三步:行为指纹归因。
	report.applyFingerprint(outputs, model)
	return report, nil
}

// handleModeltrace 处理 POST /codex-turn-state/modeltrace。请求体(可选)JSON:
// {"model":"gpt-6-astra","turns":3,"source":"fc"}。
func handleModeltrace(body []byte) pluginapi.ManagementResponse {
	var params struct {
		Model   string `json:"model"`
		Turns   int    `json:"turns"`
		Source  string `json:"source"`
		URL     string `json:"url"`
		Account string `json:"account"`
		Path    string `json:"path"`
		APIKey  string `json:"api_key"`
		CpaURL  string `json:"cpa_url"`
		Gateway string `json:"gateway"`
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
	if path != "fc" && path != "client" {
		return managementError(http.StatusBadRequest, "path 只能是 fc 或 client")
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

	// 面板传真实账号名(也兼容旧的指纹传参)。空 = 取第一个可用。
	account := ""
	if params.Account != "" {
		for _, a := range cfg.ProbeAccounts {
			if a == params.Account || cloudFingerprint(a) == params.Account {
				account = a
				break
			}
		}
		if account == "" {
			return managementError(http.StatusBadRequest, "未知账号选择")
		}
	}

	// 整体时限给足:每轮 TimeoutMS 加富余,避免管理调用比单轮更早被砍。
	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 90 * time.Second
	}
	// 一轮铸票 + turns 轮 grade,整体时限给足。
	ctx, cancel := context.WithTimeout(context.Background(), perTurn*time.Duration(turns+1)+60*time.Second)
	defer cancel()

	report, err := runModeltraceProbe(ctx, cfg, model, source, params.URL, account, path, params.APIKey, params.CpaURL, params.Gateway, turns)
	if err != nil {
		return managementError(http.StatusBadGateway, err.Error())
	}
	if report.Fingerprint != nil {
		cloudRecordLog("modeltrace", "%s · 路径 %s · 指纹=%s 置信 %.0f%% 匹配=%v",
			cloudSafeLabel(model), path, cloudSafeLabel(report.Fingerprint.Predicted), report.Fingerprint.Confidence*100, report.Fingerprint.Match)
	} else {
		cloudRecordLog("modeltrace", "%s · 路径 %s · %s", cloudSafeLabel(model), path, report.Note)
	}
	return jsonResponse(http.StatusOK, report)
}
