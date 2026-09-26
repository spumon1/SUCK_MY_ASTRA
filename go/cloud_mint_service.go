package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const cloudCacheMax = 256
const cloudWorkersMax = 4
const cloudFailureCooldown = 30 * time.Second

type cloudMintJob struct {
	row   cloudDashboardRow
	done  chan struct{}
	entry cloudMintEntry
	err   error
}
type cloudMintCached struct {
	row   cloudDashboardRow
	entry cloudMintEntry
	err   error
	until time.Time
}
type cloudMintService struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	cache  map[string]cloudMintCached
	jobs   map[string]*cloudMintJob
	busy   map[string]bool
}

func newCloudMintService() *cloudMintService {
	ctx, cancel := context.WithCancel(context.Background())
	return &cloudMintService{ctx: ctx, cancel: cancel, cache: map[string]cloudMintCached{}, jobs: map[string]*cloudMintJob{}, busy: map[string]bool{}}
}
func (s *cloudMintService) close() { s.cancel() }

var cloudServiceState = struct {
	sync.Mutex
	service *cloudMintService
}{service: newCloudMintService()}

func resetCloudMintService() {
	cloudServiceState.Lock()
	defer cloudServiceState.Unlock()
	cloudServiceState.service.close()
	cloudServiceState.service = newCloudMintService()
}
func currentCloudMintService() *cloudMintService {
	cloudServiceState.Lock()
	defer cloudServiceState.Unlock()
	return cloudServiceState.service
}

type cloudMintWork struct {
	cfg                   cloudMintConfig
	creds                 cloudMintCredentials
	model, key, id, group string
	proxyURL              string
	seedCookie            string
	sid                   string // 用 sid 钉住住宅出口，modeltrace 铸票与 grade 同门出入；空则沿配置轮换
}

// 摘要点齐账号、实际凭据版本、模型、传输和验收配置；缓存不收 Access Token，只留账目不留金条。
func (w cloudMintWork) cacheKey() string {
	raw, _ := json.Marshal([]any{w.cfg, w.creds.AuthID, w.creds.AccessToken, w.creds.AccountID, w.model, w.key, w.proxyURL, w.seedCookie})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *cloudMintService) get(cfg cloudMintConfig, creds cloudMintCredentials, model string) (cloudMintEntry, error) {
	return s.getWithRoute(cfg, creds, cloudMintRoute{Model: model})
}

func (s *cloudMintService) getWithRoute(cfg cloudMintConfig, creds cloudMintCredentials, route cloudMintRoute) (cloudMintEntry, error) {
	if err := cfg.validate(); err != nil {
		return cloudMintEntry{}, err
	}
	seed, err := cloudMintSeedCookie(route.Cookie, cfg.Gateway, time.Now())
	if err != nil {
		cloudRecordLog("路由 Cookie 拒绝", "%s", err)
		return cloudMintEntry{}, err
	}
	key := os.Getenv(cfg.KeyEnv)
	if key == "" {
		return cloudMintEntry{}, errors.New("relay key environment variable is unset")
	}
	proxyURL, err := cfg.resolvedProxy()
	if err != nil {
		return cloudMintEntry{}, err
	}
	work := cloudMintWork{proxyURL: proxyURL, seedCookie: seed, cfg: cfg, creds: creds, model: route.Model, key: key, group: cloudFingerprint(creds.AuthID + "\x00" + creds.AccessToken)}
	work.id = work.cacheKey()
	job, hit, err := s.start(work)
	if err != nil {
		return cloudMintEntry{}, err
	}
	if hit != nil {
		return hit.entry, hit.err
	}
	timer := time.NewTimer(time.Duration(cfg.WaitMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-job.done:
		return job.entry, job.err
	case <-s.ctx.Done():
		return cloudMintEntry{}, errors.New("cloud mint stopped")
	case <-timer.C:
		return cloudMintEntry{}, errors.New("cloud mint pending; retry later")
	}
}

// 同账号只开一个工位，同桶并发拼单；冷启动不能让业务线程在云端冷却门口等到天荒地老。
func (s *cloudMintService) start(work cloudMintWork) (*cloudMintJob, *cloudMintCached, error) {
	id, group := work.id, work.group
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return nil, nil, errors.New("cloud mint stopped")
	}
	if hit, ok := s.cache[id]; ok && hit.until.After(time.Now().Add(time.Second)) {
		return nil, &hit, nil
	}
	if job := s.jobs[id]; job != nil {
		return job, nil, nil
	}
	if len(s.jobs) >= cloudWorkersMax || s.busy[group] {
		return nil, nil, errors.New("cloud mint busy; retry later")
	}
	job := &cloudMintJob{done: make(chan struct{}), row: cloudWorkRow(work)}
	s.jobs[id] = job
	s.busy[group] = true
	go s.run(work, job)
	return job, nil, nil
}

func (s *cloudMintService) run(work cloudMintWork, job *cloudMintJob) {
	cfg, creds, model, id, group := work.cfg, work.creds, work.model, work.id, work.group
	ctx, cancel := context.WithTimeout(s.ctx, time.Duration(cfg.TimeoutMS)*time.Millisecond)
	defer cancel()
	cloudRecordLog("云端打票开始", "账号 #%s · %s · %s", cloudFingerprint(creds.AuthID), cloudSafeLabel(model), cfg.Transport)
	entry, err := requestCloudMint(ctx, work)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		err = errors.New("cloud mint canceled or timed out")
	}
	job.entry = entry
	job.err = err
	delete(s.jobs, id)
	delete(s.busy, group)
	if s.ctx.Err() == nil {
		if len(s.cache) >= cloudCacheMax {
			for old := range s.cache {
				delete(s.cache, old)
				break
			}
		}
		until := entry.ExpiresAt
		if err != nil {
			until = time.Now().Add(cloudFailureCooldown)
		}
		s.cache[id] = cloudMintCached{entry: entry, err: err, until: until, row: job.row}
	}
	if err != nil {
		cloudRecordLog("云端打票失败", "账号 #%s · %s · %s", cloudFingerprint(creds.AuthID), cloudSafeLabel(model), err)
	}
	close(job.done)
}

// 云端模式独占可归属 Codex 流量的注入决定，旧全局 Cookie 池不能再来抢票的目标 pair。
// 先认清凭据：非 Codex 或身份不明都原样放行，与池模式“认不清就不动”一致。
// 503 只给已确认 Codex 但票未就绪的请求，别让一个开关把隔壁提供商也关进小黑屋。
func interceptCloudMint(req pluginapi.RequestInterceptRequest, cfg pluginConfig) (out pluginapi.RequestInterceptResponse) {
	track := true
	defer func() {
		if track {
			cloudRememberRequest(req, out)
		}
	}()
	if cfg.DryRun || headerValue(req.Headers, turnStateHeader) != "" {
		return pluginapi.RequestInterceptResponse{}
	}
	creds, err := cloudCredentialResolver(req)
	if errors.Is(err, errCloudNotCodex) {
		track = false
		return pluginapi.RequestInterceptResponse{}
	}
	if err != nil {
		// 归属不明就放行：没票的 Codex 仍可交上游处理；
		// 误拦非 Codex 会断掉别家模型的通信，门卫宁可不乱伸手。
		track = false
		cloudRecordLog("凭据归属不明放行", "%s", err)
		return pluginapi.RequestInterceptResponse{}
	}
	model := pickModel(req.Model, req.RequestedModel)
	if model == "" || !cloudNamePattern.MatchString(model) {
		return cloudMintUnavailable()
	}
	entry, err := currentCloudMintService().getWithRoute(cfg.CloudMint, creds,
		cloudMintRoute{Model: model, Cookie: headerValue(req.Headers, "Cookie")})
	if err != nil || !entry.ExpiresAt.After(time.Now().Add(time.Second)) {
		return cloudMintUnavailable()
	}
	cloudRecordLog("云端票注入", "%s", formatCloudMintLog(cloudLogView{}, cloudEntryView(entry)))
	headers := http.Header{}
	headers.Set(turnStateHeader, entry.Ticket)
	headers.Set("Cookie", mergeRouteCookies(headerValue(req.Headers, "Cookie"), entry.Cookies))
	resp := pluginapi.RequestInterceptResponse{ClearHeaders: []string{turnStateHeader, "Cookie"}, Headers: headers}
	// WS 的票要写进帧 body 的 client_metadata['x-codex-turn-state']，头部只到 upgrade 门口，
	// 进不了 response.create 席位；所以同时写 body。SSE 看 header，WS 看 body，各认各的座位。
	// 这与真实客户端续轮、FC grade 回放的 relay/index.js mintGradePayload 对齐。
	// body 为空或不是 JSON 就不碰它，只保留 header 注入，不拿坏菜硬摆盘。
	if newBody, ok := injectTurnStateIntoBody(req.Body, entry.Ticket); ok {
		resp.Body = newBody
	}
	return resp
}

// clientMetadataTurnStateKey 是上游在 response.create 帧里找 turn-state 的门牌，别贴到隔壁。
const clientMetadataTurnStateKey = "x-codex-turn-state"

// injectTurnStateIntoBody 把票放进 client_metadata['x-codex-turn-state']，其余键原位留座。
// 体为空、不是 JSON 对象或票为空就回 ok=false；调用方保留原体，只走 header，不强拆别人的桌子。
func injectTurnStateIntoBody(body []byte, ticket string) ([]byte, bool) {
	if len(body) == 0 || ticket == "" {
		return nil, false
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return nil, false
	}
	meta, _ := obj["client_metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[clientMetadataTurnStateKey] = ticket
	obj["client_metadata"] = meta
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false
	}
	return out, true
}

func cloudMintUnavailable() pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: http.StatusServiceUnavailable,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}, "Retry-After": []string{"2"}},
		ResponseBody:    []byte(`{"error":{"code":"cloud_mint_unavailable","message":"ticket not ready; retry later"}}`)}
}
