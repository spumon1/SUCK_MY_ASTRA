package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// 配置是本插件的家务，默认不开席；密钥只从环境变量取，管理页与日志别来夹这道菜。
type cloudMintConfig struct {
	Enabled      bool   `yaml:"enabled"`
	URL          string `yaml:"url"`
	ProxyURL     string `yaml:"proxy_url"`
	ProxyEnv     string `yaml:"proxy_env"`
	KeyEnv       string `yaml:"key_env"`
	Transport    string `yaml:"transport"`
	Gateway      string `yaml:"gateway"`
	TicketLength int    `yaml:"ticket_length"`
	TTLSeconds   int    `yaml:"ttl_seconds"`
	WaitMS       int    `yaml:"wait_ms"`
	TimeoutMS    int    `yaml:"timeout_ms"`
	// PoolFill 开后台灌池：用 probe_accounts 定期向 FC 打票，把满血 __cflb/__oailb 放进全局池，
	// 所有账号共用；池模式的 enabled 可为 false。旧字段只在 FC、Relay 都没开时接班，
	// 搭配顶层 url/proxy 作为单源兼容；新部署请走下方具名源，别让老掌柜永远代班。
	PoolFill           bool `yaml:"pool_fill"`
	PoolFillIntervalMS int  `yaml:"pool_fill_interval_ms"`
	// FC、Relay 各有开关、地址和前置代理，打来的 pair 却进同一锅全局池。
	// FC 是公网阿里云函数，Relay 是本机住宅代理 relay；能双灶并开，也能只点一个灶。
	FC    cloudFillSource `yaml:"fc"`
	Relay cloudFillSource `yaml:"relay"`
}

// cloudFillSource 是单个灌池源的行李包：启用开关、打票端点、前置代理。
// 端点按 cloud_mint.url 验票：HTTPS，回环可 HTTP，不带凭据、查询或片段，谢绝夹带。
type cloudFillSource struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	ProxyURL string `yaml:"proxy_url"`
	ProxyEnv string `yaml:"proxy_env"`
}

// resolvedProxy 给当前源找前置代理，尺子沿用 cloudMintConfig.resolvedProxy，不另开偏门。
func (s cloudFillSource) resolvedProxy() (string, error) {
	raw := strings.TrimSpace(s.ProxyURL)
	if s.ProxyEnv != "" {
		raw = strings.TrimSpace(os.Getenv(s.ProxyEnv))
		if raw == "" {
			return "", errors.New("fill source proxy environment variable is unset")
		}
	}
	proxy, err := parseCloudMintProxy(raw)
	if err != nil {
		return "", err
	}
	if proxy == nil {
		return "", nil
	}
	return proxy.String(), nil
}

// cloudFillTarget 是灌池循环能直接开工的工单：源名、端点、前置代理三样齐活。
type cloudFillTarget struct {
	Name     string
	URL      string
	ProxyURL string
	ProxyEnv string
}

// poolFillActive 看任一具名源或旧 pool_fill 是否开着；有人点火，后台这口锅才开工。
func (c cloudMintConfig) poolFillActive() bool {
	return c.FC.Enabled || c.Relay.Enabled || c.PoolFill
}

// fillTargets 先列启用的具名源；FC、Relay 都没开而旧 pool_fill 开着，
// 才请 legacy 代班，沿用 cloud_mint 顶层 url/proxy，不抢新灶的戏。
func (c cloudMintConfig) fillTargets() []cloudFillTarget {
	var out []cloudFillTarget
	if c.FC.Enabled {
		out = append(out, cloudFillTarget{Name: "fc", URL: c.FC.URL, ProxyURL: c.FC.ProxyURL, ProxyEnv: c.FC.ProxyEnv})
	}
	if c.Relay.Enabled {
		out = append(out, cloudFillTarget{Name: "relay", URL: c.Relay.URL, ProxyURL: c.Relay.ProxyURL, ProxyEnv: c.Relay.ProxyEnv})
	}
	if len(out) == 0 && c.PoolFill {
		out = append(out, cloudFillTarget{Name: "legacy", URL: c.URL, ProxyURL: c.ProxyURL, ProxyEnv: c.ProxyEnv})
	}
	return out
}

// resolvedProxy 给 fillTargets 产出的源解析前置代理，工单有了还得认清车站。
func (t cloudFillTarget) resolvedProxy() (string, error) {
	return cloudFillSource{ProxyURL: t.ProxyURL, ProxyEnv: t.ProxyEnv}.resolvedProxy()
}

// 灌池也要喘气：间隔太小就钳到 30s，不许把水龙头当机关枪。
func (c cloudMintConfig) poolFillIntervalMS() int {
	if c.PoolFillIntervalMS < 1000 {
		return 30000
	}
	return c.PoolFillIntervalMS
}

func defaultCloudMintConfig() cloudMintConfig {
	return cloudMintConfig{KeyEnv: "CPA_RELAY_KEY", Transport: "sse", Gateway: "unified-88",
		TicketLength: 780, TTLSeconds: 240, WaitMS: 2000, TimeoutMS: 90000}
}

var cloudGatewayPattern = regexp.MustCompile(`^unified-[0-9]+$`)
var cloudNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

// validateMintEndpoint 给端点验门票：HTTPS，回环可 HTTP；凭据、查询、片段一律不夹带。
func validateMintEndpoint(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New(field + " must be an HTTPS URL without credentials/query/fragment")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return errors.New(field + " requires HTTPS (HTTP only on loopback)")
	}
	return nil
}

// validate 只给启用的源验地址和前置代理；既然开门营业，门牌与交通都得合法。
func (s cloudFillSource) validate(field string) error {
	if !s.Enabled {
		return nil
	}
	if err := validateMintEndpoint(field+".url", s.URL); err != nil {
		return err
	}
	if strings.TrimSpace(s.ProxyURL) != "" && s.ProxyEnv != "" {
		return errors.New("set only one of " + field + ".proxy_url and proxy_env")
	}
	if s.ProxyEnv != "" && !cloudNamePattern.MatchString(s.ProxyEnv) {
		return errors.New("invalid " + field + ".proxy_env")
	}
	_, err := parseCloudMintProxy(s.ProxyURL)
	return err
}

func (c cloudMintConfig) validate() error {
	// 两个具名源各验各的，启用才检查；隔壁没开灶，不替它闻锅。
	if err := c.FC.validate("cloud_mint.fc"); err != nil {
		return err
	}
	if err := c.Relay.validate("cloud_mint.relay"); err != nil {
		return err
	}
	if !c.Enabled && !c.poolFillActive() {
		return nil
	}
	// 按请求注入 enabled 或 legacy 灌池仍用顶层 url/proxy，真正上场才验这份工单。
	if c.Enabled || (c.PoolFill && !c.FC.Enabled && !c.Relay.Enabled) {
		if err := validateMintEndpoint("cloud_mint.url", c.URL); err != nil {
			return err
		}
		if err := c.validateProxy(); err != nil {
			return err
		}
	}
	if !cloudNamePattern.MatchString(c.KeyEnv) || !(c.Gateway == "any" || cloudGatewayPattern.MatchString(c.Gateway)) {
		return errors.New("invalid cloud_mint key_env or gateway")
	}
	if c.Transport != "sse" && c.Transport != "websocket" {
		return errors.New("cloud_mint.transport must be sse or websocket")
	}
	if c.TicketLength < 1 || c.TicketLength > 4096 || c.TTLSeconds < 1 || c.TTLSeconds > 3600 {
		return errors.New("invalid cloud_mint ticket_length or ttl_seconds")
	}
	if c.WaitMS < 1 || c.WaitMS > 10000 || c.TimeoutMS < c.WaitMS || c.TimeoutMS > 180000 {
		return errors.New("invalid cloud_mint wait_ms or timeout_ms")
	}
	return nil
}

type cloudMintCredentials struct{ AuthID, AccessToken, AccountID string }

var cloudHostCall = hostCallJSON
var cloudCredentialResolver = resolveCloudCredentials
var errCloudNotCodex = errors.New("not a selected Codex credential")

// 账号只认宿主亲自点的名：不借探测账号，不靠单账号猜人，更不写回或刷新 OAuth。
func resolveCloudCredentials(req pluginapi.RequestInterceptRequest) (cloudMintCredentials, error) {
	id := metadataString(req.Metadata, selectedAuthMetadataKey)
	if id == "" {
		return cloudMintCredentials{}, errCloudNotCodex
	}
	index := metadataString(req.Metadata, selectedAuthIndexMetadataKey)
	if index == "" {
		var list struct {
			Files []pluginapi.HostAuthFileEntry `json:"files"`
		}
		if cloudHostCall("host.auth.list", map[string]any{}, &list) != nil {
			return cloudMintCredentials{}, errors.New("credential lookup unavailable")
		}
		for _, file := range list.Files {
			if file.ID == id || file.Name == id {
				index = file.AuthIndex
				break
			}
		}
	}
	if index == "" {
		return cloudMintCredentials{}, errors.New("selected credential index unavailable")
	}
	var runtime pluginapi.HostAuthGetRuntimeResponse
	lookup := pluginapi.HostAuthGetRequest{AuthIndex: index}
	if cloudHostCall("host.auth.get_runtime", lookup, &runtime) != nil {
		return cloudMintCredentials{}, errors.New("credential runtime unavailable")
	}
	if runtime.Auth.ID != id && runtime.Auth.Name != id {
		return cloudMintCredentials{}, errors.New("selected credential mismatch")
	}
	provider := strings.ToLower(strings.TrimSpace(runtime.Auth.Provider))
	kind := strings.ToLower(strings.TrimSpace(runtime.Auth.Type))
	// 云端要转发真凭据，不能学只读面板按文件名看面相认提供商。
	if (provider != "" && provider != "codex") || (provider == "" && kind != "codex") {
		return cloudMintCredentials{}, errCloudNotCodex
	}
	// Unavailable 是宿主汇总的失败告示，冷却完也可能没摘；能否重试由已选中账号的宿主调度器裁定。
	// 这里再挡一次，会让冷启动 503 把缓存恢复也锁在门外。
	// 明确禁用仍拒绝，身份、提供商、物理凭据三道验票不放水。
	if runtime.Auth.Disabled || strings.EqualFold(strings.TrimSpace(runtime.Auth.Status), "disabled") {
		return cloudMintCredentials{}, errors.New("selected credential disabled")
	}
	return readCloudCredentialFile(lookup, runtime.Auth, id)
}

func readCloudCredentialFile(lookup pluginapi.HostAuthGetRequest, runtime pluginapi.HostAuthFileEntry, id string) (cloudMintCredentials, error) {
	var file pluginapi.HostAuthGetResponse
	if cloudHostCall("host.auth.get", lookup, &file) != nil {
		return cloudMintCredentials{}, errors.New("selected credential file unavailable")
	}
	if file.AuthIndex != lookup.AuthIndex || (file.Name != runtime.Name && file.Name != id) {
		return cloudMintCredentials{}, errors.New("credential file mismatch")
	}
	var token struct {
		Type        string `json:"type"`
		AccessToken string `json:"access_token"`
		AccountID   string `json:"account_id"`
	}
	if json.Unmarshal(file.JSON, &token) != nil || token.Type != "codex" || strings.TrimSpace(token.AccessToken) == "" {
		return cloudMintCredentials{}, errors.New("invalid Codex credential")
	}
	return cloudMintCredentials{AuthID: id, AccessToken: token.AccessToken, AccountID: token.AccountID}, nil
}
