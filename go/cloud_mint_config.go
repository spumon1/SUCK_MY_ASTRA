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

// 配置属于本插件，默认关闭；密钥只从环境变量读取，不能进入管理页或日志。
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
	// PoolFill 开启后台灌池循环:用 probe_accounts 的账号定期调 FC 打票,把满血
	// __cflb/__oailb 灌进全局池,供所有账号复用(池模式下 enabled 可为 false)。
	// 旧字段:当 FC / Relay 两个源都未启用时,退回用它 + 上面的 url/proxy 作为
	// 单一灌池源(向后兼容)。新部署应改用下面的两个具名源。
	PoolFill           bool `yaml:"pool_fill"`
	PoolFillIntervalMS int  `yaml:"pool_fill_interval_ms"`
	// FC 与 Relay 是两个各自独立开关、各自地址与前置代理的灌池源,都把打到的
	// pair 灌进同一个全局池。FC 指公网阿里云函数;Relay 指本机住宅代理 relay。
	// 两者可同时启用并行灌池,也可各自单开。
	FC    cloudFillSource `yaml:"fc"`
	Relay cloudFillSource `yaml:"relay"`
}

// cloudFillSource 是一个灌池源:自己的启用开关、打票端点与前置代理。端点与
// 校验规则同 cloud_mint.url(HTTPS,回环可 HTTP,不含凭据/查询/片段)。
type cloudFillSource struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	ProxyURL string `yaml:"proxy_url"`
	ProxyEnv string `yaml:"proxy_env"`
}

// resolvedProxy 解析该源的前置代理,规则同 cloudMintConfig.resolvedProxy。
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

// cloudFillTarget 是灌池循环解析后的一个可执行源:名字 + 端点 + 前置代理。
type cloudFillTarget struct {
	Name     string
	URL      string
	ProxyURL string
	ProxyEnv string
}

// poolFillActive 报告后台灌池循环是否应该运行:任一具名源启用,或旧的 pool_fill 开。
func (c cloudMintConfig) poolFillActive() bool {
	return c.FC.Enabled || c.Relay.Enabled || c.PoolFill
}

// fillTargets 列出本轮要执行的灌池源。优先用两个具名源(启用的);两者都没
// 启用而旧 pool_fill 开着时,退回单一 legacy 源(用 cloud_mint 顶层 url/proxy)。
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

// resolvedProxy 解析某个灌池源(fillTargets 产物)的前置代理。
func (t cloudFillTarget) resolvedProxy() (string, error) {
	return cloudFillSource{ProxyURL: t.ProxyURL, ProxyEnv: t.ProxyEnv}.resolvedProxy()
}

// 灌池间隔,过小则钳到 30s。
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

// validateMintEndpoint 校验一个打票端点:HTTPS(回环可 HTTP),不含凭据、查询或片段。
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

// validate 校验源:启用则地址与前置代理都要合法。
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
	// 两个具名灌池源各自独立校验(启用才校验)。
	if err := c.FC.validate("cloud_mint.fc"); err != nil {
		return err
	}
	if err := c.Relay.validate("cloud_mint.relay"); err != nil {
		return err
	}
	if !c.Enabled && !c.poolFillActive() {
		return nil
	}
	// 按请求注入(enabled)或旧 legacy 灌池仍读顶层 url/proxy,需要时才校验。
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

// 只相信宿主选中的账号，不借用探测账号，不按单账号部署推断，更不写回或刷新 OAuth。
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
	// 云端凭据转发不能像只读面板那样按文件名猜提供商。
	if (provider != "" && provider != "codex") || (provider == "" && kind != "codex") {
		return cloudMintCredentials{}, errCloudNotCodex
	}
	// Unavailable 是宿主的聚合失败摘要，冷却到期仍可能为 true；是否可重试由
	// 已选中该账号的宿主调度器决定。这里再次否决会让冷启动 503 阻断缓存恢复。
	// 明确禁用仍须拒绝，且账号身份、提供商与物理凭据校验保持不变。
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
