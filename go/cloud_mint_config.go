package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
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
}

func defaultCloudMintConfig() cloudMintConfig {
	return cloudMintConfig{KeyEnv: "CPA_RELAY_KEY", Transport: "sse", Gateway: "unified-88",
		TicketLength: 780, TTLSeconds: 240, WaitMS: 2000, TimeoutMS: 90000}
}

var cloudGatewayPattern = regexp.MustCompile(`^unified-[0-9]+$`)
var cloudNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

func (c cloudMintConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("cloud_mint.url must be an HTTPS URL without credentials/query/fragment")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return errors.New("cloud_mint.url requires HTTPS (HTTP only on loopback)")
	}
	if err := c.validateProxy(); err != nil {
		return err
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
