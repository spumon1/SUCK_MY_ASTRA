package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const cloudMintTLSHandshakeTimeout = 10 * time.Second

// 前置代理只管插件到 FC 这一程，不继承宿主环境代理，也不替 CPA 业务改道。
func parseCloudMintProxy(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	proxy, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || proxy.Hostname() == "" || proxy.Opaque != "" || proxy.RawQuery != "" || proxy.ForceQuery || proxy.Fragment != "" || (proxy.Path != "" && proxy.Path != "/") {
		return nil, errors.New("invalid cloud_mint proxy URL; require proxy origin without path/query/fragment")
	}
	proxy.Scheme = strings.ToLower(proxy.Scheme)
	switch proxy.Scheme {
	case "http", "https", "socks5":
	case "socks5h":
		proxy.Scheme = "socks5" // Go SOCKS5 已把目标域名交代理解析，别又替司机认一遍路。
	default:
		return nil, errors.New("cloud_mint proxy supports http/https/socks5/socks5h only")
	}
	if port := proxy.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("invalid cloud_mint proxy port")
		}
	}
	return proxy, nil
}

func (c cloudMintConfig) validateProxy() error {
	if strings.TrimSpace(c.ProxyURL) != "" && c.ProxyEnv != "" {
		return errors.New("set only one of cloud_mint.proxy_url and proxy_env")
	}
	if c.ProxyEnv != "" && !cloudNamePattern.MatchString(c.ProxyEnv) {
		return errors.New("invalid cloud_mint.proxy_env")
	}
	_, err := parseCloudMintProxy(c.ProxyURL)
	return err
}

func (c cloudMintConfig) resolvedProxy() (string, error) {
	raw := strings.TrimSpace(c.ProxyURL)
	if c.ProxyEnv != "" {
		raw = strings.TrimSpace(os.Getenv(c.ProxyEnv))
		if raw == "" {
			return "", errors.New("cloud mint proxy environment variable is unset")
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

func newCloudMintTransport(raw string) (*http.Transport, error) {
	proxy, err := parseCloudMintProxy(raw)
	if err != nil {
		return nil, err
	}
	// 单开 Transport，不借用或改动 http.DefaultTransport、CPA 全局代理及 TLS；自家换锅不拆邻居灶。
	transport := &http.Transport{TLSHandshakeTimeout: cloudMintTLSHandshakeTimeout, ForceAttemptHTTP2: true}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	return transport, nil
}
