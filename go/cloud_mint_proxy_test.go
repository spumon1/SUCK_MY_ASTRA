package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloudMintProxyValidation(t *testing.T) {
	for _, raw := range []string{"ftp://proxy.invalid:21", "http://proxy.invalid/path", "http://proxy.invalid?key=secret", "http://proxy.invalid#secret", "http://proxy.invalid:0", "http://proxy.invalid:99999"} {
		cfg := defaultCloudMintConfig()
		cfg.Enabled = true
		cfg.URL = "https://fc.invalid/"
		cfg.ProxyURL = raw
		if err := cfg.validate(); err == nil {
			t.Fatalf("accepted invalid proxy %s", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:3128", "https://proxy.invalid:443", "socks5://127.0.0.1:1080", "socks5h://user:secret@127.0.0.1:1080", ""} {
		cfg := defaultCloudMintConfig()
		cfg.Enabled = true
		cfg.URL = "https://fc.invalid/"
		cfg.ProxyURL = raw
		if err := cfg.validate(); err != nil {
			t.Fatal("valid proxy rejected", err)
		}
	}
}

// 目标回环端口故意不营业；显式代理扮 FC，NO_PROXY 不能把这位替身绕过去。
func TestCloudMintReachesFCThroughForwardProxy(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Host != "localhost:4444" || r.Method != "POST" {
			t.Error("wrong proxy destination")
		}
		if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("X-Relay-Key") != "relay-key" {
			t.Error("missing FC headers")
		}
		json.NewEncoder(w).Encode(cloudTestResult(time.Now().Truncate(time.Second), "gpt-6-sol"))
	}))
	defer proxy.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = "http://localhost:4444/"
	cfg.ProxyURL = proxy.URL
	cfg.WaitMS = 1000
	t.Setenv(cfg.KeyEnv, "relay-key")
	t.Setenv("NO_PROXY", "*")
	service := newCloudMintService()
	defer service.close()
	if _, err := service.get(cfg, cloudMintCredentials{AuthID: "A", AccessToken: "access"}, "gpt-6-sol"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("explicit proxy was not used")
	}
}

func TestCloudMintProxyFailureNeverFallsBackToDirect(t *testing.T) {
	var direct atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1) }))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "proxy unavailable", 502) }))
	defer proxy.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = origin.URL
	cfg.ProxyURL = proxy.URL
	cfg.WaitMS = 1000
	t.Setenv(cfg.KeyEnv, "key")
	service := newCloudMintService()
	defer service.close()
	if _, err := service.get(cfg, cloudMintCredentials{AuthID: "A", AccessToken: "access"}, "gpt-6-sol"); err == nil {
		t.Fatal("proxy failure accepted")
	}
	if direct.Load() != 0 {
		t.Fatal("failed proxy silently fell back to direct")
	}
}

func TestCloudMintProxyEnvironmentIsRequiredWhenConfigured(t *testing.T) {
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = "https://fc.invalid/"
	cfg.ProxyEnv = "CPA_MINT_PROXY"
	t.Setenv(cfg.ProxyEnv, "")
	t.Setenv(cfg.KeyEnv, "key")
	service := newCloudMintService()
	defer service.close()
	if _, err := service.get(cfg, cloudMintCredentials{AuthID: "A", AccessToken: "access"}, "gpt-6-sol"); err == nil {
		t.Fatal("missing proxy env silently accepted")
	}
	cfg.ProxyURL = "http://127.0.0.1:3128"
	if cfg.validate() == nil {
		t.Fatal("ambiguous proxy sources accepted")
	}
}

func TestCloudMintEmptyProxyDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://bad.invalid:1234")
	t.Setenv("HTTPS_PROXY", "http://bad.invalid:1234")
	tr, err := newCloudMintTransport("")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	if tr.Proxy != nil {
		t.Fatal("empty proxy must be explicit direct")
	}
}

func cloudTestConnectProxy(t *testing.T, secure bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "CONNECT" {
			t.Error("expected CONNECT")
			http.Error(w, "bad method", 400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret")) {
			t.Error("proxy authentication missing")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Relay-Key") != "" {
			t.Error("FC secrets leaked outside TLS tunnel")
		}
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "dial failed", 502)
			return
		}
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		defer connection.Close()
		defer target.Close()
		fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n")
		buffer.Flush()
		go func() { io.Copy(target, buffer); target.Close() }()
		io.Copy(connection, target)
	})
	if secure {
		return httptest.NewTLSServer(handler), calls
	}
	return httptest.NewServer(handler), calls
}

func TestCloudMintHTTPAndHTTPSProxyKeepOriginTLSVerification(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("proxy credentials leaked to FC")
				}
				io.WriteString(w, "fc-ok")
			}))
			defer origin.Close()
			proxy, calls := cloudTestConnectProxy(t, secure)
			defer proxy.Close()
			proxyURL, _ := url.Parse(proxy.URL)
			proxyURL.User = url.UserPassword("proxy-user", "proxy-secret")
			tr, err := newCloudMintTransport(proxyURL.String())
			if err != nil {
				t.Fatal(err)
			}
			defer tr.CloseIdleConnections()
			roots := x509.NewCertPool()
			roots.AddCert(origin.Certificate())
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			client := &http.Client{Transport: tr, Timeout: time.Second}
			req, _ := http.NewRequest("GET", origin.URL, nil)
			req.Header.Set("Authorization", "Bearer access")
			req.Header.Set("X-Relay-Key", "relay-key")
			res, err := client.Do(req)
			if err != nil {
				t.Fatal("proxy tunnel failed", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if string(body) != "fc-ok" || calls.Load() != 1 {
				t.Fatal("did not reach FC through CONNECT")
			}
			tr.CloseIdleConnections()
			untrusted, err := newCloudMintTransport(proxyURL.String())
			if err != nil {
				t.Fatal(err)
			}
			defer untrusted.CloseIdleConnections()
			if res, err := (&http.Client{Transport: untrusted, Timeout: time.Second}).Get(origin.URL); err == nil {
				res.Body.Close()
				t.Fatal("untrusted TLS certificate accepted")
			}
		})
	}
}

func TestCloudMintProxyErrorsNeverEchoCredentials(t *testing.T) {
	raw := "http://proxy-user:very-private-password@proxy.invalid/path?secret=token"
	_, err := newCloudMintTransport(raw)
	if err == nil {
		t.Fatal("bad URL accepted")
	}
	for _, value := range []string{"proxy-user", "very-private-password", "token"} {
		if strings.Contains(err.Error(), value) {
			t.Fatal("proxy error leaked credentials")
		}
	}
}

func TestCloudMintProxyEnvironmentChangeInvalidatesCache(t *testing.T) {
	var first, second atomic.Int32
	handler := func(calls *atomic.Int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			json.NewEncoder(w).Encode(cloudTestResult(time.Now().Truncate(time.Second), "gpt-6-sol"))
		}
	}
	p1 := httptest.NewServer(handler(&first))
	defer p1.Close()
	p2 := httptest.NewServer(handler(&second))
	defer p2.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = "http://localhost:4444/"
	cfg.ProxyEnv = "CPA_MINT_PROXY"
	cfg.WaitMS = 1000
	t.Setenv(cfg.KeyEnv, "key")
	t.Setenv(cfg.ProxyEnv, p1.URL)
	service := newCloudMintService()
	defer service.close()
	creds := cloudMintCredentials{AuthID: "A", AccessToken: "access"}
	if _, err := service.get(cfg, creds, "gpt-6-sol"); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cfg.ProxyEnv, p2.URL)
	if _, err := service.get(cfg, creds, "gpt-6-sol"); err != nil {
		t.Fatal(err)
	}
	if first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("proxy environment change reused old cache: %d/%d", first.Load(), second.Load())
	}
}
