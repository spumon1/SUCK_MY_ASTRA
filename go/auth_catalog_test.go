package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// --- 凭据目录接缝：认工牌，别看艺名 ---
// 引导门禁听宿主报告，先 provider，再 type，最后文件名。
// Codex 名字的文件可能装其他提供商凭据；只有 provider 优先，才不会把 OpenAI 房卡送错剧组。

// withAuthCatalog 给一个用例装假完整凭据目录；门禁有 2 秒缓存，安装和清理都重置，旧花名册别跨场串戏。
func withAuthCatalog(t *testing.T, files []pluginapi.HostAuthFileEntry, err error) {
	t.Helper()
	authCatalogLister = func() ([]pluginapi.HostAuthFileEntry, error) {
		return files, err
	}
	resetAuthCache()
	t.Cleanup(func() {
		authCatalogLister = listAuthCatalog
		resetAuthCache()
	})
}

func TestEntryIsCodexProviderPrecedence(t *testing.T) {
	cases := []struct {
		name string
		file pluginapi.HostAuthFileEntry
		want bool
	}{
		// provider 双向压过文件名，工牌是真身份，艺名再响也没用。
		{"provider codex, plain name", pluginapi.HostAuthFileEntry{Name: "work.json", Provider: "codex"}, true},
		{"provider codex, case-insensitive", pluginapi.HostAuthFileEntry{Name: "work.json", Provider: "Codex"}, true},
		{"provider gemini, codex name", pluginapi.HostAuthFileEntry{Name: "codex-evil.json", Provider: "gemini"}, false},
		{"provider unknown, codex name", pluginapi.HostAuthFileEntry{Name: "codex-x.json", Provider: "unknown"}, false},
		// provider 没填才轮到 type 顶班，替补别抢首发。
		{"type codex, provider empty", pluginapi.HostAuthFileEntry{Name: "work.json", Type: "codex"}, true},
		{"type gemini, codex name", pluginapi.HostAuthFileEntry{Name: "codex-evil.json", Type: "gemini"}, false},
		// 两项都空才靠文件名约定认人，线索只剩门口招牌。
		{"codex name, nothing reported", pluginapi.HostAuthFileEntry{Name: "codex-a.json"}, true},
		{"codex id, nothing reported", pluginapi.HostAuthFileEntry{ID: "codex-b.json"}, true},
		{"plain name, nothing reported", pluginapi.HostAuthFileEntry{Name: "work.json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := entryIsCodex(tc.file); got != tc.want {
				t.Fatalf("entryIsCodex(%+v) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

// 修静默漏引导：文件名不像 Codex，但宿主说是 Codex 就得引导，别按发型拒客。
func TestSteerUsesProviderNotFilename(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "work-account.json", Name: "work-account.json", Provider: "codex"},
	}, nil)

	resp := interceptAfter(t, request("work-account.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("a provider-verified Codex account under a plain filename was not steered: %q", cookie)
	}
}

// 防泄漏正题：文件名叫 codex，provider 写 gemini，信 provider；pair 不许跟错车。
func TestSteerRefusesCodexNamedForeignCredential(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-evil.json", Name: "codex-evil.json", Provider: "gemini"},
	}, nil)

	resp := interceptAfter(t, request("codex-evil.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("a codex-named foreign credential carried the pool pair: %q", cookie)
	}
}

// 目录能读却找不到所选 auth，是竞态或不一致；不能拿文件名给未知来客开后门。
func TestSteerRefusesAuthAbsentFromCatalog(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-a.json", Name: "codex-a.json", Provider: "codex"},
	}, nil)

	resp := interceptAfter(t, request("codex-ghost.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("an auth the catalog does not list carried the pool pair: %q", cookie)
	}
}

// 目录本身读不到才进入降级，剩文件名这一条线索，沿用旧规矩摸路。
func TestSteerFallsBackToFilenameWhenCatalogDown(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, nil, errors.New("host API unavailable"))

	resp := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("the filename fallback did not steer a codex-named account: %q", cookie)
	}
	resp2 := interceptAfter(t, request("gemini-someone.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp2.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("the filename fallback steered a foreign-named account: %q", cookie)
	}
}

// 先匹配 index 再 id；改名后 index 仍在，别被换招牌骗到隔壁。
func TestSteerMatchesBySelectedAuthIndex(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "original.json", Name: "original.json", AuthIndex: "idx-9", Provider: "codex"},
		{ID: "codex-decoy.json", Name: "codex-decoy.json", AuthIndex: "idx-4", Provider: "gemini"},
	}, nil)

	// codex 风格 id 查不到，但 index 指真 Codex 条目，听 index，照常引导。
	req := request("renamed.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77))
	req.Metadata[selectedAuthIndexMetadataKey] = "idx-9"
	resp := interceptAfter(t, req)
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("an index-verified Codex account was not steered: %q", cookie)
	}

	// 反向才真考优先级：id 指 CODEX，index 指 GEMINI。必须 index 先查并拒绝，
	// 否则 id 抢答就把 pair 搬上 Gemini 的车。
	req2 := request("original.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77))
	req2.Metadata[selectedAuthIndexMetadataKey] = "idx-4"
	resp2 := interceptAfter(t, req2)
	if cookie := resp2.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("the index pointed at a foreign provider yet the pair was attached: %q", cookie)
	}
}

// 只带 index、没有 selected_auth_id 也能归属，有座位号不必再喊艺名。
func TestSteerAttributesByIndexAlone(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-a.json", Name: "codex-a.json", AuthIndex: "idx-9", Provider: "codex"},
	}, nil)

	req := pluginapi.RequestInterceptRequest{
		Model:    "gpt-5.6-sol",
		Metadata: map[string]any{selectedAuthIndexMetadataKey: "idx-9"},
		Headers:  http.Header{},
	}
	resp := interceptAfter(t, req)
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("an index-only Codex request was not steered: %q", cookie)
	}
}

// 单账号推断与门禁说同一套话：目录说 Codex 就算文件名不像也引导；说别家就拒绝，不认口音认工牌。
func TestSoleAccountInferenceVerifiedByCatalog(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthList(t, enabledAccounts("work.json"), nil)
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "work.json", Name: "work.json", Provider: "codex"},
	}, nil)

	resp := interceptAfter(t, request("", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("the sole Codex account under a plain filename was not steered: %q", cookie)
	}
}

func TestSoleAccountInferenceRefusedByCatalog(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	// Codex 列表按文件名把它点进来，目录却说 gemini；门禁信 provider，pair 不跟着凑热闹。
	withAuthList(t, enabledAccounts("codex-suspect.json"), nil)
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-suspect.json", Name: "codex-suspect.json", Provider: "gemini"},
	}, nil)

	resp := interceptAfter(t, request("", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("an inferred account the catalog calls foreign carried the pair: %q", cookie)
	}
}
