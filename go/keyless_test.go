package main

// 免密动作四人组 dry_run、role、clear、selftest 挂在未鉴权资源前缀；
// 带副作用的 GET 由 confirm=1 把门，dry_run/role 的运行时覆盖跨重启保留。
// 运营者明确选择这四项免密，不等于秘密也免检；会吐代理 userinfo 的 config
// 必须待在鉴权管理路由，不能挤进资源区，这里两边一起验门票。

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

const (
	opsDryRunPath   = mgmtResourcePath + "ops/dry-run"
	opsRolePath     = mgmtResourcePath + "ops/role"
	opsClearPath    = mgmtResourcePath + "ops/clear"
	opsSelftestPath = mgmtResourcePath + "ops/selftest"
)

// driveResource 带 query 发一次免密 GET 资源请求；driveManagement 的 Query 写死为空。
// 这些动作靠 query 收参数，不能请一个没嘴的传话人。
func driveResource(t *testing.T, path string, query url.Values) mgmtResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Method":  http.MethodGet,
		"Path":    path,
		"Headers": http.Header{},
		"Query":   query,
		"Body":    nil,
	})
	if err != nil {
		t.Fatalf("marshal resource request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementHandle, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.handle) GET %s: %v", path, errHandle)
	}
	var resp mgmtResponse
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
			t.Fatalf("decode resource response: %v", errUnmarshal)
		}
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return resp
}

func confirmed(extra url.Values) url.Values {
	q := url.Values{"confirm": {"1"}}
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return q
}

func readOverrideFile(t *testing.T, dir string) runtimeOverride {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, runtimeOverrideFileName))
	if err != nil {
		t.Fatalf("read %s: %v", runtimeOverrideFileName, err)
	}
	var ov runtimeOverride
	if err := json.Unmarshal(data, &ov); err != nil {
		t.Fatalf("decode %s: %v", runtimeOverrideFileName, err)
	}
	return ov
}

// 四个动作必须是免密 Resources，吐代理秘密的 config 必须反过来待在管理 Routes。
// 注册就是授权；改名或搬家若反了方向，不是给动作加锁，就是给密码开橱窗，两种都抓。
func TestKeylessRoutesRegisteredUnauthenticated(t *testing.T) {
	reg := driveManagementRegister(t)

	resourcePaths := make(map[string]mgmtRoute)
	for _, r := range reg.Resources {
		resourcePaths[r.Path] = r
	}
	routePaths := make(map[string]bool)
	for _, r := range reg.Routes {
		routePaths[r.Path] = true
	}

	for _, p := range []string{"/ops/dry-run", "/ops/role", "/ops/clear", "/ops/selftest"} {
		res, ok := resourcePaths[p]
		if !ok {
			t.Errorf("%s is not registered as a resource; a keyless action must be, or it would still demand a management key", p)
			continue
		}
		if res.Menu != "" {
			t.Errorf("%s declares Menu %q; the actions are fetched by script, not navigated to, and a menu entry misrepresents them", p, res.Menu)
		}
		if routePaths[p] {
			t.Errorf("%s is also a management route; the keyless action must live only on the unauthenticated resource prefix", p)
		}
	}

	// config 会吐代理 userinfo，必须鉴权且绝不注册为资源；密码不能穿透明雨衣上街。
	for _, r := range reg.Resources {
		if strings.HasSuffix(r.Path, "/config") {
			t.Errorf("config route %q is registered as a resource; it emits proxy secrets and must stay behind the key", r.Path)
		}
	}
}

// 会改状态的 GET 全靠 confirm=1 把关；没确认就不做事并说明，
// 裸导航、预取和爬虫不能路过一下就替人按按钮。
func TestKeylessActionRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // dry_run: true

	resp := driveResource(t, opsDryRunPath, url.Values{"value": {"off"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dry-run without confirm returned %d, want 400 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if st := mustManagementStatus(t); !st.DryRun {
		t.Error("dry_run changed even though the action was refused for lack of confirm=1")
	}
}

// 破坏性动作没拿到 confirm 就拒绝，拒绝不是嘴上说说，文件一张也不能少。
func TestKeylessClearRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, dir)
	recordObservation(cfg, "codex-x.json", "gpt-5.5", 292, false)

	resp := driveResource(t, opsClearPath, url.Values{"all": {"1"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("clear without confirm returned %d, want 400", resp.StatusCode)
	}
	found := false
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.AuthID == "codex-x.json" && bucket.Model == "gpt-5.5" && bucket.Observed != nil {
			found = true
		}
	}
	if !found {
		t.Error("observation row deleted despite the clear being refused for lack of confirm=1")
	}
}

// 宿主资源前缀只准 GET，处理器也复查；误闯的 POST 收 405，不可偷偷改变状态。
func TestKeylessActionRejectsNonGet(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resp := driveManagement(t, http.MethodPost, opsDryRunPath, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST to a keyless action returned %d, want 405", resp.StatusCode)
	}
}

// dry_run 免密切换后要跨重启：写下覆盖文件，下一次 configure 即便读到
// config.yaml 仍写 dry_run:true，也由覆盖值定为 false，旧菜单不能压过新订单。
func TestKeylessDryRunTogglesAndPersists(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // dry_run: true

	resp := driveResource(t, opsDryRunPath, confirmed(url.Values{"value": {"off"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless dry-run off returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if st := mustManagementStatus(t); st.DryRun {
		t.Error("dry_run is still on right after a keyless off")
	}

	ov := readOverrideFile(t, dir)
	if ov.DryRun == nil || *ov.DryRun {
		t.Errorf("runtime override did not record dry_run=false: %+v", ov)
	}

	// 模拟重启：再读仍写 dry_run:true 的 config.yaml；覆盖值要真有老板说了算的权力。
	mustConfigure(t, probeRoleConfig(dir))
	if st := mustManagementStatus(t); st.DryRun {
		t.Error("dry_run reverted to config.yaml on restart; the runtime override was not applied")
	}
}

func TestKeylessDryRunRejectsBadValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resp := driveResource(t, opsDryRunPath, confirmed(url.Values{"value": {"maybe"}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dry-run with a bad value returned %d, want 400", resp.StatusCode)
	}
	if st := mustManagementStatus(t); !st.DryRun {
		t.Error("dry_run changed on an unrecognised value; a typo must not silently turn it off")
	}
}

// role 也像 dry_run 一样免密换班并持久保留，不能重启就装失忆。
func TestKeylessRoleSwitchesAndPersists(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // role: probe

	resp := driveResource(t, opsRolePath, confirmed(url.Values{"value": {"business"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless role switch returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if st := mustManagementStatus(t); st.Role != roleBusiness {
		t.Errorf("role is %q right after a keyless switch to business", st.Role)
	}

	ov := readOverrideFile(t, dir)
	if ov.Role == nil || *ov.Role != roleBusiness {
		t.Errorf("runtime override did not record role=business: %+v", ov)
	}

	mustConfigure(t, probeRoleConfig(dir)) // config.yaml 仍喊 probe，覆盖值要能纠正旧台词
	if st := mustManagementStatus(t); st.Role != roleBusiness {
		t.Errorf("role reverted to %q on restart; the runtime override was not applied", st.Role)
	}
}

func TestKeylessRoleRejectsUnknownValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resp := driveResource(t, opsRolePath, confirmed(url.Values{"value": {"supervisor"}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("role with an unknown value returned %d, want 400", resp.StatusCode)
	}
	if st := mustManagementStatus(t); st.Role != roleProbe {
		t.Errorf("role changed to %q on an unknown value; only probe/business are allowed", st.Role)
	}
}

// query 清单个 bucket 要真删文件，与 JSON body 的 POST 路线同案同判。
func TestKeylessClearOneBucket(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, dir)
	recordObservation(cfg, "codex-x.json", "gpt-5.5", 292, false)

	resp := driveResource(t, opsClearPath, confirmed(url.Values{
		"auth_id": {"codex-x.json"}, "model": {"gpt-5.5"},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless clear returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var res mgmtClearResult
	if err := json.Unmarshal(resp.Body, &res); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if res.Cleared != 1 {
		t.Errorf("cleared %d buckets, want 1", res.Cleared)
	}
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.AuthID == "codex-x.json" && bucket.Model == "gpt-5.5" && bucket.Observed != nil {
			t.Error("observation row still present after keyless clear")
		}
	}
}

// ?all=1 清全部时，路由 Cookie 池和每行观测都要退场，别留隐藏观众。
func TestKeylessClearAll(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, dir)
	for _, m := range []string{"gpt-5.5", "gpt-5.6-sol"} {
		recordObservation(cfg, "codex-x.json", m, 292, false)
	}
	state.mu.Lock()
	state.noteRouteCookiesLocked(routeCookieSet{
		pairs:  map[string]string{"__cflb": "a", "__oailb": "b"},
		seenAt: time.Now(),
	}, "")
	poolLen := len(state.cookies)
	state.mu.Unlock()
	if poolLen == 0 {
		t.Fatal("pool entry was not recorded")
	}

	resp := driveResource(t, opsClearPath, confirmed(url.Values{"all": {"1"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless clear all returned %d, want 200", resp.StatusCode)
	}
	var res mgmtClearResult
	if err := json.Unmarshal(resp.Body, &res); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if res.Cleared != 1 {
		t.Errorf("cleared=%d, want 1 (the pool)", res.Cleared)
	}
	state.mu.Lock()
	poolLen = len(state.cookies)
	state.mu.Unlock()
	if poolLen != 0 {
		t.Errorf("pool still holds %d entries after clear all", poolLen)
	}
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.Observed != nil {
			t.Errorf("observation for %s/%s survived clear all", bucket.AuthID, bucket.Model)
		}
	}
}

// 运行时覆盖在 configure 时盖在 config.yaml 上，只应用实际设置字段。
// 先写覆盖再首次 configure（部署后重启）也要生效，提前到场不算旷工。
func TestRuntimeOverrideLayeredOnConfigure(t *testing.T) {
	dir := t.TempDir()
	if err := writeRuntimeOverride(dir, roleBusiness, false); err != nil {
		t.Fatalf("writeRuntimeOverride: %v", err)
	}
	// config.yaml 点的是 probe/true，覆盖单点的是 business/false；按覆盖单上菜。
	mustConfigure(t, probeRoleConfig(dir))
	st := mustManagementStatus(t)
	if st.Role != roleBusiness {
		t.Errorf("role is %q, want business from the override", st.Role)
	}
	if st.DryRun {
		t.Error("dry_run is true, want false from the override")
	}
}

// 覆盖文件坏了不能拖垮注册；退回配置文件值，让坏纸条自己罚站。
func TestRuntimeOverrideMalformedIsIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, runtimeOverrideFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad override: %v", err)
	}
	mustConfigure(t, probeRoleConfig(dir)) // 坏覆盖不能拖注册摔跤
	st := mustManagementStatus(t)
	if st.Role != roleProbe || !st.DryRun {
		t.Errorf("a malformed override was not ignored: role=%q dry_run=%v (want probe/true from config.yaml)", st.Role, st.DryRun)
	}
}

func TestParseBoolParam(t *testing.T) {
	cases := []struct {
		in    string
		value bool
		ok    bool
	}{
		{"on", true, true}, {"true", true, true}, {"1", true, true}, {"yes", true, true},
		{"off", false, true}, {"false", false, true}, {"0", false, true}, {"no", false, true},
		{"ON", true, true}, {" off ", false, true},
		{"", false, false}, {"maybe", false, false}, {"2", false, false},
	}
	for _, c := range cases {
		value, ok := parseBoolParam(c.in)
		if value != c.value || ok != c.ok {
			t.Errorf("parseBoolParam(%q) = (%v, %v), want (%v, %v)", c.in, value, ok, c.value, c.ok)
		}
	}
}

func TestQueryTrue(t *testing.T) {
	for _, in := range []string{"1", "true", "on", "yes", "TRUE", " 1 "} {
		if !queryTrue(in) {
			t.Errorf("queryTrue(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "0", "false", "off", "no", "2", "maybe"} {
		if queryTrue(in) {
			t.Errorf("queryTrue(%q) = true, want false", in)
		}
	}
}
