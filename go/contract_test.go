package main

// 合同测试盯插件公开的形状，不只盯它怎么干活。其他测试问“这请求得这结果吗”，
// 这里逐项钉免密文档 JSON 键、免密路径、向宿主声明的配置字段，故意对改名敏感。
// 要改公开面就连字面量一起审，不能让新字段偷偷拿旧票进场。
// 只验形状，不验内容！probe_run.lines、store_error、accounts_error、config_errors
// 以及代理检查的 detail/note 都是自由文本，其安全靠 probeRedact、maskProxyURL
// 和 TestAnonymousStatusResourceNeverLeaksTokenValues；这里绿灯不等于秘密没上镜。
// statusResponse 与 managementRegister 原来只靠注释警告公开范围，最近的防线是
// management_test.go 的特定 token 黑名单；未想到种进样本的新字段它抓不到。
// 已验证：给 statusResponse 加 probe_management_key，旧套件仍全绿。门卫只认几张照片，陌生秘密就能溜进来。

import (
	"encoding"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// --- 1. 匿名状态文档：公开橱窗逐格点名 ---

// statusResponsePublicFields 列 handleStatus 能吐出的全部 JSON 键路径；
// /v0/management/codex-turn-state/status 与免密 /v0/resource/plugins/codex-turn-state/status
// 返回同文档，无逐路由过滤。嵌套写 parent.child，切片元素摊成 buckets.<field>，每字段一次。
// 这里添一行就是公开一格橱窗：probe_management_key 永不展示（遮罩也不行），代理 URL 可能带 userinfo，先验货再开窗。
var statusResponsePublicFields = []string{
	"accounts_error",
	"accounts_source",
	"buckets",
	"buckets.auth_id",
	"buckets.enabled",
	"buckets.len",
	"buckets.model",
	// 观测账只收计数、封闭 kind（normal/limited/silent/other）、长度与时刻，逐字段审过，不给凭据留口袋。
	// bucketObservation.Hourly 特意不公开：小时历史在磁盘快照，页面只取 recent_24h；
	// 每桶 48 槽页面不画还塞进轮询文档，只会把账本送成砖头。
	"buckets.observed",
	"buckets.observed.injected_limited",
	"buckets.observed.injected_normal",
	"buckets.observed.injected_other",
	"buckets.observed.injected_silent",
	"buckets.observed.last_at",
	"buckets.observed.last_kind",
	"buckets.observed.last_len",
	"buckets.observed.last_natural_at",
	"buckets.observed.last_natural_kind",
	// 最近一次上游真签发读数，不论有无注入；类型同 last_natural_*：时刻、封闭 kind、bool，不添秘密菜。
	"buckets.observed.last_signed_at",
	"buckets.observed.last_signed_kind",
	"buckets.observed.last_signed_wrote",
	"buckets.observed.last_wrote",
	"buckets.observed.natural_limited",
	"buckets.observed.natural_normal",
	"buckets.observed.natural_other",
	"buckets.observed.recent_24h",
	"buckets.observed.recent_24h.injected_limited",
	"buckets.observed.recent_24h.injected_normal",
	"buckets.observed.recent_24h.injected_other",
	"buckets.observed.recent_24h.injected_silent",
	"buckets.observed.recent_24h.natural_limited",
	"buckets.observed.recent_24h.natural_normal",
	"buckets.observed.recent_24h.natural_other",
	"buckets.ready",
	// 账号池中 __cflb/__oailb pair 只报剩余秒数，不报 Cookie 真身。
	"buckets.route_cookies_seconds_left",
	"config_errors",
	"counters",
	"counters.harvest",
	"counters.pass",
	"counters.skip",
	"counters.steer",
	"counters_since",
	"dry_run",
	"generated_at",
	"models",
	// 实时流 auth_id 是带客户邮件的凭据文件名，buckets 已公开同类值；新增的其实是
	// 逐账号请求时间戳及活动规律。仅对回环绑定面板做过此选择，暴露到可达网络可不能照抄菜单。
	"observation_feed",
	"observation_feed.at",
	"observation_feed.auth_id",
	"observation_feed.kind",
	"observation_feed.len",
	"observation_feed.model",
	// 实服与请求不同时记录实际模型，这是统一格式后的降级信号；模型 ID 与 observation_feed.model 同类，名牌不冒充能力证明。
	"observation_feed.served",
	"observation_feed.wrote",
	"observations_since",
	"probe_accounts",
	"probe_proxies",
	"probe_proxies_rotating",
	"probe_proxy_count",
	"probe_proxy_rotating_count",
	"probe_run",
	"probe_run.current",
	"probe_run.done",
	"probe_run.error",
	"probe_run.finished_at",
	"probe_run.lines",
	"probe_run.running",
	"probe_run.started_at",
	"probe_run.total",
	"replace_length",
	"role",
	"store_dir",
	"store_error",
	"targets_ready",
	"targets_total",
	"template_length",
	"ttl_seconds",
}

// choicesResponsePublicFields 是免密 /ops/choices 菜单；accounts.name 公开完整文件名（含邮件），
// accounts.label 才是页面展示的遮罩值。提交需真文件名，两者都公开，所以要把橱窗形状钉牢。
var choicesResponsePublicFields = []string{
	"accounts",
	"accounts.disabled",
	"accounts.label",
	"accounts.name",
	"accounts.selected",
	"error",
	"models",
	"models.name",
	"models.selected",
}

// proxyCheckResponsePublicFields 对应免密 /ops/proxy-check；results.proxy 经 probeShowProxy，
// results.detail 是上游错误自由文本。这里只钉形状，不担保值安全；每加一字段都等于多开一扇免密窗。
var proxyCheckResponsePublicFields = []string{
	"blocked",
	"checked",
	"dead",
	"direct",
	"distinct_ips",
	"mismatches",
	"ms",
	"note",
	"ok",
	"other",
	"results",
	"results.colo",
	"results.country",
	"results.detail",
	"results.exit_ip",
	"results.index",
	"results.mismatch",
	"results.ms",
	"results.pool",
	"results.proxy",
	"results.rotated",
	"results.status_code",
	"results.verdict",
	"static_checked",
	"timed_out",
}

// TestAnonymouslyReadableShapesArePinned 遍历文档类型，不看某个序列化样本，omitempty 也点名。
// 样本没填的新字段恰是漏网之鱼，不能因为演员今天请假就说剧组没这人。
func TestAnonymouslyReadableShapesArePinned(t *testing.T) {
	for _, doc := range []struct {
		name  string
		typ   reflect.Type
		want  []string
		route string
	}{
		{"statusResponse", reflect.TypeOf(statusResponse{}), statusResponsePublicFields, "/status"},
		{"choicesResponse", reflect.TypeOf(choicesResponse{}), choicesResponsePublicFields, "/ops/choices"},
		{"proxyCheckResponse", reflect.TypeOf(proxyCheckResponse{}), proxyCheckResponsePublicFields, "/ops/proxy-check"},
	} {
		t.Run(doc.name, func(t *testing.T) {
			got := jsonFieldPaths(t, doc.typ, "")
			assertSetEqual(t, doc.name+" fields", got, doc.want,
				"this document is served on "+doc.route+", which needs no credential; "+
					"if the new field can carry a secret it does not belong on this struct at all")
		})
	}
}

// --- 2. 遍历器：查户口的人也要考试 ---

// 钉字段有意义的前提是遍历真下潜；jsonFieldPaths 若只报顶层，嵌套结构全裸也能绿灯。
// 专给遍历器道具考题，门卫也验自己的眼镜。

type walkerProbeInner struct {
	Alpha  string `json:"alpha"`
	Omit   string `json:"-"`
	hidden string //nolint:unused // 故意在场，好查遍历器真会跳过隐身客
}

// walkerProbeEmbedded 无标签嵌入，和 bucketObservation 计数同形状；类型故意不导出，
// encoding/json 仍提升其中导出字段，这处最容易把祖孙辈分算错。
type walkerProbeEmbedded struct {
	Promoted string `json:"promoted"`
}

type walkerProbeOuter struct {
	walkerProbeEmbedded
	Top      int                `json:"top"`
	Nested   walkerProbeInner   `json:"nested"`
	List     []walkerProbeInner `json:"list"`
	Pointer  *walkerProbeInner  `json:"pointer"`
	Names    []string           `json:"names"`
	Untagged bool
}

func TestJSONFieldPathsDescends(t *testing.T) {
	got := jsonFieldPaths(t, reflect.TypeOf(walkerProbeOuter{}), "")
	want := []string{
		"Untagged", // 没 tag 就让 encoding/json 按 Go 字段名点名
		"list",
		"list.alpha", // 切片元素摊在切片键下，不按人头加楼层
		"names",      // []string 到此是叶子，不再钻树洞
		"nested",
		"nested.alpha",
		"pointer", // *struct 还要跟进去查房
		"pointer.alpha",
		"promoted", // 无标签嵌入提升到父级，不另开嵌套包厢
		"top",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the walk does not descend as the pins above assume.\n got: %v\nwant: %v", got, want)
	}
	for _, path := range got {
		if strings.Contains(path, "Omit") || strings.Contains(path, "hidden") {
			t.Errorf("walk emitted %q; json:\"-\" and unexported fields are never serialised", path)
		}
	}

	// 上表只是人对 encoding/json 的理解，未导出嵌入类型的提升最易记错；
	// 请 marshaller 本尊核对顶层键完全一致，不靠脑内小剧场判法。
	raw, err := json.Marshal(walkerProbeOuter{})
	if err != nil {
		t.Fatalf("marshalling the probe: %v", err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(raw, &emitted); err != nil {
		t.Fatalf("unmarshalling the probe: %v", err)
	}
	var actual []string
	for key := range emitted {
		actual = append(actual, key)
	}
	var walked []string
	for _, path := range got {
		if !strings.Contains(path, ".") {
			walked = append(walked, path)
		}
	}
	sort.Strings(actual)
	sort.Strings(walked)
	if !reflect.DeepEqual(walked, actual) {
		t.Errorf("the walk and encoding/json disagree about the top-level keys; every pin in this file "+
			"is a claim about what ships, so the walk has to match the marshaller.\n walked: %v\nmarshalled: %v",
			walked, actual)
	}
}

// jsonFieldPaths 递归结构、指针、切片/数组，列出 encoding/json 会产生的全部键路径。
// map、interface、[]byte（json.RawMessage 随内容变形）及自带 MarshalJSON/MarshalText
// 无法从类型定键就失败，不能悄悄当叶子；漏报一层会让公开面合同变成假收据。
func jsonFieldPaths(t *testing.T, typ reflect.Type, prefix string) []string {
	t.Helper()
	var out []string
	collectJSONFields(t, typ, prefix, &out)
	sort.Strings(out)
	return out
}

func collectJSONFields(t *testing.T, typ reflect.Type, prefix string, out *[]string) {
	t.Helper()

	typ = derefType(typ)
	if typ.Kind() != reflect.Struct {
		t.Fatalf("collectJSONFields called on %s, which is not a struct", typ)
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]

		if field.Anonymous && name == "" {
			// encoding/json 将无标签嵌入结构的导出字段提升到父级，嵌入类型未导出也如此，
			// 因此先处理再查 PkgPath。实际发 observed.natural_normal，却钉 observed.counts.natural_normal，
			// 等于给不存在的房子验门锁，整表绿了也没用。
			// 带标签嵌入另算，按标签嵌套，继续走普通路径，别给所有亲戚硬排同一辈。
			embedded := derefType(field.Type)
			if embedded.Kind() != reflect.Struct {
				t.Fatalf("%s embeds the non-struct %s; encoding/json's rules there are subtle "+
					"(an unexported one is dropped outright) and nothing in this plugin does it, "+
					"so this walk refuses to guess", typ, field.Type)
			}
			rejectOpaque(t, embedded, typ.String()+"."+field.Name)
			collectJSONFields(t, embedded, prefix, out)
			continue
		}

		if field.PkgPath != "" {
			continue // 未导出不序列化，后台人员不上公开名单
		}
		if name == "" {
			name = field.Name
		}

		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		*out = append(*out, path)

		descendJSONField(t, field.Type, path, out, typ.String()+"."+field.Name)
	}
}

func descendJSONField(t *testing.T, typ reflect.Type, path string, out *[]string, where string) {
	t.Helper()

	typ = derefType(typ)
	rejectOpaque(t, typ, where)

	switch typ.Kind() {
	case reflect.Struct:
		collectJSONFields(t, typ, path, out)
	case reflect.Slice, reflect.Array:
		// 元素字段摊到切片自身键，每字段一条不按人数复印；嵌套切片继续摊平。
		descendJSONField(t, typ.Elem(), path, out, where+" element")
	}
}

// rejectOpaque 在每层含切片元素拒绝键不能由类型决定的形状；[]map[string]X 和 map[string]X 一样藏东西，穿数组外套也不放行。
func rejectOpaque(t *testing.T, typ reflect.Type, where string) {
	t.Helper()

	var (
		jsonMarshaler = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
		textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	)
	for _, iface := range []reflect.Type{jsonMarshaler, textMarshaler} {
		if typ.Implements(iface) || reflect.PointerTo(typ).Implements(iface) {
			t.Fatalf("%s is a %s with its own %s; its JSON keys are not readable off the type. "+
				"If it serialises to a single scalar (time.Time does, as an RFC3339 string), say so here "+
				"and allow it; if it serialises to an object, its fields need pinning of their own.",
				where, typ, iface.Name())
		}
	}

	switch typ.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("%s is a %s, whose keys cannot be pinned by walking the type; "+
			"an open-ended container on an anonymously readable document needs its own assertion", where, typ.Kind())
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s is a %s (json.RawMessage or []byte); it serialises as whatever it happens to hold, "+
				"which is not something this walk can pin", where, typ)
		}
	}
}

func derefType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

// --- 3. 免密面：注册即开门 ---

// keylessResourcePaths 是资源前缀下所有路径；宿主不鉴权，所以 managementRegister.Resources
// 每加一项就真开一扇免密门，无论有没有想明白。
// TestManagementRegisterExposesExactlyOneMenuResource 已守 Menu 不乱加，此处守更广的整组路径。
var keylessResourcePaths = []string{
	"/dashboard",
	"/ops/choices",
	"/ops/clear",
	"/ops/dry-run",
	"/ops/probe/cancel",
	"/ops/probe/start",
	"/ops/proxy-check",
	"/ops/role",
	"/ops/scope",
	"/ops/selftest",
	"/status",
}

// authenticatedRoutes 留在 key 后面，routeConfig 尤其承重：原样返回配置，probe bearer 最可能从这里探头。
// 绝不移入资源表，也不挂 Menu；宿主会把带 Menu 的 GET 再挂免密资源前缀，招牌能悄悄变通行证。
var authenticatedRoutes = []string{
	"GET /codex-turn-state/cloud-status",
	"GET /codex-turn-state/config",
	"GET /codex-turn-state/status",
	"POST /codex-turn-state/buckets/clear",
	"POST /codex-turn-state/selftest",
	"POST /codex-turn-state/modeltrace",
	"POST /codex-turn-state/gateway-sweep",
}

// managementRegister 不读配置，注册不随角色变；配一种角色就能考完整名单，没必要请全剧组换装。
func TestKeylessSurfaceIsPinned(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)

	var gotResources []string
	for _, res := range reg.Resources {
		gotResources = append(gotResources, res.Path)
	}
	assertSetEqual(t, "keyless resource paths", gotResources, keylessResourcePaths,
		"every path here is served without a credential; adding one is a deliberate act")

	var gotRoutes []string
	for _, route := range reg.Routes {
		gotRoutes = append(gotRoutes, route.Method+" "+route.Path)
	}
	assertSetEqual(t, "authenticated management routes", gotRoutes, authenticatedRoutes,
		"moving one of these to the resource list would publish it")
}

// --- 4. 声明配置：菜单名字也是合同 ---

// configFieldNames 按序列宿主被告知可接收的字段，宿主拿它渲染；改名改的是用户 YAML 键，删项会悄悄从菜单消失。
// 只钉名字不钉说明文案；说明可润色，之前两个角色描述还写错过，别把台词锁成石碑。
var configFieldNames = []string{
	"role",
	"store_dir",
	"template_length",
	"replace_length",
	"ttl_seconds",
	"dry_run",
	"log_decisions",
	"models",
	"probe_accounts",
	"probe_proxies",
	"probe_proxies_rotating",
	"probe_management_key",
	"probe_base_url",
	"cloud_mint", // 新增插件自有配置坐末席，旧字段座次不挪。
}

func TestDeclaredConfigFieldsArePinned(t *testing.T) {
	fields := pluginRegistration().Metadata.ConfigFields

	var got []string
	for _, field := range fields {
		got = append(got, field.Name)
	}
	if !reflect.DeepEqual(got, configFieldNames) {
		t.Errorf("declared config fields changed.\n got: %v\nwant: %v\n"+
			"Order matters here because the host renders them in it.", got, configFieldNames)
	}

	// 声明字段没说明，用户见的是无字说明书；数项关于探测范围的警告只在 UI 此处出现，不能省成谜语。
	for _, field := range fields {
		if strings.TrimSpace(field.Description) == "" {
			t.Errorf("config field %q is declared without a description", field.Name)
		}
	}
}

// --- 帮手：收尾时也逐项对账 ---

func assertSetEqual(t *testing.T, what string, got, want []string, why string) {
	t.Helper()

	if len(got) == 0 {
		t.Fatalf("%s: nothing was declared, so this assertion would pass vacuously", what)
	}

	seen := make(map[string]bool, len(want))
	for _, entry := range want {
		seen[entry] = true
	}
	for _, entry := range got {
		if !seen[entry] {
			t.Errorf("%s gained %q -- %s", what, entry, why)
		}
		delete(seen, entry)
	}
	var missing []string
	for entry := range seen {
		missing = append(missing, entry)
	}
	sort.Strings(missing)
	for _, entry := range missing {
		t.Errorf("%s lost %q; update the literal if the removal is intended", what, entry)
	}
}
