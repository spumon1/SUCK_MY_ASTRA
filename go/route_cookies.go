// 路由 Cookie 是负载均衡器的座位牌，带请求落到特定上游网关。
// 2026-09-22 的实测（FINDINGS.md）显示，上游有 chat.gateway.unified-N.api.openai.com 等节点，
// 落点看 __cflb/__oailb pair，不看出口 IP 或账号；pair 自己就是可跨账号复用的路由凭据，
// 单靠它即可保持所测服务状态正常，这条池路径不用 turn-state 票。
// 所以池是全局的：一个出口铸的 pair 能给所有账号用，多出口是在收集更多节点。
// 节点名藏在 Cookie 里，由 gatewayLabel 取出，负载均衡器看自己的牌就能带位。
// 只存和回放这两个 LB 名称。设备 ID、会话材料不能跟着搬桌，否则路由引导会变成身份串台。

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// routeCookieWanted 只认要回放的 LB 名字：去前导下划线、折叠大小写后比较。
// _cflb、__cflb 等同类拼法都可验票，落盘仍保留线上原名，不替上游改艺名。
func routeCookieWanted(name string) bool {
	switch strings.ToLower(strings.TrimLeft(name, "_")) {
	case "cflb", "oailb":
		return true
	}
	return false
}

// routeCookieSet 装一批 Set-Cookie 的 name=value 和时刻：seenAt 是收到时刻，
// expireAt 是该组最早声明期限（Max-Age 或 Expires），无人声明则零值；座位牌也要写散场时间。
type routeCookieSet struct {
	pairs    map[string]string
	seenAt   time.Time
	expireAt time.Time
}

// routeCookiesFromResponseHeaders 从上游 Set-Cookie 里捡路由 Cookie。
// Max-Age<=0 或 Expires 已过期都按删除处理，退票告示不能当新门票收藏。
func routeCookiesFromResponseHeaders(headers http.Header, now time.Time) routeCookieSet {
	set := routeCookieSet{seenAt: now}
	for key, values := range headers {
		if !strings.EqualFold(key, "Set-Cookie") {
			continue
		}
		for _, line := range values {
			name, value, deadline := parseSetCookieLine(line, now)
			if name == "" || !routeCookieWanted(name) {
				continue
			}
			if !deadline.IsZero() && !deadline.After(now) {
				// 上游已经宣布删除，退休凭据不再入库，别请离场演员回台上站岗。
				continue
			}
			if set.pairs == nil {
				set.pairs = map[string]string{}
			}
			set.pairs[name] = value
			if !deadline.IsZero() && (set.expireAt.IsZero() || deadline.Before(set.expireAt)) {
				set.expireAt = deadline
			}
		}
	}
	return set
}

// parseSetCookieLine 拆 name、value 和期限；只看首个分号后的 Max-Age 秒数与 Expires HTTP 日期。
// __cflb 只有 Expires，不能只看 Max-Age 就替它发永久居留证。
// Path、Domain、SameSite 等约束浏览器投递，不约束本插件向采集源单一主机回放。
// 值里可能还有更权威期限：__oailb JWT 的 exp 才是网关执行的时限。
// 实测 exp-iat=3900，而属性写 3600，也观察过属性过期后仍服务；有 JWT exp 就以它为准，
// 没 claim 才取两种属性中较早者，都没有则零值。凭据自己说何时散场，比外包装更算数。
func parseSetCookieLine(line string, now time.Time) (name, value string, deadline time.Time) {
	segments := strings.Split(line, ";")
	first := strings.TrimSpace(segments[0])
	eq := strings.Index(first, "=")
	if eq <= 0 {
		return "", "", time.Time{}
	}
	name = strings.TrimSpace(first[:eq])
	value = strings.TrimSpace(first[eq+1:])
	if !cookieNameSafe(name) || !cookieValueSafe(value) {
		return "", "", time.Time{}
	}
	for _, attr := range segments[1:] {
		attr = strings.TrimSpace(attr)
		switch {
		case len(attr) > 8 && strings.EqualFold(attr[:8], "max-age="):
			if parsed, err := strconv.ParseInt(strings.TrimSpace(attr[8:]), 10, 64); err == nil {
				d := now.Add(time.Duration(parsed) * time.Second)
				if deadline.IsZero() || d.Before(deadline) {
					deadline = d
				}
			}
		case len(attr) > 8 && strings.EqualFold(attr[:8], "expires="):
			// 日期解析不了就忽略这条属性，不把坏日期当有效承诺；破钟不能指挥全店作息。
			if t, err := http.ParseTime(strings.TrimSpace(attr[8:])); err == nil {
				if deadline.IsZero() || t.Before(deadline) {
					deadline = t
				}
			}
		}
	}
	if t := jwtExpiresAt(value); !t.IsZero() {
		deadline = t
	}
	return name, value, deadline
}

// jwtExpiresAt 只读 JWT 的 exp，不验签：这里需要的是上游凭据内嵌的时限，不是自封验票机关。
// 非 JWT 或没 claim 回零值；不凭空写散场钟点。
func jwtExpiresAt(value string) time.Time {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0).UTC()
}

// cookieNameSafe 拒绝会往 Cookie 请求头偷塞结构的名字；名字可以长，不能顺手拆墙。
func cookieNameSafe(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	return strings.IndexAny(name, "=; \t\r\n,") < 0
}

// cookieValueSafe 同样检查值；空值合法，表示清空但未删除，空碗也得留席。
func cookieValueSafe(value string) bool {
	if len(value) > 4096 {
		return false
	}
	return strings.IndexAny(value, "; \t\r\n,") < 0
}

// usable 判断现在能否发送，窗口取池评分所用 TTL。2026-09-22 实测 pair 可用远超一小时，
// 早期约 240s 是票的寿命，不是 pair 的寿命；上游期限仍可把窗口缩短。
// seenAt 跑到未来就拒绝：时钟偏斜或手改记录都不能给凭据凭空续寿。
func (s routeCookieSet) usable(now time.Time, ttl time.Duration) bool {
	if len(s.pairs) == 0 || s.seenAt.IsZero() || s.seenAt.After(now) {
		return false
	}
	if !now.Before(s.seenAt.Add(ttl)) {
		return false
	}
	if !s.expireAt.IsZero() && !now.Before(s.expireAt) {
		return false
	}
	return true
}

// header 把这组 Cookie 排好名字后拼成请求头；顺序稳定，也给池去重一张不变的合影。
func (s routeCookieSet) header() string {
	return cookieHeaderValue(s.pairs)
}

// cookieHeaderValue 把 name=value 映射按键排序后拼成 Cookie 头，不能让 map 随机排座次。
func cookieHeaderValue(pairs map[string]string) string {
	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+pairs[name])
	}
	return strings.Join(parts, "; ")
}

// mergeRouteCookies 将池里的名字覆盖请求同名 Cookie，客户端旧 pair 可能指向别的节点，得换座位牌。
// 池没涉及的名字保留客户端原位置；合并结果没变就不用动头，不为摆谱重搬一遍桌。
func mergeRouteCookies(existing string, pairs map[string]string) string {
	if len(pairs) == 0 {
		return existing
	}
	type pair struct{ name, value string }
	var pairs2 []pair
	positions := map[string]int{}
	for _, segment := range strings.Split(existing, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		name, value := segment, ""
		if eq := strings.Index(segment, "="); eq >= 0 {
			name, value = strings.TrimSpace(segment[:eq]), segment[eq+1:]
		}
		if _, seen := positions[name]; seen {
			continue
		}
		positions[name] = len(pairs2)
		pairs2 = append(pairs2, pair{name, value})
	}
	for name, value := range pairs {
		if at, seen := positions[name]; seen {
			pairs2[at].value = value
			continue
		}
		positions[name] = len(pairs2)
		pairs2 = append(pairs2, pair{name, value})
	}
	var b strings.Builder
	for i, p := range pairs2 {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(p.name)
		b.WriteString("=")
		b.WriteString(p.value)
	}
	return b.String()
}

// 路由池开席：以下管理座位牌，不管理客人的身份证。

// routeCookieGatewayRe 从值里认节点名，负载均衡器也靠 pair 内自己的名字带路。
// 观测形状为 chat.gateway.unified-N.api.openai.com；匹配故意宽些，抓节点 ID，不挑门牌花边。
var routeCookieGatewayRe = regexp.MustCompile(`(?i)(unified[-_.]?\d+|gateway[-_.][a-z0-9\-]+)`)

// gatewayLabel 给节点取短展示名；值未暴露可读节点时，可路由能力并不因此消失。
// 实现用哈希兜底区分匿名条目，免得面板把不同蒙面客挤成同一行。
func gatewayLabel(pairs map[string]string) string {
	for _, name := range []string{"__oailb", "__cflb"} {
		if m := routeCookieGatewayRe.FindString(pairs[name]); m != "" {
			return m
		}
	}
	// 两个值都看不出节点名，就用 pair 自身指纹挂牌；蒙面也得一人一席，不能并成无名氏。
	h := fnv.New32a()
	_, _ = h.Write([]byte(cookieHeaderValue(pairs)))
	return fmt.Sprintf("lb-%08x", h.Sum32())
}

// routeCookieEntry 是池里一对 Cookie 的档案，附来路和好坏记录，座位牌也有出勤表。
type routeCookieEntry struct {
	// Pairs 保存原样回放的 name=value，不替座位牌添字画押。
	Pairs map[string]string `json:"pairs"`
	// Gateway 是从 pair 值取出的展示名，只是招牌，不是另造的凭据。
	Gateway string `json:"gateway,omitempty"`
	// Via 记铸票出口 URL，普通业务采集则为空，因为它走账号自己的出口。
	// 保留来路便于探测再访高产出口；凡展示都脱敏，不把司机钥匙挂路牌上。
	Via string `json:"via,omitempty"`
	// SeenAt 记上游最近一次用 Set-Cookie 送来该 pair 的时刻，以到货签收为准。
	SeenAt string `json:"seen_at"`
	// ExpireAt 记声明的期限；有 Max-Age 或 Expires 才填写，不擅自延长营业时间。
	ExpireAt string `json:"expire_at,omitempty"`
	// GoodAt 记携带此 pair 的请求最近收到正常状态的时刻，这是节点还认座位牌的硬证据。
	GoodAt string `json:"good_at,omitempty"`
	// BadAt 记引导后最近一次降级。坏一次可能是账号限流，不一定是节点失灵，
	// 所以只降低优先级，不直接除名；一次糊锅不能当场拆店。
	BadAt string `json:"bad_at,omitempty"`
}

// routeCookiePoolFile 是 scope 文件旁的顶层 JSON。以前 pair 挂在各桶账下，
// 现在与账号无关，全池一本总账，不按客人各印菜单。
const routeCookiePoolFile = "route-cookies.json"

const routeCookiePoolVersion = 1

type routeCookiePoolDoc struct {
	Version   int                `json:"version"`
	UpdatedAt string             `json:"updated_at"`
	Entries   []routeCookieEntry `json:"entries"`
}

// cookieEntryKey 用规范化 pair 自身去重；不同出口若给出同一凭据，就并成一个条目。
// 换辆车送来同一张票，不算两张票。
func cookieEntryKey(pairs map[string]string) string {
	return cookieHeaderValue(pairs)
}

// entrySeen 解析 seen_at，缺失或读不懂回零值，不请算命先生补时辰。
func entrySeen(e routeCookieEntry) time.Time {
	t, _ := time.Parse(time.RFC3339, e.SeenAt)
	return t
}

// entryExpiry 解析期限，没写就零值；空日历不能猜日期。
func entryExpiry(e routeCookieEntry) time.Time {
	t, _ := time.Parse(time.RFC3339, e.ExpireAt)
	return t
}

// entryUsable 按最近收到时刻加窗口、再受期限约束，检查池里凭据是否还活着。
// goodAt 不续命：五分钟前服务正常也不能救一小时前铸的过期 pair，上游会轮换值。
func entryUsable(e routeCookieEntry, now time.Time, ttl time.Duration) bool {
	set := routeCookieSet{pairs: e.Pairs, seenAt: entrySeen(e), expireAt: entryExpiry(e)}
	return set.usable(now, ttl)
}

// entryBad 看近期降级记录是否还挂着，查的是暂时黄牌，不是终身黑名单。
func entryBad(e routeCookieEntry, now time.Time, penalty time.Duration) bool {
	bad, err := time.Parse(time.RFC3339, e.BadAt)
	if err != nil {
		return false
	}
	return now.Sub(bad) < penalty
}

// entryScore 先看最新 good_at 的实绩，再看铸票新鲜度。
// 受罚条目无论分多高都排无罚之后；刚糊过锅的师傅先让没试过的上。
func entryScore(e routeCookieEntry, now time.Time) time.Time {
	if good, err := time.Parse(time.RFC3339, e.GoodAt); err == nil && good.After(entrySeen(e)) {
		return good
	}
	return entrySeen(e)
}

// routeCookieBadPenalty 是降级黄牌的短暂降权期。312 可能是账号也可能是节点，
// 只提醒试试别的 pair，不封店；用变量便于测试缩短候场。
var routeCookieBadPenalty = 90 * time.Second

// routeCookieFlushInterval 限制池文件重写频率。标记与 seenAt 几乎每个响应都变，
// 落盘只需保证重启认得活 pair，不必每上一道菜就重印账本。
var routeCookieFlushInterval = 15 * time.Second

// loadRouteCookiePool 启动或 configure 时读池，并迁入旧 <auth>/<model>.json 的 route_cookies。
// 所有写者都在进程里，加载后内存说了算，不额外派一个人盯着账本眨眼。
func loadRouteCookiePool(dir string) map[string]*routeCookieEntry {
	out := make(map[string]*routeCookieEntry)
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return out
	}
	data, errRead := os.ReadFile(filepath.Join(dir, routeCookiePoolFile))
	if errRead == nil {
		var doc routeCookiePoolDoc
		if errUnmarshal := json.Unmarshal(data, &doc); errUnmarshal != nil {
			log.Printf(logPrefix+"%s unreadable, pool starts empty: %v", routeCookiePoolFile, errUnmarshal)
		} else if doc.Version != routeCookiePoolVersion {
			log.Printf(logPrefix+"%s is version %d, want %d; pool starts empty", routeCookiePoolFile, doc.Version, routeCookiePoolVersion)
		} else {
			for i := range doc.Entries {
				e := doc.Entries[i]
				if len(e.Pairs) == 0 {
					continue
				}
				out[cookieEntryKey(e.Pairs)] = &e
			}
		}
	} else if !os.IsNotExist(errRead) {
		log.Printf(logPrefix+"could not read %s: %v", routeCookiePoolFile, errRead)
	}
	// 旧桶里的同类 pair 幂等合并，加载时扫一次目录；升级保住热池，比重新生火便宜。
	for _, e := range legacyRouteCookieEntries(dir) {
		key := cookieEntryKey(e.Pairs)
		if cur, ok := out[key]; !ok || entrySeen(e).After(entrySeen(*cur)) {
			out[key] = &e
		}
	}
	return out
}

// writeRouteCookiePool 原子落盘，写时剔除死条目；账本不能给退休座位牌无限加页。
func writeRouteCookiePool(dir string, pool map[string]*routeCookieEntry, now time.Time, ttl time.Duration) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty")
	}
	doc := routeCookiePoolDoc{Version: routeCookiePoolVersion, UpdatedAt: now.UTC().Format(time.RFC3339)}
	for _, e := range pool {
		if entryUsable(*e, now, ttl) {
			doc.Entries = append(doc.Entries, *e)
		}
	}
	sort.Slice(doc.Entries, func(i, j int) bool { return doc.Entries[i].Gateway < doc.Entries[j].Gateway })
	data, errMarshal := json.MarshalIndent(doc, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	return atomicWrite(filepath.Join(dir, routeCookiePoolFile), append(data, '\n'))
}

// entrySecondsLeft 给面板报 pair 剩余窗口，哪条期限先到就听谁的，不拿晚钟拖堂。
func entrySecondsLeft(e routeCookieEntry, now time.Time, ttl time.Duration) int64 {
	if !entryUsable(e, now, ttl) {
		return 0
	}
	deadline := entrySeen(e).Add(ttl)
	if expire := entryExpiry(e); !expire.IsZero() && expire.Before(deadline) {
		deadline = expire
	}
	return int64(deadline.Sub(now).Seconds())
}

// bestRouteCookie 给下个请求挑 pair：无罚先于有罚，最新有效好评先于单纯存在。
// 池里全无可用项才回 ok=false；选厨师看实绩，不能只数帽子高低。
func bestRouteCookie(pool map[string]*routeCookieEntry, now time.Time, ttl time.Duration) (routeCookieEntry, bool) {
	var best, fallback *routeCookieEntry
	var bestScore, fallbackScore time.Time
	for _, e := range pool {
		if !entryUsable(*e, now, ttl) {
			continue
		}
		score := entryScore(*e, now)
		if entryBad(*e, now, routeCookieBadPenalty) {
			if fallback == nil || score.After(fallbackScore) {
				fallback, fallbackScore = e, score
			}
			continue
		}
		if best == nil || score.After(bestScore) {
			best, bestScore = e, score
		}
	}
	if best != nil {
		return *best, true
	}
	// 全体可用项都受罚仍可选；312 只是含糊黄牌，不能因此把整池椅子收走。
	if fallback != nil {
		return *fallback, true
	}
	return routeCookieEntry{}, false
}

// pluginState 的池管线负责接收入池、选 pair、回记结果以及适度落盘，让重启不丢热池。
// 以下都在 state.mu 下运行。note 路径内同步写盘是有意选择：小文件 atomicWrite 只需几毫秒，
// 最多每 routeCookieFlushInterval 一次，这家小店不再雇专职 flush goroutine。

// noteRouteCookiesLocked 合并新见 pair；via 记探测出口供后续再访，普通业务采集则为空。
// 调用方必须持 state.mu，账本开锁才能记账。
func (s *pluginState) noteRouteCookiesLocked(set routeCookieSet, via string) {
	if len(set.pairs) == 0 || set.seenAt.IsZero() {
		return
	}
	key := cookieEntryKey(set.pairs)
	e := s.cookies[key]
	if e == nil {
		e = &routeCookieEntry{
			Pairs:   set.pairs,
			Gateway: gatewayLabel(set.pairs),
		}
		s.cookies[key] = e
	}
	if set.seenAt.After(entrySeen(*e)) {
		e.SeenAt = set.seenAt.UTC().Format(time.RFC3339)
	}
	if !set.expireAt.IsZero() {
		e.ExpireAt = set.expireAt.UTC().Format(time.RFC3339)
	}
	if via != "" {
		// 最后一次产出有效 pair 的出口更新来路，续票找最近真干过活的司机。
		e.Via = via
	}
	s.cookiesDirty = true
	s.flushRouteCookiesLocked(time.Now())
}

// flushRouteCookiesLocked 在 dirty 且距上次写满 routeCookieFlushInterval 时落盘，调用方持 state.mu。
// 写失败保留 dirty，下一次 note 再试；账没交上不能先盖已结清章。
func (s *pluginState) flushRouteCookiesLocked(now time.Time) {
	if !s.cookiesDirty || s.config.StoreDir == "" {
		return
	}
	if !s.cookiesFlushed.IsZero() && now.Sub(s.cookiesFlushed) < routeCookieFlushInterval {
		return
	}
	if err := writeRouteCookiePool(s.config.StoreDir, s.cookies, now, s.config.ttl()); err != nil {
		log.Printf(logPrefix+"pool flush failed: %v", err)
		return
	}
	s.cookiesDirty = false
	s.cookiesFlushed = now
}

// bestRouteCookieLocked 同时返回 pair 与池键，让响应钩子给实际用过的条目记成绩。
// 不能响应时重新评一次“最佳”，分数已变可能认错人；调用方必须持 state.mu。
func (s *pluginState) bestRouteCookieLocked(now time.Time, ttl time.Duration) (routeCookieSet, string, bool) {
	e, ok := bestRouteCookie(s.cookies, now, ttl)
	if !ok {
		return routeCookieSet{}, "", false
	}
	return routeCookieSet{pairs: e.Pairs, seenAt: entrySeen(e), expireAt: entryExpiry(e)},
		cookieEntryKey(e.Pairs), true
}

// poolRow 只给面板看节点、来路和时刻，不含 Cookie 值。
// Via 是 cloud-fill 这类纯标签可原样显示，像带凭据代理 URL 的就遮住，招牌不带钥匙。
type poolRow struct {
	Gateway     string `json:"gateway"`
	Via         string `json:"via,omitempty"`
	State       string `json:"state"` // "usable" | "penalized" | "expired"
	SecondsLeft int64  `json:"seconds_left"`
	AgeSeconds  int64  `json:"age_seconds"`
}

// poolSnapshot 是全局池瞬时合影：总量、窗口内数量、各网关可用数和逐条明细。
// 池会变化，镜头里还可用的 pair 转眼也可能降级，照片不是终身健康证。
type poolSnapshot struct {
	Total    int            `json:"total"`
	Usable   int            `json:"usable"`
	Gateways map[string]int `json:"gateways"`
	Rows     []poolRow      `json:"rows"`
}

// poolSnapshotLocked 拍面板合影，调用方必须持 state.mu，拍照时先稳住队伍。
func (s *pluginState) poolSnapshotLocked(now time.Time, ttl time.Duration) poolSnapshot {
	snap := poolSnapshot{Gateways: map[string]int{}, Rows: []poolRow{}}
	for _, e := range s.cookies {
		if e == nil {
			continue
		}
		snap.Total++
		// 优先展示 __oailb JWT 解出的 unified-N 真节点；读不到才用已存指纹名，不拿化名抢真名的座。
		gw := cloudCookieGateway(e.Pairs)
		if gw == "" {
			gw = e.Gateway
		}
		if gw == "" {
			gw = "未知"
		}
		row := poolRow{Gateway: gw, Via: poolViaLabel(e.Via)}
		if seen := entrySeen(*e); !seen.IsZero() {
			row.AgeSeconds = int64(now.Sub(seen).Seconds())
		}
		deadline := entrySeen(*e).Add(ttl)
		if exp := entryExpiry(*e); !exp.IsZero() && exp.Before(deadline) {
			deadline = exp
		}
		if d := int64(deadline.Sub(now).Seconds()); d > 0 {
			row.SecondsLeft = d
		}
		switch {
		case !entryUsable(*e, now, ttl):
			row.State = "expired"
		case entryBad(*e, now, routeCookieBadPenalty):
			row.State = "penalized"
		default:
			row.State = "usable"
			snap.Usable++
			snap.Gateways[gw]++
		}
		snap.Rows = append(snap.Rows, row)
	}
	sort.Slice(snap.Rows, func(i, j int) bool {
		order := map[string]int{"usable": 0, "penalized": 1, "expired": 2}
		if order[snap.Rows[i].State] != order[snap.Rows[j].State] {
			return order[snap.Rows[i].State] < order[snap.Rows[j].State]
		}
		return snap.Rows[i].SecondsLeft > snap.Rows[j].SecondsLeft
	})
	return snap
}

// poolViaLabel 保留 cloud-fill、probe 等纯标签，带代理凭据的一律脱敏，面板不公开 userinfo。
func poolViaLabel(via string) string {
	via = strings.TrimSpace(via)
	if via == "" {
		return ""
	}
	if strings.Contains(via, "@") || strings.Contains(via, "://") {
		return maskProxyURL(via)
	}
	return via
}

// markRouteCookieOutcomeLocked 根据上游签出的状态给实际引导条目写 good_at 或 bad_at。
// 只要不是已知降级长度就可作好评，other 也算：长度按套餐变化，健康的 332 或 780 不能误罚。
// 只有已知降级签名给黄牌，而且只降权不删除，因为也可能是账号限流；静默不下判断。
// 调用方必须持 state.mu，别在账本没锁时给别人扣分。
func (s *pluginState) markRouteCookieOutcomeLocked(key, kind string, now time.Time) {
	e := s.cookies[key]
	if e == nil {
		return
	}
	switch kind {
	case observationLimited:
		e.BadAt = now.UTC().Format(time.RFC3339)
	case observationSilent:
		return
	default:
		e.GoodAt = now.UTC().Format(time.RFC3339)
	}
	s.cookiesDirty = true
	s.flushRouteCookiesLocked(now)
}

// poolSecondsLeftLocked 给面板报池中最长剩余可发送时间；调用方持 state.mu，问的是最后哪张票散场。
func (s *pluginState) poolSecondsLeftLocked(now time.Time, ttl time.Duration) int64 {
	var left int64
	for _, e := range s.cookies {
		if l := entrySecondsLeft(*e, now, ttl); l > left {
			left = l
		}
	}
	return left
}
