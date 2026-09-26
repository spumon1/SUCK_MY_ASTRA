// 观察域给每个（账号、模型）记上游实际状态，也记本次是否由池 pair 引导。
// CPA 请求日志有响应头却没选中凭据；插件两边都看得见，所以能把菜和点菜的人对上。
// 这里只旁观原本就在跑的流量，不改请求响应；主动探测关着也能长期开这本账。
// 记录刻意浅：Since 起累计、最近两天逐小时计数、有界近期事件。累计值回答不了“今天比昨天差吗”，
// 细到逐请求、超过两天或任意区间的查询请去决策日志汇总，别让小插件长成大数据库。

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// observationsFileName 放 store_dir 顶层，与 index.json、runtime.json 邻居。
	// scanStoreRecords 只读账号子目录 <auth_id>/<model>.json，顶层观察账不会被误认成一桶凭据。
	observationsFileName = "observations.json"

	// observationsVersion 守快照版本，不匹配就忽略并从空账重记，不写迁移。
	// 这只是可丢弃的观察计数，不是契约数据，养永久迁移链比重记更费粮。
	// 版本 2 加小时历史，并把 injected-other 从 natural_other 分出，旧数含义因此变了。
	observationsVersion = 2

	// observationsRecentMax 限近期播报，也限面板轮询状态文档的体积；100 条约 12 KB，舞台再热闹也不无限加座。
	observationsRecentMax = 100

	// observationsBucketMax 限桶数，防错误或恶意模型 ID 撑爆 map；满了请最久未见的桶先退席。
	observationsBucketMax = 256

	// observationsHourlyMax 每桶最多留两天小时记录，够比今天昨天，不给账本无止境加页。
	// 有流量的小时才占位，空闲桶不记空账；最坏规模由它乘 observationsBucketMax 封顶。
	observationsHourlyMax = 48

	// observationLearnMin 是陌生签名长度晋升本桶 normal 所需次数，不能把上游观测当永恒常量。
	// 2026-09-22 格式统一时 gpt-6-astra 从 292 变 780，死白名单会把健康新格式永远扔进 other。
	// 见两次是最小的重复证据：一次算生面孔，两次才考虑是新制服。
	observationLearnMin = 2

	// observationLensMax 限每桶候选长度表；长度可为任意整数，满了先赶最罕见项，防怪客无限占桌。
	observationLensMax = 8
)

// observationsFlushInterval 是整份快照写盘的最短间隔，写更勤只缩短硬杀时丢账窗口。
// 用变量让测试强制 flush，不必等一分钟；生产不重赋值，算盘节奏不随客人拍桌改。
var observationsFlushInterval = 60 * time.Second

// 这里分上游对 turn-state 做的三种事，不把我们的解读冒充事实。
// limited 只说签出了 312，不等于已证明模型质量；运营解释看面板文案，别见黄灯就宣布天黑。
const (
	observationNormal  = "normal"  // template_length 或本桶学会的长度，认熟面孔不只看旧名册
	observationLimited = "limited" // replace_length：上游已签降级，黄牌有凭据才挂
	observationSilent  = "silent"  // 未签任何状态，静默不是随口报平安
	observationOther   = "other"   // 本桶没认过的已签长度，先记生面孔
)

// bucketObservation 是一个（账号、模型）账格，按我们是否真的用池 pair 引导分开统计。
// 混成总比例并不是降级率。natural 看未引导流量，injected 则给 pair 本身积累证据，
// 引导后正常会由 markRouteCookieOutcomeLocked 给池项好评。
// NaturalNormal 是自然签正常；NaturalLimited 是自然签降级；InjectedSilent 是引导后未签状态；
// InjectedLimited 是引导仍降级，可能 pair 旧了也可能账号限流，须结合 natural 区分；
// InjectedNormal 是引导后新签正常；InjectedOther 是引导后签未知长度，如 FINDINGS.md 的套餐漂移。
// 两桌账分清，才不会把厨师的问题算到点菜客人身上。
type bucketObservation struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`

	observationCounts

	// Last* 记最近任意观察，静默也算，回答“这桶有没有流量”。
	// 面板还要另问“上游有没有说状态”，才能分清注入后静默与根本无人来吃饭。
	LastKind  string `json:"last_kind"`
	LastLen   int    `json:"last_len"`
	LastWrote bool   `json:"last_wrote"`
	LastAt    string `json:"last_at"`

	// LastSigned* 记最近真正带状态的观察，不管是否注入，面板据此算证据年龄。
	// 不能只算 LastNatural*：注入后的 292 仍是上游正常服务证据，不能把亮着的灯登记成瞎。
	LastSignedKind  string `json:"last_signed_kind,omitempty"`
	LastSignedAt    string `json:"last_signed_at,omitempty"`
	LastSignedWrote bool   `json:"last_signed_wrote,omitempty"`

	// LastNatural* 只记未引导观察；两桌账分开是统计有意义的根本，不能上菜后忘记哪桌点的。
	LastNaturalKind string `json:"last_natural_kind,omitempty"`
	LastNaturalAt   string `json:"last_natural_at,omitempty"`

	// Hourly 只收有流量的小时，旧在前，最多 observationsHourlyMax；没客的时辰不用写空菜单。
	Hourly []hourlyObservation `json:"hourly,omitempty"`

	// SignedLens 统计不属配置两类的签名长度，供 other -> normal 学习，最多 observationLensMax 项。
	// replace_length 已提前判为降级，永不进候选，不能靠多来几次把黄牌洗成嘉宾证。
	SignedLens map[int]int `json:"signed_lens,omitempty"`
}

// observationCounts 是累计与逐小时共用的七路账，一个类型一个 add，免得两份 switch 漏同步。
// 无标签嵌入让 JSON 扁平：读 observed.natural_normal，不是 observed.counts.natural_normal。
// 一本算盘管两本账，别让历史和总账各唱各的戏。
type observationCounts struct {
	NaturalNormal  int64 `json:"natural_normal"`
	NaturalLimited int64 `json:"natural_limited"`
	NaturalOther   int64 `json:"natural_other"`

	InjectedSilent  int64 `json:"injected_silent"`
	InjectedLimited int64 `json:"injected_limited"`
	InjectedNormal  int64 `json:"injected_normal"`
	InjectedOther   int64 `json:"injected_other"`
}

// add 记一条观察；silent 且未引导早被 recordObservation 当噪声挡住，末支只可能 other 且未引导。
// 每种引导情况都显式列出，不能把 InjectedOther 滑进 NaturalOther，污染唯一能看比例的分桌账。
func (c *observationCounts) add(wrote bool, kind string) {
	switch {
	case wrote && kind == observationSilent:
		c.InjectedSilent++
	case wrote && kind == observationLimited:
		c.InjectedLimited++
	case wrote && kind == observationNormal:
		c.InjectedNormal++
	case wrote:
		c.InjectedOther++
	case kind == observationNormal:
		c.NaturalNormal++
	case kind == observationLimited:
		c.NaturalLimited++
	default:
		c.NaturalOther++
	}
}

// addAll 合并整组计数；TestObservationCountsAddAllCoversEveryField 挨字段点名，谁也别躲桌底逃账。
func (c *observationCounts) addAll(o observationCounts) {
	c.NaturalNormal += o.NaturalNormal
	c.NaturalLimited += o.NaturalLimited
	c.NaturalOther += o.NaturalOther
	c.InjectedSilent += o.InjectedSilent
	c.InjectedLimited += o.InjectedLimited
	c.InjectedNormal += o.InjectedNormal
	c.InjectedOther += o.InjectedOther
}

// hourlyObservation 记一个小时的同类计数，只在有流量时开账。
// 累计回答开业至今多少，小时记录才回答今天是否比昨天差，老黄历不能当今日菜单。
type hourlyObservation struct {
	Hour string `json:"hour"` // UTC 的 RFC3339 整点，分钟秒钟请去隔壁候场
	observationCounts
}

// hourSlot 取当前小时计数，首条则新增，满了丢最旧。返回指针指向 slice，下一次 append 后可能失效。
// 所有调用者都在锁内立刻用，别拿旧座号跑去扩建后的宴会厅找人。
func (b *bucketObservation) hourSlot(now time.Time) *observationCounts {
	hour := now.UTC().Truncate(time.Hour).Format(time.RFC3339)

	// 正常时当前小时在末项；往前扫是防时钟回拨，不让同一时辰多开一张重复饭票。
	for i := len(b.Hourly) - 1; i >= 0; i-- {
		if b.Hourly[i].Hour == hour {
			return &b.Hourly[i].observationCounts
		}
	}

	b.Hourly = append(b.Hourly, hourlyObservation{Hour: hour})
	if len(b.Hourly) > observationsHourlyMax {
		b.Hourly = b.Hourly[len(b.Hourly)-observationsHourlyMax:]
	}
	return &b.Hourly[len(b.Hourly)-1].observationCounts
}

// rollup 汇总窗口内完整小时槽；24h 是最近 24 个小时槽，不是精确到秒的 24 小时。
// 足够比较今天昨天，不为较这几秒而把逐请求时间戳全请进仓库。
func (b bucketObservation) rollup(now time.Time, window time.Duration) observationCounts {
	cutoff := now.UTC().Add(-window)
	var out observationCounts
	for _, h := range b.Hourly {
		at, err := time.Parse(time.RFC3339, h.Hour)
		if err != nil || at.Before(cutoff) {
			continue
		}
		out.addAll(h.observationCounts)
	}
	return out
}

// observationSummary 去掉账号、模型键，挂到已有这些键的状态行。
// 同一文档别放两套户口本，免得同一个人出现两个生日。
type observationSummary struct {
	observationCounts

	LastKind  string `json:"last_kind"`
	LastLen   int    `json:"last_len"`
	LastWrote bool   `json:"last_wrote"`
	LastAt    string `json:"last_at"`

	LastSignedKind  string `json:"last_signed_kind,omitempty"`
	LastSignedAt    string `json:"last_signed_at,omitempty"`
	LastSignedWrote bool   `json:"last_signed_wrote,omitempty"`

	LastNaturalKind string `json:"last_natural_kind,omitempty"`
	LastNaturalAt   string `json:"last_natural_at,omitempty"`

	// Recent24h 把小时历史汇成各计数，弥补累计只涨不减、没法比较今昔的毛病。
	// 小时原账落盘供画图，不把每桶 48 槽都塞进轮询文档，面板吃不了这么大一盆菜。
	Recent24h observationCounts `json:"recent_24h"`
}

func (b bucketObservation) summary(now time.Time) observationSummary {
	return observationSummary{
		observationCounts: b.observationCounts,
		LastKind:          b.LastKind,
		LastLen:           b.LastLen,
		LastWrote:         b.LastWrote,
		LastAt:            b.LastAt,
		LastSignedKind:    b.LastSignedKind,
		LastSignedAt:      b.LastSignedAt,
		LastSignedWrote:   b.LastSignedWrote,
		LastNaturalKind:   b.LastNaturalKind,
		LastNaturalAt:     b.LastNaturalAt,
		Recent24h:         b.rollup(now, 24*time.Hour),
	}
}

// observationEvent 是实时播报一行，只收结构化字段，不开自由文本留言板。
// 状态文档匿名可读，随意文本容易漏秘密；probe_run.lines 已有相应约束，这里不再开侧门。
type observationEvent struct {
	At     string `json:"at"`
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	Len    int    `json:"len"`
	Wrote  bool   `json:"wrote"`
	Kind   string `json:"kind"`
	// Served 只在 SSE 声明模型与请求不同的降级事件里填写，代表统一格式下的安全缓冲回退模型。
	// 按长度分类的事件留空，不拿猜测给演员补名字。
	Served string `json:"served,omitempty"`
}

// observationSnapshot 是原子重写的全状态，不做追加。
// 每分钟约 20 KB 重写很轻，没必要为半截追加再养一队修账先生。
type observationSnapshot struct {
	Version   int                 `json:"version"`
	Since     string              `json:"since"`
	UpdatedAt string              `json:"updated_at"`
	Buckets   []bucketObservation `json:"buckets"`
	Recent    []observationEvent  `json:"recent"`
}

// observations 用自己的锁，绝不用 state.mu。handleStatus 已避开 state.mu 与探测锁同时持有，
// 不能再塞第三把锁重演死锁相声；本域从不取 state.mu，因此不进那个环。
var observations = struct {
	mu      sync.Mutex
	since   time.Time
	byKey   map[string]*bucketObservation
	recent  []observationEvent
	dirty   bool
	lastOut time.Time // 最近成功落盘时刻，账真送到才盖章
	writing bool      // 正有 flush goroutine 送账，别重开一班车
	dir     string    // 本账所属 store_dir，不和隔壁仓库认错亲
}{byKey: make(map[string]*bucketObservation)}

// classifyObservation 用配置长度判断上游动作，它们是实测值不是协议铁律。
// 2026-09-22 正常 prolite 为 292，self_serve_business_prolite 为 332，同日统一格式又把账号推向 780。
// 这里是静态半边，noteSignedLen 给重复未知长度学成本桶正常，免得换制服就永久关进 other。
// 健康流量连续 other 仍可能只是签名反复变化，不等于账号坏了，详见 FINDINGS.md。
func classifyObservation(cfg pluginConfig, valueLen int) string {
	switch valueLen {
	case 0:
		return observationSilent
	case cfg.TemplateLength:
		return observationNormal
	case cfg.ReplaceLength:
		return observationLimited
	default:
		return observationOther
	}
}

// noteSignedLen 先给未知长度记次数再判定，所以第二次晋升，第一次仍是 other。
// 只接静态分类已判 other 的值，配置降级长度早被拦走，不可能混进学堂洗白。
// 调用方持 observations.mu，给新制服登记也得先锁账本。
func (b *bucketObservation) noteSignedLen(l int) bool {
	if b.SignedLens == nil {
		b.SignedLens = make(map[int]int, observationLensMax)
	}
	b.SignedLens[l]++
	if len(b.SignedLens) > observationLensMax {
		// 淘汰最罕见候选；同次数选更小长度，保持确定性，不让 map 遍历顺序当抽签主持。
		rarest, rarestN := 0, 0
		for cand, n := range b.SignedLens {
			if cand == l {
				continue
			}
			if rarestN == 0 || n < rarestN || (n == rarestN && cand < rarest) {
				rarest, rarestN = cand, n
			}
		}
		delete(b.SignedLens, rarest)
	}
	return b.SignedLens[l] >= observationLearnMin
}

// recordObservation 记录响应长度；wrote 只认请求钩子真写了池 pair，不认“本来想写”。
// dry_run 不算写，不然观察模式的 natural/injected 分账就成了假账。
// 在采集自己的检查前调用，无状态也记录：引导后上游未新签是有意义的静默，别把无台词的镜头剪掉。
func recordObservation(cfg pluginConfig, authID, model string, valueLen int, wrote bool) {
	recordEvent(authID, model, classifyObservation(cfg, valueLen), valueLen, wrote, "")
}

// recordDowngrade 记录统一格式下的降级证据：SSE 声明 served 与 requested 不同，即安全缓冲模型接手。
// 格式统一后拒绝路径也铸正常 780，长度不再携带限流信号，改看 served-model，并记为 limited。
// 和旧 312 归同类账，但证据换了，不能拿旧尺量新衣。
func recordDowngrade(authID, model, served string, tsLen int, wrote bool) {
	if strings.TrimSpace(served) == "" {
		return
	}
	recordEvent(authID, model, observationLimited, tsLen, wrote, served)
}

// recordEvent 为两种读数共用收尾：归账号模型桶、按 kind 与 steered 分账、更新时间、推近期播报。
// 长度事件 served 为空，降级事件填声明模型；对不上号就别硬给演员排座。
func recordEvent(authID, model, kind string, valueLen int, wrote bool, served string) {
	authID = strings.TrimSpace(authID)
	model = strings.TrimSpace(model)
	if authID == "" || model == "" {
		// 归属不明就不计；塞进占位桶会把甲的限流挂到乙门口，宁缺账也不乱认亲。
		return
	}
	if kind == observationSilent && !wrote {
		// 双方都没动静：没送模板，也没收到状态。大部分流量如此，静默本身不透露服务状态。
		return
	}

	now := time.Now()
	key := bucketKey(authID, model)

	observations.mu.Lock()
	cell := observations.byKey[key]
	if cell == nil {
		evictObservationBucketLocked()
		cell = &bucketObservation{AuthID: authID, Model: model}
		observations.byKey[key] = cell
	}
	if kind == observationOther && cell.noteSignedLen(valueLen) {
		// 静态表不认识，本桶却反复见过该长度；这是上游当前制服，不是偶然穿错的戏服。
		kind = observationNormal
	}

	cell.observationCounts.add(wrote, kind)
	cell.hourSlot(now).add(wrote, kind)

	cell.LastKind = kind
	cell.LastLen = valueLen
	cell.LastWrote = wrote
	cell.LastAt = now.UTC().Format(time.RFC3339)

	// 非静默就是上游给出的新证据，不管本次是否注入都算。
	// 静默本身不带签署状态；注入下的接受信号也不能冒充上游新签的证明。
	if kind != observationSilent {
		cell.LastSignedKind = kind
		cell.LastSignedAt = cell.LastAt
		cell.LastSignedWrote = wrote
		if !wrote {
			cell.LastNaturalKind = kind
			cell.LastNaturalAt = cell.LastAt
		}
	}

	observations.recent = append(observations.recent, observationEvent{
		At:     cell.LastAt,
		AuthID: authID,
		Model:  model,
		Len:    valueLen,
		Wrote:  wrote,
		Kind:   kind,
		Served: served,
	})
	if len(observations.recent) > observationsRecentMax {
		observations.recent = observations.recent[len(observations.recent)-observationsRecentMax:]
	}
	observations.dirty = true
	dir := observations.dir
	due := now.Sub(observations.lastOut) >= observationsFlushInterval && !observations.writing
	if due {
		observations.writing = true
	}
	observations.mu.Unlock()

	if due && dir != "" {
		// 磁盘写放到响应路径外，不能每个上游响应都坐在柜台等账本晾干。
		go flushObservations(dir)
	}
}

// evictObservationBucketLocked 在满表时请最久未见的桶离席；调用方持 observations.mu。
func evictObservationBucketLocked() {
	if len(observations.byKey) < observationsBucketMax {
		return
	}
	oldestKey, oldestAt := "", ""
	for key, cell := range observations.byKey {
		if oldestKey == "" || cell.LastAt < oldestAt {
			oldestKey, oldestAt = key, cell.LastAt
		}
	}
	if oldestKey != "" {
		delete(observations.byKey, oldestKey)
	}
}

// observationsSnapshot 为状态文档复制并排序，面板轮询时别让各行像抢凳子一样换位。
func observationsSnapshot() ([]bucketObservation, []observationEvent, string) {
	observations.mu.Lock()
	defer observations.mu.Unlock()

	buckets := make([]bucketObservation, 0, len(observations.byKey))
	for _, cell := range observations.byKey {
		buckets = append(buckets, *cell)
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].AuthID != buckets[j].AuthID {
			return buckets[i].AuthID < buckets[j].AuthID
		}
		return buckets[i].Model < buckets[j].Model
	})

	// 最新在前；来客问的是刚发生什么，不是先翻开业第一天的旧账。
	recent := make([]observationEvent, 0, len(observations.recent))
	for i := len(observations.recent) - 1; i >= 0; i-- {
		recent = append(recent, observations.recent[i])
	}

	since := ""
	if !observations.since.IsZero() {
		since = observations.since.UTC().Format(time.RFC3339)
	}
	return buckets, recent, since
}

// flushObservations 锁内复制、锁外写盘；磁盘慢可以慢，别拉响应钩子一起排队。
func flushObservations(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return
	}

	observations.mu.Lock()
	if !observations.dirty {
		observations.writing = false
		observations.mu.Unlock()
		return
	}
	snap := observationSnapshot{
		Version:   observationsVersion,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Recent:    append([]observationEvent(nil), observations.recent...),
	}
	if !observations.since.IsZero() {
		snap.Since = observations.since.UTC().Format(time.RFC3339)
	}
	for _, cell := range observations.byKey {
		snap.Buckets = append(snap.Buckets, *cell)
	}
	observations.dirty = false
	observations.mu.Unlock()

	sort.Slice(snap.Buckets, func(i, j int) bool {
		if snap.Buckets[i].AuthID != snap.Buckets[j].AuthID {
			return snap.Buckets[i].AuthID < snap.Buckets[j].AuthID
		}
		return snap.Buckets[i].Model < snap.Buckets[j].Model
	})

	data, errMarshal := json.MarshalIndent(snap, "", "  ")
	if errMarshal == nil {
		errWrite := atomicWrite(filepath.Join(dir, observationsFileName), append(data, '\n'))
		if errWrite != nil {
			// 失败不致命也不立即重试；内存账仍在，下次整份重写，别为一张回执当场掀桌。
			log.Printf(logPrefix+"could not write %s: %v", observationsFileName, errWrite)
			observations.mu.Lock()
			observations.dirty = true
			observations.mu.Unlock()
		}
	}

	observations.mu.Lock()
	observations.lastOut = time.Now()
	observations.writing = false
	observations.mu.Unlock()
}

// loadObservations 为 dir 恢复计数或开新账，由 configure 调用。
// store_dir 换了就跟着换账，不把两家店的营业额混成一家。
func loadObservations(dir string) {
	dir = strings.TrimSpace(dir)

	observations.mu.Lock()
	defer observations.mu.Unlock()

	if observations.dir == dir && !observations.since.IsZero() {
		// 同一存储已加载就保留计数，重新配置不能顺手把操作者眼前的账擦了。
		return
	}

	observations.dir = dir
	observations.byKey = make(map[string]*bucketObservation)
	observations.recent = nil
	observations.since = time.Now()
	observations.dirty = false
	// 从当前时刻起算 flush 节奏，不从零时刻算起。
	// 否则刚加载第一条就立刻写盘；重启不是每条响应都要交一次入场费。
	observations.lastOut = time.Now()

	if dir == "" {
		return
	}

	raw, errRead := os.ReadFile(filepath.Join(dir, observationsFileName))
	if errRead != nil || len(raw) == 0 {
		// 首次无文件是正常开张，配置新 store_dir 不必每次为白纸大声报案。
		return
	}
	var snap observationSnapshot
	if errUnmarshal := json.Unmarshal(raw, &snap); errUnmarshal != nil {
		log.Printf(logPrefix+"%s is unreadable, observation counts restart from empty: %v", observationsFileName, errUnmarshal)
		return
	}
	if snap.Version != observationsVersion {
		log.Printf(logPrefix+"%s is version %d, want %d; observation counts restart from empty",
			observationsFileName, snap.Version, observationsVersion)
		return
	}
	for i := range snap.Buckets {
		cell := snap.Buckets[i]
		if strings.TrimSpace(cell.AuthID) == "" || strings.TrimSpace(cell.Model) == "" {
			continue
		}
		observations.byKey[bucketKey(cell.AuthID, cell.Model)] = &cell
	}
	if len(snap.Recent) > observationsRecentMax {
		snap.Recent = snap.Recent[len(snap.Recent)-observationsRecentMax:]
	}
	observations.recent = snap.Recent
	if parsed, errParse := time.Parse(time.RFC3339, snap.Since); errParse == nil && !parsed.IsZero() {
		observations.since = parsed
	}
}

// flushObservationsNow 同步落盘，专供关闭或重配；最后一班车不能指望下一班来送账。
func flushObservationsNow() {
	observations.mu.Lock()
	dir := observations.dir
	observations.writing = true
	observations.mu.Unlock()
	flushObservations(dir)
}

// deleteObservation 删一个桶的计数与近期事件，返回原行是否存在。
// 池本身不按桶存状态，所以面板“清此桶”只是忘掉该桶观测，不是去全局池拆椅子。
func deleteObservation(authID, model string) bool {
	key := bucketKey(authID, model)
	observations.mu.Lock()
	defer observations.mu.Unlock()
	if _, ok := observations.byKey[key]; !ok {
		return false
	}
	delete(observations.byKey, key)
	observations.recent = dropObservationEventsLocked(observations.recent, key)
	observations.dirty = true
	return true
}

// clearAllObservations 清全部计数和播报，是同一清理按钮的全范围版本，一本账整本翻新。
func clearAllObservations() {
	observations.mu.Lock()
	defer observations.mu.Unlock()
	observations.byKey = make(map[string]*bucketObservation)
	observations.recent = nil
	observations.dirty = true
}

// dropObservationEventsLocked 移除某桶近期事件；调用方持 observations.mu，清桌前先稳住账本。
func dropObservationEventsLocked(events []observationEvent, key string) []observationEvent {
	out := events[:0]
	for _, e := range events {
		if bucketKey(e.AuthID, e.Model) == key {
			continue
		}
		out = append(out, e)
	}
	return out
}
