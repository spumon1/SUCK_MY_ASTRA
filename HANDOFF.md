# Handoff — B 落点清单

状态快照（2026-09-22）:`go build ./... && go vet ./... && go test .` 在
`golang:1.26` 容器内全绿（~3.7s)。工作区是 route-cookie 重构的落点：
`__cflb`/`__oailb` 全局池 + 请求侧引导，turn-state 票只用于观测分类。

## 已由本会话落定（B 若改判，看这几处）

1. **paired-312 → TryNext**(`probe_runner.go` `probeConsume`):200 响应带
   `replace_length`(312）状态时不再算 stored —— pair 仍在入口先入池
   （config 注释「包括回 312 的响应」不变），但该出口不记成功、步进下一
   出口；日志含 `degraded` 与 `(pair still pooled: …)`。
2. **`ttl_seconds` 默认 3600 + `Expires` 解析**:`parseSetCookieLine` 对
   `Max-Age`/`Expires` 取早者，畸形声明忽略；全部注释/文档已对齐
   （README 示例与表格、config.example.yaml、FINDINGS、main.go 包注释）。
3. **测试自死锁修复**:`TestProbeMintsBareAndPools` 的 `defer Unlock` 曾
   持锁二次 harvest → 改显式 Unlock，套件才得以跑完。
4. **测试对齐**:5 处断言入池的用例补 `upstream.setCookies`（沿用 B 在
   `TestProbePoolsTheMintedPair`/`TestProbeAdvancesToNextExitOn312` 的
   模式）;contract literal 删 `buckets.attribution`;clear/observations
   断言改为观测行口径；测试 YAML 里死字段 `harvest_inband`/`inject_mode`
   已清。
5. **死代码清理**:`statusBucket` 删 `IssuedAt`/`ExpiresAt`/`SecondsLeft`
   （重构后从不写入，contract literal 同步删）;`indexFileName` 常量删；
   全文件「template/inject」陈旧注释统一改为 pair/steer 口径
   （`injected_*` 计数器的 JSON 名保留 —— contract 钉死，语义现为
   "steered")。
6. **观测分类放宽（实测驱动）**:`markRouteCookieOutcomeLocked` 对
   `other` 也记 `good_at` —— 实测 steered 请求回 200+332/780 均为健康
   服务，pair 引导成功应记功；`cell.Ready` 改为「签过名且非已知降级
   档」（混部署下 ssbp 的 332 不再永久误报未就绪）;`recognisedLen`
   归因门从「292/312 白名单」放宽为 `len>0`。锁定测试：
   `TestProbeConsumePaired312PoolsButTriesNext`、
   `TestSteeredPairMarksGoodOnOtherLength`。
7. **TTL 实测已主动跳过**（用户指示）：采样至 age=2254s 全存活后停。
   附带发现：steered 响应的 turn-state 长度还随内容浮动（观察到 780，
   随后 prolite 连续 7 次全 780 —— 长度连「计划档」都不稳定）。
8. **TTL 中位数=3900，expireAt 改取凭证自身死线**：7 次连采 `__oailb`
   JWT `exp-iat` 全为 3900（网关真执行的死线；HTTP Max-Age/Expires 只
   声明 3600，且 pair 实测活过它）。`parseSetCookieLine` 现对 JWT 值
   优先取内嵌 `exp`（`jwtExpiresAt`，不验签——读的是上游自己的声明），
   属性作兜底。`ttl_seconds` 默认改 **3900**：窗口 =
   `min(seenAt+ttl, expireAt)` —— expireAt 硬 cap 从「保守属性」变成
   「凭证真死线」，原预警随之消解。测试：
   `TestRouteCookiesPrefersTheTokensOwnExpiry`、
   `TestRouteCookiesNonJwtFallsBackToAttributes`。

## 等 B 落点（决策项）

1. ~~**分类器按计划/账号分档**~~ **已落地（按桶学习）**：上游统一
   X-Codex-Turn-State 格式后，同桶签名整体搬迁（gpt-6-astra 292→780,
   585B/33 块），任何固定映射表都会随格式升级失效。`bucketObservation`
   新增 `signed_lens` 计数表：未识别长度首现记 `other`，桶内复发
   （≥2 次）即晋升该桶的 `normal`;`replace_length` 在分类时先判，永远
   不可学习；表上限 8 项，逐出最罕见者。锁定测试：
   `TestRecurringUnrecognisedLengthPromotesToNormal`、
   `TestDegradedLengthIsNeverLearned`、`TestSignedLensTableStaysBounded`。
   **降级签名已实测定位**：不在长度上，而在 SSE 载荷 —— 响应头
   `x-codex-safety-buffering-enabled/faster-model` 是每模型静态的回退链
   声明（sol/terra/astra→5.6-luna,6-sol→6-luna,luna 是链底），真正的
   降级事件是 `response.model` 被换成 fallback。插件已落地检测：header-
   init 时按 RequestID 武装 `pendingModelScan`，首个载荷块取 `"model"`
   字段，与请求模型不符即记 `limited` + pair 记 bad（同 312 的权重）;
   feed 事件新增 `served` 字段，看板判定语改「降级 → X」。健康账号实测
   阴性：约 50 发覆盖 7 模型 × 6 节点（125/95/88/157/97/179 转向）× 变
   载荷 × 工具 × effort × 突发 × 安全评审 prompt，全一致；请求侧全部
   旋钮（buffering 头/service_tier/store/meta/routing-hint）均不可关
   降级。续轮实测：`previous_response_id` 被拒（400)，续跑只靠回放
   turn-state 头，被接受时 ts=0 不再铸票（=steered 签名）。
2. **README / DEPLOY 大面积旧机制叙述**：仍写 `inject_mode`/
   `harvest_inband`/per-bucket store/Fernet 票替换——整篇重写。
3. **ui.html 旧文案**：死字段读取已修——矩阵格子的倒计时改读
   `route_cookies_seconds_left`,「签发/过期」改读 `observed.last_signed_at`,
   「~240s 票窗口」叙述删除（全量测试+UI 测试绿）。**剩余**：面板文案里
   「模板/注入/替换成 store 模板」的叙述仍是大面积旧机制口径，与 README/
   DEPLOY 重写同属一项，等明确措辞再动。
4. **最终值复核**:`ttl_seconds` 已按 JWT 中位数定 **3900**(expireAt
   现优先取 `__oailb` JWT 的 exp)—— 若实测死亡年龄 <3900 再回看。

## pair 寿命实测（已按指示跳过，存档）

设计：铸一对新 pair，每 ~10 分钟经 proxychains4 携带重放同一 ping；
**死亡信号 = 响应重铸出不同值的 `__cflb`/`__oailb`**（边缘不再认这个
pin)。产物在 `.gocache/ttl_probe/`（已 gitignore):`pair.json` 存 pair
值+铸造时刻，`replay.sh` 单次重放，`log.csv` 累计 (age_s, http, ts_len,
reminted)。采样至 age=2254s 全存活即停，死亡年龄未测。

**替代实测已落地**:7 次连采 `__oailb` JWT `exp-iat` 中位数 **3900**
（凭证自身声明，比 HTTP 属性的 3600 多 300s；早前闲置 pair 活 3700s+
与之吻合）—— `ttl_seconds` 默认与 `expireAt` 来源均据此改定。

## 实测数据（proxychains4 直连验证，可引用）

- `prolite` 凭据（7836420d):gpt-5.5×SIN、gpt-5.6-sol×IAD → turn-state
  **292**;`x-codex-plan-type: prolite`。
- `self_serve_business_prolite` 凭据（de21c38c)：三模型×两出口 →
  **332**(249B,12 个密文块）;`x-codex-plan-type` 同名。
- Cookie 声明：`__oailb` `Max-Age=3600`+`Expires=+1h` 双声明；
  `__cflb` 仅 `Expires=+1h` —— 与代码注释一致。
- 转向验证：跨出口携带 pair 重放 → 200 + 332,**边缘不重铸 pair**
  （只回 `__cf_bm`)= 「steered 请求的典型响应」实证。
- Fernet:`issued_at` = 响应时刻，每轮新铸。
- **上游已统一 X-Codex-Turn-State 格式**：同一 prolite 凭据 × 7 模型
  (gpt-5.5/5.6-sol/5.6-luna/5.6-terra/6-astra/6-sol/6-luna)× 6 机房
  (SJC/SIN/HKG/MAN/NRT/RUH)× 21 发全签 **780**(585B,33 块）——gpt-6-sol、
  gpt-6-luna 实测确认，不再是推测。仍是 Fernet(0x80+ts+IV+33 块+HMAC),
  变大的是加密载荷（约 +368B 新字段，外部不可见）。新格式长度**不随内容
  浮动**:ping / 4KB 输入 / 多轮对话全签 780;log.csv 里的 292→780→292
  抖动是新旧格式混跑的过渡期。客户端语义不变：新 turn 首包不带 state、
  响应铸票、同 turn 续跑只回放首值。

## 复现方法

```bash
# 同一 ping（模型可换）：经 proxychains4 打 backend-api/codex/responses
proxychains4 -q curl -sS -m 60 -D /tmp/h.txt -o /dev/null \
  -X POST https://chatgpt.com/backend-api/codex/responses \
  -H "Authorization: Bearer $AT" -H "Chatgpt-Account-Id: $AID" \
  -H "Content-Type: application/json" -H "Accept: text/event-stream" \
  -H "Originator: codex-tui" -H "Session-Id: $SID" \
  -H "User-Agent: codex-tui/0.154.0 (Ubuntu 24.04; x86_64) OVH (codex-tui; 0.154.0)" \
  --data-binary @ping.json
# ping.json 即 probeFireUpstream 的载荷（go/probe_runner.go:1123)。
# 看 x-codex-turn-state 长度与 set-cookie 名即可（值勿打印）。
```
