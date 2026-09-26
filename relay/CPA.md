# 原生插件 + 云端打票

**产品边界：有限取票＋路由复用＋协议校验。** 票长 780 仅是格式要求，`response.model` 仅是上游模型声明，`unified-N` 仅用于路由判断；这些信息只是门票与名牌,不是模型实际能力的武状元证书，不替“满血”盖章,也不做隐性降级过滤；门卫不会看票就替人算武功。

这间柜台守本分：此模式不修改 CLIProxyAPI 核心、不改业务回源地址、不写 OAuth 账号文件，也不接管 Refresh Token。
本地场记记载：已按本仓库依赖 CLIProxyAPI v7.3.4 / 插件 Schema 6 实现并进行本地测试；换了宿主戏台就另做加载验收,不能拿旧票直接冲门。

## 工作方式

1. CPA 点名选定账号后，插件不另点一桌，只使用 `selected_auth_id` / `selected_auth_index` 对应的凭据。
2. 用 `host.auth.get_runtime` 先查身份与提供商这两张名牌，再用只读 `host.auth.get` 取得该账号文件中的 Access Token。
3. 插件向 FC 发 HTTP 打票请求，通过 `X-Mint-Transport` 选择 FC 到上游的 SSE 或 WebSocket 协议。当前业务请求带完整有效的目标路由 pair 时，仅将 `__cflb` / `__oailb` 作为种子传给 FC；其他 Cookie 不准借队伍溜进取票控制面。
4. 收票先过柜台的尺子：验收返回的协议、模型声明、票长、Fernet 时间戳、Cookie 网关及有效期，在内存中缓存。
5. 票验好才上场：把票注入 `X-Codex-Turn-State`，仅合并 `__cflb` / `__oailb`，其他 Cookie 留在原位，不抢别人的板凳。

“验收通过”“ready”和面板缓存数量只是协议与有效期这关点了头,不等于质量评测给它戴了大红花。保留明确的协议拒收，不因无法测量能力而放弃鉴权、验期或模型声明一致性检查；账号/模型缓存隔离及既有目标网关配置不变。

先看客人有没有自带票：只有没有原始 `X-Codex-Turn-State` 的请求才会注入；客户端已有状态不覆盖,不能把客人的票据改成自己的签名。`dry_run: true` 不请求 FC、不注入。
归属没认清或不是 Codex 就不伸手；已确认选中的 Codex 凭据不可读取、打票未就绪或验收失败时，返回 `503 cloud_mint_unavailable` 和 `Retry-After: 2`，不拿别的账号的票顶包,哪怕队伍排到街口。

读凭据也得认门牌,不能隔空摸口袋：当前 SDK 的 `host.auth.get` 返回物理账号文件，不能凭空取得仅内存账号的 Access Token，也不能保证文件比宿主刚刷新的内存 token 更新。遇到这些情况就拒绝此次注入,不改文件、不自行刷新,柜台不兼职修锁。

### 503 后的恢复边界

宿主已点名选中账号,插件不拿旧账再拦一次；不再用账号摘要 `Unavailable=true` 二次否决。
旧账可能记的是已到期的冷却，或其他模型的失败；CPA 调度器按当前模型和恢复时间
判断能否重试。旧逻辑像拿过期告示当门神：会在首次短等待返回 503 后，连后台已打好、面板显示 `ready`
的缓存票也拒绝读取，使后续请求持续 503。插件仍拒绝 `Disabled=true` 或
`Status=disabled`，并保留账号归属、提供商、文件读取以及票据/pair 验收。

`cloud_mint_recovery_test.go` 覆盖冷启动 503 → 后台票就绪 → 宿主重新选中账号 →
复用缓存注入的恢复链路。这次修复不包治百病：不消除正常冷启动短等待、云端失败或无效凭据产生的
503；上线是否命中这一缺陷，得核对运行版本和故障日志,不能凭一声咳嗽就开药方。

原生库编好后也要上台对同一出恢复戏（仅连接本地模拟云函数、使用虚构宿主凭据）：

```bash
NATIVE_PLUGIN_PATH=build/linux/amd64/codex-turn-state-cloud-mint.so \
  python3 scripts/test_native_cloud_recovery.py
```

测试通过真实 C ABI 提供 `host.auth.get_runtime` / `host.auth.get`，检查首次 503
后缓存注入恢复且不重复打票，再确认禁用账号仍被拦截。脚本在独立子进程启动前
注入虚构 relay key，免得 Go 原生库拿旧环境快照,Python 却拿新口供,两边各唱各的。

## 配置

配置要添菜,不要掀桌：合并到现有 CPA 配置中，**不要覆盖整个配置文件**：

```yaml
plugins:
  enabled: true
  dir: /data/plugins
  configs:
    codex-turn-state-cloud-mint:
      enabled: true
      role: business
      dry_run: false
      cloud_mint:
        enabled: true
        url: https://HOST/
        proxy_url: ""              # 可选：HTTP/HTTPS/SOCKS5/SOCKS5H 前置代理
        proxy_env: ""              # 可选：例如 CPA_MINT_PROXY，与 proxy_url 二选一
        key_env: CPA_RELAY_KEY
        transport: sse
        gateway: unified-88
        ticket_length: 780
        ttl_seconds: 240
        wait_ms: 2000
        timeout_ms: 90000
```

`CPA_RELAY_KEY` 必须注入 **CPA 进程/容器**，与 FC 的 `RELAY_KEY` 相同。配置只记钥匙柜的名字,不记钥匙牙纹；不要把密钥放进 URL、日志或提交到仓库。
URL 禁止账号密码、query 和 fragment；生产要求 HTTPS，HTTP 只允许回环测试地址。重定向不跟,路边喊换个门也不去。

如果 FC 采用 `RELAY_MODE=transparent`，就让打票柜台歇业,不再使用云端打票链路：将这里的
`cloud_mint.enabled` 设为 `false`（或停用该插件），把业务请求的上游地址改为
FC 透明网关，并在客户端到 FC 之间配置独立的 HTTP/SOCKS5 前置代理。此时
`CPA_RELAY_KEY`、`cloud_mint.url` 和 `cloud_mint.proxy_*` 不参与业务透传；FC
仍要求每个请求携带 `X-Relay-Key`。
### 云函数前置代理

```text
CPA 插件 → 前置代理 → HTTPS 云函数地址 → FC 的原有上游回源
```

`cloud_mint.proxy_url` 支持 `http://HOST:PORT`、`https://HOST:PORT`、`socks5://HOST:PORT`、`socks5h://HOST:PORT`；可包含代理自己的账号密码，但推荐把完整代理 URL 放在 CPA 进程的 `CPA_MINT_PROXY` 环境变量中，再仅配置 `proxy_env: CPA_MINT_PROXY`，免得把代理密码贴成 YAML 门口的告示。

- 两者都为空：明确走直连这扇门,不继承 `HTTP_PROXY` / `HTTPS_PROXY`、CPA 全局代理或账号业务代理。
- `proxy_env` 已配置但缺少对应环境变量：返回未就绪，不偷偷换到直连小门。两个代理来源不能同时配置。
- HTTP/HTTPS 代理通过 CONNECT 隧道访问 HTTPS FC；FC 的 TLS 证书照查,坐了轿子也不能免查身份。SOCKS5/SOCKS5H 将目标域名交给代理解析，不需要本机先解析 FC 域名。
- 前置代理失败、认证失败或证书失败：按既有失败冷却处理，代理这扇门关了就报错,不绕后墙直接访问 FC。仍禁止 HTTP 重定向。
- 这张通行证只管插件访问 FC。FC 到上游的出口、CPA 业务流量的出口均不改变；打票模式为 WebSocket 时，插件到 FC 仍是 HTTP(S) 调用，因此同样经过此前置代理。
- 代理变化（包括环境变量里的地址或凭据变化）隔离缓存，不能复用旧代理路径上的失败冷却。代理密码不登标准日志的公告栏；只在网络拨号期间使用。

已有面板 `runtime.json` 可以覆盖 `dry_run`，启用后得看实际生效状态,别把写好菜单当成已经上菜。

- 此能力默认不登台；未启用时保留旧插件行为。
- `transport` 可选 `sse` / `websocket`，得与准备注入的业务通道对上号，不能穿错戏服；当前不自动检测或切换 CPA 的执行器。
- 缓存按账号、Access Token 版本、模型、传输、验收配置、FC URL、密钥和实际前置代理分桌隔离，不落盘记长账。
- 同桶并发只排一队；同账号同时只打一个模型，最多 4 个云端任务。
- 业务线程最多等待 `wait_ms`（上限 10 秒）；后台任务最多执行 `timeout_ms`（上限 180 秒）。等待超时返回 503，但已有任务继续到完成或其期限，后来的请求仍可取结果，不必见短等待失败就宣布整出戏散场。
- 后台失败就在本实例坐冷板凳 30 秒，避免每个业务请求重新发起失败打票。云函数内部仍有自己的按轮冷却。
- 云函数还带自己的总账上限，客人喊加菜也不能突破：默认 `MINT_MAX_TOTAL_ATTEMPTS=24`、`MINT_TOTAL_TIMEOUT_MS=75000`，覆盖所有模型、补 pair、在途 SSE/WS 和冷却；请求头不能扩大这两个上限。建议 FC 总时限小于插件 `timeout_ms` 并留回传余量。FC HTTP 网关可能不传播客户端断连，因此仅缩短插件超时不能替代服务端限制。
- `gateway` 不匹配或没有合法 `response.created.response.model` 时仍严格拒收，不能见 HTTP 200 配票长 780 就敲成功的锣。FC `mint_attempt.reject_reason` 给出初筛原因，`mint.stop_reason` 给出总预算/总时限/取消原因；没有有效票/pair 时有限返回 `502 mint_exhausted`。
- 修改云端配置、角色或 dry-run 状态，以及插件正常退出时，旧任务收摊，不能拿新菜单继续做旧菜。当前插件 ABI 的请求拦截没有可用的客户端取消上下文，因此不承诺业务客户端断开就立即取消共享预热；预热始终有超时与并发上限。

## 构建、安装及回滚

构建使用原项目流程或 `go build -buildmode=c-shared`，不用再请新依赖进戏班。此次产物名为 `codex-turn-state-cloud-mint.so`，**CPA 从文件名派生插件 ID `codex-turn-state-cloud-mint`**，配置得住进同名键,不能门牌叫张家,账本写李家。Metadata.Name 仅用于显示，不决定配置键。此前把注册名写成 codex-turn-state 是叫错名,说明已纠正,不让旧名继续顶包。
将其放入 CPA 已配置的插件目录并重启前，应先停止加载旧版同名插件：**不要同时启用旧 `codex-turn-state.so` 和新 `codex-turn-state-cloud-mint.so`**。先请一个账号试走位,别让全班演员同时冲门。

仅将 `cloud_mint.enabled` 改为 `false` 会回到旧插件的 Cookie 池行为；若要完全恢复原版 CPA 请求行为，需要停用整个 `codex-turn-state` 插件。
这份记录里的本次工作没改宿主配置、没部署云函数,运行中的插件也没换角。

若将文件重命名为 `codex-turn-state.so`，配置键也必须改回 `codex-turn-state`。新版根据宿主 `ResourceBasePath` 自动生成管理接口与页面配置地址，兼容这两种安装名；不能只换招牌却继续沿用另一个 ID 的账本。

## 正式前端（0.3.3-ws-chain）

`/v0/resource/plugins/codex-turn-state-cloud-mint/dashboard` 已切换到内嵌 `cloud_mint_ui.html`，页面的名牌写着 `cloud-mint-ui-20260924-ws-chain`。别认错演员：不是 `design/` 下的独立示例，也不再显示旧探测/代理池导航。

- 页面读取真实缓存、任务、失败冷却和最近 80 条内存脱敏日志。没任务就让桌子空着,不摆演示数据冒充客人。
- 数据通过鉴权的 `GET /v0/management/codex-turn-state-cloud-mint/cloud-status` 获取，不给匿名访客另开日志小门。
- 输入 **CPA 管理密钥**（不是 RELAY_KEY）连接；密钥只在当前页面内存里坐一会儿，不放 URL、localStorage 或 sessionStorage。若管理入口限制本机访问，请通过现有安全隧道访问，不为面板随意放开公网管理。
- 保存调用 CPA 原生 `PATCH /v0/management/plugins/codex-turn-state-cloud-mint/config`，只合并 `cloud_mint` 和 `dry_run`；保存前确认，保留其他插件配置及未知的嵌套字段。页面不越俎代庖去改环境变量。
- 页面区分“配置已保存”和“运行参数同步”。若重载失败或 runtime.json 覆盖 dry_run，应检查实际运行参数，不能菜单刚写完就宣布满桌菜已出锅。
- 只影响 UI：旧探测相关后端接口为兼容仍保留，但不在新面板继续占台口。
- WS 只记录合法 `response.created` 的模型声明和异常事件，取消逐 delta 日志及明文账号输出；WS 事件仍不能提供握手票头。

换完插件得重启 CPA，换演员不能只换后台名单（同名 native 插件可能按路径缓存）；扫描目录只放一个 `codex-turn-state` 插件。确认加载版本为 `0.3.3-ws-chain`，再强制刷新页面，让前台也认新名牌。

## 日志

流水账各入各账：日志输出到 CPA 标准日志、正式面板的鉴权内存流水，以及 FC 的每次尝试日志；不新增持久化日志数据库或无鉴权日志接口。
CPA 侧可在进程/容器日志中搜索 `云端打票`、`云端票注入`、`业务回源观测`。

把这张流水账摊开看：

```text
云端打票 · 定向 Cookie #短指纹 · unified-199 · 得到 unified-88 · 票长 780 · #短指纹 · 这张票龄 22s · 未见模型 · 网关变化
业务回源观测 · cookie-780 · 票长 780 · #旧票指纹 · unified-88 · 得到 unified-88 · 票长 780 · #新票指纹 · 这张票龄 22s · 未见模型 · 网关未变
```

指纹是 SHA-256 的 Base64URL 前 8 个字符，**不是从票/Cookie 身上剪下来的前 8 个字符**。
日志不输出完整票、Cookie、Access Token、Refresh Token 或云端密钥。账号也只留哈希指纹，真人不登公告栏。

- `cookie-780` 表示请求确实注入过长度 780 的票；云函数裸打或只带 Cookie 的请求不会冒充“带票请求”。
- `未见模型` 表示当前观测点没有合法模型声明，不拿请求模型来代答,考生没报名字就不能替他填。
- 前后网关都报上名且相等，才准记 `网关未变`；不同写 `网关变化`；缺任何一侧写 `网关变化未知`。
- SSE 业务响应头到达时尚未拿到模型事件，所以这条头部观测可能写 `未见模型`；完整 SSE `response.created` 到达后会更新同一条请求记录，不以模糊字符串匹配取值。WS 事件观测没有握手响应头时明确显示“未观测”，不能给没见过的新票或网关画一张证件照。
- FC 的 `attempt_log` 在最终 JSON/错误响应中最多保留最近 40 次脱敏记录，插件只念限定字段，不把整本私账朗读出来；冷却中的实时进度看 FC 日志；若需跨实例/重启保留，需由运维启用 FC 平台日志投递，本次未修改 SLS/部署配置。旧 FC 没有该字段时仍可打票，但插件没有逐次尝试详情。

## 必须灰度验证的部分

这是打票控制面接入，业务流量仍使用 CPA 原有出口/代理，不自动走 FC。票跨出口、跨连接的可用性及线上 WebSocket 是否签发票头，仍得请真实环境验票,纸上排练不算开演。
WS 注入只能影响尚未建立的握手；插件不强制拆掉 CPA 已复用的长连接，不能声称每个后续 WS turn 都更新了握手票。先让 SSE 过验收这道门,再单独查 WS 模式,不让两位演员互相代考。

## 带 Cookie 取票与业务 WS 续链（0.3.3）

- `cloud_mint.transport: websocket` 控制 FC 的取票方式，不会自动把业务请求迁移到另一条连接；业务 WS 的创建/复用仍归 CPA 和客户端调度，取票柜台不抢导演椅。
- 业务已有票时仍沿用，不再多领一张凑热闹；缺票且有路由 pair 时首发即可定向。pair 必须匹配 `cloud_mint.gateway`，不会把网关字符串改成另一个节点，也不跨账号借 Cookie。
- Cookie 的精确摘要加入取票任务和缓存键，改变 pair 不会误命中旧任务/失败冷却。显式 pair 无效就在本地拦下,不让 FC 白跑一趟。
- 插件保留请求中的 `previous_response_id` 和新增 input，不从别的请求、账号或取票探针自动补入 ID。新记录只保存 previous/response 的 SHA-256 短指纹和 created/completed/incomplete/failed 状态；created 只是报到,不能当作对话已谢幕。
- 请求头和后续 WS 模型/完成事件合并为同一条记录，补充事件只补账，不准让钟倒着走；最近 80 条按时间展示。缺少请求关联标为“关联未知”，不是“注入”。`faster-model` 与响应 model 分开，tier 仅来源于响应的 `service_tier`。
- 新包还没替任何运行中的插件或生产配置换装，不能提前喊部署收工。部署需同时使用支持 Cookie 种子的 FC `index.js` 与新 `.so`；同名原生库替换后需要受控重启 CPA。

### 实测与本地验证边界

线上使用用户授权账号、既有代理及 FC：已验证捕获 Cookie 和 `unified-125 / gpt-6-sol` 同 socket 两轮续链。未承诺“不降智”，未证明 `unified-15` 可从该出口裸打获得。原账号文件和测试 CPA 配置没换装,保持不变。

插件测试使用虚构 Cookie/票/响应 ID；真实新 `.so` 已通过原生 ABI 与本地 FC/WS 联调。日志只展示指纹，完整响应 ID 仍由客户端从原始 API 响应取得。共享续链状态不坐票缓存这张桌,两者别混账。
