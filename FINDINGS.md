# Findings:`X-Codex-Turn-State` 是个什么东西,以及为什么回放能成

这份文档记录插件到底在摆弄什么——不摆凭证值、不摆密钥、不摆账号标识,
只摊结构与观测行为。茶馆可以说书,柜台钥匙不能当醒木敲。

## 复用规则(插件强制执行的天条)

1. `state` 值**不能**跨账号复用——你拿自己的房卡敲我的门,门锁没有义务配合演出。
2. `state` 值**不能**跨模型复用,同账号内也不行,同一饭桌不等于人人共用一只碗。
3. 同账号 + 同模型的 `state` 值**可以跨 IP 复用**——换了门卫也认房卡,不是认来客鞋底的泥。
4. `state` 值实际只能用 **~240 秒**,不是它签名里写的那一小时——
   票面像写了长寿秘诀,240s 一到却可能先退场。
5. `state` 值只在**同账号的活 `__cflb`/`__oailb` cookie 对**搭同一请求
   顺风车时才成立——票和房卡要搭伴上台,少一位就唱不了这出戏。

插件把每个模板都钉在 `(账号, 模型)` 上,两条桌沿绝不越过,正好对应规则
1–3。规则 4、5 是实测行为,各有一节如下。

## `X-Codex-Turn-State` 是 Fernet 令牌

值是 Fernet 令牌,base64url 编码——像一张把生辰八字缝进内衬的票:

```
0x80  (1 byte, version)
ts    (8 bytes, big-endian Unix seconds — issuance time)
IV    (16 bytes)
ciphertext (AES-CBC, multiple of 16 bytes)
HMAC  (32 bytes)
```

每个观测值都以 `0x80` 版本字节开头(base64url 后是 `gAAAAA…`)。第 2–9
字节是令牌的**签发时刻**,不用密钥就能读——读出生时刻不必先把整间档案室撬开:

```python
import base64, struct
from datetime import datetime, timezone

def issued_at(token: str):
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    version = raw[0]                          # 0x80
    ts = struct.unpack(">Q", raw[1:9])[0]     # issuance time, Unix seconds
    return version, datetime.fromtimestamp(ts, timezone.utc)
```

实测:内嵌时间戳等于值首次出现在响应上的那一刻,精确到秒。令牌是**逐
turn 现铸**的,不回锅热炒——每张截获值从铸出那秒就开始倒计时。

令牌里的时钟签了一小时,但门卫下班并不听它指挥——可用窗口见下面两节。

## 票离了负载均衡 cookie 就站不住(2026-09-22 实测)

铸出 292 的那次响应同时下发两个 cookie:`__cflb` 和 `__oailb`。只回放
票不带这俩,上游不认——柜台要求「票 + 房卡」一起报到,票自己耍单刀不算数。

实测序列:一张 292 经一个机房(`IST`)铸出,换到另一个出口(`Oracle`)
连同当初那对 cookie 一起回放——3s、27s、50s 一路被接受,最晚 **192s**
还认,**267s** 被拒(上游另铸一张新 312 请它重新排队)。更早的同类失败落在
65s–220s 之间。所以可用窗口**约 240s**,先死的到底是票还是 cookie——
还没查实;cookie 先退场只是推测,不能给推测颁证书。

再把两次交叉验证请到前排,免得笑话盖住证据:

- **票 ↔ cookie 不绑定。** A 票配 B 的 cookie 组、B 票配 A 的 cookie 组,
  都接受。同一 `session_id` 里换票也一样。
- **`__cflb`/`__oailb` 是账号级路由凭据,不是按票发放的。** 账号任何一对
  活的 pair 都能伺候它任何一张票——在该账号的范围里,房卡换了搭档也能登台。

插件的应对:pair 进**全局**池——凭据是账号无关的,池子统一开饭,账号不另起锅;从
每次上游响应里刷新(包括不铸任何 state 的响应),并贴在一切能引导的
请求上。一对 pair 自观测起信 `ttl_seconds`,再被凭据自身死线截短——
`__oailb` JWT 的 `exp`(2026-09-22 连采 7 次签名全为 3900s)若存在取它,
否则取声明的 `Max-Age`/`Expires`(3600)。

只回放 `__cflb`/`__oailb`。Codex 响应还会下别的 cookie——设备身份、
会话材料——把那些转发出去像替陌生人配门钥匙,采集时就请它们止步。

## 两种长度,差的是什么

| 状态 | base64 字符 | 解码字节 |
|---|---:|---:|
| 正常 | 292 | 217 |
| 降级 | 312 | 233 |

差的**恰好 16 字节——一个 AES-CBC 块**。长值不是另一种令牌,是同一
结构额外背了一块密文砖头。实际上:

- **292(217 字节)** 是当时正常服务状态的票面尺码，不是永久武功榜。
- **312(233 字节)** 是当时降级/限流状态的票面尺码，换票版后不能照旧认人。

多出来的东西在密文里,外面看不见——只露出长度这截衣角,于是这 16 字节
之差是个逐字节可靠的信号,是当时观测的账,不是茶馆里猜的数。

**长度按计划分档(2026-09-22 实测)。** 同一 Apple id 下两个凭据并排
打:`prolite` 账号每次正常响应签 **292**(gpt-5.5 和 gpt-5.6-sol,两个
不同边缘机房),而 `self_serve_business_prolite` 账号每次正常响应签
**332**(249 字节,12 个密文块),三模型×两出口全一致。所以上表是
分档读数,不是普适标准——ssbp 的「正常」已经比 prolite 的「降级」还多
一块,拿一把全局尺子分两类,尺子再严肃也分不清。运维含义:`template_length`/
`replace_length` 必须按本部署自家凭据的实签值配;健康流量上一连串
`other` 判定说明配置说的是别家档位,不能因此宣布所有请求集体倒地。

**档还随格式整体搬迁,不只随计划(2026-09-22 实测)。** 上游把
`X-Codex-Turn-State` 统一到大载荷:同一 prolite 凭据,六个边缘机房 ×
七模型(gpt-5.5、gpt-5.6-sol/luna/terra、gpt-6-astra/sol/luna),21
发全签 **780**——几小时前同一桶还签 292,柜台已经换了票版,旧尺子还在量旧戏服。
令牌仍是 Fernet(`0x80` 版本、内嵌签发时刻、528 字节密文 = 33 块、
32 字节 HMAC);变大的是加密载荷,约 +368 字节新字段,外部不可见。
长度也不再随内容浮动:裸 "ping"、4KB 输入、三条消息的 turn 全签 780。
官方客户端语义没变——新 turn 首发不带 state、首个响应铸票、续跑回放
首值——戏路没换,只是票的外套突然多缝了几层。

- 任何固定长度白名单都跨不过格式升级。观测计数因此按桶学习:未识别
  签名长度首现记 `other`,桶内复发即晋升该桶的 `normal`。
  `template_length` 是定位用的锚,不是全场唯一能进门的请帖。
- `replace_length` 仍是唯一*实测过*的降级签名,而且是在旧格式上测的。
  新格式的降级信号在健康账号上勾引不出来(2026-09-22 实测):单出口
  10 发串行突发 + 15 发并行突发全回 200+780;更说明问题的是——回放
  一张过期 292、一张截断票、一串纯垃圾,全都铸出正常 780。旧的
  「拒绝就铸 312」路径没了:统一格式下,所有拒绝/自愈路径都签同一个
  长度——衣服一样长也可能唱不同角色,长度不再替行为判案。

**降级信号搬到哪儿去了(2026-09-22 实测)。** 统一格式下,尺寸这位旧门卫退居二线,观测要看**换人上场**:当请求模型有 safety-buffering 回退时,响应带
两个声明头:`x-codex-safety-buffering-enabled: true` 与
`x-codex-safety-buffering-faster-model: <model>`。七模型实测回退链:

| 请求模型 | buffering 头 | 回退到 |
|---|---|---|
| gpt-5.5 | 无 | — |
| gpt-5.6-luna | 无 | — |
| gpt-6-luna | 无 | — |
| gpt-5.6-sol | 有 | gpt-5.6-luna |
| gpt-5.6-terra | 有 | gpt-5.6-luna |
| gpt-6-astra | 有 | gpt-5.6-luna |
| gpt-6-sol | 有 | gpt-6-luna |

这些头在每次健康响应上都宣告回退链——它们只是在门口贴出「可能换
人」的告示,并不代表替身已经上场。事件本身是 SSE 载荷里 `response.model` 真的被换成
回退模型(luna 家族是链底:每条链都终结在 luna 变体)。所以插件读
流里第一个 `"model"` 字段,与请求不符即记 `limited`——跟当年 312 一
个罪名——对 steered pair 同样降权。若新格式还有长度级降级签名,那只
能藏在密文里(+368B 新字段);在抓到一次真实降级响应之前,一个新的
降级长度档会被学成 normal——这是不用固定尺寸当门神必须记下的代价。

**回退不能靠请求侧旋钮谈掉(2026-09-22 实测)。** 健康账号上把请求侧
旋钮全拧了一遍:请求头带 `x-codex-safety-buffering-enabled: false`
毫无变化(响应照样宣告回退链);`service_tier:"default"` 和
`"priority"` 被接受但头仍在;`service_tier:"auto"` 和 `"flex"` 直接
被拒(`Unsupported service_tier`),`store:true` 被拒
(`Store must be set to false`)。约 50 发探测覆盖七模型、六个网关节点
(unified-125/95/88/157/97/179,由回放 pair 定向)、带工具请求、
high/xhigh effort、串行与并行突发、安全评审 prompt——全部
served==requested 且正常 780。没有任何客户端旋钮能保证
served==requested——buffering 决定权全在上游:客户端把旋钮拧冒烟,也不能替上游拍板。
客户端能做的正是这个插件在做的:在流上发现换人,然后给换出人的出口
在账本上记上一笔,不把账本装成能力鉴定书。

**续轮机制(2026-09-22 实测)。** `previous_response_id` 被拒
(`Unsupported parameter`):续轮不认另一张空头支票,turn 的续跑只回放 `X-Codex-Turn-State` 头。
回放当前有效的 state 会被静默接受——200、模型正确、**不再铸新
state**——与 cookie 路径的「steered and accepted」读数对得上账,无需再摆一张新票。

**该端点的硬请求约束(2026-09-22 实测)。** 柜台的规矩不随嗓门大小改变： `store` 必须 `false`,
`stream` 必须 `true`,`service_tier` 只接受缺省/`default`/`priority`
(`auto`、`flex` 被拒),responses-lite 头要求
`reasoning.context:"all_turns"`。官方客户端的额外头
(`x-codex-beta-features`、`x-openai-subagent`、window id)无可观测影响。

**直连网关不是捷径(2026-09-23 实测)。** `__oailb` JWT 里的
`chat.gateway.unified-N.api.openai.com` 域名解析到普通 Cloudflare 边缘
IP,不是节点专属监听。用它们自己的 SNI 去敲,出示的是
`*.gateway.unified-N` Let's Encrypt 证书和一个除了 404 就不肯多说一句的 HTTP 服务
——而且时灵时不灵:TLS 有指纹/速率门,几乎每次都拒握手。把同一个 IP
当 `chatgpt.com` 用倒是正常服务 backend-api(200,chatgpt.com 证书)
——但铸出的 pair 是**别的节点**(unified-26 的 IP 铸出 unified-95):
节点由边缘分配,IP 没拿到拍板的官印——想进哪个门,只有 `__cflb`/`__oailb` 回放这
一条道,正是插件干的事。

**`turn/steer` 交互(codex app-server,PR openai/codex#10690)。**
稳定的 Steer 面(活动 turn 上的 `turn/start`,或协议里的 `turn/steer`
参数)给在飞的 turn 追加用户输入;它带 `thread_id`、`input`、
`expected_turn_id`、`responsesapi_client_metadata`(压平进
`x-codex-turn-metadata` 请求头)与 `additional_context`——**没有模型
字段**:被 steer 的 turn 继承原请求谈下的模型,回退也一样继承。轮中
换模型要 `turn/settings/update`,返回 `Applied` 或
`TargetUnavailable`。所以在 buffered(luna)节点上开场的 turn,继续
steer 只会一直喂给同一个降级服务——检测仍是唯一出路,不能把续轮当成凭空变出来的换演员通道。

## 行为备注

- 落在降级路径上的请求常表现为 `server_is_overloaded`。把这个错误和
  降级读数当成一个信号,不是两个——旧格式看 312,新格式看换人。
- `Encrypted content could not be decrypted` 出现在令牌过窗回放或轮换
  中途。这就是「抓到什么注什么」朴素玩法会踩的坑——也是为什么过期要
  按令牌自带时间戳算,不能按代理偶然瞧见它的时刻算；老票不能因晚到柜台就装嫩。

## 传输面变化(2026-09-24 实测)

当天观测到上游协议面两处变化,适配前云端打票整桌停筷:

- **SSE 响应改穿 `application/octet-stream` 马甲**,带
  `Content-Disposition: attachment`,不再报 `text/event-stream`。正文
  没变——同样的 `event:`/`data:` 流,`response.created` 仍带
  `response.model`。`x-codex-turn-state` 票头和 `__cflb`/`__oailb`
  `Set-Cookie` 行仍在 HTTP 响应上。
- **WebSocket 传输不再把 `x-codex-turn-state` 放在 101 升级响应头上。**
  票改从 `codex.response.metadata` WS 消息的
  `headers["x-codex-turn-state"]`(780 长度值)里来,在
  `response.created` 之前到达——证件没站到门口,改在消息的内兜里递出来。pair cookie 仍铸在
  101 的 `Set-Cookie` 行上,`response.created.response.model` 不变。

## 插件拿这些干什么

292 进库认两张来路单,入站请求不在名单上,不能翻墙插队:

- **离线探测**直接以某个账号调
  `chatgpt.com/backend-api/codex/responses`,上游铸出 state 归探测收下。
  CPA 不参与,它的任何状态都没碰——两张桌子各吃各的饭,不动对方的账本。
- **响应钩子**读上游给普通业务流量铸的 state。零成本——请求反正要
  出去;而且自我收敛:桶里一旦有了模板,请求钩子就注它,上游就不再
  为该桶铸新票,这一侧安静下来直到模板过期。

进来的**请求**上带着 292 是另一回事,不收:来路不明——可能是回放,
也可能是别的会话的 state 被客户端顺手捎上。这条路(`harvest_inband`)
对 business 角色强制关——来历没核明的票,再热情也不往柜台里塞。

出门方向,`request.intercept_after` 把 312 换成桶里的活 292(或
`inject_mode: always` 下给没带头的请求强加一张),并把账号池化的
`__cflb`/`__oailb` 并进请求的 Cookie 头——同名以库存为准,客户端
其余 cookie 原样保留。过期按令牌内嵌 Fernet 时间戳(`go/main.go` 的
`fernetIssuedAt`)算,晚到柜台的老模板,不能靠重新登记就冒充新生。

插件从不伪造任何值,也从不跨越账号或模型边界——配角可以认真演戏,
账号和模型却不能串场。
