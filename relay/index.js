'use strict';
// chatgpt.com 中继 / 打票服务 —— 同一份代码,两种部署模式,靠环境变量切换:
// 代码只领一份工资，环境变量却给它排了两个班。
//
//   [FC 模式]   部署到阿里云函数计算(`s deploy`)。**必须**设 MINT_UPSTREAM_PROXY
//               指向动态住宅代理,并设 MINT_GATEWAY=any。不设住宅代理?
//               打票回源从 FC 实例自己出网(出口 = 函数地域的阿里云数据中心 IP),
//               上游一看机房 IP:把验票窗改成了 429 广播站，持续拒绝招呼
//               (`no live target pair … total_attempt_limit`)——2026-09-25
//               实测:同一批账号,FC 机房出口全 429,补上住宅代理后 6/6 出 780 满血票。
//               数据中心 IP 会被降级/限流——机房门口挂着限流牌，住宅出口另走一条巷子,
//               FC 与本地一个待遇。
//   [本地模式]  本机 `node index.js` 直接跑,设 MINT_UPSTREAM_PROXY 指向动态住宅
//               代理(如 novproxy),打票回源经住宅出口。数据中心 IP 常被上游降级
//               (拿到 turn-state 却无 response.created,或持续 429),住宅出口才稳。
//
//   两班倒的排班表：
//     MINT_UPSTREAM_PROXY  打票回源的前置代理 socks5h/socks5/http/https;空=直连出网。
//                          FC 与本地都应设为动态住宅代理,否则机房 IP 出口会被 429/降级。
//     MINT_ROTATE_SID      =1 时每次连接轮换代理用户名里的 -sid-<token>(动态住宅换 IP)
//     MINT_GATEWAY         打票目标网关;any = 接受任意网关(配合动态出口每次落点不同),
//                          unified-N = 定向某个网关。默认 unified-88。注意:代码读的是
//                          MINT_GATEWAY(见下方 config.gateway),不是 MINT_FORCE_GATEWAY。
//   CPA 插件侧对应切换:cloud_mint.fc.url / cloud_mint.relay.url 指向 FC 地址或本地
//   http://127.0.0.1:<port>/;两个源都灌进同一个全局池;cloud_mint.gateway 用 any
//   (配合动态出口)或具体 unified-N(定向)。
//
// 阿里云函数计算(FC 3.0 Web 函数)— chatgpt.com 透明中继
//
// 客户端把原本发往 https://chatgpt.com 的请求改发到本函数;函数以 chatgpt.com
// 的身份回源(Host 头、TLS SNI、证书校验都按上游域名),响应——含 SSE 流与逐条
// Set-Cookie——原样流式回传。等于把两件事搬进云函数,云函数搬两箱货，不负责给箱子改姓:
//
//   出口 IP  —— 回源从 FC 实例出网,出口是函数所在地域的阿里云地址;
//   边缘选择 —— 默认按正常 DNS 解析上游;请求带 X-Edge-IP: <ip> 时 TCP 直拨该
//               IP,SNI/Host/证书仍是上游域名(「边缘 IP + chatgpt.com SNI」通路)。
//               钉的是 Cloudflare 边缘;gateway 节点仍由 __cflb/__oailb 决定
//               (见 FINDINGS.md「Direct gateway access」)。
//
// 形态:零依赖 Node HTTP server。FC 自定义运行时以 `node index.js` 启动,监听
// $FC_SERVER_PORT(默认 9000)。FC 以响应是否 chunked 判定流式;上游响应不带
// Content-Length 时(SSE 即是),本服务按 chunked 转发,事件因此逐块到达客户端。
// 部署(s.yaml)与接入方式见同目录 README.md。
//
// 打票:已鉴权请求带 X-Relay-Mint 时不走透传 —— 函数以客户端的
// Authorization/Chatgpt-Account-Id 向上游发 codex ping 铸票:每个目标模型
// 各一张,验收票长(默认 780)、所属 pair 的目标网关(默认 unified-88,
// __oailb JWT 内嵌节点名)与上游模型声明;这些检查不能证明实际能力或排除隐性降级——
// 名牌验过不等于武功验过，模型声明不能当擂台成绩单。
// 打出的票与 pair 按凭据缓存,TTL 内复用、过期重打,最后把票和 pair 以
// JSON 返回。打票不依赖任何客户端会话状态,等同一个按需铸票端点;其余
// 请求照常透明中继。RELAY_MODE=transparent 时完全关闭这条分支,所有请求
// 都只做透明中继,即使客户端误带 X-Relay-Mint 也不会打票——说好不打就不打。
//
// 鉴权:必须设置 RELAY_KEY,请求带同值 X-Relay-Key 才放行;未设置则全拒。本函数
// 转发 Authorization,等于凭据代理,公网触发器上不能不设防——代拿钥匙的先锁好自己的门，
// 不然门卫倒成了公共钥匙柜。

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const { pipeline } = require('node:stream');

const UPSTREAM_DEFAULT = 'https://chatgpt.com';
const CONNECT_TIMEOUT_DEFAULT_MS = 10_000;
const WS_RESPONSE_HEADER_LIMIT = 16 * 1024;
const RELAY_MODE_DEFAULT = 'mint';

// 打票默认值:模型/验收参数可被 X-Mint-* 覆盖;冷却和整次调用上限只能由服务端配置——
// 客官可以点菜,但厨子掂量着办。
const MINT_PATH = '/backend-api/codex/responses';
const MINT_UA = 'codex-tui/0.154.0 (Ubuntu 24.04; x86_64) OVH (codex-tui; 0.154.0)';
// 默认目标网关。动态住宅出口每次落到不同 unified-N,满血与否由 served_model/行为
// 判定而非网关号,所以本地/动态出口部署应显式设 MINT_GATEWAY=any(见 s.yaml)不限
// 网关——其实门牌号不重要,里面住的是谁才重要;要定向某个已知网关时设 MINT_GATEWAY=unified-N。
const MINT_GATEWAY_DEFAULT = 'unified-88';
const MINT_MODELS_DEFAULT = 'gpt-6-sol,gpt-6-luna,gpt-6-astra';
const MINT_TICKET_LEN_DEFAULT = 780;
const MINT_TICKET_TTL_DEFAULT_S = 240; // 票实测可用窗口 ~240s(FINDINGS.md)——票只租约 ~240s，钟一到就从通行证变纪念品
const MINT_MAX_ATTEMPTS_DEFAULT = 24;
// 整次调用独立封顶;FC 网关可能不会把调用方断连传给运行时——客人走了菜还在炒,必须自己关火。
const MINT_MAX_TOTAL_ATTEMPTS_DEFAULT = 24;
const MINT_TOTAL_TIMEOUT_DEFAULT_MS = 75_000;
const MINT_TOTAL_TIMEOUT_MAX_MS = 180_000;
const MINT_RETRY_COOLDOWN_DEFAULT_MS = 30_000;
const MINT_RETRY_COOLDOWN_MAX_MS = 300_000;
const MINT_ATTEMPT_TIMEOUT_DEFAULT_MS = 60_000;
const MINT_CACHE_MAX = 256;
// 只认完整 response.created 的模型声明;SSE 扫描/WS 单消息上限 16 KiB。
// 没有合法事件就拒收,不退回模糊字段搜索——验票就验票,不猜谜。
const MINT_BODY_SCAN_BYTES = 16 * 1024;
const MINT_SNIPPET_BYTES = 512; // 非 200 响应留这么长一段诊断体——给人家留点面子,也给自己留点线索
// 凭据/载荷被上游正面拒绝:重试不会变出别的结果,循环直接停——人家说不行就是不行。
const MINT_FATAL_STATUS = new Set([400, 401, 403, 404, 422]);
// 节点名内嵌在 __oailb JWT 载荷里(chat.gateway.unified-N.api.openai.com),也可能
// 出现在 cookie 值明文里;与 Go 侧 routeCookieGatewayRe 同款宽松写法——师出同门。
const MINT_GATEWAY_RE = /unified[-_.]?(\d+)|gateway[-_.][a-z0-9-]+/i;

// 不逐跳转发的请求头:连接级字段;Host 固定改写为上游;中继自己的控制头;
// x-forwarded-* 等会把真实调用方暴露给上游;x-fc-* 是平台注入的(函数配了
// 角色时含临时 AK/STS 凭据),绝不能外发——家丑不可外扬,凭据更不能。
const DROP_REQUEST_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authorization', 'proxy-connection',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'expect',
  'x-relay-key', 'x-edge-ip', 'x-relay-mint', 'x-relay-grade',
  'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port',
  'x-forwarded-proto', 'x-forwarded-scheme', 'x-forwarded-server',
  'x-real-ip', 'true-client-ip', 'client-ip', 'via',
]);
const DROP_REQUEST_PREFIXES = ['x-fc-', 'x-mint-'];
const DROP_RESPONSE_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);
// WS 只重建 Connection/Upgrade/Host,保留 sec-websocket-* 协商字段;
// 剥离其余逐跳头、中继控制头、身份头与平台注入头——该留的留,该走的走。
const WS_DROP_REQUEST_HEADERS = new Set([
  'host', 'connection', 'upgrade', 'keep-alive', 'te', 'trailer',
  'transfer-encoding', 'content-length', 'proxy-authorization', 'proxy-connection', 'expect',
  'x-relay-key', 'x-edge-ip', 'x-relay-mint', 'x-relay-grade',
  'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port',
  'x-forwarded-proto', 'x-forwarded-scheme', 'x-forwarded-server',
  'x-real-ip', 'true-client-ip', 'client-ip', 'via',
]);

// X-Edge-IP 只接受公网 IP 字面量,防止把中继当内网探针(SSRF)——
// 这是公网中继，不是听到门牌就冲进别人客厅的送货员。
// IPv4-mapped IPv6(::ffff:a.b.c.d) 虽披 IPv6 外衣，BlockList 仍按 IPv4 规矩验票。
const NON_PUBLIC = new net.BlockList();
for (const [prefix, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 3], // 组播、保留、广播都别挤进公网单客通道
]) NON_PUBLIC.addSubnet(prefix, bits, 'ipv4');
for (const [prefix, bits] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64],
  ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
]) NON_PUBLIC.addSubnet(prefix, bits, 'ipv6');

function isPublicIP(ip) {
  const family = net.isIP(ip);
  return family !== 0 && !NON_PUBLIC.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

// 每请求读取:部署后环境变量不变,读取成本可忽略,测试可逐用例切换——随叫随到,童叟无欺。
function config() {
  const mode = String(process.env.RELAY_MODE || RELAY_MODE_DEFAULT).trim().toLowerCase();
  if (mode !== 'mint' && mode !== 'transparent') {
    throw new Error('RELAY_MODE must be mint or transparent');
  }
  const upstream = new URL(process.env.RELAY_UPSTREAM || UPSTREAM_DEFAULT);
  if (upstream.protocol !== 'https:' && upstream.protocol !== 'http:') {
    throw new Error(`RELAY_UPSTREAM must be an http(s) URL, got ${upstream.protocol}`);
  }
  // 请求路径原样取自客户端,这里写的路径不会被拼接 —— 与其静默忽略,不如直接报错:
  // 写了也是白写,白写不如报错。
  if (upstream.pathname !== '/' || upstream.search || upstream.hash || upstream.username || upstream.password) {
    throw new Error('RELAY_UPSTREAM must be an origin (scheme://host[:port]) without path, query or credentials');
  }
  const connectTimeoutMs = Number(process.env.RELAY_CONNECT_TIMEOUT_MS);
  const attemptTimeoutMs = Number(process.env.MINT_ATTEMPT_TIMEOUT_MS);
  return {
    mode,
    relayKey: process.env.RELAY_KEY || '',
    upstream,
    connectTimeoutMs: connectTimeoutMs > 0 ? connectTimeoutMs : CONNECT_TIMEOUT_DEFAULT_MS,
    allowPrivateEdge: process.env.ALLOW_PRIVATE_EDGE_IPS === '1',
    // 打票上游代理:让 FC 连 chatgpt 时走住宅出口(数据中心直连拿不到满血——
    // 机房门口不发优待券）。仅作用于打票 dial(SSE/WS)，透明中继业务透传不改道。
    mintProxy: parseProxy(process.env.MINT_UPSTREAM_PROXY),
    // 动态住宅代理:每次连接把用户名里的 -sid-XXXX 换成随机值 → 每次尝试换一个出口 IP。
    // 住宅 IP 质量参差(有的 reset/返回非 SSE/被降级),逐次轮换才能命中干净出口——
    // 抽卡嘛,总有一发是 SSR。
    mintProxyRotate: process.env.MINT_ROTATE_SID === '1',
    mint: {
      transport: process.env.MINT_TRANSPORT || 'sse',
      gateway: process.env.MINT_GATEWAY || MINT_GATEWAY_DEFAULT,
      // 满血验证(MINT_VERIFY_STATE=1):打到票后,带着该票的 x-codex-turn-state
      // 与路由 cookie 再发一次;上游回来不带新 state = 满血,带了新 state = 已降级。
      // 只有满血票才交回;非满血当作拒收继续循环——残次品不出厂。默认关(不影响 FC/原有行为)。
      verifyState: process.env.MINT_VERIFY_STATE === '1',
      // 满血验证的重试次数:住宅出口偶发传输错,换 IP 再验,拿到明确判定为止——
      // 一次失手不算输,次次失手才算命。
      verifyAttempts: clampInt(process.env.MINT_VERIFY_ATTEMPTS, 3, 1, 10),
      models: parseModels(process.env.MINT_MODELS || process.env.MINT_MODEL || MINT_MODELS_DEFAULT),
      // 0 表示不查票长 —— 上游改过签名格式(292→780),留个不更新代码的逃生口:
      // 万一哪天票又换发型,不用半夜起来改代码。
      ticketLen: nonNegInt(process.env.MINT_TICKET_LEN, MINT_TICKET_LEN_DEFAULT),
      // 票的有效窗口:命中缓存直接复用,过期才重打。0 = 不缓存,每次都打——
      // 票会过期,缓存不会骗人。
      ticketTtlS: nonNegInt(process.env.MINT_TICKET_TTL_S, MINT_TICKET_TTL_DEFAULT_S),
      maxAttempts: clampInt(process.env.MINT_MAX_ATTEMPTS, MINT_MAX_ATTEMPTS_DEFAULT, 1, 128),
      maxTotalAttempts: clampInt(process.env.MINT_MAX_TOTAL_ATTEMPTS, MINT_MAX_TOTAL_ATTEMPTS_DEFAULT, 1, 128),
      totalTimeoutMs: clampInt(process.env.MINT_TOTAL_TIMEOUT_MS,
        MINT_TOTAL_TIMEOUT_DEFAULT_MS, 1, MINT_TOTAL_TIMEOUT_MAX_MS),
      retryCooldownMs: clampInt(process.env.MINT_RETRY_COOLDOWN_MS,
        MINT_RETRY_COOLDOWN_DEFAULT_MS, 1, MINT_RETRY_COOLDOWN_MAX_MS),
      attemptTimeoutMs: attemptTimeoutMs > 0 ? attemptTimeoutMs : MINT_ATTEMPT_TIMEOUT_DEFAULT_MS,
    },
  };
}

function nonNegInt(v, dflt) {
  if (v === undefined || v === '') return dflt;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : dflt;
}

function clampInt(v, dflt, lo, hi) {
  const n = Number(v);
  if (!Number.isInteger(n)) return dflt;
  return Math.min(hi, Math.max(lo, n));
}

// 比较摘要而非原串:定长比较,不因长度不同提前返回(timingSafeEqual 要求等长)——
// 开锁不问钥匙长什么样,只看咬不咬得上。
function keyMatches(expected, given) {
  if (!expected || typeof given !== 'string') return false;
  const digest = (s) => crypto.createHash('sha256').update(s).digest();
  return crypto.timingSafeEqual(digest(expected), digest(given));
}

function first(v) {
  return Array.isArray(v) ? v[0] : v;
}

function filterRequestHeaders(inHeaders) {
  const out = {};
  for (const [name, value] of Object.entries(inHeaders || {})) {
    if (DROP_REQUEST_HEADERS.has(name)) continue;
    if (DROP_REQUEST_PREFIXES.some((p) => name.startsWith(p))) continue;
    out[name] = value;
  }
  return out;
}

function filterResponseHeaders(inHeaders) {
  const out = {};
  for (const [name, value] of Object.entries(inHeaders || {})) {
    if (DROP_RESPONSE_HEADERS.has(name)) continue;
    out[name] = value; // set-cookie 在 Node 里本就是数组,writeHead 逐条写出——散装进,散装出
  }
  return out;
}

// 中继自身产生的错误:OpenAI 风格错误体(客户端能直接显示 message),外加
// X-Relay-Error 头 —— 与上游的 401/403/5xx 区分开,免得被当成账号或上游故障——
// 自己闯的祸自己认账,不甩锅。
// details 把打票失败的账本（尝试次数、上次观测值等）塞进 error，一起交差。
function sendError(res, status, code, message, details) {
  if (res.headersSent) {
    res.destroy(); // 响应已经开始:只能掐断,让客户端知道流不完整——覆水难收,直接掀桌
    return;
  }
  const body = JSON.stringify({
    error: { message: `relay: ${message}`, type: 'relay_error', code, ...details },
  });
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'x-relay-error': code,
  });
  res.end(body);
}

// 只管「TCP 建连 + TLS 握手」这一段窄路。ClientRequest.setTimeout 在 socket 连上之前不计时,
// 建连卡住它管不到,所以自己布表——自己的坑自己填。响应头与响应体阶段不设限:responses/compact
// 这类非流式调用要等模型算完才回头部,SSE 也允许长时间静默 —— 兜底是客户端
// 断开(联动拆上游)和 FC 函数超时:天塌下来有它们顶着。
function armConnectTimeout(upReq, ms) {
  upReq.once('socket', (socket) => {
    // 自定义 agent(mintUpstreamAgent 的代理隧道)在 connect/secureConnect 之后
    // 才把 socket 交回 request —— 'socket' 事件里再挂 once('connect'/'secureConnect')
    // 永远等不到,计时器变僵尸:人早就进门了,你还在门口等门铃,ms 后误杀在途请求。
    // 已建连的 socket 不布表;connecting 覆盖 TCP 建连,secureConnecting 覆盖
    // TLS 握手还没签完到的情形。
    if (!socket.connecting && !socket.secureConnecting) return;
    const timer = setTimeout(() => {
      const err = new Error(`connect timeout after ${ms}ms`);
      err.code = 'ETIMEDOUT';
      upReq.destroy(err);
    }, ms);
    const disarm = () => clearTimeout(timer);
    socket.once(socket.encrypted ? 'secureConnect' : 'connect', disarm);
    socket.once('close', disarm);
  });
}

// --- 住宅代理带路班(零依赖 SOCKS5 / HTTP CONNECT)-----------------------
// FC 打票默认从函数自己的数据中心 IP 直连 chatgpt,只能拿到 turn-state 却出不来
// 正常 response.created(满血须走住宅出口——机房门口那张限流告示不肯下班)。MINT_UPSTREAM_PROXY 让打票 dial 经
// 一个住宅代理隧道到上游;支持 socks5/socks5h/http/https,代理凭据只在这条通道用——
// 好人做到底,密不透风。
function parseProxy(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  let u;
  try { u = new URL(s); } catch { throw new Error('MINT_UPSTREAM_PROXY must be a URL'); }
  const protocol = u.protocol.replace(/:$/, '').toLowerCase();
  if (!['socks5', 'socks5h', 'http', 'https'].includes(protocol)) {
    throw new Error(`MINT_UPSTREAM_PROXY unsupported protocol: ${protocol}`);
  }
  const port = Number(u.port) || (protocol === 'http' ? 80 : protocol === 'https' ? 443 : 1080);
  return {
    protocol,
    host: u.hostname,
    port,
    user: u.username ? decodeURIComponent(u.username) : '',
    pass: u.password ? decodeURIComponent(u.password) : '',
  };
}

// SOCKS5(RFC1928)+ 可选用户名/密码认证(RFC1929)。握手完成后 sock 即已隧道到
// host:port,交回调;之后由调用方在其上做 TLS——穿针引线到此为止,开锁的活儿归下家。
function socks5Handshake(sock, host, port, proxy, cb) {
  const useAuth = !!(proxy.user || proxy.pass);
  let stage = 'greet';
  let buf = Buffer.alloc(0);
  let done = false;
  const finish = (err) => {
    if (done) return;
    done = true;
    sock.removeListener('data', onData);
    cb(err || null);
  };
  const sendConnect = () => {
    stage = 'connect';
    const fam = net.isIP(host);
    let addr;
    if (fam === 4) addr = Buffer.from([0x01, ...host.split('.').map((n) => Number(n) & 0xff)]);
    else if (fam === 6) finish(new Error('socks5: IPv6 target unsupported'));
    else { const h = Buffer.from(host); addr = Buffer.concat([Buffer.from([0x03, h.length]), h]); }
    if (done) return;
    const pbuf = Buffer.alloc(2); pbuf.writeUInt16BE(port);
    sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, pbuf]));
  };
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    try {
      if (stage === 'greet') {
        if (buf.length < 2) return;
        if (buf[0] !== 0x05) throw new Error('socks5: bad version');
        const method = buf[1]; buf = buf.subarray(2);
        if (method === 0x02) {
          if (!useAuth) throw new Error('socks5: proxy demands auth but none set');
          const u = Buffer.from(proxy.user), p = Buffer.from(proxy.pass);
          sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
          stage = 'auth';
        } else if (method === 0x00) { sendConnect(); }
        else throw new Error(`socks5: unsupported auth method ${method}`);
      } else if (stage === 'auth') {
        if (buf.length < 2) return;
        if (buf[1] !== 0x00) throw new Error('socks5: auth failed');
        buf = buf.subarray(2); sendConnect();
      } else if (stage === 'connect') {
        if (buf.length < 4) return;
        if (buf[1] !== 0x00) throw new Error(`socks5: connect rejected (rep ${buf[1]})`);
        const atyp = buf[3];
        const addrLen = atyp === 0x01 ? 4 : atyp === 0x04 ? 16
          : atyp === 0x03 ? (buf.length >= 5 ? buf[4] + 1 : Infinity) : -1;
        if (addrLen < 0) throw new Error(`socks5: bad atyp ${atyp}`);
        const total = 4 + addrLen + 2;
        if (buf.length < total) return;
        const leftover = buf.subarray(total);
        finish(null);
        if (leftover.length) sock.unshift(leftover);
      }
    } catch (e) { finish(e); }
  };
  sock.on('data', onData);
  sock.write(useAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]));
}

// HTTP CONNECT 隧道(http/https 前置代理)——敲门、报口令、放行,一气呵成。
function httpConnectHandshake(sock, host, port, proxy, cb) {
  const target = net.isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
  let head = `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n`;
  if (proxy.user || proxy.pass) {
    const cred = Buffer.from(`${proxy.user}:${proxy.pass}`).toString('base64');
    head += `Proxy-Authorization: Basic ${cred}\r\n`;
  }
  head += '\r\n';
  let buf = Buffer.alloc(0);
  let done = false;
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    const idx = buf.indexOf('\r\n\r\n');
    if (idx === -1) return;
    done = true;
    sock.removeListener('data', onData);
    const statusLine = buf.subarray(0, buf.indexOf('\r\n')).toString('latin1');
    const m = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);
    if (!m || m[1] !== '200') { cb(new Error(`proxy CONNECT failed: ${statusLine}`)); return; }
    const leftover = buf.subarray(idx + 4);
    cb(null);
    if (leftover.length) sock.unshift(leftover);
  };
  sock.on('data', onData);
  sock.write(head);
}

// 连到代理并隧道到 host:port,返回已建好的裸 socket(未 TLS)——地道挖好了,上面盖什么楼随意。
function proxyRawConnect(proxy, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (err, sock) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) { sock?.destroy?.(); reject(err); } else resolve(sock);
    };
    const timer = setTimeout(
      () => settle(Object.assign(new Error('proxy connect timeout'), { code: 'ETIMEDOUT' })),
      timeoutMs);
    const proxyTls = proxy.protocol === 'https';
    const raw = proxyTls
      ? tls.connect({ host: proxy.host, port: proxy.port, servername: proxy.host })
      : net.connect({ host: proxy.host, port: proxy.port });
    raw.once('error', (e) => settle(e));
    raw.once(proxyTls ? 'secureConnect' : 'connect', () => {
      const cb = (e) => (e ? settle(e) : settle(null, raw));
      if (proxy.protocol === 'socks5' || proxy.protocol === 'socks5h') {
        socks5Handshake(raw, host, port, proxy, cb);
      } else {
        httpConnectHandshake(raw, host, port, proxy, cb);
      }
    });
  });
}

// 供 http(s).request 的 createConnection 使用:经代理隧道后按需 TLS 包一层——
// 地道归地道,防盗门归防盗门,两道都得上。
// 轮换动态代理会话:把用户名里的 -sid-<token> 换成随机值(novproxy 等按此换出口 IP)——
// 换个马甲再进门,每次都当新客。
function rotateProxySid(proxy) {
  const re = /(-sid-)[^-]+/;
  if (!proxy || !re.test(proxy.user || '')) return proxy;
  return { ...proxy, user: proxy.user.replace(re, `$1${crypto.randomBytes(6).toString('hex')}`) };
}

// 钉住动态代理会话:把 -sid-<token> 换成指定值(同一 sid = 同一 120min 粘性出口)。
// 供 modeltrace 让铸票与 grade 走同一个出口 IP —— 票从哪个门出来就从哪个门进去,
// 否则"非出生出口"用起来会失真。只接受安全的 sid(字母数字),避免注入进代理用户名——
// 名字只能我来起,你别想往里塞东西。
function safeSid(v) {
  return /^[A-Za-z0-9]{1,32}$/.test(v || '') ? v : '';
}

function pinProxySid(proxy, sid) {
  const re = /(-sid-)[^-]+/;
  if (!proxy || !sid || !re.test(proxy.user || '')) return proxy;
  return { ...proxy, user: proxy.user.replace(re, `$1${sid}`) };
}

function makeProxyConnect(proxy, timeoutMs, isHttps, defaultServername, rotate, pinnedSid) {
  return function (options, cb) {
    const useProxy = pinnedSid ? pinProxySid(proxy, pinnedSid) : (rotate ? rotateProxySid(proxy) : proxy);
    proxyRawConnect(useProxy, options.host, options.port, timeoutMs).then((raw) => {
      if (!isHttps) { cb(null, raw); return; }
      const tlsOpts = {
        socket: raw,
        servername: options.servername || defaultServername,
        ALPNProtocols: ['http/1.1'],
      };
      // Node 拒绝 checkServerIdentity: undefined,只有确为函数时才带上——它挑嘴,不喂虚空。
      if (typeof options.checkServerIdentity === 'function') {
        tlsOpts.checkServerIdentity = options.checkServerIdentity;
      }
      const tlsSock = tls.connect(tlsOpts);
      tlsSock.once('secureConnect', () => cb(null, tlsSock));
      tlsSock.once('error', (e) => cb(e));
    }).catch((e) => cb(e));
  };
}

// 打票 dial 用的 agent:无代理时返回 false(保持原直连行为),有代理时返回一个
// createConnection 走隧道的一次性 agent——用完即弃,绝不留恋。
function mintUpstreamAgent(isHttps, cfg) {
  if (!cfg.mintProxy) return false;
  const Agent = isHttps ? https.Agent : http.Agent;
  const agent = new Agent({ keepAlive: false, maxSockets: Infinity });
  agent.createConnection = makeProxyConnect(cfg.mintProxy, cfg.connectTimeoutMs, isHttps, cfg.upstream.hostname, cfg.mintProxyRotate, cfg.mintPinnedSid);
  return agent;
}

// --- 打票窗口开张(X-Relay-Mint)---------------------------------------------------
//
// 一发打票 = 一次 codex ping:裸打(不带 __cflb/__oailb)时边缘分配新节点并铸
// 新 pair;定向打(携带已验收的 pair)时请求钉在该节点上铸票,边缘不再发
// pair —— 房卡认准哪扇门，打票就在哪个窗口排队;实测见 FINDINGS.md。每个模型各打一张票,单票的验收条件:
//   票长     —— X-Codex-Turn-State 长度 == ticketLen(780 仅是预期格式长度)
//   节点     —— 票所属 pair 内嵌节点名 == 目标(__oailb JWT 解码后与值明文两边都查)
//   模型声明 —— 完整 response.created.response.model == 请求模型,禁止模糊搜索——
//               验票要看身份证,不准看相
// 打出的票与 pair 按凭据缓存:TTL 内复用,过期才重打。每轮每模型上限 maxAttempts
// 发,总预算/总时限内才允许冷却续打;401/403 整单停,400/404/422 只弃当前模型——
// 人家把门焊死就别敲了,哪个窗口说不了就换哪个窗口。

function jwtPayloadText(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return '';
  try {
    return Buffer.from(parts[1], 'base64url').toString('utf8');
  } catch {
    return '';
  }
}

// pair 的节点名:先查 __oailb 的 JWT 载荷(节点名在里面),再退到两个值的明文。
// 规范化成 unified-N;查不到返回 '' —— pair 仍能路由,只是叫不出名字——
// 房卡能开门，未必还肯向你报房东姓名。
function mintGatewayLabel(cflb, oailb) {
  for (const src of [jwtPayloadText(oailb), oailb, cflb]) {
    const m = MINT_GATEWAY_RE.exec(src || '');
    if (!m) continue;
    const u = /unified[-_.]?(\d+)/i.exec(m[0]);
    return u ? `unified-${u[1]}` : m[0].toLowerCase();
  }
  return '';
}

// X-Relay-Mint 的值只在明确写着网关样内容(unified-N / gateway-x)时才当目标;
// 空值、1、true 这类布尔写法不算 —— 否则会把它误读成 unified-1,那就贻笑大方了。
function mintGatewayHint(v) {
  const s = String(v || '').trim();
  // 显式 any/* 作为"不限网关"透传给 mintGatewayTarget(→null),让客户端可直接用
  // 请求头声明不限网关,无需依赖 FC 的 MINT_GATEWAY 环境变量(重部署也不丢)——
  // 客官说随便,那就真的随便。
  if (/^(any|\*)$/i.test(s)) return s;
  return /unified[-_.]?\d+|gateway[-_.][a-z0-9-]+/i.test(s) ? s : undefined;
}

// 目标网关写法规范化:'any'/'*'/'' → null(不查);'88'、'unified_88' → 'unified-88'——
// 不管你写大写小写下划线,最后都叫这个名。
function mintGatewayTarget(v) {
  const s = String(v || '').trim().toLowerCase();
  if (!s || s === 'any' || s === '*') return null;
  const u = /^unified[-_.]?(\d+)$/.exec(s);
  if (u) return `unified-${u[1]}`;
  if (/^\d+$/.test(s)) return `unified-${s}`;
  return s;
}

// __oailb JWT 自带的 exp 是网关真正执行的死线(实测签名 3900s);Max-Age/Expires
// 只是嘴上说说。读声明不验签 —— 跟 Go 侧 jwtExpiresAt 一个口径,师兄弟同练一套拳。
function mintExpiry(oailb, setCookie) {
  try {
    const claims = JSON.parse(jwtPayloadText(oailb) || '{}');
    if (Number.isFinite(claims.exp) && claims.exp > 0) {
      return new Date(claims.exp * 1000).toISOString();
    }
  } catch { /* 非 JSON 载荷,落属性兜底 */ }
  for (const line of setCookie || []) {
    if (!/^__oailb=/i.test(line)) continue;
    const ma = /(?:^|;)\s*max-age=(\d+)/i.exec(line);
    if (ma) return new Date(Date.now() + Number(ma[1]) * 1000).toISOString();
    const ex = /(?:^|;)\s*expires=([^;]+)/i.exec(line);
    if (ex) {
      const t = Date.parse(ex[1]);
      if (!Number.isNaN(t)) return new Date(t).toISOString();
    }
  }
  return undefined;
}

function mintPairs(setCookie) {
  const pairs = {};
  for (const line of setCookie || []) {
    const m = /^(__cflb|__oailb)=([^;]*)/i.exec(line);
    if (m) pairs[m[1].toLowerCase()] = m[2];
  }
  return pairs.__cflb && pairs.__oailb ? pairs : null;
}

// 显式输入的 pair 是路由种子,不是账号身份;只准两个 LB Cookie,不转发会话 Cookie——
// 开门只收房卡,不收人家钥匙圈。
function mintSeedPair(cookie, target) {
  const pairs = {};
  for (const part of String(cookie || '').split(';')) {
    const match = /^\s*(__cflb|__oailb)=(.*)$/.exec(part);
    if (!match) continue;
    const [, name, value] = match;
    if (Object.hasOwn(pairs, name) || !value || value.length > 4096 || /[^\x21-\x7e]|[,;]/.test(value)) {
      throw new Error('invalid route cookie pair');
    }
    pairs[name] = value;
  }
  if (!Object.keys(pairs).length) return null;
  if (!pairs.__cflb || !pairs.__oailb) throw new Error('incomplete route cookie pair');
  const gateway = mintGatewayLabel(pairs.__cflb, pairs.__oailb);
  let claims;
  try { claims = JSON.parse(jwtPayloadText(pairs.__oailb)); } catch { /* fail closed */ }
  const expiresAt = claims?.exp * 1000;
  if (!gateway || (target && target !== gateway) || !Number.isSafeInteger(claims?.exp) || expiresAt <= Date.now()) {
    throw new Error('expired, unknown or off-target route cookie pair');
  }
  return { pairs, gateway, expiresAt };
}

// 同一套严格判据:完整 JSON + 指定类型 + 响应 ID + 模型字符串。这是上游的模型
// 声明,不把其他事件或其他对象里的 model 当作执行模型证明——是骡子是马,看名牌不看脸。
// SSE（本地住宅）仍在 response.created 窗口验名；FC/WS 搬到 codex.response.metadata，由调用方报窗口。
function createdModelFromJson(text, eventName = '', type = 'response.created') {
  try {
    const event = JSON.parse(text);
    if (event?.type !== type || (eventName && eventName !== event.type)) return undefined;
    const response = event.response;
    if (typeof response?.id !== 'string' || !response.id.trim()) return undefined;
    if (typeof response.model !== 'string' || !response.model.trim()) return undefined;
    return response.model;
  } catch { return undefined; }
}

// 扫描缓冲最多 16 KiB,只分发空行结束的完整 SSE 事件;网络分包由调用方累积——
// 半句话不算数,说完整才算数。
function readMintSse(buf, readEvent) {
  const lines = buf.toString('utf8').replace(/^\uFEFF/, '').split(/\r\n|\r|\n/);
  lines.pop(); // 未终止的一行不能参与事件判定——话没说完不许上桌
  let eventName = '';
  let data = [];
  for (const line of lines) {
    if (line === '') {
      const result = readEvent(data.join('\n'), eventName);
      if (result !== undefined) return result;
      eventName = '';
      data = [];
      continue;
    }
    if (line.startsWith(':')) continue;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '');
    if (field === 'event') eventName = value;
    if (field === 'data') data.push(value);
  }
  return undefined;
}

function createdModelFromSse(buf) {
  return readMintSse(buf, createdModelFromJson);
}

// HTTP 200 仍可能携带 error/response.failed——穿西装的未必是好人。只保留受控错误类别,绝不记录正文。
function mintEventError(text, eventName = '') {
  let event;
  try { event = JSON.parse(text); } catch { return undefined; }
  if (!['error', 'response.failed'].includes(event?.type)
      || (eventName && eventName !== event.type)) return undefined;
  const error = event.error || event.response?.error || event;
  const knownCodes = new Set(['invalid_request_error', 'invalid_request', 'invalid_argument',
    'model_not_found', 'unsupported_model', 'invalid_model', 'authentication_error',
    'invalid_api_key', 'permission_denied', 'insufficient_quota', 'rate_limit_exceeded',
    'rate_limit_error', 'server_error', 'internal_error', 'overloaded_error']);
  const code = knownCodes.has(error.code) ? error.code
    : (knownCodes.has(error.type) ? error.type : 'unknown');
  const authStatus = ['authentication_error', 'invalid_api_key'].includes(code) ? 401
    : (code === 'permission_denied' ? 403 : undefined);
  const status = authStatus ?? event.status ?? error.status;
  return { code, status: Number.isInteger(status) && status >= 400 && status <= 599 ? status : undefined,
    terminal: ['invalid_request_error', 'invalid_request', 'invalid_argument', 'model_not_found',
      'unsupported_model', 'invalid_model', 'authentication_error', 'invalid_api_key',
      'permission_denied', 'insufficient_quota'].includes(code) };
}

function mintSseDecision(buf) {
  return readMintSse(buf, (text, eventName) => {
    const error = mintEventError(text, eventName);
    if (error) return { error };
    const model = createdModelFromJson(text, eventName);
    return model === undefined ? undefined : { model };
  });
}

function parseModels(v) {
  const list = String(v || '').split(',').map((s) => s.trim()).filter(Boolean);
  return [...new Set(list)];
}

// 票是 Fernet(0x80 + 8B 大端秒 = 签发时刻 + IV + 密文 + HMAC)—— 签发时刻
// 不验签就能读,跟看出生证明不用问接生婆一个道理;与 Go 侧 fernetIssuedAt 同口径;
// 读不出来退到采集时刻。
function fernetIssuedAt(ticket, fallbackMs) {
  try {
    const raw = Buffer.from(String(ticket), 'base64url');
    if (raw.length >= 9 && raw[0] === 0x80) {
      const sec = Number(raw.readBigUInt64BE(1));
      if (sec > 0) return sec * 1000;
    }
  } catch { /* 非 Fernet,落兜底 */ }
  return fallbackMs;
}

// 打出的票与 pair 按凭据缓存:TTL 内直接复用,过期才重打 —— 打票烧的是真配额,
// 能省一发是一发。key 只存凭据摘要,内存不落 token。票与 pair 各自记期:
//   票   —— Fernet 内嵌签发时刻 + ticketTtlS(实测窗口 ~240s,票的租约到点就退房)
//   pair —— __oailb JWT 自己的死线(实测 3900s),由 mintExpiry 读出
// off-target 的 pair 永不入缓存:留它只会把之后的调用钉到错误节点上——进错门不如不进。
const mintCache = new Map();

function mintCacheKey(creds, kind, ...rest) {
  const h = crypto.createHash('sha256')
    .update(`${creds.authorization}|${creds.accountId || ''}`)
    .digest('hex').slice(0, 16);
  return [kind, h, ...rest].join('|');
}

function mintCacheGet(key) {
  const e = mintCache.get(key);
  if (!e) return null;
  if (e.expiresAt <= Date.now()) {
    mintCache.delete(key);
    return null;
  }
  return e;
}

// 每次调用重新验收缓存票:更严格的票长/TTL 不能被旧缓存绕过——昨日的票过不了今天的安检。
// 本次只准缩短租约，不准续命，也不去涂改其他调用共用的缓存户口本。
function mintCachedTicket(key, want) {
  if (want.ticketTtlS === 0) return null;
  const hit = mintCacheGet(key);
  if (!hit || (want.ticketLen > 0 && hit.len !== want.ticketLen)) return null;
  const expiresAt = Math.min(hit.expiresAt, hit.issuedAt + want.ticketTtlS * 1000);
  return expiresAt > Date.now() ? { ...hit, expiresAt } : null;
}

function mintCacheSet(key, e) {
  if (mintCache.size >= MINT_CACHE_MAX) {
    mintCache.delete(mintCache.keys().next().value); // Map 保插入序:逐最旧——座位满了请最早来的让位
  }
  mintCache.set(key, e);
}

// 打票请求的头部:客户端凭据照传,其余按真实 codex-tui 的形态补齐 —— 这发是
// 代客户端铸票,不是透传:跑龙套也要把戏服穿正,头部不继承调用方的杂项。
// session-id 每发领新工牌。cookieHeader 为空就空手打票（边缘才分配新节点）；
// 带已验收 pair 就去指定窗口（在该 pair 节点铸票，边缘不再多发一张房卡）。
function mintHeaders(creds, sid, cookieHeader) {
  const h = {
    authorization: creds.authorization,
    'content-type': 'application/json',
    accept: 'text/event-stream',
    'accept-encoding': 'identity',
    originator: 'codex-tui',
    'session-id': sid,
    'user-agent': MINT_UA,
  };
  if (creds.accountId) h['chatgpt-account-id'] = creds.accountId;
  if (cookieHeader) h.cookie = cookieHeader;
  return h;
}

function mintPayload(model) {
  return JSON.stringify({
    model,
    instructions: '',
    stream: true,
    store: false,
    input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: 'ping' }] }],
    reasoning: { effort: 'low' },
    tool_choice: 'auto',
    parallel_tool_calls: false,
  });
}

// 一发 SSE 打票。只读响应头和有限事件数据:票/pair 在头上,模型声明取 created,
// 拿到判决就拆流 —— 把补全跑完只会白烧配额,差不多得了。返回 {req, done}:req 给调用方在
// 客户端断开时拆连接;done 永不 reject,一切结果(含传输错)都归结成一次
// attempt 记录交给循环判——报喜不报忧,但账都记着呢。
function fireSseMintAttempt(cfg, edgeIp, creds, model, cookieHeader) {
  const { upstream } = cfg;
  const isHttps = upstream.protocol === 'https:';
  let upReq = null;
  const done = new Promise((resolve) => {
    const out = { status: 0, len: 0, gateway: '', served: undefined, steered: !!cookieHeader, model };
    let finished = false;
    const finish = (extra) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({ ...out, ...extra });
    };

    upReq = (isHttps ? https : http).request({
      host: edgeIp || upstream.hostname,
      port: upstream.port || (isHttps ? 443 : 80),
      method: 'POST',
      path: MINT_PATH,
      headers: mintHeaders(creds, crypto.randomUUID(), cookieHeader),
      agent: mintUpstreamAgent(isHttps, cfg),
      servername: isHttps ? upstream.hostname : undefined,
    });
    armConnectTimeout(upReq, cfg.connectTimeoutMs);
    const timer = setTimeout(() => {
      upReq.destroy(Object.assign(new Error('mint attempt timeout'), { code: 'ETIMEDOUT' }));
    }, cfg.mint.attemptTimeoutMs);

    upReq.on('response', (upRes) => {
      readMintHeaders(out, upRes);
      // 纯读头模式(verifyState 开):票(780 turn-state)就在响应头里,满血与否由
      // 后续 state-echo 判定,无需读 body 里的 response.created。头里有票即收,
      // 跳过 content-type 早退与 served_model 校验——顺带绕开"空 content-type/
      // served 空"导致的误杀(US/EU 那类)。票先到碗里来,好不好吃后面再验。
      if (cfg.mint.verifyState && upRes.statusCode === 200 && out.ticket) {
        out.served = model;
        finish({ reason: 'ok' });
        upRes.destroy();
        return;
      }
      // 上游已把 SSE 响应声明为 application/octet-stream(正文仍是 SSE 文本)——
      // 穿马甲也认得;模型声明由 mintSseDecision 严格解析,content-type 只做早退优化,放宽白名单。
      const mintCt = upRes.headers['content-type'] || '';
      if (upRes.statusCode === 200
          && mintCt
          && !/^text\/event-stream(?:;|$)/i.test(mintCt)
          && !/^application\/octet-stream(?:;|$)/i.test(mintCt)) {
        finish({ reason: 'bad_sse_content_type' });
        upRes.destroy();
        return;
      }

      const cap = upRes.statusCode === 200 ? MINT_BODY_SCAN_BYTES : MINT_SNIPPET_BYTES;
      let buf = Buffer.alloc(0);
      upRes.on('data', (chunk) => {
        if (finished) return;
        if (buf.length < cap) {
          buf = Buffer.concat([buf, chunk.subarray(0, cap - buf.length)]);
          if (upRes.statusCode === 200) {
            const decision = mintSseDecision(buf);
            if (decision?.error) {
              const error = decision.error;
              if (error.status) out.status = error.status;
              finish({ reason: `sse_error:${error.code}`, terminalError: error.terminal });
              upRes.destroy();
              return;
            }
            out.served = decision?.model ?? out.served;
          }
        }
        // 200 拿到判决或扫满窗口即拆;非 200 攒够诊断体同样拆。先 finish 再
        // destroy:拆流引发的 error 晚一步到,被 finished 闸门挡在外面——
        // 先官宣结果再拆台,顺序不能反。
        if (out.served !== undefined || buf.length >= cap) {
          finish({ reason: 'ok' });
          upRes.destroy();
        }
      });
      upRes.on('end', () => {
        out.snippet = upRes.statusCode === 200 ? undefined : buf.toString('utf8', 0, MINT_SNIPPET_BYTES);
        finish({ reason: 'ok' });
      });
      upRes.on('error', (err) => {
        out.snippet = upRes.statusCode === 200 ? undefined : buf.toString('utf8', 0, MINT_SNIPPET_BYTES);
        finish({ reason: `stream:${err.code || 'err'}` });
      });
      upRes.on('aborted', () => finish({ reason: 'aborted' }));
    });

    upReq.on('error', (err) => finish({ reason: err.code === 'ETIMEDOUT' ? 'timeout' : `transport:${err.code || err.message}` }));
    upReq.end(mintPayload(model));
  });
  return { req: upReq, done };
}

// 打票传输适配:两种协议共用验收、缓存、冷却与取消流程——一个灶台两口锅。
function mintStatusOK(attempt) {
  return attempt.status === (attempt.transport === 'websocket' ? 101 : 200);
}

function fireMintAttempt(cfg, edgeIp, creds, model, cookieHeader) {
  return cfg.mint.transport === 'websocket'
    ? fireWsMintAttempt(cfg, edgeIp, creds, model, cookieHeader)
    : fireSseMintAttempt(cfg, edgeIp, creds, model, cookieHeader);
}

// 满血验证(带重试):住宅出口偶发 reset/timeout,一次传输错不代表票坏,重试几次
// (每次换出口 IP)直到拿到明确判定;全都传输错才判 unverifiable——
// 失手可以重来,投降才判刑。
async function verifyFullStrength(cfg, edgeIp, creds, ticket, cookieHeader, model) {
  const tries = cfg.mint.verifyAttempts;
  let lastErr = 'unverifiable';
  for (let i = 0; i < tries; i += 1) {
    const r = await verifyStateOnce(cfg, edgeIp, creds, ticket, cookieHeader, model);
    if (!r.error) return r;      // 明确判定(满血/降级)即返回——是骡子是马当场见分晓
    lastErr = r.error;           // 传输错 → 换 IP 再验——换个门口再敲门
  }
  return { full: false, error: lastErr };
}

// 单发 state-echo:带 turn-state + 路由 cookie 再发一次(只读响应头即断)。
// 上游对一个「活」的 turn-state:满血 → 不下发新 state;已降级 → 下发一个新 state——
// 满血的票没人再补发新的,被补发的都是出了问题的。
function verifyStateOnce(cfg, edgeIp, creds, ticket, cookieHeader, model) {
  const { upstream } = cfg;
  const isHttps = upstream.protocol === 'https:';
  return new Promise((resolve) => {
    let done = false;
    let timer = null;
    const finish = (v) => { if (done) return; done = true; clearTimeout(timer); resolve(v); };
    const headers = { ...mintHeaders(creds, crypto.randomUUID(), cookieHeader) };
    headers[turnStateEchoHeader] = ticket; // 必须真的发一个 live turn-state,否则上游必回 state,判据失效——空口无凭,票得真带
    const req = (isHttps ? https : http).request({
      host: edgeIp || upstream.hostname,
      port: upstream.port || (isHttps ? 443 : 80),
      method: 'POST',
      path: MINT_PATH,
      headers,
      agent: mintUpstreamAgent(isHttps, cfg),
      servername: isHttps ? upstream.hostname : undefined,
    });
    armConnectTimeout(req, cfg.connectTimeoutMs);
    timer = setTimeout(() => { req.destroy(); finish({ full: false, error: 'timeout' }); }, cfg.mint.attemptTimeoutMs);
    req.on('response', (resp) => {
      const newState = first(resp.headers[turnStateEchoHeader]) || '';
      resp.destroy(); // 只读头,不读 body——看完证件就走,不进屋
      // 不带新 state(或与原票一致)= 满血;带了不同的新 state = 已降级——被补票的就是有问题的。
      finish({ full: !newState || newState === ticket, newState });
    });
    req.on('error', (err) => finish({ full: false, error: err.code || 'err' }));
    req.end(mintPayload(model));
  });
}
const turnStateEchoHeader = 'x-codex-turn-state';

function readMintHeaders(out, response) {
  out.status = response.statusCode;
  out.edgeIp = response.socket?.remoteAddress;
  out.ticket = first(response.headers['x-codex-turn-state']) || '';
  out.len = out.ticket.length;
  out.pairs = mintPairs(response.headers['set-cookie']);
  out.routeCookieChanged = (response.headers['set-cookie'] || []).some((line) => /^__(?:cflb|oailb)=/i.test(line));
  if (out.pairs) {
    out.gateway = mintGatewayLabel(out.pairs.__cflb, out.pairs.__oailb);
    out.expiresAt = mintExpiry(out.pairs.__oailb, response.headers['set-cookie']);
  }
}

// 客户端帧必须掩码——见人都得戴面具,规矩如此;打票只发送小型文本消息、pong 和 close,不协商压缩。
function mintWsClientFrame(opcode, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  if (body.length > 65535) throw new Error('outgoing websocket message too large');
  const extended = body.length >= 126;
  const header = Buffer.alloc(extended ? 4 : 2);
  header[0] = 0x80 | opcode;
  header[1] = 0x80 | (extended ? 126 : body.length);
  if (extended) header.writeUInt16BE(body.length, 2);
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(body);
  for (let i = 0; i < masked.length; i += 1) masked[i] ^= mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

// 严格解析服务端帧头,大长度在分配消息缓冲之前拒绝——来路不明的大块头先拦下再说话。
// 半帧返回 null 等待续包。maxFrame 可放宽:铸票只读小消息(默认 16 KiB),
// grade 轮要收模型完整输出(更大——吃完整顿饭,不是只尝一口)。
function readMintWsFrame(buf, maxFrame = MINT_BODY_SCAN_BYTES) {
  if (buf.length < 2) return null;
  const fin = !!(buf[0] & 0x80);
  const opcode = buf[0] & 0x0f;
  if ((buf[0] & 0x70) || (buf[1] & 0x80)) throw new Error('unexpected websocket flags');
  if (![0, 1, 8, 9, 10].includes(opcode)) throw new Error('unsupported websocket opcode');
  let length = buf[1] & 0x7f;
  let offset = 2;
  if (opcode >= 8 && (!fin || length > 125)) throw new Error('invalid websocket control frame');
  if (length === 126) {
    if (buf.length < 4) return null;
    length = buf.readUInt16BE(2);
    if (length < 126) throw new Error('noncanonical websocket length');
    offset = 4;
  } else if (length === 127) {
    if (buf.length < 10) return null;
    if (buf.readUInt32BE(2) !== 0) throw new Error('websocket frame too large'); // 高 32 位非零必超限——长得没边了
    length = buf.readUInt32BE(6);
    if (length <= 65535) throw new Error('noncanonical websocket length');
    offset = 10;
  }
  if (length > maxFrame) throw new Error('websocket frame too large');
  if (buf.length < offset + length) return null;
  return { fin, opcode, payload: buf.subarray(offset, offset + length), consumed: offset + length };
}

// 合并文本分片,控制帧可以穿插。只有完整 UTF-8 JSON 消息进入模型判定——
// 七零八落的先攒着,攒齐了才算一条。
// wireBytes 是「当前消息的线路成本」:每条完整消息交付即清零 —— 桥接是长连接,
// 若按连接生命周期累计,长会话必然撞上 totalMax 被误杀:记账记一辈子的账房,谁都吃不消。
function mintWsReader(socket, onMessage, onStop, limits) {
  const frameMax = limits?.frame ?? MINT_BODY_SCAN_BYTES;
  const msgMax = limits?.msg ?? MINT_BODY_SCAN_BYTES;
  const totalMax = limits?.total ?? MINT_BODY_SCAN_BYTES * 4;
  let pending = Buffer.alloc(0);
  let fragment = null;
  let wireBytes = 0;
  return (chunk) => {
    try {
      wireBytes += chunk.length;
      if (wireBytes > totalMax) throw new Error('websocket scan limit');
      pending = Buffer.concat([pending, chunk]);
      while (pending.length) {
        const frame = readMintWsFrame(pending, frameMax);
        if (!frame) break;
        pending = pending.subarray(frame.consumed);
        if (frame.opcode === 8) { onStop('ws_closed'); return; }
        if (frame.opcode === 9) { socket.write(mintWsClientFrame(10, frame.payload)); continue; }
        if (frame.opcode === 10) continue;
        if ((frame.opcode === 0) !== (fragment !== null)) throw new Error('invalid websocket continuation');
        fragment = fragment === null ? frame.payload : Buffer.concat([fragment, frame.payload]);
        if (fragment.length > msgMax) throw new Error('websocket message too large');
        if (!frame.fin) continue;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(fragment);
        fragment = null;
        wireBytes = 0;
        if (onMessage(text)) return;
      }
    } catch { onStop('ws_protocol'); }
  };
}

function fireWsMintAttempt(cfg, edgeIp, creds, model, cookieHeader) {
  let request;
  let socket;
  let timer;
  let finished = false;
  let finish;
  const out = { transport: 'websocket', status: 0, len: 0, gateway: '', steered: !!cookieHeader, model };
  const done = new Promise((resolve) => {
    finish = (extra) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({ ...out, ...extra });
      socket?.destroy();
      request?.destroy();
    };
    const key = crypto.randomBytes(16).toString('base64');
    const hostname = cfg.upstream.hostname.replace(/^\[|\]$/g, '');
    const secure = cfg.upstream.protocol === 'https:';
    const headers = { ...mintHeaders(creds, crypto.randomUUID(), cookieHeader),
      host: cfg.upstream.host, connection: 'Upgrade', upgrade: 'websocket',
      'sec-websocket-key': key, 'sec-websocket-version': '13',
      'openai-beta': 'responses_websockets=2026-02-06',
    };
    delete headers.accept;
    delete headers['content-type'];
    request = (secure ? https : http).request({
      host: edgeIp || hostname, port: cfg.upstream.port || (secure ? 443 : 80),
      method: 'GET', path: MINT_PATH, headers, agent: mintUpstreamAgent(secure, cfg),
      servername: secure && !net.isIP(hostname) ? hostname : undefined,
      checkServerIdentity: (_host, cert) => tls.checkServerIdentity(hostname, cert),
    });
    armConnectTimeout(request, cfg.connectTimeoutMs);
    timer = setTimeout(() => finish({ reason: 'timeout' }), cfg.mint.attemptTimeoutMs);
    request.on('error', (err) => finish({ reason: `transport:${err.code || 'err'}` }));
    request.on('response', (res) => readWsMintRejection(res, out, finish));
    request.on('upgrade', (res, connection, head) => {
      socket = connection;
      if (finished) { socket.destroy(); return; }
      attachMintWebSocket({ res, socket, head, key, out, model, finish });
    });
    request.end();
  });
  // 与 HTTP ClientRequest 的取消接口一致,关闭升级后的 socket,不只关闭握手请求——
  // 分手要分干净,连锅端。
  return { req: { destroy: () => finish({ reason: 'aborted' }) }, done };
}

function attachMintWebSocket({ res, socket, head, key, out, model, finish }) {
  socket.on('error', () => finish({ reason: 'ws_transport' }));
  socket.on('close', () => finish({ reason: 'ws_closed' }));
  const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  readMintHeaders(out, res);
  if (res.statusCode !== 101 || res.headers['sec-websocket-accept'] !== accept
      || res.headers.upgrade?.toLowerCase() !== 'websocket'
      || !res.headers.connection?.toLowerCase().split(',').some((token) => token.trim() === 'upgrade')
      || res.headers['sec-websocket-extensions'] || res.headers['sec-websocket-protocol']) {
    finish({ reason: 'ws_bad_handshake' });
    return;
  }
  const receive = mintWsReader(socket, (text) => wsMintMessage(text, out, finish),
    (reason) => finish({ reason }));
  socket.on('data', receive);
  const payload = JSON.parse(mintPayload(model));
  delete payload.stream;
  socket.write(mintWsClientFrame(1, JSON.stringify({ ...payload, type: 'response.create' })));
  if (head.length) receive(head);
}

function wsMintMessage(text, out, finish) {
  // 上游把响应头搬进了 codex.response.metadata 消息:票(x-codex-turn-state)不再
  // 出现在 101 握手头上,在这里取——证件改到内兜放了。模型声明可能在这条消息里、
  // 也可能在 response.created 里(见下方两者都认),故取票后不提前返回,继续校验模型。
  if (text.includes('"codex.response.metadata"')) {
    try {
      const meta = JSON.parse(text);
      const ticket = meta?.headers?.['x-codex-turn-state'];
      if (typeof ticket === 'string' && ticket) { out.ticket = ticket; out.len = ticket.length; }
    } catch { /* 非完整 JSON,按普通消息继续 */ }
  }
  const error = mintEventError(text);
  if (error) {
    if (error.status) out.status = error.status;
    finish({ reason: error.code === 'unknown' ? 'ws_error_event' : `ws_error:${error.code}`,
      terminalError: error.terminal });
    return true;
  }
  // 上游 WS 的模型声明可能落在 codex.response.metadata,也可能仍在 response.created
  // (实测两种形态都出现过——它藏东西爱换地方);两者都认,哪个先带合格 response.id+model 就用哪个。
  const model = createdModelFromJson(text, '', 'codex.response.metadata')
    ?? createdModelFromJson(text);
  if (model !== undefined) {
    out.served = model;
    finish({ reason: 'ok' });
    return true;
  }
  return false;
}

// ── grade 考场(modeltrace 指纹验证)────────────────────────────────────────
// 回放一张已铸的票发一轮真实 WS 请求,收集模型输出的文本,交由调用方做行为指纹——
// 是骡子是马,牵出来遛遛。与铸票分开:铸票只读 response.created 取票即停;
// grade 要读到 response.completed 才收工。回放方式:把票放进 response.create 帧的
// client_metadata['x-codex-turn-state'](与真实客户端续轮一致——票走正门,
// 不是塞在袜子里)。不带 reasoning.encrypted_content,避免超大帧。
const MINT_GRADE_FRAME_MAX = 512 * 1024;
const MINT_GRADE_TOTAL_MAX = 8 * 1024 * 1024;
const MINT_GRADE_TIMEOUT_MS = 120000;

function mintGradePayload(model, promptText, token) {
  return JSON.stringify({
    type: 'response.create',
    model,
    input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: promptText }] }],
    reasoning: { effort: 'low' },
    store: false,
    stream: true,
    tool_choice: 'auto',
    parallel_tool_calls: false,
    client_metadata: { 'x-codex-turn-state': token },
  });
}

// 累积 output_text.delta,记录 served 模型,读到终态即结束——攒到喊停为止。
function wsGradeMessage(text, out, finish) {
  let event;
  try { event = JSON.parse(text); } catch { return false; }
  const type = event?.type;
  if (type === 'response.output_text.delta') {
    if (typeof event.delta === 'string') out.output += event.delta;
    return false;
  }
  if (type === 'response.created' || type === 'response.in_progress') {
    const m = event.response?.model;
    if (typeof m === 'string' && m) out.served = m;
    return false;
  }
  if (type === 'response.completed' || type === 'response.incomplete') {
    const m = event.response?.model;
    if (typeof m === 'string' && m) out.served = m;
    finish({ reason: 'ok' });
    return true;
  }
  const error = mintEventError(text);
  if (error) {
    if (error.status) out.status = error.status;
    finish({ reason: error.code === 'unknown' ? 'ws_error_event' : `ws_error:${error.code}`, terminalError: error.terminal });
    return true;
  }
  return false;
}

function attachGradeWebSocket({ res, socket, head, key, out, model, prompt, token, finish }) {
  socket.on('error', () => finish({ reason: 'ws_transport' }));
  socket.on('close', () => finish({ reason: 'ws_closed' }));
  const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  readMintHeaders(out, res);
  if (res.statusCode !== 101 || res.headers['sec-websocket-accept'] !== accept
      || res.headers.upgrade?.toLowerCase() !== 'websocket'
      || !res.headers.connection?.toLowerCase().split(',').some((token) => token.trim() === 'upgrade')
      || res.headers['sec-websocket-extensions'] || res.headers['sec-websocket-protocol']) {
    finish({ reason: 'ws_bad_handshake' });
    return;
  }
  const receive = mintWsReader(socket, (text) => wsGradeMessage(text, out, finish),
    (reason) => finish({ reason }), { frame: MINT_GRADE_FRAME_MAX, msg: MINT_GRADE_FRAME_MAX, total: MINT_GRADE_TOTAL_MAX });
  socket.on('data', receive);
  socket.write(mintWsClientFrame(1, mintGradePayload(model, prompt, token)));
  if (head.length) receive(head);
}

function fireWsGradeAttempt(cfg, edgeIp, creds, model, cookieHeader, prompt, token) {
  let request;
  let socket;
  let timer;
  let finished = false;
  let finish;
  const out = { transport: 'websocket', status: 0, len: 0, gateway: '', output: '', model };
  const done = new Promise((resolve) => {
    finish = (extra) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({ ...out, ...extra });
      socket?.destroy();
      request?.destroy();
    };
    const key = crypto.randomBytes(16).toString('base64');
    const hostname = cfg.upstream.hostname.replace(/^\[|\]$/g, '');
    const secure = cfg.upstream.protocol === 'https:';
    const headers = { ...mintHeaders(creds, crypto.randomUUID(), cookieHeader),
      host: cfg.upstream.host, connection: 'Upgrade', upgrade: 'websocket',
      'sec-websocket-key': key, 'sec-websocket-version': '13',
      'openai-beta': 'responses_websockets=2026-02-06',
    };
    delete headers.accept;
    delete headers['content-type'];
    request = (secure ? https : http).request({
      host: edgeIp || hostname, port: cfg.upstream.port || (secure ? 443 : 80),
      method: 'GET', path: MINT_PATH, headers, agent: mintUpstreamAgent(secure, cfg),
      servername: secure && !net.isIP(hostname) ? hostname : undefined,
      checkServerIdentity: (_host, cert) => tls.checkServerIdentity(hostname, cert),
    });
    armConnectTimeout(request, cfg.connectTimeoutMs);
    timer = setTimeout(() => finish({ reason: 'timeout' }), MINT_GRADE_TIMEOUT_MS);
    request.on('error', (err) => finish({ reason: `transport:${err.code || 'err'}` }));
    request.on('response', (res) => readWsMintRejection(res, out, finish));
    request.on('upgrade', (res, connection, head) => {
      socket = connection;
      if (finished) { socket.destroy(); return; }
      attachGradeWebSocket({ res, socket, head, key, out, model, prompt, token, finish });
    });
    request.end();
  });
  return { req: { destroy: () => finish({ reason: 'aborted' }) }, done };
}

// grade 请求入口:X-Relay-Grade 触发。回放 X-Mint-Replay-State 的票 + X-Mint-Prompt
// 的挑战,发一轮真实 WS,回传模型输出文本供调用方做指纹——验货时间到,是骡子是马遛一遛。
async function gradeTicket(req, res, cfg, entry, edgeIp) {
  req.resume();
  entry.grade = {};
  const authorization = first(req.headers['authorization']);
  if (!authorization) { sendError(res, 400, 'grade_no_auth', 'grade needs the request Authorization + Chatgpt-Account-Id'); return; }
  const creds = { authorization, accountId: first(req.headers['chatgpt-account-id']) };
  const model = (first(req.headers['x-mint-model']) || '').trim();
  const token = (first(req.headers['x-mint-replay-state']) || '').trim();
  const promptB64 = first(req.headers['x-mint-prompt']) || '';
  if (!model || !token || !promptB64) {
    sendError(res, 400, 'grade_bad_params', 'X-Mint-Model, X-Mint-Replay-State and X-Mint-Prompt (base64) are required');
    return;
  }
  let prompt;
  try { prompt = Buffer.from(promptB64, 'base64').toString('utf8'); } catch { prompt = ''; }
  if (!prompt) { sendError(res, 400, 'grade_bad_params', 'X-Mint-Prompt must be base64-encoded text'); return; }
  const cookieHeader = first(req.headers.cookie) || '';
  entry.grade = { model, has_cookie: !!cookieHeader };
  cfg = { ...cfg, mintPinnedSid: safeSid(first(req.headers['x-mint-sid'])) };
  const attempt = fireWsGradeAttempt(cfg, edgeIp, creds, model, cookieHeader, prompt, token);
  res.on('close', () => attempt.req.destroy());
  const result = await attempt.done;
  entry.grade.reason = result.reason;
  entry.grade.served = result.served;
  entry.grade.output_len = (result.output || '').length;
  const ok = result.reason === 'ok';
  res.writeHead(ok ? 200 : 502, { 'content-type': 'application/json' });
  res.end(JSON.stringify({
    served: result.served || '', output_text: result.output || '',
    status: result.status || 0, reason: result.reason || '',
  }));
}

function readWsMintRejection(res, out, finish) {
  out.status = res.statusCode;
  let snippet = Buffer.alloc(0);
  res.on('data', (chunk) => {
    snippet = Buffer.concat([snippet, chunk.subarray(0, MINT_SNIPPET_BYTES - snippet.length)]);
    if (snippet.length >= MINT_SNIPPET_BYTES) {
      finish({ reason: 'ws_upgrade_rejected', snippet: snippet.toString() });
      res.destroy();
    }
  });
  res.on('end', () => finish({ reason: 'ws_upgrade_rejected', snippet: snippet.toString() }));
  res.on('error', () => finish({ reason: 'ws_transport' }));
  res.on('aborted', () => finish({ reason: 'aborted' }));
}

// 票归属节点的判定:本发若新铸/轮换了 pair,票就在那个新节点上;定向打且没
// 重铸时,票在当前 pair 的节点上;裸打又没发 cookie 则节点不可知('' → 有目标
// 时必拒收——报不出户口的一律不放行)。
function mintAttemptAccepted(attempt, want, pair) {
  if (!mintStatusOK(attempt)) return `http:${attempt.status || 'err'}`;
  if (!attempt.ticket) return 'no_ticket';
  if (want.ticketLen > 0 && attempt.len !== want.ticketLen) return `len:${attempt.len}`;
  const node = attempt.pairs ? attempt.gateway : (attempt.steered && pair ? pair.gateway : '');
  if (want.gateway && node !== want.gateway) return `gateway:${node || '?'}`;
  if (attempt.served === undefined) return 'no_model_field';
  if (attempt.served !== attempt.model) return `served:${attempt.served}`;
  return null; // 全部条件盖章，准予过关
}

// 等待期间不发上游请求——歇脚的时候不烧火;客户端断开立即取消定时器并解除事件监听。
function waitMintCooldown(signal, milliseconds) {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const finish = (ready) => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onClose);
      resolve(ready);
    };
    const onClose = () => finish(false);
    const timer = setTimeout(() => finish(true), milliseconds);
    signal.addEventListener('abort', onClose, { once: true });
  });
}

// 服务端独立截止时间不依赖 HTTP 触发器传播 close——自己的表自己掐;
// 总预算覆盖模型、补 pair 和冷却轮次。
function mintLifetime(res, limits) {
  const controller = new AbortController();
  let inFlight;
  let attempts = 0;
  const stop = (reason) => {
    if (controller.signal.aborted) return;
    controller.abort(reason);
    inFlight?.destroy();
  };
  const onClose = () => stop('client_closed');
  res.once('close', onClose);
  const timer = setTimeout(() => stop('total_timeout'), limits.totalTimeoutMs);
  timer.unref();
  return {
    signal: controller.signal,
    get reason() { return controller.signal.aborted ? controller.signal.reason : ''; },
    take() {
      if (!this.available()) return false;
      attempts += 1;
      return true;
    },
    available() {
      if (attempts >= limits.maxTotalAttempts) stop('total_attempt_limit');
      return !controller.signal.aborted;
    },
    track(request) {
      inFlight = request;
      if (controller.signal.aborted) request.destroy();
    },
    clear() { inFlight = null; },
    close() {
      clearTimeout(timer);
      res.removeListener('close', onClose);
      inFlight?.destroy();
    },
  };
}

// 上游错误消息可能含凭据;日志只给受控原因和安全标签,不输出原始正文——
// 嘴上得有把门的。
function mintTraceReason(reason) {
  if (!reason) return 'candidate_ok'; // 单发初筛通过不代表最终票/pair 验期成功——过了初试不等于录用
  if (reason.startsWith('served:')) return 'model_mismatch';
  return /^(?:gateway:unified-\d+|gateway:\?|http:\d+|http:err|len:\d+|[a-z_]+(?::[A-Z0-9_]+|:[a-z_]+)?)$/.test(reason)
    ? reason : 'unclassified_failure';
}

// 打票日志只输出 SHA-256 短指纹,绝不截取原始票或 Cookie——
// 见人只说代号,真名烂在肚子里。
function mintFingerprint(value) {
  return value ? crypto.createHash('sha256').update(value).digest('base64url').slice(0, 8) : '';
}

function mintAttemptTrace(sent, attempt, diagnostic = {}) {
  const issued = fernetIssuedAt(attempt.ticket, NaN);
  const age = Number.isFinite(issued) ? Math.max(0, Math.floor((Date.now() - issued) / 1000)) : null;
  // 定向打且上游没发新 pair 时,票铸在发送 pair 钉住的节点上 —— 与
  // mintAttemptAccepted 的 node 判定同口径,不能记成"网关未知"——
  // 一个门里出来的票,不能说不知道哪个门。
  const gateway = attempt.pairs ? attempt.gateway : (sent.gateway || '');
  const served = /^[a-z0-9][a-z0-9._-]{0,95}$/i.test(attempt.served || '') ? attempt.served : '';
  const change = sent.gateway && gateway ? (sent.gateway === gateway ? '网关未变' : '网关变化') : '网关变化未知';
  const trace = {
    sent_gateway: sent.gateway || '', sent_cookie_fingerprint: mintFingerprint(sent.cookie || ''),
    received_gateway: gateway, ticket_length: attempt.len || 0,
    ticket_fingerprint: mintFingerprint(attempt.ticket || ''), ticket_age_s: age,
    served_model: served, status: attempt.status,
  };
  const input = sent.cookie ? `定向 Cookie · #${trace.sent_cookie_fingerprint} · ${sent.gateway || '网关未知'}` : '裸打';
  const output = `得到 ${gateway || '网关未知'} · 票长 ${trace.ticket_length} · #${trace.ticket_fingerprint || '未知'}`;
  const model = served ? `模型 ${served}` : '未见模型';
  const line = `${input} · ${output} · ${age === null ? '票龄未知' : `这张票龄 ${age}s`} · ${model} · ${change}`;
  // 诊断字段只加入 FC 日志,原有 attempt_log 响应结构保持兼容——
  // 旧主顾吃惯的菜不换样。
  console.log(JSON.stringify({ fn: 'chatgpt-relay', event: 'mint_attempt', ...trace, ...diagnostic, line }));
  return trace;
}

// 打票模式入口。参数:请求头 > 环境变量 > 默认——客官点菜优先,没有点菜的才按本店招牌来。
// X-Relay-Mint 的值顺手当目标网关用(X-Relay-Mint: unified-88),不是网关样的值就退回
// X-Mint-Gateway/环境变量。
//
// 流程:每个模型一张票。缓存里有活票直接复用(TTL 判定,过期才算缺失——
// 昨天的票今天刷不过闸机);缺的进打票循环 —— 有 on-target 活 pair 就携带定向打
// (票铸在该节点上),没有就裸打(顺带铸 pair)。上游一旦发新 pair 即采纳:
// on-target 入缓存继续定向,off-target 不入缓存、下一发自然回裸打——
// 进错门的房卡不留。票与 pair 不绑定(实测),所以票只跟自己的 TTL 走,
// pair 死了单独重打——票是票,pair 是 pair,各算各的命。
async function mintTickets(req, res, cfg, entry, edgeIp) {
  req.resume(); // 调用方可能带了体 —— 打票不用它,排空别占着 socket:不喝的汤先倒掉
  entry.mint = {}; // 日志行先打上标记,再填 want/attempts——先挂号再看病

  const authorization = first(req.headers['authorization']);
  if (!authorization) {
    sendError(res, 400, 'mint_no_auth', 'X-Relay-Mint mints with the request\'s Authorization + Chatgpt-Account-Id; both absent');
    return;
  }
  const creds = { authorization, accountId: first(req.headers['chatgpt-account-id']) };

  const transport = first(req.headers['x-mint-transport']) || cfg.mint.transport;
  if (!['sse', 'websocket'].includes(transport)) {
    sendError(res, 400, 'mint_bad_params', 'X-Mint-Transport must be sse or websocket');
    return;
  }
  cfg = { ...cfg, mint: { ...cfg.mint, transport }, mintPinnedSid: safeSid(first(req.headers['x-mint-sid'])) };
  const want = {
    gateway: mintGatewayTarget(
      // MINT_FORCE_GATEWAY 若设置则强制覆盖客户端发来的网关(设为 any/* 即接受任意网关);
      // 本地 relay + 动态住宅出口每次落的 unified-N 不同,先用它把打票跑通——
      // 老板说了算,客官点的菜可以退。
      process.env.MINT_FORCE_GATEWAY
      || first(req.headers['x-mint-gateway']) || mintGatewayHint(first(req.headers['x-relay-mint'])) || cfg.mint.gateway,
    ),
    models: parseModels(first(req.headers['x-mint-models']) || first(req.headers['x-mint-model']) || cfg.mint.models.join(',')),
    ticketLen: nonNegInt(first(req.headers['x-mint-len']), cfg.mint.ticketLen),
    ticketTtlS: nonNegInt(first(req.headers['x-mint-ttl']), cfg.mint.ticketTtlS),
    maxAttempts: clampInt(first(req.headers['x-mint-attempts']), cfg.mint.maxAttempts, 1, 128),
  };
  if (!want.models.length) {
    sendError(res, 400, 'mint_bad_params', 'mint model list must not be empty');
    return;
  }
  let seed;
  try { seed = mintSeedPair(first(req.headers.cookie), want.gateway); }
  catch {
    sendError(res, 400, 'mint_bad_cookie', 'route Cookie must contain one complete, unexpired pair for the requested gateway');
    return;
  }
  Object.assign(entry.mint, {
    transport, models: want.models, want_gateway: want.gateway || 'any', want_len: want.ticketLen,
  });

  const lifetime = mintLifetime(res, cfg.mint);
  try {
    await mintWithLifetime({ res, cfg, entry, edgeIp, want, creds, transport, lifetime, seed });
  } finally {
    if (lifetime.reason) entry.mint.stop_reason = lifetime.reason;
    lifetime.close();
  }
}

async function mintWithLifetime({ res, cfg, entry, edgeIp, want, creds, transport, lifetime, seed }) {
  // 握手取得的票可能具有协议相关语义,不同传输的票与 pair 保守隔离——
  // 各家的票各回各家,不串台。
  const seedKey = seed ? crypto.createHash('sha256').update(JSON.stringify(seed.pairs)).digest('hex') : '';
  const gwKey = `${transport}|${want.gateway || 'any'}${seed ? `|seed:${seedKey}` : ''}`;
  const pairKey = mintCacheKey(creds, 'pair', gwKey);
  const tickets = {};   // model → {ticket, len, served, issuedAt, expiresAt, edgeIp}
  const cachedHit = new Set();
  let missing = [];
  const errors = {};    // model → {attempts, last:{status,len,gateway,served,reason,why}}
  const seen = { gateways: new Set() };
  let pair = (want.ticketTtlS > 0 ? mintCacheGet(pairKey) : null) || seed;
  let attempts = 0;
  let last = null;
  const attemptLog = [];

  for (const m of want.models) {
    const hit = mintCachedTicket(mintCacheKey(creds, 'ticket', gwKey, m), want);
    if (hit) {
      tickets[m] = hit;
      cachedHit.add(m);
    } else {
      missing.push(m);
    }
  }

  // 定向条件:有 pair、没过期、且在目标节点上。off-target 的 pair 携带只会把
  // 请求钉到错误节点 —— 带错房卡不如空手,不如裸打让边缘重新分。
  const pairLive = () => pair && pair.expiresAt > Date.now()
    && (!want.gateway || pair.gateway === want.gateway);
  const cookieHeader = () => `__cflb=${pair.pairs.__cflb}; __oailb=${pair.pairs.__oailb}`;

  // 补票与补 pair 共用一次请求的记账、取消及凭据级拒绝处理——一本账,不分家。
  const runAttempt = async (model) => {
    // 显式要求带 Cookie 的调用,失去有效目标 pair 后不能静默切回裸打——
    // 客人指定要房卡的,房卡没了就得明说,不能假装还给开。
    if (seed && !pairLive()) {
      if (!last) last = { model, why: 'seed_pair_expired' };
      return null;
    }
    if (!lifetime.take()) return null;
    attempts += 1;
    entry.mint.attempts = attempts;
    const sent = pairLive() ? { gateway: pair.gateway, cookie: cookieHeader() } : {};
    const shot = fireMintAttempt(cfg, edgeIp, creds, model, sent.cookie || null);
    lifetime.track(shot.req);
    const attempt = await shot.done;
    lifetime.clear();
    if (lifetime.reason === 'client_closed') return null;
    const why = lifetime.reason || (attempt.reason !== 'ok' ? attempt.reason : mintAttemptAccepted(attempt, want, pair));
    attemptLog.push(mintAttemptTrace(sent, attempt, {
      request_id: entry.reqId, wanted_gateway: want.gateway || 'any',
      requested_model: /^[a-z0-9][a-z0-9._-]{0,95}$/i.test(model) ? model : '',
      reject_reason: mintTraceReason(why),
    }));
    if (attemptLog.length > 40) attemptLog.shift();
    last = {
      model, status: attempt.status, len: attempt.len,
      gateway: attempt.gateway || undefined, served: attempt.served, reason: attempt.reason, why: why || undefined,
    };
    if (attempt.gateway) seen.gateways.add(attempt.gateway);
    if (lifetime.reason) return null;
    if (attempt.status === 401 || attempt.status === 403) {
      entry.mint.attempts = attempts;
      sendError(res, 502, 'mint_rejected', `upstream rejected the mint request (status ${attempt.status})`, {
        attempts, model, upstream_status: attempt.status, upstream_body: attempt.snippet, attempt_log: attemptLog,
      });
      return null;
    }
    // 只接受完整成功响应中的 pair;过期/非目标轮换同时清掉旧缓存,下发改回裸打——
    // 烂掉的房卡当场撕了,绝不收着。
    if (mintStatusOK(attempt) && attempt.reason === 'ok' && attempt.pairs) {
      const expiresAt = attempt.expiresAt ? Date.parse(attempt.expiresAt) : Date.now() + 3600_000;
      pair = { pairs: attempt.pairs, gateway: attempt.gateway, expiresAt, edgeIp: attempt.edgeIp };
      if (!pairLive()) mintCache.delete(pairKey);
      else if (want.ticketTtlS > 0) mintCacheSet(pairKey, pair);
    } else if (seed && attempt.routeCookieChanged) {
      pair = null;
    }
    if (seed && !pairLive()) {
      last.why = why || 'seed_route_lost';
      return null;
    }
    return attempt;
  };

  const terminalModels = new Set();
  // 一轮单模型打票:false 表示已成功或永久失败,true 表示预算耗尽,null 表示整单停止——
  // 三种下场,没有第四种。
  const mintModelRound = async (model) => {
    delete errors[model];
    for (let i = 1; i <= want.maxAttempts && !lifetime.reason; i += 1) {
      const before = attempts;
      const attempt = await runAttempt(model);
      if (!attempt) {
        errors[model] = { attempts: i - 1 + (attempts - before),
	      last: { ...last, why: lifetime.reason || last?.why || 'rejected' } };
        return null;
      }
      if (MINT_FATAL_STATUS.has(attempt.status) || attempt.terminalError) {
        terminalModels.add(model);
        errors[model] = { attempts: i, last: { ...last, why: attempt.terminalError ? attempt.reason : `http:${attempt.status}` } };
        return false;
      }
      const why = attempt.reason !== 'ok' ? attempt.reason : mintAttemptAccepted(attempt, want, pair);
      if (why) {
        last.why = why;
        continue;
      }
      // 满血门:基础校验过后,用 state-echo 判定这张票是不是满血;非满血当拒收继续循环——
      // 光有证不行,还得验真身,残次品不出厂。
      if (cfg.mint.verifyState) {
        const vpairs = attempt.pairs || (pair && pair.pairs);
        if (!vpairs || !vpairs.__cflb || !vpairs.__oailb) { last.why = 'verify_no_pair'; continue; }
        const vcookie = `__cflb=${vpairs.__cflb}; __oailb=${vpairs.__oailb}`;
        const verdict = await verifyFullStrength(cfg, edgeIp, creds, attempt.ticket, vcookie, model);
        if (!verdict.full) { last.why = verdict.error ? `verify:${verdict.error}` : 'downgraded'; continue; }
      }
      const issuedAt = fernetIssuedAt(attempt.ticket, Date.now());
      const rec = {
        ticket: attempt.ticket, len: attempt.len, served: attempt.served,
        issuedAt, expiresAt: issuedAt + want.ticketTtlS * 1000, edgeIp: attempt.edgeIp,
      };
      if (want.ticketTtlS > 0 && rec.expiresAt <= Date.now()) {
        last.why = 'expired_ticket';
        continue;
      }
      if (want.ticketTtlS > 0) mintCacheSet(mintCacheKey(creds, 'ticket', gwKey, model), rec);
      tickets[model] = rec;
      return false;
    }
    errors[model] = { attempts: want.maxAttempts, last };
    return true;
  };

  // 每轮失败预算耗尽后冷却再继续——打不动先喝口水;永久拒绝不重试,总次数跨轮累计。
  rounds: while (!lifetime.reason) {
    let retry = false;
    for (const model of missing) {
      const exhausted = await mintModelRound(model);
      if (exhausted === null) break rounds;
      retry ||= exhausted;
    }
    if (lifetime.reason) break;

    // 票与 pair 独立续期:即使全票命中也要补失效 pair——票还在房里,房卡过期也得换;
    // 已有票保持原样。每轮补 pair 共享 maxAttempts 次预算,不重复使用已被明确拒绝的模型。
    const pairModels = want.models.filter((model) => tickets[model] && !terminalModels.has(model));
    for (let i = 0; i < want.maxAttempts && pairModels.length && !pairLive() && !lifetime.reason; i += 1) {
      const attempt = await runAttempt(pairModels[0]);
      if (!attempt) break rounds;
      if (MINT_FATAL_STATUS.has(attempt.status) || attempt.terminalError) terminalModels.add(pairModels.shift());
      if (!pairLive()) last.why = 'no_live_pair';
    }
    if (lifetime.reason) break;

    if (!pairLive() && pairModels.length) retry = true;
    if (!retry) break;
    if (!lifetime.available()) break;

    entry.mint.cooldowns = (entry.mint.cooldowns || 0) + 1;
    console.log(JSON.stringify({ fn: 'chatgpt-relay', event: 'mint_cooldown', request_id: entry.reqId,
      attempts, wait_ms: cfg.mint.retryCooldownMs }));
    if (!await waitMintCooldown(lifetime.signal, cfg.mint.retryCooldownMs)) break;
    // 冷却中票/pair 可能过期:喝口水的功夫票就馊了——保留仍有效的票,
    // 只重打缺失或失效且可重试的模型。
    for (const model of want.models) {
      if (want.ticketTtlS > 0 && tickets[model]?.expiresAt <= Date.now()) {
        delete tickets[model];
        cachedHit.delete(model);
      }
    }
    missing = want.models.filter((model) => !tickets[model] && !terminalModels.has(model));
  }
  if (lifetime.reason === 'client_closed' || res.writableEnded) return;

  // 未轮到的模型也要说明未完成原因,不能在部分成功响应中静默消失——
  // 没排到队的也得给个说法,不能让人白等。
  if (lifetime.reason) {
    for (const model of want.models) {
      if (!tickets[model] && !errors[model]) {
        errors[model] = { attempts: 0, last: { model, why: lifetime.reason } };
      }
    }
  }

  const now = Date.now();
  const goodPair = pairLive();
  const ticketsOut = {};
  for (const m of want.models) {
    const rec = tickets[m];
    if (!rec) continue;
    // 其他模型补票/补 pair 可能耗时很久,序列化前再验期,不能把过期票报成功——
    // 端上桌前再闻一遍馊没馊。
    if (want.ticketTtlS > 0 && rec.expiresAt <= now) {
      errors[m] = { last: { why: 'expired_ticket' } };
      cachedHit.delete(m);
      continue;
    }
    ticketsOut[m] = {
      turn_state: rec.ticket,
      ticket_len: rec.len,
      served_model: rec.served,
      issued_at: new Date(rec.issuedAt).toISOString(),
      expires_at: new Date(rec.expiresAt).toISOString(),
      age_s: Math.max(0, Math.round((now - rec.issuedAt) / 1000)),
      cached: cachedHit.has(m),
    };
  }
  const okCount = Object.keys(ticketsOut).length;
  entry.mint.attempts = attempts;
  entry.mint.cached = cachedHit.size;
  if (pair && pair.gateway) entry.mint.gateway = pair.gateway;

  if (okCount === 0 || !goodPair) {
    entry.mint.last = last;
    const message = !goodPair ? 'no live target pair' : 'no acceptable ticket';
    const stopped = lifetime.reason ? ` (${lifetime.reason})` : '';
    sendError(res, 502, 'mint_exhausted', `${message} after ${attempts} attempts${stopped}`, {
      attempts,
      want: { models: want.models, ticket_len: want.ticketLen, gateway: want.gateway || 'any' },
      last,
      gateways_seen: [...seen.gateways],
      attempt_log: attemptLog,
      errors: Object.keys(errors).length ? errors : undefined,
    });
    return;
  }

  const body = JSON.stringify({
    transport,
    gateway: goodPair ? pair.gateway : want.gateway || undefined,
    cookies: goodPair ? pair.pairs : undefined,
    cookie_header: goodPair ? `__cflb=${pair.pairs.__cflb}; __oailb=${pair.pairs.__oailb}` : undefined,
    expires_at: goodPair ? new Date(pair.expiresAt).toISOString() : undefined,
    edge_ip: (goodPair && pair.edgeIp) || undefined,
    attempts,
    attempt_log: attemptLog,
    tickets: ticketsOut,
    errors: Object.keys(errors).length ? errors : undefined,
    // 单模型调用保留平铺字段,方便调用方不翻 tickets 表——常客不用看菜单。
    ...(want.models.length === 1 && ticketsOut[want.models[0]] ? {
      model: want.models[0],
      turn_state: ticketsOut[want.models[0]].turn_state,
      ticket_len: ticketsOut[want.models[0]].ticket_len,
      served_model: ticketsOut[want.models[0]].served_model,
    } : {}),
  });
  res.writeHead(200, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function relay(req, res) {
  const started = Date.now();
  const entry = {
    fn: 'chatgpt-relay',
    reqId: first(req.headers['x-fc-request-id']),
    method: req.method,
    path: req.url.split('?')[0], // 不记 query——问太多不礼貌
  };
  let bytes = 0;
  res.on('close', () => {
    if (res.headersSent) entry.status = res.statusCode;
    entry.bytes = bytes;
    entry.ms = Date.now() - started;
    if (!res.writableFinished) entry.aborted = true;
    console.log(JSON.stringify(entry));
  });

  let cfg;
  try {
    cfg = config();
  } catch (err) {
    entry.error = err.message;
    sendError(res, 500, 'relay_misconfigured', err.message);
    return;
  }

  // 鉴权:RELAY_KEY 未配置 = 全拒(fail closed)——没钥匙宁可错杀,不能错放。
  if (!keyMatches(cfg.relayKey, first(req.headers['x-relay-key']))) {
    sendError(res, 403, 'bad_relay_key', 'bad or missing X-Relay-Key');
    return;
  }

  const edgeIp = (first(req.headers['x-edge-ip']) || '').trim();
  if (edgeIp) {
    if (!net.isIP(edgeIp)) {
      sendError(res, 400, 'bad_edge_ip', 'X-Edge-IP must be an IP literal');
      return;
    }
    if (!cfg.allowPrivateEdge && !isPublicIP(edgeIp)) {
      sendError(res, 400, 'bad_edge_ip', 'X-Edge-IP must be a public IP');
      return;
    }
    entry.edge = edgeIp;
  }

  // 打票模式:控制头存在即触发,路径与方法都无意义,不进透传——
  // 对上暗号的去包厢,没对上的走大堂。
  // 透明模式完全关闭云端打票:即使客户端误带 X-Relay-Mint,也按普通请求
  // 继续透传；控制头会在 filterRequestHeaders 中被剥离,不会外发给上游——
  // 说好不打就不打,带错暗号也只当没听见。
  if (cfg.mode !== 'transparent' && 'x-relay-grade' in req.headers) {
    gradeTicket(req, res, cfg, entry, edgeIp).catch((err) => {
      entry.error = String((err && err.stack) || err);
      sendError(res, 500, 'internal', 'internal error');
    });
    return;
  }
  if (cfg.mode !== 'transparent' && 'x-relay-mint' in req.headers) {
    mintTickets(req, res, cfg, entry, edgeIp).catch((err) => {
      entry.error = String((err && err.stack) || err);
      sendError(res, 500, 'internal', 'internal error');
    });
    return;
  }

  // 只接受 origin-form(/path?query):absolute-form 会让上游按请求行里的主机
  // 路由,绕开我们固定的 Host——客人自己改地址,那还要门房干什么。
  if (!req.url.startsWith('/')) {
    sendError(res, 400, 'bad_target', 'request target must be an origin-form path');
    return;
  }

  const { upstream } = cfg;
  const isHttps = upstream.protocol === 'https:';
  const headers = filterRequestHeaders(req.headers);
  headers.host = upstream.host; // 非默认端口时含端口——门牌号写谁就是谁

  // agent:false —— 每个请求一条新连接,响应结束即关:一次一换,绝不留恋:
  //  · 钉 IP 天然逐请求生效,不会被连接池复用到别的 IP 上;
  //  · FC 空闲时会冻结实例,池里的 keep-alive 连接解冻后可能已被对端关掉——
  //    冻住的旧情史不可靠,复用它会让本可成功的请求 ECONNRESET;
  //  · 代价是每请求一次握手 —— FC 与 Cloudflare 边缘同地域,只有几毫秒,便宜。
  // 钉 IP 时拨号地址换成该 IP,servername 仍是上游域名:SNI 与证书校验不变——
  // 敲的是隔壁的门,报的还是本家的名。
  const upReq = (isHttps ? https : http).request({
    host: edgeIp || upstream.hostname,
    port: upstream.port || (isHttps ? 443 : 80),
    method: req.method,
    path: req.url,
    headers,
    agent: false,
    servername: isHttps ? upstream.hostname : undefined,
  });
  armConnectTimeout(upReq, cfg.connectTimeoutMs);

  upReq.on('response', (upRes) => {
    const out = filterResponseHeaders(upRes.headers);
    // 回报实际连上的边缘 IP:默认 DNS 时是解析结果,钉 IP 时就是所钉的 IP——
    // 最后敲的是哪家门,得告诉客人。
    const edgeAddr = upRes.socket && upRes.socket.remoteAddress;
    if (edgeAddr) out['x-relay-edge-ip'] = edgeAddr;
    // FC 网关自身按 chunked 判定流式;这是给链路上可能存在的 nginx 系反代的提示——
    // 跟中间商打个招呼:别囤货,即来即走。
    if (/^text\/event-stream/i.test(String(upRes.headers['content-type'] || ''))) {
      out['x-accel-buffering'] = 'no';
    }
    res.writeHead(upRes.statusCode, out);
    upRes.on('data', (chunk) => { bytes += chunk.length; });
    // pipeline:背压 + 任一端出错两端一起拆——一根绳上的蚂蚱。上游中途断开时
    // 客户端连接被直接掐断(而不是 end()),截断的流不会被当成完整响应——
    // 半桌菜不能当全席卖。
    pipeline(upRes, res, (err) => {
      if (err && !entry.error) entry.error = err.code || err.message;
    });
  });

  upReq.on('error', (err) => {
    if (!entry.error) entry.error = err.code || err.message;
    // 响应已开始时交给 pipeline 收尾:上游断开会传导成客户端连接被掐断;
    // 而上游已完整回了响应(如提前回 401 后关连接)时不该再去掐它——
    // 人家把话说完了还送客,就别再追出去砍一刀。
    if (res.headersSent) return;
    if (err.code === 'ETIMEDOUT') sendError(res, 504, 'upstream_timeout', err.message);
    else sendError(res, 502, 'upstream_unreachable', err.code || err.message);
  });

  // 客户端提前断开(含响应中途)→ 拆掉上游,不白占 FC 时长——客人走了还炒什么菜。
  res.on('close', () => {
    if (!res.writableFinished) upReq.destroy();
  });

  // 请求体流式转发。用 pipe 而不是 pipeline:上游出错时 pipeline 会连带销毁 req,
  // 进而掐断客户端连接,就回不了 502/504 了——留条活路好交代。
  req.pipe(upReq);
}

// 同步阶段的意外异常不能冒泡:一个实例同时承载多条流,进程崩了全断——
// 一人摔倒,全桌买单,这个险冒不得。
function handler(req, res) {
  try {
    relay(req, res);
  } catch (err) {
    console.log(JSON.stringify({ fn: 'chatgpt-relay', msg: 'handler error', error: String(err && err.stack || err) }));
    sendError(res, 500, 'internal', 'internal error');
  }
}

// --- WebSocket 搬货隧道(FC HTTP 触发器支持 Upgrade)---------------------------
//
// FC 把 upgrade 请求交给运行时的 HTTP server,'upgrade' 事件给出客户端裸
// socket。实现是握手后字节级隧道:重建客户端的升级请求(滤掉控制/身份头、
// Host 改上游)写进上游连接,然后双向 splice —— 之后的 WS 帧、扩展协商、
// ping/pong 全部透明,本服务不解析任何帧——我就是个传话的,你们聊你们的。
// 101 和非 101 都原样送达，客户端自己判开门还是吃闭门羹。
// 会话时长被函数 timeout 封顶(平台上限 86400s);空闲保活靠 WS 自带
// ping/pong,经隧道透传无需处理。

// upgrade 握手没有 res 对象,拒绝只能把错误写在裸 socket 上再关掉——
// 连门口都没让进,只能在门上贴张字条。
function wsError(socket, status, code, message) {
  if (socket.destroyed) return;
  const body = JSON.stringify({ error: { message: `relay: ${message}`, type: 'relay_error', code } });
  socket.end(
    `HTTP/1.1 ${status} ${http.STATUS_CODES[status] || ''}\r\n`
    + 'content-type: application/json\r\n'
    + `x-relay-error: ${code}\r\n`
    + `content-length: ${Buffer.byteLength(body)}\r\n`
    + 'connection: close\r\n\r\n'
    + body,
  );
}

// 重建发往上游的升级请求头:逐条过 rawHeaders(保序保大小写),丢控制/身份/
// 平台头,Host 改写为上游——换身干净行头再登门。
function wsRequestHead(req, upstream) {
  const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
  const hopHeaders = new Set((req.headers.connection || '').toLowerCase().split(',').map((v) => v.trim()));
  for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i];
    const lower = name.toLowerCase();
    if (WS_DROP_REQUEST_HEADERS.has(lower) || hopHeaders.has(lower)) continue;
    if (DROP_REQUEST_PREFIXES.some((p) => lower.startsWith(p))) continue;
    lines.push(`${name}: ${req.rawHeaders[i + 1]}`);
  }
  lines.push(`Host: ${upstream.host}`, 'Connection: Upgrade', 'Upgrade: websocket');
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function wsRelay(req, socket, head) {
  const started = Date.now();
  const entry = {
    fn: 'chatgpt-relay',
    reqId: first(req.headers['x-fc-request-id']),
    method: req.method,
    path: req.url.split('?')[0],
    ws: true,
  };
  let bytes = 0;
  let finished = false;
  const logOnce = () => {
    if (finished) return;
    finished = true;
    entry.bytes = bytes;
    entry.ms = Date.now() - started;
    console.log(JSON.stringify(entry));
  };

  let cfg;
  try {
    cfg = config();
  } catch (err) {
    entry.error = err.message;
    logOnce();
    wsError(socket, 500, 'relay_misconfigured', err.message);
    return;
  }
  // 业务满血桥接:路径 /k/<relaykey>/backend-api/codex/responses。CPA 账号 base_url
  // 指到 FC 时带不了 X-Relay-Key 头,所以 key 走路径——门口没地儿塞名片,
  // 就把名字写进地址里。命中即由 wsBridge 用住宅出口铸票+注入+双向中继
  // (满血),不进下面的透明中继分支——走 VIP 通道的不去大堂排队。
  {
    const m = req.url.match(/^\/k\/([^/]+)(\/.*)$/);
    if (m && cfg.mode !== 'transparent' && keyMatches(cfg.relayKey, decodeURIComponent(m[1]))) {
      const authorization = first(req.headers['authorization']);
      if (!authorization) {
        logOnce();
        wsError(socket, 400, 'bridge_no_auth', 'bridge needs the account Authorization header');
        return;
      }
      const be = (first(req.headers['x-edge-ip']) || '').trim();
      entry.bridge = true;
      req.url = m[2]; // 先卸下 /k/<key> 门禁前缀，不带它去回源
      wsBridge(req, socket, head, cfg,
        { authorization, accountId: first(req.headers['chatgpt-account-id']) },
        net.isIP(be) && (cfg.allowPrivateEdge || isPublicIP(be)) ? be : '', logOnce);
      return;
    }
  }
  if (!keyMatches(cfg.relayKey, first(req.headers['x-relay-key']))) {
    logOnce();
    wsError(socket, 403, 'bad_relay_key', 'bad or missing X-Relay-Key');
    return;
  }
  const edgeIp = (first(req.headers['x-edge-ip']) || '').trim();
  if (edgeIp) {
    if (!net.isIP(edgeIp) || (!cfg.allowPrivateEdge && !isPublicIP(edgeIp))) {
      logOnce();
      wsError(socket, 400, 'bad_edge_ip', 'X-Edge-IP must be a public IP literal');
      return;
    }
    entry.edge = edgeIp;
  }
  if (!req.url.startsWith('/')) {
    logOnce();
    wsError(socket, 400, 'bad_target', 'request target must be an origin-form path');
    return;
  }

  if (req.method !== 'GET' || (req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    logOnce();
    wsError(socket, 400, 'bad_upgrade', 'only GET websocket upgrades are supported');
    return;
  }

  const { upstream } = cfg;
  const hostname = upstream.hostname.replace(/^\[|\]$/g, '');
  const isHttps = upstream.protocol === 'https:';
  const up = isHttps
    ? tls.connect({
      host: edgeIp || hostname,
      port: Number(upstream.port) || 443,
      servername: net.isIP(hostname) ? undefined : hostname,
      checkServerIdentity: (_host, cert) => tls.checkServerIdentity(hostname, cert),
    })
    : net.connect({
      host: edgeIp || hostname,
      port: Number(upstream.port) || 80,
    });
  up.setNoDelay(true);

  let spliced = false;  // 隧道是否已建立(建了之后只拆连接,不再写 HTTP 错误——生米煮成熟饭)
  let replied = false;  // 错误头只写一次,写第二个就是坏协议——一句话只说一遍
  const replyErr = (status, code, msg) => {
    if (replied || socket.destroyed) return;
    replied = true;
    wsError(socket, status, code, msg);
  };

  // 超时覆盖 TCP/TLS 与完整 WS 响应头——等人等到这步为止;
  // 升级成功后不设空闲超时,你们爱聊多久聊多久。
  const connTimer = setTimeout(() => {
    entry.error = 'ETIMEDOUT';
    up.destroy();
    replyErr(504, 'upstream_timeout', `websocket handshake timeout after ${cfg.connectTimeoutMs}ms`);
    logOnce();
  }, cfg.connectTimeoutMs);
  const disarm = () => clearTimeout(connTimer);

  up.once(isHttps ? 'secureConnect' : 'connect', () => {
    if (socket.destroyed || replied) { up.destroy(); return; }
    entry.edge = edgeIp || up.remoteAddress;
    up.write(wsRequestHead(req, upstream));
    if (head && head.length) up.write(head);
    // splice:write 先于 pipe 排进同一发送队列,顺序不乱——先敬礼,再谈事。
    socket.pipe(up);
  });

  // 完整握手头到达前暂存,防止部分响应与本地 502/504 拼成损坏的 HTTP——
  // 半句话不许往外传,免得两头不是人。
  let responseHead = Buffer.alloc(0);
  const onHandshake = (chunk) => {
    responseHead = Buffer.concat([responseHead, chunk]);
    const end = responseHead.indexOf('\r\n\r\n');
    if ((end < 0 ? responseHead.length : end + 4) > WS_RESPONSE_HEADER_LIMIT) {
      replyErr(502, 'upstream_bad_handshake', 'upstream response headers too large');
      up.destroy();
      return;
    }
    if (end < 0) return;
    const status = /^HTTP\/1\.[01] (\d{3}) /.exec(responseHead.toString('latin1', 0, end));
    if (!status) {
      replyErr(502, 'upstream_bad_handshake', 'invalid upstream response');
      up.destroy();
      return;
    }
    disarm();
    spliced = true;
    entry.status = Number(status[1]);
    up.removeListener('data', onHandshake);
    // 包含握手之后随包的首帧,必须先写再接上 pipe,保持字节序与背压——
    // 头先过,尾巴再跟上,不能乱了辈分。
    bytes += responseHead.length;
    socket.write(responseHead);
    responseHead = null;
    up.on('data', (data) => { bytes += data.length; });
    up.pipe(socket);
  };
  up.on('data', onHandshake);
  up.on('end', () => {
    if (!spliced) replyErr(502, 'upstream_unreachable', 'upstream closed before handshake');
  });

  up.on('error', (err) => {
    disarm();
    if (!entry.error) entry.error = err.code || err.message;
    if (!spliced) replyErr(502, 'upstream_unreachable', err.code || err.message);
    else socket.destroy();
    logOnce();
  });
  // 任一端收摊都拆掉对端:一个要走,另一个也别干坐着——
  // 客户端断开不白占函数时长,上游断开不吊着客户端。
  socket.on('error', () => { up.destroy(); });
  socket.on('close', () => { disarm(); up.destroy(); logOnce(); });
  up.on('close', () => {
    disarm();
    if (!spliced) replyErr(502, 'upstream_unreachable', 'upstream closed before handshake');
    // 正常 EOF 交给 pipe/end 排空缓冲——好聚好散,盘里的菜让客人吃完;
    // 只有异常断流才直接销毁客户端。
    else if (!up.readableEnded) socket.destroy();
    logOnce();
  });
}

// --- 业务桥接搭台(方案 B)-------------------------------------------------
// 客户端(CPA 的 codex WS executor,账号 base_url 指到 FC)用 WS 连过来,FC 在
// 本次连接里演全套:① 用住宅出口、钉一个本连接专属 sid 铸一张满血票
// (state-echo 验收)② 用同一个 sid 开上游 WS(住宅出口,与铸票同 IP——
// 在哪儿出生就在哪儿用)③ 把客户端的 response.create 帧注入该票的
// client_metadata['x-codex-turn-state'] 后转上游 ④ 上游帧原样回传客户端。
// 铸与用同 IP + 帧内带满血票 → 满血(等价于已验证的 mint+grade,
// 只是用客户端真实内容——桥接负责搬戏服，台词仍由客户端自己交)。

// 服务端帧:不掩码(自家人说话不用戴面具),支持 126/127 扩展长度
// (模型完整输出可能较大——话多的得给大信封)。
function wsServerFrame(opcode, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const n = body.length;
  let header;
  if (n < 126) { header = Buffer.alloc(2); header[1] = n; }
  else if (n <= 65535) { header = Buffer.alloc(4); header[1] = 126; header.writeUInt16BE(n, 2); }
  else { header = Buffer.alloc(10); header[1] = 127; header.writeUInt32BE(0, 2); header.writeUInt32BE(n, 6); }
  header[0] = 0x80 | opcode;
  return Buffer.concat([header, body]);
}

// 客户端帧(发给上游):掩码(出门做客得戴面具),支持 126/127
// (长对话的 response.create 可能超 64KiB——简历厚点正常)。
function wsMaskedFrameBig(opcode, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const n = body.length;
  let header;
  if (n < 126) { header = Buffer.alloc(2); header[1] = 0x80 | n; }
  else if (n <= 65535) { header = Buffer.alloc(4); header[1] = 0x80 | 126; header.writeUInt16BE(n, 2); }
  else { header = Buffer.alloc(10); header[1] = 0x80 | 127; header.writeUInt32BE(0, 2); header.writeUInt32BE(n, 6); }
  header[0] = 0x80 | opcode;
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(body);
  for (let i = 0; i < masked.length; i += 1) masked[i] ^= mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

// 把满血票塞进 response.create/response.append 的 client_metadata['x-codex-turn-state']
//(与真实客户端续轮、grade 回放一致——票从正门进,光明正大)。
// 非该类帧或非 JSON 原样返回——不是这条道的,别拦人家。
function bridgeInjectState(text, token) {
  let obj;
  try { obj = JSON.parse(text); } catch { return text; }
  if (!obj || (obj.type !== 'response.create' && obj.type !== 'response.append')) return text;
  const meta = (obj.client_metadata && typeof obj.client_metadata === 'object') ? obj.client_metadata : {};
  meta['x-codex-turn-state'] = token;
  obj.client_metadata = meta;
  return JSON.stringify(obj);
}

// 铸一张满血票(住宅出口,按 cfg.mintPinnedSid 钉出口)。返回 {ticket, cookieHeader,
// edgeIp} 或 null。空手裸打（不带路由 cookie），让边缘当场分座位。
// 逐次换 sid(住宅出口)铸票,直到拿到满血票——抽卡抽到出 SSR 为止;
// 返回中选的 sid,供上游桥接钉同一 IP。池能满血靠的就是轮换出口找到满血节点,
// 桥接同理 —— 固定单一 sid 若碰到坏出口会一路失败,死守一扇破门没有出路。
// isAborted:桥接客户端已断开时别再烧打票次数——客人都走了,菜还炒什么(每发都是账号配额)。
async function bridgeMintTicket(baseCfg, edgeIp, creds, model, isAborted) {
  const attempts = Math.max(1, Math.min(baseCfg.mint?.maxAttempts || 12, 24));
  let last = 'no_attempt';
  for (let i = 0; i < attempts; i += 1) {
    if (isAborted && isAborted()) return { fail: 'client_gone' };
    const sid = safeSid(crypto.randomBytes(8).toString('hex')) || undefined;
    const cfg = { ...baseCfg, mintPinnedSid: sid };
    let attempt;
    try { attempt = await fireMintAttempt(cfg, edgeIp, creds, model, null).done; } catch (err) { last = `exc:${(err && err.code) || 'err'}`; continue; }
    if (!mintStatusOK(attempt) || attempt.reason !== 'ok') { last = `mint:${attempt.status || 0}/${attempt.reason || '?'}`; continue; }
    if (!attempt.ticket || !attempt.pairs || !attempt.pairs.__cflb || !attempt.pairs.__oailb) { last = `nopair:len${attempt.len || 0}`; continue; }
    const cookieHeader = `__cflb=${attempt.pairs.__cflb}; __oailb=${attempt.pairs.__oailb}`;
    if (cfg.mint.verifyState) {
      const verdict = await verifyFullStrength(cfg, edgeIp, creds, attempt.ticket, cookieHeader, model);
      if (!verdict.full) { last = `verify:${verdict.error || 'downgraded'}`; continue; }
    }
    return { ticket: attempt.ticket, cookieHeader, edgeIp: attempt.edgeIp || edgeIp, sid };
  }
  return { fail: last };
}

// 客户端→服务端帧解析:客户端帧必须带掩码(与 readMintWsFrame 的服务端帧相反——
// 来客都得戴面具,这是规矩),解掩码后交回。半帧返回 null 等待续包——话没说完等着。
function readClientWsFrame(buf, maxFrame) {
  if (buf.length < 2) return null;
  const fin = !!(buf[0] & 0x80);
  const opcode = buf[0] & 0x0f;
  if (buf[0] & 0x70) throw new Error('unexpected websocket flags');
  if (![0, 1, 2, 8, 9, 10].includes(opcode)) throw new Error('unsupported websocket opcode');
  if (!(buf[1] & 0x80)) throw new Error('client frame must be masked');
  let length = buf[1] & 0x7f;
  let offset = 2;
  if (opcode >= 8 && (!fin || length > 125)) throw new Error('invalid websocket control frame');
  if (length === 126) {
    if (buf.length < 4) return null;
    length = buf.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buf.length < 10) return null;
    if (buf.readUInt32BE(2) !== 0) throw new Error('websocket frame too large');
    length = buf.readUInt32BE(6);
    offset = 10;
  }
  if (length > maxFrame) throw new Error('websocket frame too large');
  if (buf.length < offset + 4 + length) return null;
  const mask = buf.subarray(offset, offset + 4);
  offset += 4;
  const payload = Buffer.from(buf.subarray(offset, offset + length));
  for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
  return { fin, opcode, payload, consumed: offset + length };
}

// 客户端侧读取器:合并分片、控制帧穿插,pong 以无掩码服务端帧回——
// 人家 ping 你就得 pong,来而不往非礼也。
// wireBytes 同样按消息边界清零(见 mintWsReader)——桥接是长连接,生命周期累计
// 上限会让正常的长会话在总量越线时被 ws_protocol 误杀:记一辈子的账,谁都顶不住。
function wsClientSideReader(socket, onMessage, onStop, limits) {
  const frameMax = limits?.frame ?? MINT_BODY_SCAN_BYTES;
  const msgMax = limits?.msg ?? MINT_BODY_SCAN_BYTES;
  const totalMax = limits?.total ?? MINT_BODY_SCAN_BYTES * 4;
  let pending = Buffer.alloc(0);
  let fragment = null;
  let wireBytes = 0;
  return (chunk) => {
    try {
      wireBytes += chunk.length;
      if (wireBytes > totalMax) throw new Error('websocket scan limit');
      pending = Buffer.concat([pending, chunk]);
      while (pending.length) {
        const frame = readClientWsFrame(pending, frameMax);
        if (!frame) break;
        pending = pending.subarray(frame.consumed);
        if (frame.opcode === 8) { onStop('ws_closed'); return; }
        if (frame.opcode === 9) { socket.write(wsServerFrame(10, frame.payload)); continue; }
        if (frame.opcode === 10) continue;
        if ((frame.opcode === 0) !== (fragment !== null)) throw new Error('invalid websocket continuation');
        fragment = fragment === null ? frame.payload : Buffer.concat([fragment, frame.payload]);
        if (fragment.length > msgMax) throw new Error('websocket message too large');
        if (!frame.fin) continue;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(fragment);
        fragment = null;
        wireBytes = 0;
        if (onMessage(text)) return;
      }
    } catch { onStop('ws_protocol'); }
  };
}

function wsBridge(req, socket, head, baseCfg, creds, edgeIp0, logOnce) {
  socket.on('error', () => socket.destroy());
  socket.setTimeout(0);
  socket.setNoDelay(true);
  const key = first(req.headers['sec-websocket-key']);
  if (req.method !== 'GET' || (req.headers.upgrade || '').toLowerCase() !== 'websocket' || !key) {
    wsError(socket, 400, 'bad_upgrade', 'only GET websocket upgrades are supported');
    if (logOnce) logOnce();
    return;
  }
  const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n'
    + `sec-websocket-accept: ${accept}\r\n\r\n`);

  let up = null;
  let upReady = false;
  let token = null;
  let model = '';
  let setupStarted = false;
  let setupTries = 0;
  let closed = false;
  let producedOutput = false;
  const BRIDGE_SETUP_MAX = 3;
  // setup 墙钟上限:铸票循环本身无总时限(最多 3 轮 × 每轮 24 次铸票 × 每次 ≤60s),
  // 期间对客户端一个帧都不发 —— 厨子炒菜慢也得先吱一声,不然客人当你倒闭了:
  // 客户端读死线或网关空闲超时先触发就只剩断连。
  const BRIDGE_SETUP_MAX_MS = 90_000;
  const clientQueue = [];

  // 建联期与轮次间静默都靠心跳保活:ping 是协议级帧,客户端协议栈自动回 pong,
  // 不进 onMessage——隔一阵喊一声「还在呢」,15s 一拍覆盖 FC 网关与中间盒的空闲窗口。
  const heartbeat = setInterval(() => {
    if (closed || socket.destroyed) return;
    try { socket.write(wsServerFrame(9, Buffer.alloc(0))); } catch { /* best effort */ }
  }, 15_000);
  const setupTimer = setTimeout(() => {
    if (!upReady) shutdown('setup_timeout');
  }, BRIDGE_SETUP_MAX_MS);

  const shutdown = (reason) => {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    clearTimeout(setupTimer);
    // TODO(灰度诊断): 还没产出任何上游输出就关闭时,把原因作为一条 output_text.delta
    // 回给客户端——死也要死个明白,便于 modeltrace 探针看到失败原因(FC 未开日志)。
    // 灰度确认后撤掉这张临时告示。
    if (!producedOutput && reason && typeof reason === 'string') {
      try {
        socket.write(wsServerFrame(1, Buffer.from(JSON.stringify({ type: 'response.output_text.delta', delta: `[bridge-diag] ${reason}` }))));
        socket.write(wsServerFrame(1, Buffer.from(JSON.stringify({ type: 'response.completed', response: { model: `bridge-diag:${reason}` } }))));
      } catch { /* best effort */ }
    }
    try { socket.write(wsServerFrame(0x8, Buffer.alloc(0))); } catch { /* best effort */ }
    socket.destroy();
    if (up) up.destroy();
    if (logOnce) logOnce();
  };

  const sendUpstream = (text) => {
    if (!up || up.destroyed) return;
    up.write(wsMaskedFrameBig(1, Buffer.from(bridgeInjectState(text, token))));
  };

  // connectUpstream 用中选 sid 的 cfg 钉同一住宅 IP——票从哪扇门出来就从哪扇门进。
  // 升级前失败 → onPreFail(整体换 sid 重来);升级后失败 → shutdown
  // (戏已开场,不能再换角)。host 用域名而非 edgeIp:经 SOCKS 隧道时 mint 记录的
  // edgeIp 是代理 IP,拿它当上游 host 会让代理去连自己
  // (ERR_SSL_WRONG_VERSION_NUMBER——自己给自己打电话,接通的是鬼故事)。
  // 同 sid 管 IP 亲和，cookie 管网关；edge 钉定不来抢这两份差事。
  const connectUpstream = (cfg, cookieHeader, onPreFail) => {
    const { upstream } = cfg;
    const hostname = upstream.hostname.replace(/^\[|\]$/g, '');
    const secure = upstream.protocol === 'https:';
    const headers = {
      ...mintHeaders(creds, crypto.randomUUID(), cookieHeader),
      host: upstream.host, connection: 'Upgrade', upgrade: 'websocket',
      'sec-websocket-key': crypto.randomBytes(16).toString('base64'),
      'sec-websocket-version': '13', 'openai-beta': 'responses_websockets=2026-02-06',
    };
    delete headers.accept;
    delete headers['content-type'];
    const request = (secure ? https : http).request({
      host: hostname, port: upstream.port || (secure ? 443 : 80),
      method: 'GET', path: MINT_PATH, headers, agent: mintUpstreamAgent(secure, cfg),
      servername: secure && !net.isIP(hostname) ? hostname : undefined,
      checkServerIdentity: (_host, cert) => tls.checkServerIdentity(hostname, cert),
    });
    armConnectTimeout(request, cfg.connectTimeoutMs);
    let settled = false;
    request.on('error', (err) => { if (settled) return; settled = true; onPreFail(`upstream_transport:${(err && err.code) || 'err'}`); });
    request.on('response', (res) => { if (settled) return; settled = true; onPreFail(`upstream_rejected:${res.statusCode}`); });
    request.on('upgrade', (_res, connection, uphead) => {
      settled = true;
      if (closed) { connection.destroy(); return; }
      up = connection;
      up.setNoDelay(true);
      const reader = mintWsReader(up, (text) => {
        producedOutput = true;
        if (!closed && !socket.destroyed) socket.write(wsServerFrame(1, Buffer.from(text)));
        return false;
      }, (reason) => shutdown(`upstream_${reason}`), { frame: MINT_GRADE_FRAME_MAX, msg: MINT_GRADE_FRAME_MAX, total: MINT_GRADE_TOTAL_MAX });
      up.on('data', reader);
      up.on('close', () => shutdown('upstream_closed'));
      up.on('error', (err) => shutdown(`upstream_error:${(err && err.code) || 'err'}`));
      upReady = true;
      clearTimeout(setupTimer);
      for (const t of clientQueue) sendUpstream(t);
      clientQueue.length = 0;
      if (uphead && uphead.length) reader(uphead);
    });
    request.end();
  };

  // trySetup:铸票(逐次换 sid 找满血)→ 用中选 sid 开上游;上游升级前失败则整体换
  // sid 重来(铸+连是一个单元,票和门必须是同一扇,保证票与上游同 IP)。
  const trySetup = async () => {
    if (closed) return;
    setupTries += 1;
    if (setupTries > BRIDGE_SETUP_MAX) { shutdown('setup_exhausted'); return; }
    let minted = null;
    try { minted = await bridgeMintTicket(baseCfg, edgeIp0, creds, model, () => closed); } catch (err) { shutdown(`mint_exception:${(err && err.message) || 'err'}`); return; }
    if (closed) return;
    if (!minted || !minted.ticket) { shutdown(`mint_failed:${(minted && minted.fail) || '?'}`); return; }
    token = minted.ticket;
    const cfg = { ...baseCfg, mintPinnedSid: minted.sid };
    connectUpstream(cfg, minted.cookieHeader, () => { if (!closed) trySetup(); });
  };

  const startSetup = (firstText) => {
    setupStarted = true;
    try { const o = JSON.parse(firstText); if (o && typeof o.model === 'string') model = o.model; } catch { /* use default */ }
    if (!model) model = (baseCfg.mint && baseCfg.mint.models && baseCfg.mint.models[0]) || 'gpt-6-astra';
    trySetup();
  };

  const clientReader = wsClientSideReader(socket, (text) => {
    if (closed) return true;
    if (!setupStarted) { clientQueue.push(text); startSetup(text); return false; }
    if (upReady) sendUpstream(text); else clientQueue.push(text);
    return false;
  }, (reason) => shutdown(`client_${reason}`), { frame: MINT_GRADE_FRAME_MAX, msg: MINT_GRADE_FRAME_MAX, total: MINT_GRADE_TOTAL_MAX });
  socket.on('data', clientReader);
  socket.on('close', () => shutdown('client_closed'));
  if (head && head.length) clientReader(head);
}

function wsHandler(req, socket, head) {
  // 鉴权失败也可能遇到客户端复位,必须在任何写操作之前接住 socket error——
  // 门还没开完人已经摔倒了,先扶住再说。
  socket.on('error', () => socket.destroy());
  socket.setTimeout(0);
  socket.setNoDelay(true);
  try {
    wsRelay(req, socket, head);
  } catch (err) {
    console.log(JSON.stringify({ fn: 'chatgpt-relay', msg: 'ws handler error', error: String((err && err.stack) || err) }));
    socket.destroy();
  }
}

// FC 对自定义运行时 HTTP Server 的要求(「自定义运行时 基本原理」):监听 0.0.0.0,
// 连接保持 keep-alive,服务端超时不小于函数最大运行时长(24h)。三项超时全部关掉——
// 平台的规矩是长工,自己掐表会出人命:
//  · keepAliveTimeout:Node 默认 5s 关闭空闲连接,与平台网关的连接复用竞态 ——
//    网关复用到一条刚被关掉的连接,这次调用直接失败;
//  · requestTimeout:Node 18+ 默认须在 300s 内收完请求;
//  · timeout:socket 空闲超时,Node 13+ 默认已是 0,显式写明。
function createServer() {
  const server = http.createServer(handler);
  // HTTP 触发器放行 Upgrade 时(FC 支持 WebSocket 触发),同一端口走隧道;
  // 平台不放行时该事件根本不触发,不影响 HTTP 中继——门不开就不开,
  // 大堂照常营业。
  server.on('upgrade', wsHandler);
  server.keepAliveTimeout = 0;
  server.requestTimeout = 0;
  server.timeout = 0;
  return server;
}

// FC 自定义运行时/本地直跑:`node index.js`,监听 $FC_SERVER_PORT(默认 9000)——
// 开门营业,童叟无欺。
if (require.main === module) {
  const server = createServer();
  server.listen(Number(process.env.FC_SERVER_PORT || 9000), '0.0.0.0', () => {
    console.log(JSON.stringify({ fn: 'chatgpt-relay', msg: `listening on 0.0.0.0:${server.address().port}` }));
  });
}

module.exports = {
  handler,
  createServer,
  // 内部件只向测试开后厨门，业务客人别从这里点菜
  _internals: {
    isPublicIP, keyMatches, filterRequestHeaders, filterResponseHeaders,
    mintGatewayLabel, mintGatewayTarget, createdModelFromSse, createdModelFromJson, mintPairs,
    fernetIssuedAt, parseModels, mintAttemptTrace, mintFingerprint, fireMintAttempt, mintWsClientFrame, readMintWsFrame,
    fireWsGradeAttempt, mintGradePayload,
  },
};
