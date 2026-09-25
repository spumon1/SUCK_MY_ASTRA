'use strict';
// relay/index.js 的测试:本地假上游 + 真 relay(createServer,与生产同一份 server
// 配置)。覆盖鉴权、头部剥离、Set-Cookie/压缩透传、SSE 流式与断流语义、边缘 IP
// 钉选、默认 DNS 回源、超时。TLS 用例以子进程跑真实入口 `node index.js`(即 FC
// 启动命令),证书校验保持开启 —— 测试证书经 NODE_EXTRA_CA_CERTS 信任。
// 全部只连本机:上游域名一律钉到 127.0.0.1 或用 localhost。

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const { createServer, _internals } = require('./index.js');
const { isPublicIP, filterRequestHeaders } = _internals;

const RELAY_KEY = 'test-key-123';

// 仅测试用的自签证书(CN=nonexistent.invalid,SAN 含 chatgpt.com)。
const TEST_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCKCWuL4sjPFVLK
9cEa8hLOsnsJZ4jvg0zdn/TfvP7uG4c5riYQ2R4NQxucZnqDf2/IysjU6BubW6Q+
hjkcdIBHDfdA+h+wCJe2anw+9Vg0QjTGj8O2WMUvCjHUcouF5aOOIHmpUj4W8u2r
b/W8qPoZEJ0H99GA72qz5dnqQkjkDi0umOzKQraFkCLVhwGmOlsteRYEHvVpNhjK
GK8P/DkyNAfrdPSSYbOvx4vyi7oyLesyTRRHaoxyy+D1zIm+orRwpyCmUIVTcJI8
SZjRgtt++QSmovdPshQThPzpqQefekDbnjdM779vDWJ4PBjxE4Eeao+7KrnJIU5q
SU1HMlAPAgMBAAECggEAKw16GiSvHguYCY5x3q4e2JIJVusQZietGzivHvNrDafP
WtmqrLmTKm7CV1sNHiNqoZVB40nLhn6kMQ4bFPlvIvpDomQA6x4a932p59cM3ivC
GyYu1BpG0f+bgBgD1UzE4OjXGUz56Z12LHDck62eZ5/rYldUZCMIRDjN6UcoRdyC
x+MnBPULz4dIekxAW8g3kCiHuGRZu3Hj1ZG4qEVB0xz8ewrX5sFKxrJtrtPufyGi
7dAyoGtABqZL4Sko81dbdYVlwLBSMdmEyDTfMzgBMrVjGzATwpoOu7nlRuAYN8P5
vvu52gv+rxjjWGehDN/n2tA/9aiaEnIlol7AnNBGrQKBgQDAFjxrEVrevVqoE4qA
lxYDamQly+K/BG8SUnpKmj72UTUqGI5Y4sb4ru+Lxh7vnAF2a5Pdmjbyig2O1xkc
5hpM7A1+c04oqqeczGJojntHppcWtHeii28pEmzTgUY8xHRkECrJNw5xvtFNmjEH
yUyNVNJFoU9UrfAQYu+fqxz0GwKBgQC390Eshn0j1x++Z+20c5wbZBKHayOFAQvK
ukC3FPXAENJJHJUm2MzaDQIm+FxRaiSwv7IjYBkgNpO4MTxzWInSdP2V39kQpE4Q
VhBWemiqctxUkwCONnPiG8tVEEYZMIxFhbETc3TMLMrzl+CBFW4IwAs9LvjS5gyz
uwK/iyCLHQKBgHjSA7K8udF8fPdXQzjaz4fadZ+ofLj1iv+VTUJ7frrkHXKa+35B
NjHZpubd+TtxfyIDTICIraMk3p5IAY3B1i0oFNzCnhjKLp9bl1J4vGY3DLXFUbK1
zXeiFT18BLfYQfVmjeL+dGFrSq9rGwfwv+vtvEz7x7BVr7g+4sYllRKdAoGAbEJ2
OSSf6gKD7MIuUZ4jRL88ZDK5gWDfNpsq0FLmV/POPDY009qLmtpC5PoNIeAr3VPC
Gi1IO/vCLIfVAjAdUxuDy7oifDektNpg3PNGOuBDJwYnMol64pnmq5VbGyHFunf1
f/PWzPyjJny/IlehHEcflg7ZYQr+eJpaAKx4J0UCgYBgKKAwU9aftn6eqXM8n2dG
JvlClqqbEIM77vJctDeNBZFWbxSpmQiGufw/Da3W2vYxn1yrj81ZIkIyvoarCKiG
N8WATuKiGEgySLVMkvEAAhGE1mkEUGZKP9w5WHm8Ogn2E8shk8X+BOAcZDqJTsCw
QNLjkk/aD94r+kYJoRv0EA==
-----END PRIVATE KEY-----`;
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUeGIjvsoVvYbkgZEaAyagl0OASr0wDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTbm9uZXhpc3RlbnQuaW52YWxpZDAeFw0yNjA5MjMwNjAz
MTVaFw0zNjA5MjAwNjAzMTVaMB4xHDAaBgNVBAMME25vbmV4aXN0ZW50LmludmFs
aWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCKCWuL4sjPFVLK9cEa
8hLOsnsJZ4jvg0zdn/TfvP7uG4c5riYQ2R4NQxucZnqDf2/IysjU6BubW6Q+hjkc
dIBHDfdA+h+wCJe2anw+9Vg0QjTGj8O2WMUvCjHUcouF5aOOIHmpUj4W8u2rb/W8
qPoZEJ0H99GA72qz5dnqQkjkDi0umOzKQraFkCLVhwGmOlsteRYEHvVpNhjKGK8P
/DkyNAfrdPSSYbOvx4vyi7oyLesyTRRHaoxyy+D1zIm+orRwpyCmUIVTcJI8SZjR
gtt++QSmovdPshQThPzpqQefekDbnjdM779vDWJ4PBjxE4Eeao+7KrnJIU5qSU1H
MlAPAgMBAAGjgYAwfjAdBgNVHQ4EFgQUyTUC+sw7jC+GKN2qP2yrS/XC/TIwHwYD
VR0jBBgwFoAUyTUC+sw7jC+GKN2qP2yrS/XC/TIwDwYDVR0TAQH/BAUwAwEB/zAr
BgNVHREEJDAighNub25leGlzdGVudC5pbnZhbGlkggtjaGF0Z3B0LmNvbTANBgkq
hkiG9w0BAQsFAAOCAQEAOA+p+ulnT86yQMDXz+udbaNMB+yIG4MAhcLcFKNnTquG
fTBmrhSxv/cxtdQT+5bO4iQGYXFoLSdKlBvp0IZllZKctJVEPpLjutIhGSkduIiD
6U7SF4ZrH8UwPCc2S/udPGtRihHd50dtrZ2ANoV1zA45So8KpoEnZYT0Wx+QVN7m
oMSVjQvO4ZzKHlk3KpiThFVkxXy1aDGONDja7sT1V2JqE6brIGzCTOWJHMRMl7NE
XmA9qZOk8vH1xEkdVTfC9X+JY15Odbssy06l6QRKiTHzqx6hdGexd9bfjPBd8evJ
ouGqW6LyLBOMgJJPO64yPSYLoc0iPEAqGvFiUfk/dg==
-----END CERTIFICATE-----`;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function listen(server) {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}
function closeServer(server) {
  // relay 不设 keep-alive 超时(FC 要求),空闲连接会一直挂着;直接掐掉所有连接收尾。
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  return new Promise((resolve) => server.close(resolve));
}

// 起一个服务并登记收尾,返回端口。
async function serve(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  const port = await listen(server);
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    return closeServer(server);
  });
  return port;
}
function startRelay(t) {
  return serve(t, createServer());
}

// 以子进程跑真实入口(与 FC 启动命令一致),返回其监听端口。测试证书经
// NODE_EXTRA_CA_CERTS 信任 —— 中继本身没有、也不该有「跳过证书校验」的开关。
function spawnRelay(t, env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-test-'));
  const caFile = path.join(dir, 'ca.pem');
  fs.writeFileSync(caFile, TEST_CERT);
  const child = spawn(process.execPath, [path.join(__dirname, 'index.js')], {
    env: {
      ...process.env,
      FC_SERVER_PORT: '0',
      RELAY_KEY,
      ALLOW_PRIVATE_EDGE_IPS: '1',
      NODE_EXTRA_CA_CERTS: caFile,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  t.after(() => {
    child.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
      const m = /listening on 0\.0\.0\.0:(\d+)/.exec(out);
      if (m) resolve(Number(m[1]));
    });
    child.once('exit', (code) => reject(new Error(`relay exited before listening (code ${code})`)));
  });
}

// 保存/恢复环境变量
function withEnv(t, vars) {
  const saved = {};
  for (const k of Object.keys(vars)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  t.after(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

// 简单客户端:返回 {status, headers, body}
function call(port, { method = 'GET', path: reqPath = '/', headers = {}, body, key = RELAY_KEY } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    if (key !== null) h['x-relay-key'] = key;
    const req = http.request(
      { host: '127.0.0.1', port, method, path: reqPath, headers: h, agent: false },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// 假上游:回显 method/path/收到的头/请求体
function echoUpstream(extra) {
  return http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (extra) return extra(req, res, Buffer.concat(chunks));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        method: req.method,
        path: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      }));
    });
  });
}

// 假 SSE 上游:先写一块,之后的行为由 then(res) 决定。
function sseUpstream(then) {
  return http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('data: one\n\n');
    then(res);
  });
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

test('RELAY_KEY 未配置时 fail-closed,带 key 也 403', async (t) => {
  withEnv(t, { RELAY_KEY: undefined, RELAY_UPSTREAM: 'http://127.0.0.1:1' });
  const port = await startRelay(t);

  const r = await call(port, {});
  assert.equal(r.status, 403);
  assert.equal(r.headers['x-relay-error'], 'bad_relay_key');
});

test('key 错误 403;key 正确才回源', async (t) => {
  const uport = await serve(t, echoUpstream());
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const bad = await call(port, { key: 'wrong' });
  assert.equal(bad.status, 403);

  const ok = await call(port, { path: '/ping' });
  assert.equal(ok.status, 200);
  assert.equal(JSON.parse(ok.body).path, '/ping');
});

// ---------------------------------------------------------------------------
// 透传与头部剥离
// ---------------------------------------------------------------------------

test('路径/query/方法/请求体原样透传,Host 改写为上游', async (t) => {
  const uport = await serve(t, echoUpstream());
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, {
    method: 'POST',
    path: '/backend-api/codex/responses?foo=bar&baz=%20',
    headers: { 'content-type': 'application/json', authorization: 'Bearer at' },
    body: '{"a":1}',
  });
  assert.equal(r.status, 200);
  const echo = JSON.parse(r.body);
  assert.equal(echo.method, 'POST');
  assert.equal(echo.path, '/backend-api/codex/responses?foo=bar&baz=%20');
  assert.equal(echo.body, '{"a":1}');
  assert.equal(echo.headers.host, `127.0.0.1:${uport}`);
  assert.equal(echo.headers.authorization, 'Bearer at');
});

test('RELAY_MODE=transparent 时忽略打票头并继续透明透传', async (t) => {
  const uport = await serve(t, echoUpstream());
  const port = await startRelay(t);
  withEnv(t, {
    RELAY_KEY,
    RELAY_MODE: 'transparent',
    RELAY_UPSTREAM: `http://127.0.0.1:${uport}`,
  });

  const r = await call(port, {
    method: 'POST',
    path: '/backend-api/codex/responses',
    headers: {
      'x-relay-mint': 'unified-88',
      'x-mint-model': 'gpt-6-astra',
      authorization: 'Bearer at-transparent',
      'content-type': 'application/json',
    },
    body: '{"input":"ping"}',
  });
  assert.equal(r.status, 200);
  const echo = JSON.parse(r.body);
  assert.equal(echo.path, '/backend-api/codex/responses');
  assert.equal(echo.body, '{"input":"ping"}');
  assert.equal(echo.headers.authorization, 'Bearer at-transparent');
  assert.equal(echo.headers['x-relay-mint'], undefined);
  assert.equal(echo.headers['x-mint-model'], undefined);
});

test('RELAY_MODE 非法时 fail-closed 返回 relay_misconfigured', async (t) => {
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_MODE: 'unknown', RELAY_UPSTREAM: 'http://127.0.0.1:1' });

  const r = await call(port, {});
  assert.equal(r.status, 500);
  assert.equal(r.headers['x-relay-error'], 'relay_misconfigured');
});

test('逐跳头/控制头/FC 注入头不传给上游', async (t) => {
  const uport = await serve(t, echoUpstream());
  const port = await startRelay(t);
  // x-edge-ip 是真实生效的控制头:钉到本机上游,顺带验证它本身不外发。
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, ALLOW_PRIVATE_EDGE_IPS: '1' });

  const r = await call(port, {
    headers: {
      'x-edge-ip': '127.0.0.1',
      'x-forwarded-for': '9.9.9.9',
      'x-real-ip': '9.9.9.9',
      'x-fc-request-id': 'fc-internal',
      'x-fc-security-token': 'sts-token',
      'x-mint-model': 'gpt-5.5',
      'x-mint-gateway': 'unified-1',
      forwarded: 'for=9.9.9.9',
      via: '1.1 fc',
      'x-custom-keep': 'yes',
    },
  });
  assert.equal(r.status, 200);
  const echo = JSON.parse(r.body);
  for (const gone of [
    'x-edge-ip', 'x-relay-key', 'x-forwarded-for', 'x-real-ip',
    'x-fc-request-id', 'x-fc-security-token', 'x-mint-model', 'x-mint-gateway',
    'forwarded', 'via',
  ]) {
    assert.equal(echo.headers[gone], undefined, `${gone} 不应到达上游`);
  }
  assert.equal(echo.headers['x-custom-keep'], 'yes');
});

test('多个 Set-Cookie 逐条透传(不被折叠),逐跳响应头剥离', async (t) => {
  const uport = await serve(t, echoUpstream((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/plain',
      'set-cookie': [
        '__cflb=aaa; Path=/; Expires=Wed, 23 Sep 2026 07:00:00 GMT',
        '__oailb=bbb; Path=/; Max-Age=3600',
      ],
      'x-upstream-mark': 'kept',
    });
    res.end('ok');
  }));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, {});
  assert.equal(r.status, 200);
  const cookies = r.headers['set-cookie'];
  assert.ok(Array.isArray(cookies) && cookies.length === 2, 'set-cookie 应是两条');
  assert.ok(cookies[0].startsWith('__cflb='));
  assert.ok(cookies[1].startsWith('__oailb='));
  assert.equal(r.headers['x-upstream-mark'], 'kept');
  assert.equal(r.body.toString(), 'ok');
});

test('302 不跟随,Location 原样透传', async (t) => {
  const uport = await serve(t, echoUpstream((req, res) => {
    res.writeHead(302, { location: 'https://chatgpt.com/elsewhere' });
    res.end();
  }));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, {});
  assert.equal(r.status, 302);
  assert.equal(r.headers.location, 'https://chatgpt.com/elsewhere');
});

test('压缩响应原样透传:不解压,Content-Encoding 与字节都不变', async (t) => {
  const gz = zlib.gzipSync(JSON.stringify({ ok: true }));
  let acceptEncoding;
  const uport = await serve(t, echoUpstream((req, res) => {
    acceptEncoding = req.headers['accept-encoding'];
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-encoding': 'gzip',
      'content-length': gz.length,
    });
    res.end(gz);
  }));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, { headers: { 'accept-encoding': 'gzip, br' } });
  assert.equal(acceptEncoding, 'gzip, br');
  assert.equal(r.headers['content-encoding'], 'gzip');
  assert.deepEqual(r.body, gz);
});

// ---------------------------------------------------------------------------
// SSE 流式与断流语义
// ---------------------------------------------------------------------------

test('SSE 逐块回传且按 chunked 转发(FC 据此判定流式)', async (t) => {
  let secondWrittenAt = 0;
  const uport = await serve(t, sseUpstream((res) => {
    setTimeout(() => {
      secondWrittenAt = Date.now();
      res.write('data: two\n\n');
      res.end();
    }, 300);
  }));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const started = Date.now();
  const firstChunkAt = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/', headers: { 'x-relay-key': RELAY_KEY }, agent: false },
      (res) => {
        assert.equal(res.statusCode, 200);
        assert.match(String(res.headers['content-type']), /text\/event-stream/);
        assert.equal(res.headers['transfer-encoding'], 'chunked');
        assert.equal(res.headers['content-length'], undefined);
        assert.equal(res.headers['x-accel-buffering'], 'no');
        res.once('data', (chunk) => {
          assert.match(chunk.toString(), /data: one/);
          const firstAt = Date.now(); // 首块到达时刻
          // 等响应完整结束再 resolve —— 此刻上游的 secondWrittenAt 才已赋值。
          res.on('end', () => resolve(firstAt));
        });
        res.resume();
      });
    req.on('error', reject);
    req.end();
  });

  assert.ok(firstChunkAt - started < 250,
    `首块 ${firstChunkAt - started}ms 到达,疑似被整包缓冲`);
  assert.ok(firstChunkAt < secondWrittenAt,
    '首块应在上游写第二块之前到达(真流式)');
});

test('上游中途断流:客户端连接被掐断,截断的流不会以正常结束收尾', async (t) => {
  const uport = await serve(t, sseUpstream((res) => {
    setTimeout(() => res.socket.destroy(), 50);
  }));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const complete = await new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/', headers: { 'x-relay-key': RELAY_KEY }, agent: false },
      (res) => {
        res.resume();
        res.once('close', () => resolve(res.complete));
      });
    req.on('error', () => resolve(false));
    req.end();
  });
  assert.equal(complete, false, '截断的流不应以完整响应呈现给客户端');
});

test('客户端中途断开:上游连接随之拆除,不白占函数时长', { timeout: 5000 }, async (t) => {
  let upstreamGone;
  const gone = new Promise((resolve) => { upstreamGone = resolve; });
  // 写完首块后既不再写也不结束,只有中继主动拆连接才会触发 close。
  const uport = await serve(t, sseUpstream((res) => res.once('close', upstreamGone)));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const req = http.request(
    { host: '127.0.0.1', port, path: '/', headers: { 'x-relay-key': RELAY_KEY }, agent: false },
    (res) => res.once('data', () => req.destroy()));
  req.on('error', () => {}); // destroy 之后的 socket hang up 属预期
  req.end();
  await gone;
});

// ---------------------------------------------------------------------------
// 边缘 IP 与默认 DNS
// ---------------------------------------------------------------------------

test('x-edge-ip 非 IP 字面量 → 400;私网 IP 默认拒绝', async (t) => {
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: 'http://127.0.0.1:1' });

  for (const bad of ['not-an-ip', 'example.com', '1.2.3.4,5.6.7.8']) {
    const r = await call(port, { headers: { 'x-edge-ip': bad } });
    assert.equal(r.status, 400, `${bad} 应 400`);
    assert.equal(r.headers['x-relay-error'], 'bad_edge_ip');
  }
  for (const priv of ['10.1.2.3', '192.168.1.1', '172.16.0.1', '127.0.0.1',
    '169.254.1.1', '100.64.0.1', '100.100.100.200', '::1', 'fd00::1', 'fe80::1',
    '::ffff:127.0.0.1']) {
    const r = await call(port, { headers: { 'x-edge-ip': priv } });
    assert.equal(r.status, 400, `${priv} 应被私网检查拦下`);
  }
});

test('钉 IP:拨号地址换成该 IP,Host 仍取上游 URL,X-Relay-Edge-IP 回报所钉 IP', async (t) => {
  // 上游域名故意不可解析 —— 只有拨号地址真的换成 127.0.0.1 才能通。
  const uport = await serve(t, echoUpstream());
  const port = await startRelay(t);
  withEnv(t, {
    RELAY_KEY,
    RELAY_UPSTREAM: `http://nonexistent.invalid:${uport}`,
    ALLOW_PRIVATE_EDGE_IPS: '1',
  });

  const r = await call(port, {
    path: '/pinned',
    headers: { 'x-edge-ip': '127.0.0.1' },
  });
  assert.equal(r.status, 200);
  const echo = JSON.parse(r.body);
  assert.equal(echo.path, '/pinned');
  assert.equal(echo.headers.host, `nonexistent.invalid:${uport}`);
  assert.equal(r.headers['x-relay-edge-ip'], '127.0.0.1');
});

test('不钉 IP 时按 DNS 解析上游,X-Relay-Edge-IP 回报实际连上的地址', async (t) => {
  const uport = await serve(t, echoUpstream());
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://localhost:${uport}` });

  const r = await call(port, { path: '/dns' });
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).headers.host, `localhost:${uport}`);
  assert.equal(r.headers['x-relay-edge-ip'], '127.0.0.1');
});

test('不钉 IP 时域名不可解析 → 502', async (t) => {
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: 'http://nonexistent.invalid:443' });

  const r = await call(port, {});
  assert.equal(r.status, 502);
  assert.equal(r.headers['x-relay-error'], 'upstream_unreachable');
});

// ---------------------------------------------------------------------------
// TLS:子进程跑真实入口,证书校验开启
// ---------------------------------------------------------------------------

test('钉 IP 走 TLS:SNI 与证书校验都按上游域名,不变成 IP', async (t) => {
  let sniSeen = null;
  let hostSeen = null;
  const uport = await serve(t, https.createServer(
    {
      key: TEST_KEY,
      cert: TEST_CERT,
      SNICallback: (servername, cb) => {
        sniSeen = servername;
        cb(null, null); // null → 用默认证书
      },
    },
    (req, res) => {
      hostSeen = req.headers.host;
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('tls-ok');
    }));
  const port = await spawnRelay(t, { RELAY_UPSTREAM: `https://chatgpt.com:${uport}` });

  const r = await call(port, { path: '/tls', headers: { 'x-edge-ip': '127.0.0.1' } });
  assert.equal(r.status, 200);
  assert.equal(r.body.toString(), 'tls-ok');
  assert.equal(sniSeen, 'chatgpt.com', 'SNI 应为上游域名而非边缘 IP');
  assert.equal(hostSeen, `chatgpt.com:${uport}`);
  assert.equal(r.headers['x-relay-edge-ip'], '127.0.0.1');
});

test('证书与上游域名不符 → 502:钉 IP 不绕过证书校验', async (t) => {
  let reached = false;
  const uport = await serve(t, https.createServer({ key: TEST_KEY, cert: TEST_CERT }, (req, res) => {
    reached = true;
    res.end('should-not-reach');
  }));
  // 证书 SAN 只有 nonexistent.invalid 与 chatgpt.com。
  const port = await spawnRelay(t, { RELAY_UPSTREAM: `https://other.invalid:${uport}` });

  const r = await call(port, { headers: { 'x-edge-ip': '127.0.0.1' } });
  assert.equal(r.status, 502);
  assert.equal(r.headers['x-relay-error'], 'upstream_unreachable');
  assert.match(JSON.parse(r.body).error.message, /ERR_TLS_CERT_ALTNAME_INVALID/);
  assert.equal(reached, false, '校验失败的连接不应发出请求');
});

// ---------------------------------------------------------------------------
// 超时与配置
// ---------------------------------------------------------------------------

test('TLS 握手卡住 → 504 upstream_timeout,按建连超时放弃', async (t) => {
  // 只收下 TCP 连接、从不回 ServerHello:卡在握手阶段。
  const sockets = new Set();
  const blackhole = net.createServer((s) => {
    sockets.add(s);
    s.on('error', () => {});
  });
  const bport = await listen(blackhole);
  t.after(() => {
    for (const s of sockets) s.destroy();
    return new Promise((resolve) => blackhole.close(resolve));
  });
  const port = await startRelay(t);
  withEnv(t, {
    RELAY_KEY,
    RELAY_UPSTREAM: `https://chatgpt.com:${bport}`,
    RELAY_CONNECT_TIMEOUT_MS: '200',
    ALLOW_PRIVATE_EDGE_IPS: '1',
  });

  const started = Date.now();
  const r = await call(port, { headers: { 'x-edge-ip': '127.0.0.1' } });
  assert.equal(r.status, 504);
  assert.equal(r.headers['x-relay-error'], 'upstream_timeout');
  assert.ok(Date.now() - started < 2000, '应在建连超时处放弃,而不是一直等');
});

test('RELAY_UPSTREAM 带路径 → 500 relay_misconfigured(不静默丢弃路径)', async (t) => {
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: 'https://chatgpt.com/backend-api/codex' });

  const r = await call(port, {});
  assert.equal(r.status, 500);
  assert.equal(r.headers['x-relay-error'], 'relay_misconfigured');
});

test('createServer 满足 FC 对 HTTP Server 的要求:keep-alive 与请求均不超时', () => {
  const server = createServer();
  assert.equal(server.keepAliveTimeout, 0);
  assert.equal(server.requestTimeout, 0);
  assert.equal(server.timeout, 0);
});

// ---------------------------------------------------------------------------
// WebSocket 隧道(upgrade 事件 → 握手后字节级 splice)
// ---------------------------------------------------------------------------

// 假 WS 上游(裸 TCP):读到 \r\n\r\n 收头后按描述回响应,之后按需 echo。
// hits[i] = {head: 请求头原文, tail: 头后随包字节, socket}
function wsUpstream(script) {
  const hits = [];
  const server = net.createServer((conn) => {
    let buf = Buffer.alloc(0);
    let headDone = false;
    conn.on('data', (chunk) => {
      if (headDone) return;
      buf = Buffer.concat([buf, chunk]);
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return;
      headDone = true;
      const d = (typeof script === 'function' ? script(hits.length) : script[Math.min(hits.length, script.length - 1)]) || {};
      hits.push({ head: buf.subarray(0, i).toString(), tail: buf.subarray(i + 4), socket: conn });
      conn.write(d.response || 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
      if (d.close) return conn.destroy();
      if (d.echo !== false) conn.on('data', (c) => conn.write(c));
    });
  });
  return { server, hits };
}

// 裸 TCP 客户端发 WS 升级请求;resolve({head, socket}) 在拿到完整响应头时。
function wsHandshake(port, { path = '/ws', headers = {}, tail = '' } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1');
    let buf = Buffer.alloc(0);
    sock.on('connect', () => {
      const lines = [
        `GET ${path} HTTP/1.1`,
        'Host: relay.local',
        `Connection: ${headers.Connection || 'Upgrade'}`,
        `Upgrade: ${headers.Upgrade || 'websocket'}`,
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Key: a2V5',
      ];
      for (const [k, v] of Object.entries(headers)) {
        if (k !== 'Connection' && k !== 'Upgrade') lines.push(`${k}: ${v}`);
      }
      sock.write(`${lines.join('\r\n')}\r\n\r\n${tail}`);
    });
    const onHead = (c) => {
      buf = Buffer.concat([buf, c]);
      if (!buf.includes('\r\n\r\n')) return;
      clearTimeout(timer);
      sock.removeListener('data', onHead);
      resolve({ head: buf.toString(), socket: sock });
    };
    sock.on('data', onHead);
    sock.on('error', reject);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('wsHandshake timeout'));
    }, 3000);
    sock.once('close', () => {
      clearTimeout(timer);
      if (!buf.includes('\r\n\r\n')) reject(new Error('closed before handshake'));
    });
    timer.unref();
  });
}

test('WS 隧道:101 原样回传,帧双向透明;控制/身份/平台头不外发,Host 改上游', async (t) => {
  const { server, hits } = wsUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, ALLOW_PRIVATE_EDGE_IPS: '1' });

  const { head, socket } = await wsHandshake(port, {
    path: '/backend-api/codex/responses',
    headers: {
      'X-Relay-Key': RELAY_KEY,
      'X-Edge-IP': '127.0.0.1',
      'X-Mint-Model': 'should-not-leak',
      'X-FC-Security-Token': 'sts',
      'X-Forwarded-For': '9.9.9.9',
      'Sec-WebSocket-Protocol': 'chat',
      'X-Custom': 'kept',
    },
    tail: 'EXTRA',
  });
  assert.match(head, /^HTTP\/1\.1 101/, '101 响应头应原样回传');

  // 隧道已建立:帧字节双向透明。
  const echo = await new Promise((resolve, reject) => {
    socket.once('data', (c) => resolve(c.toString()));
    socket.on('error', reject);
    socket.write('PING-BYTES');
  });
  assert.equal(echo, 'PING-BYTES');
  socket.destroy();

  const up = hits[0];
  assert.match(up.head, /^GET \/backend-api\/codex\/responses HTTP\/1\.1/);
  assert.match(up.head, /upgrade: websocket/i);
  assert.match(up.head, /connection: upgrade/i);
  assert.match(up.head, /sec-websocket-key: a2V5/i);
  assert.match(up.head, /sec-websocket-protocol: chat/i, 'WS 握手字段必须原样保留');
  assert.match(up.head, /x-custom: kept/i);
  assert.match(up.head, new RegExp(`host: 127\\.0\\.0\\.1:${uport}`, 'i'), 'Host 改写为上游');
  for (const gone of ['x-relay-key', 'x-edge-ip', 'x-mint-model', 'x-fc-security-token', 'x-forwarded-for']) {
    assert.ok(!new RegExp(`^${gone}:`, 'mi').test(up.head), `${gone} 不应到达上游`);
  }
  assert.equal(up.tail.toString(), 'EXTRA', '头后随包字节要原样进上游');
});

test('WS 隧道:上游回非 101 原样透传给客户端', async (t) => {
  const { server } = wsUpstream([{
    response: 'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n',
  }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const { head, socket } = await wsHandshake(port, { headers: { 'X-Relay-Key': RELAY_KEY } });
  socket.destroy();
  assert.match(head, /^HTTP\/1\.1 401/);
});

test('WS 隧道:key 错误 → 403,不拨上游', async (t) => {
  const { server, hits } = wsUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const { head } = await wsHandshake(port, { headers: { 'X-Relay-Key': 'wrong' } });
  assert.match(head, /^HTTP\/1\.1 403/);
  assert.match(head, /x-relay-error: bad_relay_key/);
  assert.equal(hits.length, 0);
});

// ---------------------------------------------------------------------------
// 纯函数件
// ---------------------------------------------------------------------------

test('isPublicIP 分类', () => {
  for (const good of ['1.1.1.1', '8.8.8.8', '172.64.0.1', '2606:4700::1111']) {
    assert.equal(isPublicIP(good), true, good);
  }
  for (const bad of ['0.0.0.0', '10.0.0.1', '127.0.0.1', '169.254.0.1',
    '172.16.5.5', '192.168.0.1', '100.64.1.1', '198.18.0.1', '224.0.0.1',
    '255.255.255.255', '::1', '::', 'fc00::1', 'fd12::1', 'fe80::1', 'febf::1',
    '::ffff:10.0.0.1', '::ffff:7f00:1']) {
    assert.equal(isPublicIP(bad), false, bad);
  }
});

test('filterRequestHeaders 剥逐跳/控制/身份头', () => {
  const out = filterRequestHeaders({
    'x-relay-key': 'k', 'x-edge-ip': '1.1.1.1', host: 'relay.example',
    'x-forwarded-for': '1.2.3.4', 'x-fc-uid': 'u', via: 'v',
    authorization: 'Bearer t', 'content-type': 'application/json',
    'user-agent': 'codex-tui/0.1',
  });
  assert.deepEqual(out, {
    authorization: 'Bearer t',
    'content-type': 'application/json',
    'user-agent': 'codex-tui/0.1',
  });
});

// ---------------------------------------------------------------------------
// 打票(X-Relay-Mint)
// ---------------------------------------------------------------------------

const { mintGatewayLabel, mintGatewayTarget, createdModelFromSse, mintPairs, fernetIssuedAt } = _internals;

// 测试票:Fernet 形态(0x80 + 8B 大端秒签发时刻 + 填充),len 取 4 的倍数时
// base64url 恰好 len 字符 —— 780 字符 = 585 字节,与真实票同构。
function ticketOf(len, tsSec) {
  const bytes = Buffer.alloc((len / 4) * 3);
  bytes[0] = 0x80;
  bytes.writeBigUInt64BE(BigInt(tsSec === undefined ? Math.floor(Date.now() / 1000) : tsSec), 1);
  return bytes.toString('base64url').slice(0, len);
}
// __oailb 是 JWT:节点名内嵌在载荷里(chat.gateway.unified-N.api.openai.com)。
function fakeJwt(payload) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b({ alg: 'none', typ: 'JWT' })}.${b(payload)}.sig`;
}

// 打票假上游:按第几发从 script 取响应描述。描述字段:
//   status    默认 200
//   gateway   pair 指向的节点名(JWT 载荷内嵌);null → 不发 pair
//   cflb/oailb 显式覆盖 cookie 值(测明文节点名)
//   served    SSE 里实服的模型,默认跟随请求体里的 model
//   ticketLen 默认 780;0 → 不发票头
//   ticketTs  票内嵌的签发时刻(Unix 秒),默认当下
//   body      显式覆盖响应体
function mintUpstream(script) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const i = hits.length;
      const bodyText = Buffer.concat(chunks).toString();
      let reqModel = '';
      try { reqModel = JSON.parse(bodyText).model || ''; } catch { /* 非 JSON */ }
      hits.push({
        method: req.method, url: req.url, model: reqModel,
        headers: req.headers, body: bodyText,
      });
      const d = (typeof script === 'function' ? script(i, hits[i]) : script[Math.min(i, script.length - 1)]) || {};
      const status = d.status === undefined ? 200 : d.status;
      const gateway = 'gateway' in d ? d.gateway : 'unified-88';
      const served = 'served' in d ? d.served : reqModel;
      const ticketLen = 'ticketLen' in d ? d.ticketLen : 780;
      const headers = { 'content-type': d.contentType || (status === 200 ? 'text/event-stream' : 'application/json') };
      if (ticketLen > 0) headers['x-codex-turn-state'] = ticketOf(ticketLen, d.ticketTs);
      const cookies = [];
      if (gateway !== null) {
        cookies.push(`__cflb=${d.cflb || 'cflb-value'}; Path=/; Expires=Wed, 23 Sep 2026 09:00:00 GMT`);
        const oailb = d.oailb
          || fakeJwt({ exp: Math.floor(Date.now() / 1000) + 3900, aud: `chat.gateway.${gateway}.api.openai.com` });
        cookies.push(`__oailb=${oailb}; Path=/; Max-Age=3600`);
      }
      if (cookies.length) headers['set-cookie'] = cookies;
      res.writeHead(status, headers);
      if (d.body !== undefined) return res.end(d.body);
      if (status === 200) {
        const resp = served === null ? { id: 'r1' } : { id: 'r1', model: served };
        return res.end(`data: {"type":"response.created","response":${JSON.stringify(resp)}}\n\n`);
      }
      return res.end(`{"error":{"message":"status ${status}"}}`);
    });
  });
  return { server, hits };
}

// 打票调用:默认每用一个新凭据 —— 票/pair 按凭据缓存,共用凭据会串测试。
// 需要复用缓存的用例显式传同一个 auth。
let mintSeq = 0;
function mintCall(port, headers, auth) {
  return call(port, {
    method: 'POST',
    path: '/whatever',
    headers: {
      'x-relay-mint': '1',
      authorization: auth || `Bearer at-${++mintSeq}`,
      'chatgpt-account-id': 'aid-test',
      'x-mint-model': 'gpt-6-sol',
      ...headers,
    },
  });
}

test('打票一发命中:返回票+pair JSON;上游收到裸发 ping,凭据照传、控制头不外发', async (t) => {
  const { server, hits } = mintUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, { 'x-mint-len': '780' }, 'Bearer at-test');
  assert.equal(r.status, 200);
  assert.equal(r.headers['cache-control'], 'no-store');
  const body = JSON.parse(r.body);
  assert.equal(body.ticket_len, 780);
  assert.equal(body.turn_state.length, 780);
  assert.equal(body.gateway, 'unified-88');
  assert.equal(body.model, 'gpt-6-sol');
  assert.equal(body.served_model, 'gpt-6-sol');
  assert.equal(body.attempts, 1);
  assert.ok(body.cookies.__cflb && body.cookies.__oailb);
  assert.match(body.cookie_header, /^__cflb=.+; __oailb=.+$/);
  assert.ok(body.expires_at, 'JWT exp 应给出死线');
  assert.equal(body.tickets['gpt-6-sol'].turn_state, body.turn_state);
  assert.equal(body.tickets['gpt-6-sol'].cached, false);

  assert.equal(hits.length, 1);
  const hit = hits[0];
  assert.equal(hit.method, 'POST');
  assert.equal(hit.url, '/backend-api/codex/responses');
  assert.equal(hit.headers.authorization, 'Bearer at-test');
  assert.equal(hit.headers['chatgpt-account-id'], 'aid-test');
  assert.equal(hit.headers.cookie, undefined, '打票必须裸发:带 pair 边缘就不再铸新 pair');
  assert.equal(hit.headers.originator, 'codex-tui');
  assert.ok(hit.headers['session-id'], '每发新 session-id');
  assert.match(hit.headers['user-agent'], /^codex-tui\//);
  for (const ctl of ['x-relay-key', 'x-relay-mint', 'x-mint-model', 'x-mint-len']) {
    assert.equal(hit.headers[ctl], undefined, `${ctl} 是控制头,不外发`);
  }
  const ping = JSON.parse(hit.body);
  assert.equal(ping.model, 'gpt-6-sol');
  assert.equal(ping.stream, true);
  assert.equal(ping.store, false);
});

test('SSE 打票:上游声明 application/octet-stream 时按 SSE 正文照常验收', async (t) => {
  // 上游变更实测:200 + octet-stream + attachment,正文仍是 SSE 事件流。
  const { server } = mintUpstream([{ contentType: 'application/octet-stream' }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {}, 'Bearer at-octet');
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body);
  assert.equal(body.ticket_len, 780);
  assert.equal(body.served_model, 'gpt-6-sol');
});

test('SSE 打票:非 SSE/octet-stream 声明仍拒收', async (t) => {
  const { server } = mintUpstream([{ contentType: 'text/html' }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, { 'x-mint-attempts': '2' }, 'Bearer at-html');
  assert.equal(r.status, 502);
});

test('打票重试:网关不是 unified-88 就再打一发音到命中', async (t) => {
  const { server, hits } = mintUpstream([{ gateway: 'unified-12' }, { gateway: 'unified-88' }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body);
  assert.equal(body.attempts, 2);
  assert.equal(body.gateway, 'unified-88');
  assert.equal(hits.length, 2);
});

test('打票重试:实服模型被换成 fallback(gpt-6-luna)即拒收', async (t) => {
  const { server, hits } = mintUpstream([{ served: 'gpt-6-luna' }, { served: 'gpt-6-sol' }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body);
  assert.equal(body.attempts, 2);
  assert.equal(body.served_model, 'gpt-6-sol');
  assert.equal(hits.length, 2);
});

test('打票重试:票长非 780 即拒收', async (t) => {
  const { server, hits } = mintUpstream([{ ticketLen: 312 }, { ticketLen: 780 }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).attempts, 2);
  assert.equal(hits.length, 2);
});

test('打票重试:流里没判到 model 字段也拒收(无法证明没吃 fallback)', async (t) => {
  const { server, hits } = mintUpstream([
    { body: 'data: {"type":"response.created","response":{"id":"r1"}}\n\n' },
    {},
  ]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).attempts, 2);
  assert.equal(hits.length, 2);
});

test('打票重试:可重试的上游状态(429)继续打', async (t) => {
  const { server, hits } = mintUpstream([{ status: 429, gateway: null }, {}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).attempts, 2);
  assert.equal(hits.length, 2);
});

test('打票耗尽:冷却后继续,最终模型被明确拒绝时返回诊断', async (t) => {
  const { server, hits } = mintUpstream((i) => i < 3 ? { gateway: 'unified-12' } : { status: 400 });
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, MINT_RETRY_COOLDOWN_MS: '20' });

  const r = await mintCall(port, { 'x-mint-attempts': '3' });
  assert.equal(r.status, 502);
  assert.equal(r.headers['x-relay-error'], 'mint_exhausted');
  const err = JSON.parse(r.body).error;
  assert.equal(err.attempts, 4);
  assert.equal(err.want.gateway, 'unified-88');
  assert.equal(err.last.status, 400);
  assert.ok(err.gateways_seen.includes('unified-12'));
  assert.equal(hits.length, 4);
});

test('打票被正面拒绝:401 立即停,不重试', async (t) => {
  const { server, hits } = mintUpstream([{ status: 401, gateway: null, body: '{"error":{"message":"bad token"}}' }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 502);
  assert.equal(r.headers['x-relay-error'], 'mint_rejected');
  const err = JSON.parse(r.body).error;
  assert.equal(err.upstream_status, 401);
  assert.match(err.upstream_body, /bad token/);
  assert.equal(hits.length, 1, '凭据被拒:重试无意义');
});

test('打票缺 Authorization → 400 mint_no_auth,一发不打', async (t) => {
  const { server, hits } = mintUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, { method: 'POST', headers: { 'x-relay-mint': '1' } });
  assert.equal(r.status, 400);
  assert.equal(r.headers['x-relay-error'], 'mint_no_auth');
  assert.equal(hits.length, 0);
});

test('打票网关名在 __cflb 明文里也能认出', async (t) => {
  const { server } = mintUpstream([{
    cflb: 'v1.chat.gateway.unified-88.api.openai.com',
    oailb: fakeJwt({ exp: Math.floor(Date.now() / 1000) + 3900 }), // 载荷无节点名
  }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await mintCall(port, {});
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).gateway, 'unified-88');
});

test('打票目标网关可改:X-Relay-Mint 值写 unified-N 即指定', async (t) => {
  const { server, hits } = mintUpstream([{ gateway: 'unified-88' }, { gateway: 'unified-7' }]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, {
    method: 'POST',
    headers: {
      'x-relay-mint': 'unified-7', authorization: 'Bearer at-test',
      'x-mint-model': 'gpt-6-sol',
    },
  });
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body);
  assert.equal(body.attempts, 2, '目标是 unified-7:unified-88 的 pair 也要拒收');
  assert.equal(body.gateway, 'unified-7');
  assert.equal(hits.length, 2);
});

test('打票钉边缘:X-Edge-IP 同样作用于打票拨号', async (t) => {
  const { server } = mintUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  // 上游域名故意不可解析 —— 拨通全靠钉 127.0.0.1。
  withEnv(t, {
    RELAY_KEY,
    RELAY_UPSTREAM: `http://nonexistent.invalid:${uport}`,
    ALLOW_PRIVATE_EDGE_IPS: '1',
  });

  const r = await mintCall(port, { 'x-edge-ip': '127.0.0.1' });
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).edge_ip, '127.0.0.1');
});

test('打票内部件:网关名规范化与首个 model 字段提取', () => {
  assert.equal(mintGatewayTarget('88'), 'unified-88');
  assert.equal(mintGatewayTarget('unified_88'), 'unified-88');
  assert.equal(mintGatewayTarget('Unified-88'), 'unified-88');
  assert.equal(mintGatewayTarget('any'), null);
  assert.equal(mintGatewayTarget('*'), null);
  assert.equal(mintGatewayTarget(''), null);

  const jwt88 = fakeJwt({ aud: 'chat.gateway.unified-88.api.openai.com' });
  assert.equal(mintGatewayLabel('x', jwt88), 'unified-88');
  assert.equal(mintGatewayLabel('v1.unified-157.node', 'plain-cookie'), 'unified-157');
  assert.equal(mintGatewayLabel('a', 'b'), '');

  const buf = Buffer.from('data: {"type":"response.created","response":{"model":"gpt-6-sol","id":"r"}}\n\n');
  assert.equal(createdModelFromSse(buf), 'gpt-6-sol');
  assert.equal(createdModelFromSse(Buffer.from('data: {"response":{"id":"r"}}')), undefined);

  const pairs = mintPairs(['__cflb=c1; Path=/', '__oailb=o1; Path=/', 'other=x; Path=/']);
  assert.deepEqual(pairs, { __cflb: 'c1', __oailb: 'o1' });
  assert.equal(mintPairs(['__cflb=c1; Path=/']), null, '单只 cookie 不成 pair');

  const now = Math.floor(Date.now() / 1000);
  const old = ticketOf(780, now - 300);
  assert.equal(old.length, 780);
  assert.equal(fernetIssuedAt(old, 0), (now - 300) * 1000, '应读出票内嵌的签发时刻');
  assert.ok(fernetIssuedAt(ticketOf(780), 0) > (now - 5) * 1000);
});

test('打票多模型:默认打 gpt-6-sol/luna/astra 三张票,首发裸打铸 pair、其余定向', async (t) => {
  const { server, hits } = mintUpstream([{}, {}, {}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  // 不传任何 X-Mint-Model*:默认模型集 = 三个。
  const r = await call(port, {
    method: 'POST',
    headers: { 'x-relay-mint': '1', authorization: 'Bearer at-multi' },
  });
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body);
  assert.deepEqual(Object.keys(body.tickets).sort(),
    ['gpt-6-astra', 'gpt-6-luna', 'gpt-6-sol']);
  for (const m of ['gpt-6-sol', 'gpt-6-luna', 'gpt-6-astra']) {
    assert.equal(body.tickets[m].served_model, m);
    assert.equal(body.tickets[m].ticket_len, 780);
    assert.equal(body.tickets[m].cached, false);
  }
  assert.equal(body.model, undefined, '多模型不出平铺字段');
  assert.equal(body.attempts, 3, '一对 pair 三发 ping:首发裸打铸 pair,后两发定向');

  assert.equal(hits.length, 3);
  assert.equal(JSON.parse(hits[0].body).model, 'gpt-6-sol');
  assert.equal(JSON.parse(hits[1].body).model, 'gpt-6-luna');
  assert.equal(JSON.parse(hits[2].body).model, 'gpt-6-astra');
  assert.equal(hits[0].headers.cookie, undefined, '首发必须裸打才会铸新 pair');
  assert.match(hits[1].headers.cookie, /__cflb=.+; __oailb=/, '后续模型携带 pair 定向打');
  assert.match(hits[2].headers.cookie, /__cflb=.+; __oailb=/);
});

test('打票缓存:pair 与票在 TTL 内直接复用,跨模型共享同一 pair', async (t) => {
  const { server, hits } = mintUpstream([{}, {}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const auth = 'Bearer at-cache';

  const r1 = await mintCall(port, { 'x-mint-model': 'gpt-6-sol' }, auth);
  assert.equal(r1.status, 200);
  const ticket1 = JSON.parse(r1.body).turn_state;
  assert.equal(hits.length, 1);

  // 同凭据再要同一模型:票没过期,一发都不打。
  const r2 = await mintCall(port, { 'x-mint-model': 'gpt-6-sol' }, auth);
  const body2 = JSON.parse(r2.body);
  assert.equal(body2.attempts, 0);
  assert.equal(body2.tickets['gpt-6-sol'].cached, true);
  assert.equal(body2.tickets['gpt-6-sol'].turn_state, ticket1);
  assert.equal(hits.length, 1, 'TTL 内命中缓存不应再打票');

  // 要另一模型:pair 还活着,只需定向打一发,不用再铸 pair。
  const r3 = await mintCall(port, { 'x-mint-model': 'gpt-6-luna' }, auth);
  const body3 = JSON.parse(r3.body);
  assert.equal(body3.attempts, 1);
  assert.ok(body3.tickets['gpt-6-luna']);
  assert.equal(hits.length, 2);
  assert.match(hits[1].headers.cookie, /__oailb=/, '第二模型应复用缓存的 pair 定向打');
});

test('打票缓存:上游先返回过期票时同次重打,不把过期票返回成功', async (t) => {
  const oldTs = Math.floor(Date.now() / 1000) - 300;
  const { server, hits } = mintUpstream([{ ticketTs: oldTs }, {}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const auth = 'Bearer at-stale';

  const r1 = await mintCall(port, { 'x-mint-attempts': '2' }, auth);
  const body1 = JSON.parse(r1.body);
  assert.equal(r1.status, 200);
  assert.equal(body1.tickets['gpt-6-sol'].cached, false);
  assert.ok(Date.parse(body1.tickets['gpt-6-sol'].expires_at) > Date.now());
  assert.equal(body1.attempts, 2);
  assert.equal(hits.length, 2);

  const r2 = await mintCall(port, {}, auth);
  const body2 = JSON.parse(r2.body);
  assert.equal(body2.tickets['gpt-6-sol'].cached, true);
  assert.equal(body2.attempts, 0);
  assert.equal(hits.length, 2, '只缓存第二张通过有效期检查的新票');
});

test('打票缓存:MINT_TICKET_TTL_S=0 或 x-mint-ttl:0 → 不缓存,每次都打', async (t) => {
  const { server, hits } = mintUpstream([{}, {}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const auth = 'Bearer at-nocache';

  await mintCall(port, { 'x-mint-ttl': '0' }, auth);
  await mintCall(port, { 'x-mint-ttl': '0' }, auth);
  assert.equal(hits.length, 2, 'ttl=0 时每次都重打');
});

test('打票多模型:一个模型被正面拒绝(400)只算它失败,其余票照给', async (t) => {
  const { server, hits } = mintUpstream([
    {},                                    // sol:裸打铸 pair + 票
    { status: 400, gateway: null },        // astra:400,该模型判死
  ]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });

  const r = await call(port, {
    method: 'POST',
    headers: {
      'x-relay-mint': '1', authorization: 'Bearer at-partial',
      'x-mint-models': 'gpt-6-sol,gpt-6-astra',
    },
  });
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body);
  assert.deepEqual(Object.keys(body.tickets), ['gpt-6-sol']);
  assert.ok(body.errors['gpt-6-astra'], '被拒的模型要进 errors');
  assert.equal(hits.length, 2);
});

// WS 回归：升级前后必须分开处理错误，不能把 HTTP 错误写进已建立的隧道。
test('WS:拒绝非 websocket 的 Upgrade,不拨上游', async (t) => {
  const { server, hits } = wsUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const { head, socket } = await wsHandshake(port, {
    headers: { 'X-Relay-Key': RELAY_KEY, Upgrade: 'h2c' },
  });
  socket.destroy();
  assert.match(head, /^HTTP\/1\.1 400/);
  assert.match(head, /bad_upgrade/);
  assert.equal(hits.length, 0);
});

test('WS:建连成功但上游握手静默 → 504', async (t) => {
  const uport = await serve(t, net.createServer((socket) => socket.resume()));
  const port = await startRelay(t);
  withEnv(t, {
    RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`,
    RELAY_CONNECT_TIMEOUT_MS: '100',
  });
  const { head, socket } = await wsHandshake(port, { headers: { 'X-Relay-Key': RELAY_KEY } });
  socket.destroy();
  assert.match(head, /^HTTP\/1\.1 504/);
  assert.match(head, /upstream_timeout/);
});

test('WS:上游未回握手就断开 → 502', async (t) => {
  const uport = await serve(t, net.createServer((socket) => socket.end()));
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const { head, socket } = await wsHandshake(port, { headers: { 'X-Relay-Key': RELAY_KEY } });
  socket.destroy();
  assert.match(head, /^HTTP\/1\.1 502/);
});

test('WS:剥离 Connection 指名的逐跳头,重新生成升级头', async (t) => {
  const { server, hits } = wsUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const { socket } = await wsHandshake(port, { headers: {
    'X-Relay-Key': RELAY_KEY, Connection: 'Upgrade, X-Hop', 'X-Hop': 'private',
    'Keep-Alive': 'timeout=5',
  } });
  socket.destroy();
  assert.doesNotMatch(hits[0].head, /^(x-hop|keep-alive):/mi);
  assert.match(hits[0].head, /^Connection: Upgrade$/m);
});

for (const hostname of ['chatgpt.com', 'other.invalid']) {
  test(`WS TLS:钉 IP 时按 ${hostname} 校验证书与 SNI`, async (t) => {
    let sni;
    const upstream = https.createServer({ key: TEST_KEY, cert: TEST_CERT });
    upstream.on('upgrade', (req, socket) => {
      sni = req.socket.servername;
      socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    });
    const uport = await serve(t, upstream);
    const port = await spawnRelay(t, { RELAY_UPSTREAM: `https://${hostname}:${uport}` });
    const { head, socket } = await wsHandshake(port, {
      headers: { 'X-Relay-Key': RELAY_KEY, 'X-Edge-IP': '127.0.0.1' },
    });
    socket.destroy();
    if (hostname === 'chatgpt.com') {
      assert.match(head, /^HTTP\/1\.1 101/);
      assert.equal(sni, 'chatgpt.com');
    } else {
      assert.match(head, /^HTTP\/1\.1 502/);
      assert.match(head, /ERR_TLS_CERT_ALTNAME_INVALID/);
    }
  });
}

for (const response of ['HTTP/1.1 101', 'X'.repeat(16 * 1024 + 1), 'not-http\r\n\r\n']) {
  test(`WS:不完整/超长/非法握手头不会原样污染错误响应 (${response.length})`, async (t) => {
    const { server } = wsUpstream([{ response }]);
    const uport = await serve(t, server);
    const port = await startRelay(t);
    withEnv(t, {
      RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, RELAY_CONNECT_TIMEOUT_MS: '100',
    });
    const { head, socket } = await wsHandshake(port, { headers: { 'X-Relay-Key': RELAY_KEY } });
    socket.destroy();
    assert.match(head, response === 'HTTP/1.1 101' ? /^HTTP\/1\.1 504/ : /^HTTP\/1\.1 502/);
    assert.equal((head.match(/HTTP\/1\.1/g) || []).length, 1);
  });
}

test('WS:客户端断开拆掉上游,二进制帧与 ping/pong 字节不改写', async (t) => {
  const { server, hits } = wsUpstream([{}]);
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const { socket } = await wsHandshake(port, { headers: { 'X-Relay-Key': RELAY_KEY } });
  // 隧道不解释帧,这里验证包含 NUL/高位字节的连续控制帧与数据帧无损。
  const payload = Buffer.from([0x82, 0x02, 0x00, 0xff, 0x89, 0x00, 0x8a, 0x00]);
  const echoed = await new Promise((resolve) => {
    let received = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length >= payload.length) resolve(received);
    });
    socket.write(payload);
  });
  assert.deepEqual(echoed, payload);
  const closed = new Promise((resolve) => hits[0].socket.once('close', resolve));
  socket.destroy();
  await closed;
});

for (const vars of [{ RELAY_KEY: '' }, { ALLOW_PRIVATE_EDGE_IPS: undefined }]) {
  test(`WS:鉴权与 SSRF 防线生效 (${Object.keys(vars)[0]})`, async (t) => {
    const { server, hits } = wsUpstream([{}]);
    const uport = await serve(t, server);
    const port = await startRelay(t);
    withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, ...vars });
    const { head, socket } = await wsHandshake(port, { headers: {
      'X-Relay-Key': RELAY_KEY, 'X-Edge-IP': '127.0.0.1',
    } });
    socket.destroy();
    assert.match(head, 'RELAY_KEY' in vars ? /^HTTP\/1\.1 403/ : /^HTTP\/1\.1 400/);
    assert.equal(hits.length, 0);
  });
}

test('WS:标准握手保留 Cookie 与协议,首帧和掩码 ping/pong 往返', { timeout: 3000 }, async (t) => {
  const key = 'dGhlIHNhbXBsZSBub25jZQ==';
  const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  const firstFrame = Buffer.from([0x81, 0x02, 0x6f, 0x6b]); // 文本 ok
  const ping = Buffer.from([0x89, 0x81, 1, 2, 3, 4, 0x79]); // 掩码后的 x
  const pong = Buffer.from([0x8a, 0x01, 0x78]);
  const upstream = http.createServer();
  upstream.on('upgrade', (req, socket) => {
    assert.equal(req.headers['sec-websocket-key'], key);
    socket.write(Buffer.concat([Buffer.from('HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
      + `Sec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: chat\r\n`
      + 'Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n'), firstFrame]));
    let data = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length < ping.length) return;
      assert.deepEqual(data, ping);
      socket.end(pong);
    });
  });
  const uport = await serve(t, upstream);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  await new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port, headers: {
      'X-Relay-Key': RELAY_KEY, Connection: 'Upgrade', Upgrade: 'websocket',
      'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Protocol': 'chat',
    } });
    request.on('error', reject);
    request.on('upgrade', (res, socket, head) => {
      assert.equal(res.headers['sec-websocket-accept'], accept);
      assert.equal(res.headers['sec-websocket-protocol'], 'chat');
      assert.deepEqual(res.headers['set-cookie'], ['a=1', 'b=2']);
      let received = head;
      socket.on('error', reject);
      socket.on('data', (chunk) => { received = Buffer.concat([received, chunk]); });
      socket.on('end', () => {
        assert.deepEqual(received, Buffer.concat([firstFrame, pong]));
        socket.end();
        resolve();
      });
      socket.write(ping);
    });
  });
});

// 打票边界使用可控时钟推进有效期，不靠真实等待或访问线上服务。
async function mintBoundaryFixture(t, script) {
  let now = Math.floor(Date.now() / 1000) * 1000;
  t.mock.method(Date, 'now', () => now);
  const advance = (seconds) => { now += seconds * 1000; };
  const { server, hits } = mintUpstream((i, hit) => script(i, hit, advance));
  const uport = await serve(t, server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, MINT_RETRY_COOLDOWN_MS: '20' });
  const auth = `Bearer boundary-${++mintSeq}`;
  const request = async (headers = {}) => {
    const res = await mintCall(port, { 'x-mint-attempts': '2', ...headers }, auth);
    return { status: res.status, body: JSON.parse(res.body) };
  };
  return { request, hits, advance, port, auth };
}

function shortPair(seconds) {
  return fakeJwt({ exp: Date.now() / 1000 + seconds, aud: 'chat.gateway.unified-88.api.openai.com' });
}

test('打票边界:缓存票必须符合本次票长,关闭长度检查仍可复用', async (t) => {
  const f = await mintBoundaryFixture(t, (i) => ({ ticketLen: i === 0 ? 292 : 780 }));
  await f.request({ 'x-mint-len': '0' });
  const strict = await f.request({ 'x-mint-len': '780' });
  assert.equal(strict.status, 200);
  assert.equal(strict.body.ticket_len, 780);
  assert.equal(strict.body.tickets['gpt-6-sol'].cached, false);
  assert.equal(f.hits.length, 2);
  const relaxed = await f.request({ 'x-mint-len': '0' });
  assert.equal(relaxed.body.tickets['gpt-6-sol'].cached, true);
  assert.equal(f.hits.length, 2);
});

test('打票边界:缩短 TTL 后已超期的缓存票必须重打', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  await f.request();
  f.advance(30);
  const result = await f.request({ 'x-mint-ttl': '10' });
  assert.equal(result.status, 200);
  assert.equal(result.body.tickets['gpt-6-sol'].cached, false);
  assert.equal(f.hits.length, 2);
});

test('打票边界:缩短 TTL 调整返回死线,增大 TTL 不延长缓存原始死线', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  const original = await f.request();
  f.advance(5);
  const shorter = await f.request({ 'x-mint-ttl': '10' });
  const shortTicket = shorter.body.tickets['gpt-6-sol'];
  assert.equal(shortTicket.cached, true);
  assert.equal(Date.parse(shortTicket.expires_at), Date.parse(shortTicket.issued_at) + 10_000);
  const longer = await f.request({ 'x-mint-ttl': '600' });
  assert.equal(longer.body.tickets['gpt-6-sol'].expires_at, original.body.tickets['gpt-6-sol'].expires_at);
  assert.equal(f.hits.length, 1);
});

test('打票边界:全票命中但 pair 过期时裸打补 pair,不替换缓存票', async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i === 0
    ? { oailb: shortPair(5) } : { ticketLen: 0 });
  const original = await f.request();
  f.advance(6);
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.ok(result.body.cookie_header);
  assert.ok(Date.parse(result.body.expires_at) > Date.now());
  assert.equal(result.body.turn_state, original.body.turn_state);
  assert.equal(result.body.tickets['gpt-6-sol'].cached, true);
  assert.equal(result.body.attempts, 1);
  assert.equal(f.hits.length, 2);
  assert.equal(f.hits[1].headers.cookie, undefined);
});

for (const replacement of [{ gateway: null }, { gateway: 'unified-7' }, { expired: true }]) {
  test(`打票边界:补不到有效目标 pair 时不返回伪成功 (${JSON.stringify(replacement)})`, async (t) => {
    const f = await mintBoundaryFixture(t, (i) => i === 0 ? { oailb: shortPair(5) }
      : i >= 3 ? { status: 400 } : replacement.expired ? { oailb: shortPair(-1) } : replacement);
    await f.request();
    f.advance(6);
    const result = await f.request();
    assert.equal(result.status, 502);
    assert.equal(result.body.error.code, 'mint_exhausted');
    assert.equal(f.hits.length, 4, 'pair 首轮两次失败后冷却,再遇永久拒绝才停止');
    assert.equal(f.hits[1].headers.cookie, undefined);
    assert.equal(f.hits[2].headers.cookie, undefined);
  });
}

test('打票边界:补 pair 遇到 401 即整单停止,不返回缓存票', async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i === 0 ? { oailb: shortPair(5) } : { status: 401 });
  await f.request();
  f.advance(6);
  const result = await f.request();
  assert.equal(result.status, 502);
  assert.equal(result.body.error.code, 'mint_rejected');
  assert.equal(f.hits.length, 2);
});

test('打票边界:补 pair 期间缓存票过期,返回前不能当作有效票', async (t) => {
  const f = await mintBoundaryFixture(t, (i, _hit, advance) => {
    if (i === 0) return { oailb: shortPair(1) };
    advance(10);
    return {};
  });
  await f.request({ 'x-mint-ttl': '10' });
  f.advance(2);
  const result = await f.request({ 'x-mint-ttl': '10' });
  assert.equal(result.status, 502);
  assert.equal(result.body.error.code, 'mint_exhausted');
});

test('打票边界:过期票耗尽本轮预算后冷却,直到拿到新票', async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i < 2 ? { ticketTs: Date.now() / 1000 - 300 } : {});
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.equal(result.body.attempts, 3);
  assert.ok(Date.parse(result.body.tickets['gpt-6-sol'].expires_at) > Date.now());
  assert.equal(f.hits.length, 3);
});

test('打票边界:旧缓存原始死线已到,即使增大 TTL 仍重打', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  await f.request({ 'x-mint-ttl': '10' });
  f.advance(10);
  const result = await f.request({ 'x-mint-ttl': '600' });
  assert.equal(result.status, 200);
  assert.equal(result.body.tickets['gpt-6-sol'].cached, false);
  assert.equal(f.hits.length, 2);
});

test('打票边界:TTL=0 不读取也不写入跨请求缓存', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  await f.request({ 'x-mint-ttl': '0' });
  const cached = await f.request();
  assert.equal(cached.body.tickets['gpt-6-sol'].cached, false);
  assert.equal(f.hits.length, 2);
  assert.equal(f.hits[1].headers.cookie, undefined, 'TTL=0 的 pair 也不写缓存');
  await f.request({ 'x-mint-ttl': '0' });
  assert.equal(f.hits.length, 3);
  assert.equal(f.hits[2].headers.cookie, undefined, 'TTL=0 不读旧 pair');
});

test('打票边界:补 pair 的模型被 400 拒绝后换其他已缓存模型', async (t) => {
  const f = await mintBoundaryFixture(t, (i) => [
    { oailb: shortPair(1) }, { gateway: null }, { status: 400 }, {},
  ][i]);
  const headers = { 'x-mint-models': 'gpt-6-sol,gpt-6-luna' };
  const initial = await f.request(headers);
  assert.equal(initial.status, 200);
  f.advance(2);
  const result = await f.request(headers);
  assert.equal(result.status, 200);
  assert.equal(result.body.attempts, 2);
  assert.equal(result.body.tickets['gpt-6-sol'].cached, true);
  assert.equal(result.body.tickets['gpt-6-luna'].cached, true);
  assert.equal(f.hits[2].model, 'gpt-6-sol');
  assert.equal(f.hits[3].model, 'gpt-6-luna');
  assert.equal(f.hits[3].headers.cookie, undefined, '错误响应不能把 pair 塞进缓存');
});

test('打票边界:多模型补票期间 pair 失效,最终会补齐有效 pair', async (t) => {
  const f = await mintBoundaryFixture(t, (i, _hit, advance) => {
    if (i === 0) return { oailb: shortPair(1) };
    if (i === 1) { advance(2); return { gateway: null }; }
    return {};
  });
  const result = await f.request({ 'x-mint-models': 'gpt-6-sol,gpt-6-luna' });
  assert.equal(result.status, 200);
  assert.equal(Object.keys(result.body.tickets).length, 2);
  assert.ok(Date.parse(result.body.expires_at) > Date.now());
  assert.equal(f.hits.length, 3);
  assert.equal(f.hits[2].headers.cookie, undefined);
});

test('打票边界:后续模型耗时导致早先票过期时只返回仍有效的票', async (t) => {
  const f = await mintBoundaryFixture(t, (i, _hit, advance) => {
    if (i === 1) advance(10);
    return {};
  });
  const result = await f.request({ 'x-mint-models': 'gpt-6-sol,gpt-6-luna', 'x-mint-ttl': '10' });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body.tickets), ['gpt-6-luna']);
  assert.equal(result.body.errors['gpt-6-sol'].last.why, 'expired_ticket');
});

test('打票冷却:每轮耗尽后等待配置间隔,同一请求继续到成功', { timeout: 3000 }, async (t) => {
  const times = [];
  const f = await mintBoundaryFixture(t, (i) => {
    times.push(performance.now());
    return i < 4 ? { gateway: 'unified-7' } : {};
  });
  withEnv(t, { MINT_RETRY_COOLDOWN_MS: '40' });
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.equal(result.body.attempts, 5);
  assert.ok(times[2] - times[1] >= 35, '第一轮结束后必须冷却');
  assert.ok(times[4] - times[3] >= 35, '后续轮次也必须冷却');
});

test('打票冷却:已成功模型不重复打,永久失败模型不参加新一轮', { timeout: 3000 }, async (t) => {
  const f = await mintBoundaryFixture(t, (i, hit) => {
    if (hit.model === 'gpt-6-astra') return { status: 400 };
    if (hit.model === 'gpt-6-luna' && i < 4) return { status: 429 };
    return {};
  });
  withEnv(t, { MINT_RETRY_COOLDOWN_MS: '20' });
  const result = await f.request({ 'x-mint-models': 'gpt-6-sol,gpt-6-astra,gpt-6-luna' });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body.tickets), ['gpt-6-sol', 'gpt-6-luna']);
  assert.equal(result.body.errors['gpt-6-astra'].last.why, 'http:400');
  assert.equal(result.body.errors['gpt-6-luna'], undefined);
  assert.deepEqual(f.hits.map((hit) => hit.model), [
    'gpt-6-sol', 'gpt-6-astra', 'gpt-6-luna', 'gpt-6-luna', 'gpt-6-luna',
  ]);
});

test('打票冷却:补 pair 达上限也会等待再补,保留有效缓存票', { timeout: 3000 }, async (t) => {
  const times = [];
  const f = await mintBoundaryFixture(t, (i) => {
    times.push(performance.now());
    if (i === 0) return { oailb: shortPair(1) };
    return i < 3 ? { gateway: null } : { ticketLen: 0 };
  });
  const initial = await f.request();
  f.advance(2);
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.equal(result.body.turn_state, initial.body.turn_state);
  assert.equal(result.body.tickets['gpt-6-sol'].cached, true);
  assert.equal(result.body.attempts, 3);
  assert.ok(times[3] - times[2] >= 15);
});

test('打票冷却:冷却期间旧票和 pair 到期,新一轮重新裸打', { timeout: 3000 }, async (t) => {
  const f = await mintBoundaryFixture(t, (i, _hit, advance) => {
    if (i === 0) return { oailb: shortPair(1) };
    if (i < 3) {
      if (i === 2) advance(11);
      return { status: 429 };
    }
    return {};
  });
  const result = await f.request({ 'x-mint-models': 'gpt-6-sol,gpt-6-luna', 'x-mint-ttl': '10' });
  assert.equal(result.status, 200);
  assert.deepEqual(f.hits.map((hit) => hit.model), [
    'gpt-6-sol', 'gpt-6-luna', 'gpt-6-luna', 'gpt-6-sol', 'gpt-6-sol', 'gpt-6-luna',
  ]);
  assert.equal(f.hits[3].headers.cookie, undefined);
  for (const ticket of Object.values(result.body.tickets)) {
    assert.ok(Date.parse(ticket.expires_at) > Date.now());
  }
});

test('打票冷却:客户端断开立即取消等待,不再自动发请求', { timeout: 3000 }, async (t) => {
  let reached;
  const exhausted = new Promise((resolve) => { reached = resolve; });
  const f = await mintBoundaryFixture(t, (i) => {
    if (i === 1) reached();
    return { status: 429 };
  });
  withEnv(t, { MINT_RETRY_COOLDOWN_MS: '100' });
  const req = http.request({ host: '127.0.0.1', port: f.port, method: 'POST', headers: {
    'X-Relay-Key': RELAY_KEY, 'X-Relay-Mint': '1', Authorization: f.auth,
    'X-Mint-Model': 'gpt-6-sol', 'X-Mint-Attempts': '2',
  } });
  req.on('error', () => {});
  t.after(() => req.destroy());
  req.end();
  await exhausted;
  await new Promise((resolve) => setTimeout(resolve, 10));
  const closed = new Promise((resolve) => req.once('close', resolve));
  req.destroy();
  await closed;
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(f.hits.length, 2);
});

for (const status of [401, 403, 400, 404, 422]) {
  test(`打票冷却:首发 ${status} 永久拒绝不会进入冷却重试`, async (t) => {
    const f = await mintBoundaryFixture(t, () => ({ status }));
    const result = await f.request();
    assert.equal(result.status, 502);
    assert.equal(f.hits.length, 1);
  });
}

test('打票冷却:未配置时使用 30 秒默认间隔', { timeout: 3000 }, async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i < 2 ? { status: 429 } : {});
  withEnv(t, { MINT_RETRY_COOLDOWN_MS: undefined });
  const delays = [];
  const schedule = global.setTimeout;
  t.mock.method(global, 'setTimeout', (callback, delay, ...args) => {
    delays.push(delay);
    // 只缩短默认冷却计时,其他网络与测试计时器保持原样。
    return schedule(callback, delay === 30_000 ? 10 : delay, ...args);
  });
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.ok(delays.includes(30_000));
  assert.equal(f.hits.length, 3);
});

// 模型判定只认完整的 response.created.response.model，不再搜索任意字符串。
test('严格模型事件:SSE 空白/多行/CRLF/转义兼容', () => {
  const source = ': heartbeat\r\nevent: response.created\r\n'
    + 'data: {"type": "response.created",\r\n'
    + 'data: "response": {"id":"r1", "model":"gpt-6-\\u0073ol"}}\r\n\r\n';
  assert.equal(_internals.createdModelFromSse(Buffer.from(source)), 'gpt-6-sol');
  for (let i = 0; i < source.length - 2; i += 1) {
    assert.equal(_internals.createdModelFromSse(Buffer.from(source.slice(0, i))), undefined);
  }
});

for (const event of [
  { type: 'response.completed', response: { id: 'r1', model: 'gpt-6-sol' } },
  { type: 'response.created', metadata: { model: 'gpt-6-sol' }, response: { id: 'r1' } },
  { type: 'response.created', response: { model: 'gpt-6-sol' } },
  { type: 'response.created', response: { id: 'r1', model: '' } },
  { type: 'response.created', response: { id: 'r1', model: 123 } },
]) {
  test(`严格模型事件:不接受错误位置/类型 ${JSON.stringify(event)}`, () => {
    assert.equal(_internals.createdModelFromSse(Buffer.from(`data: ${JSON.stringify(event)}\n\n`)), undefined);
  });
}

test('严格模型事件:SSE event 与 JSON type 冲突时拒收', () => {
  const event = { type: 'response.created', response: { id: 'r1', model: 'gpt-6-sol' } };
  assert.equal(_internals.createdModelFromSse(Buffer.from(`event: response.completed\ndata: ${JSON.stringify(event)}\n\n`)), undefined);
});

function serverMintFrame(opcode, data, fin = true) {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const header = Buffer.alloc(payload.length >= 126 ? 4 : 2);
  header[0] = (fin ? 0x80 : 0) | opcode;
  header[1] = payload.length >= 126 ? 126 : payload.length;
  if (header.length === 4) header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

// 假上游独立解析客户端掩码帧,避免与生产解析器共享实现而掩盖协议错误。
function acceptMintClientFrames(socket, onFrame) {
  let buffer = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 2) {
      assert.ok(buffer[1] & 0x80, '客户端必须掩码');
      const extended = (buffer[1] & 0x7f) === 126;
      if (buffer.length < (extended ? 8 : 6)) return;
      const size = extended ? buffer.readUInt16BE(2) : buffer[1] & 0x7f;
      const offset = extended ? 4 : 2;
      if (buffer.length < offset + 4 + size) return;
      const data = Buffer.from(buffer.subarray(offset + 4, offset + 4 + size));
      for (let i = 0; i < data.length; i += 1) data[i] ^= buffer[offset + i % 4];
      const opcode = buffer[0] & 0x0f;
      buffer = buffer.subarray(offset + 4 + size);
      onFrame(opcode, data);
    }
  });
}

function websocketMintUpstream(script = () => ({}), server) {
  const base = server ? { server, hits: [] } : mintUpstream([{}]);
  const hits = [];
  base.server.on('upgrade', (req, socket) => {
    socket.on('error', () => {});
    socket.on('end', () => socket.end());
    const hit = { headers: req.headers, url: req.url, socket, pongs: [] };
    hits.push(hit);
    const d = script(hits.length - 1, hit) || {};
    if (d.reject) { socket.end(`HTTP/1.1 ${d.reject} Rejected\r\nContent-Length: 0\r\n\r\n`); return; }
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key']
      + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    let header = 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
      + `Sec-WebSocket-Accept: ${d.badAccept ? 'wrong' : accept}\r\n`;
    if (d.ticketLen !== 0) header += `X-Codex-Turn-State: ${ticketOf(d.ticketLen || 780)}\r\n`;
    if (d.pair !== false) header += `Set-Cookie: __cflb=ws-pair\r\nSet-Cookie: __oailb=${d.oailb || shortPair(3900)}\r\n`;
    socket.write(header + '\r\n');
    acceptMintClientFrames(socket, (opcode, data) => {
      if (opcode === 10) { hit.pongs.push(data.toString()); d.onPong?.(socket, hit); return; }
      if (opcode !== 1) return;
      hit.payload = JSON.parse(data.toString());
      d.onCreate?.(socket, hit);
      if (d.silent) return;
      const event = d.event || { type: 'response.created', response: { id: 'ws-r1', model: d.model || hit.payload.model } };
      const json = JSON.stringify(event);
      const frames = d.frames || (d.fragment ? [
        serverMintFrame(1, json.slice(0, 18), false), serverMintFrame(9, 'ping'),
        serverMintFrame(0, json.slice(18)),
      ] : [serverMintFrame(1, json)]);
      for (const frame of frames) socket.write(frame);
    });
  });
  return { server: base.server, hits, httpHits: base.hits };
}

async function wsMintAttempt(t, script) {
  const upstream = websocketMintUpstream(script);
  const port = await serve(t, upstream.server);
  const cfg = { upstream: new URL(`http://127.0.0.1:${port}`), connectTimeoutMs: 200,
    mint: { transport: 'websocket', attemptTimeoutMs: 200 } };
  const attempt = _internals.fireMintAttempt(cfg, '', { authorization: 'Bearer ws-test' }, 'gpt-6-sol', null);
  t.after(() => attempt.req.destroy());
  return { attempt, ...upstream };
}

test('WS 打票:真实握手、掩码 response.create、分片 created 模型声明', async (t) => {
  const f = await wsMintAttempt(t, () => ({ fragment: true }));
  const result = await f.attempt.done;
  assert.equal(result.reason, 'ok');
  assert.equal(result.status, 101);
  assert.equal(result.served, 'gpt-6-sol');
  assert.equal(result.len, 780);
  assert.equal(result.gateway, 'unified-88');
  assert.equal(f.hits[0].payload.type, 'response.create');
  assert.equal(f.hits[0].payload.stream, undefined);
  assert.equal(f.hits[0].headers['sec-websocket-extensions'], undefined);
  assert.equal(f.hits[0].headers.authorization, 'Bearer ws-test');
});

for (const fixture of [
  { badAccept: true }, { silent: true },
  { event: { type: 'response.completed', response: { id: 'r', model: 'gpt-6-sol' } } },
  { event: { type: 'response.created', response: { model: 'gpt-6-sol' } } },
  { frames: [Buffer.from([0x81, 0x7f])] },
  { frames: [serverMintFrame(0, 'bad')] },
  { frames: [serverMintFrame(1, Buffer.from([0xff]))] },
  { frames: [serverMintFrame(8, '')] },
]) {
  test(`WS 打票:非法握手/事件/帧不得成功 (${JSON.stringify(fixture)})`, async (t) => {
    const f = await wsMintAttempt(t, () => fixture);
    const result = await f.attempt.done;
    assert.notEqual(result.reason, 'ok');
    assert.equal(result.served, undefined);
  });
}

test('WS 打票:完整链路模型回退重试、冷却续打及协议缓存隔离', async (t) => {
  const upstream = websocketMintUpstream((i) => i < 2 ? { model: 'gpt-6-luna' } : {});
  const uport = await serve(t, upstream.server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`, MINT_RETRY_COOLDOWN_MS: '10' });
  const auth = 'Bearer protocol-isolation';
  const sse = await mintCall(port, {}, auth);
  assert.equal(sse.status, 200);
  const ws = await mintCall(port, { 'x-mint-transport': 'websocket', 'x-mint-attempts': '2' }, auth);
  assert.equal(ws.status, 200);
  const result = JSON.parse(ws.body);
  assert.equal(result.transport, 'websocket');
  assert.equal(result.attempts, 3);
  assert.equal(result.tickets['gpt-6-sol'].cached, false);
  assert.equal(upstream.hits[0].headers.cookie, undefined);
  assert.match(upstream.hits[1].headers.cookie, /__cflb=ws-pair/);
  const cached = await mintCall(port, { 'x-mint-transport': 'websocket' }, auth);
  assert.equal(JSON.parse(cached.body).attempts, 0);
  assert.equal(upstream.hits.length, 3);
});

test('WS 打票:票可从 codex.response.metadata 消息的 headers 取得(101 头不再携带)', async (t) => {
  const ticket = ticketOf(780);
  const f = await wsMintAttempt(t, () => ({
    ticketLen: 0, // 上游新形态:101 握手头不再带 x-codex-turn-state
    frames: [
      serverMintFrame(1, JSON.stringify({ type: 'codex.response.metadata',
        headers: { 'x-codex-turn-state': ticket, 'x-codex-plan-type': 'test' } })),
      serverMintFrame(1, JSON.stringify({ type: 'response.created', response: { id: 'ws-r1', model: 'gpt-6-sol' } })),
    ],
  }));
  const result = await f.attempt.done;
  assert.equal(result.reason, 'ok');
  assert.equal(result.ticket, ticket);
  assert.equal(result.len, 780);
  assert.equal(result.served, 'gpt-6-sol');
});

test('WS 打票:metadata 无票字段时仍判 no_ticket', async (t) => {
  const f = await wsMintAttempt(t, () => ({
    ticketLen: 0,
    frames: [
      serverMintFrame(1, JSON.stringify({ type: 'codex.response.metadata', headers: { 'x-models-etag': 'x' } })),
      serverMintFrame(1, JSON.stringify({ type: 'response.created', response: { id: 'ws-r1', model: 'gpt-6-sol' } })),
    ],
  }));
  const result = await f.attempt.done;
  assert.equal(result.reason, 'ok');
  assert.equal(result.ticket, '');
  assert.equal(result.len, 0);
});

for (const reject of [401, 400]) {
  test(`WS 打票:握手 HTTP ${reject} 沿用永久拒绝处理`, async (t) => {
    const upstream = websocketMintUpstream(() => ({ reject }));
    const uport = await serve(t, upstream.server);
    const port = await startRelay(t);
    withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
    const result = await mintCall(port, { 'x-mint-transport': 'websocket' });
    assert.equal(result.status, 502);
    assert.equal(upstream.hits.length, 1);
  });
}

test('严格模型事件:SSE 跨包忽略无关 model,只在完整 created 到达后提前断流', async (t) => {
  let closed;
  const detached = new Promise((resolve) => { closed = resolve; });
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { 'content-type': 'text/event-stream', 'x-codex-turn-state': ticketOf(780) });
    res.on('close', closed);
    res.write('data: {"type":"other","model":"wrong"}\n\n');
    const event = 'event: response.created\r\ndata: {"type":"response.created","response":{"id":"r1", "model": "gpt-6-sol"}}\r\n\r\n';
    res.write(event.slice(0, 81));
    setImmediate(() => res.write(event.slice(81)));
    // 不发 completed、不结束响应:客户端必须自行提前拆流。
  });
  const port = await serve(t, server);
  const cfg = { upstream: new URL(`http://127.0.0.1:${port}`), connectTimeoutMs: 200,
    mint: { transport: 'sse', attemptTimeoutMs: 300 } };
  const attempt = _internals.fireMintAttempt(cfg, '', { authorization: 'Bearer test' }, 'gpt-6-sol');
  t.after(() => attempt.req.destroy());
  const result = await attempt.done;
  assert.equal(result.reason, 'ok');
  assert.equal(result.served, 'gpt-6-sol');
  await detached;
});

test('WS 打票:先响应 ping 为掩码 pong,再等待模型事件', async (t) => {
  const f = await wsMintAttempt(t, () => ({
    frames: [serverMintFrame(9, 'alive')],
    onPong: (socket) => socket.write(serverMintFrame(1,
      JSON.stringify({ type: 'response.created', response: { id: 'r1', model: 'gpt-6-sol' } }))),
  }));
  const result = await f.attempt.done;
  assert.equal(result.reason, 'ok');
  assert.deepEqual(f.hits[0].pongs, ['alive']);
});

test('WS 打票:取消会关闭升级后的连接,不等待超时', async (t) => {
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const f = await wsMintAttempt(t, () => ({ silent: true, onCreate: started }));
  await ready;
  const closed = new Promise((resolve) => f.hits[0].socket.once('close', resolve));
  f.attempt.req.destroy();
  assert.equal((await f.attempt.done).reason, 'aborted');
  await closed;
});

test('WS 打票 TLS:钉 IP 仍按域名发送 SNI 并校验证书', async (t) => {
  const upstream = websocketMintUpstream(() => ({}), https.createServer({ key: TEST_KEY, cert: TEST_CERT }));
  const uport = await serve(t, upstream.server);
  const port = await spawnRelay(t, { RELAY_UPSTREAM: `https://chatgpt.com:${uport}`, MINT_TRANSPORT: 'websocket' });
  const result = await mintCall(port, { 'x-edge-ip': '127.0.0.1' });
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).transport, 'websocket');
  assert.equal(upstream.hits[0].headers.host, `chatgpt.com:${uport}`);
  assert.equal(upstream.hits[0].socket.servername, 'chatgpt.com');
});

test('WS 打票 TLS:受信证书与域名不匹配也必须拒绝', async (t) => {
  const upstream = websocketMintUpstream(() => ({}), https.createServer({ key: TEST_KEY, cert: TEST_CERT }));
  const port = await serve(t, upstream.server);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mint-ws-tls-'));
  const ca = path.join(dir, 'ca.pem');
  fs.writeFileSync(ca, TEST_CERT);
  const code = `const { _internals } = require(${JSON.stringify(path.join(__dirname, 'index.js'))});
    const cfg = { upstream: new URL('https://other.invalid:${port}'), connectTimeoutMs: 1000,
      mint: { transport: 'websocket', attemptTimeoutMs: 2000 } };
    _internals.fireMintAttempt(cfg, '127.0.0.1', { authorization: 'Bearer test' }, 'gpt-6-sol')
      .done.then(result => process.stdout.write(JSON.stringify(result)));`;
  const child = spawn(process.execPath, ['-e', code], { env: { ...process.env, NODE_EXTRA_CA_CERTS: ca } });
  t.after(() => { child.kill(); fs.rmSync(dir, { recursive: true, force: true }); });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (exitCode) => exitCode === 0 ? resolve() : reject(new Error(`child exit ${exitCode}`)));
  });
  assert.match(JSON.parse(output).reason, /ERR_TLS_CERT_ALTNAME_INVALID/);
  assert.equal(upstream.hits.length, 0);
});

test('WS 打票:模型声明匹配但握手没有票仍拒收重试', async (t) => {
  const upstream = websocketMintUpstream((i) => i === 0 ? { ticketLen: 0 } : {});
  const uport = await serve(t, upstream.server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const result = await mintCall(port, { 'x-mint-transport': 'websocket' });
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).attempts, 2);
  assert.equal(upstream.hits.length, 2);
});

test('WS 打票:缓存票有效而 pair 到期时单独补 pair', async (t) => {
  let now = Math.floor(Date.now() / 1000) * 1000;
  t.mock.method(Date, 'now', () => now);
  const upstream = websocketMintUpstream((i) => i === 0 ? { oailb: shortPair(1) } : { ticketLen: 0 });
  const uport = await serve(t, upstream.server);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const auth = 'Bearer ws-pair-expiry';
  const initial = await mintCall(port, { 'x-mint-transport': 'websocket' }, auth);
  now += 2000;
  const result = await mintCall(port, { 'x-mint-transport': 'websocket' }, auth);
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).turn_state, JSON.parse(initial.body).turn_state);
  assert.equal(JSON.parse(result.body).tickets['gpt-6-sol'].cached, true);
  assert.equal(upstream.hits[1].headers.cookie, undefined);
});

test('打票传输:非法 transport 立即返回 400,不回源', async (t) => {
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY });
  const result = await mintCall(port, { 'x-mint-transport': 'auto' });
  assert.equal(result.status, 400);
  assert.equal(JSON.parse(result.body).error.code, 'mint_bad_params');
});

for (const status of [401, 400, 429]) {
  test(`WS 打票:error 事件携带 ${status} 时保留状态供共同策略判定`, async (t) => {
    const f = await wsMintAttempt(t, () => ({ event: { type: 'error', status, error: { message: 'test' } } }));
    const result = await f.attempt.done;
    assert.equal(result.status, status);
    assert.equal(result.reason, 'ws_error_event');
    assert.equal(result.served, undefined);
  });
}

for (const frame of [
  Buffer.from([0xc1, 0]), // 未协商 RSV1
  Buffer.from([0x81, 0x80]), // 服务端不允许掩码
  Buffer.from([0x09, 0]), // 控制帧不能分片
  Buffer.from([0x89, 126]), // 控制帧不能超过 125 字节
  Buffer.from([0x81, 126, 0, 1, 0]), // 非最短长度编码
  Buffer.from([0x82, 0]), // 协议只允许文本事件
  Buffer.from([0x81, 126, 0x40, 1]), // 超过单帧上限
]) {
  test(`WS 帧边界:立即拒绝 ${frame.toString('hex')}`, () => {
    assert.throws(() => _internals.readMintWsFrame(frame));
  });
}

test('WS 帧边界:网络逐字节分包必须等到整帧', () => {
  const frame = serverMintFrame(1, 'x'.repeat(200));
  for (let i = 0; i < frame.length; i += 1) {
    assert.equal(_internals.readMintWsFrame(frame.subarray(0, i)), null);
  }
  assert.equal(_internals.readMintWsFrame(frame).payload.length, 200);
});

test('打票日志:哈希指纹不泄露票/Cookie,未知模型和网关不伪装成成功', () => {
  const ticket = ticketOf(780, Math.floor(Date.now() / 1000) - 22);
  const cookie = '__cflb=secret-cookie; __oailb=secret-cookie-token';
  const trace = _internals.mintAttemptTrace({ gateway: 'unified-199', cookie }, {
    ticket, len: 780, pairs: { __cflb: 'c', __oailb: 'o' }, gateway: 'unified-88', status: 200,
  });
  assert.equal(trace.ticket_age_s, 22);
  assert.equal(trace.served_model, '');
  assert.equal(trace.sent_gateway, 'unified-199');
  assert.equal(trace.received_gateway, 'unified-88');
  assert.equal(trace.ticket_fingerprint.length, 8);
  assert.ok(!JSON.stringify(trace).includes(ticket));
  assert.ok(!JSON.stringify(trace).includes('secret-cookie'));
  assert.notEqual(trace.ticket_fingerprint, ticket.slice(0, 8));
});

test('打票日志:定向打未发新 pair 时按发送 pair 的节点记账', () => {
  const ticket = ticketOf(780);
  const trace = _internals.mintAttemptTrace(
    { gateway: 'unified-125', cookie: '__cflb=a; __oailb=b' },
    { ticket, len: 780, pairs: null, gateway: '', status: 101, steered: true });
  assert.equal(trace.received_gateway, 'unified-125');
  const bare = _internals.mintAttemptTrace({ gateway: '', cookie: '' },
    { ticket, len: 780, pairs: null, gateway: '', status: 101 });
  assert.equal(bare.received_gateway, '');
});

// 真实故障回归：只连假上游，不能用线上反复打票验证重试限制。
test('修复回归:跨轮总预算耗尽后有限失败并记录验收原因', { timeout: 1500 }, async (t) => {
  const logs = [];
  t.mock.method(console, 'log', (line) => logs.push(JSON.parse(line)));
  const f = await mintBoundaryFixture(t, () => ({ gateway: 'unified-125', served: null }));
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '3', MINT_RETRY_COOLDOWN_MS: '1' });
  const result = await f.request();
  assert.equal(result.status, 502);
  assert.equal(result.body.error.code, 'mint_exhausted');
  assert.equal(result.body.error.attempts, 3);
  assert.equal(f.hits.length, 3);
  assert.match(result.body.error.message, /total_attempt_limit/);
  const trace = logs.find((line) => line.event === 'mint_attempt');
  assert.equal(trace.wanted_gateway, 'unified-88');
  assert.equal(trace.requested_model, 'gpt-6-sol');
  assert.equal(trace.reject_reason, 'gateway:unified-125');
});

test('修复回归:默认总上限不能被每轮请求头放大', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ gateway: 'unified-125' }));
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: undefined, MINT_RETRY_COOLDOWN_MS: '1' });
  const result = await f.request({ 'x-mint-attempts': '128' });
  assert.equal(result.status, 502);
  assert.equal(f.hits.length, 24);
  assert.equal(result.body.error.attempts, 24);
});

test('修复回归:总截止时间终止冷却，不依赖客户端断连', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ status: 429 }));
  withEnv(t, { MINT_TOTAL_TIMEOUT_MS: '40', MINT_RETRY_COOLDOWN_MS: '30000' });
  const result = await f.request({ 'x-mint-attempts': '1' });
  assert.equal(result.status, 502);
  assert.match(result.body.error.message, /total_timeout/);
  assert.equal(f.hits.length, 1);
});

test('修复回归:总截止时间销毁正在读取的上游 SSE', { timeout: 1500 }, async (t) => {
  let upstreamClosed;
  const closed = new Promise((resolve) => { upstreamClosed = resolve; });
  const upstream = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(': waiting\n\n');
    res.on('close', upstreamClosed);
  });
  const upstreamPort = await serve(t, upstream);
  const port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${upstreamPort}`,
    MINT_TOTAL_TIMEOUT_MS: '40', MINT_ATTEMPT_TIMEOUT_MS: '5000' });
  const result = await mintCall(port);
  assert.equal(result.status, 502);
  assert.match(JSON.parse(result.body).error.message, /total_timeout/);
  assert.equal(JSON.parse(result.body).error.errors['gpt-6-sol'].attempts, 1);
  await closed;
});

test('修复回归:预算最后一发成功可接受，多模型共用总预算', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i === 0 ? {} : { status: 429 });
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '2', MINT_RETRY_COOLDOWN_MS: '1' });
  const result = await f.request({ 'x-mint-models': 'gpt-6-sol,gpt-6-luna' });
  assert.equal(result.status, 200);
  assert.equal(result.body.attempts, 2);
  assert.deepEqual(Object.keys(result.body.tickets), ['gpt-6-sol']);
  assert.ok(result.body.errors['gpt-6-luna']);
  assert.equal(f.hits.length, 2);
});

test('修复回归:打票载荷携带 Codex 必需的 instructions', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  assert.equal((await f.request()).status, 200);
  assert.equal(JSON.parse(f.hits[0].body).instructions, '');
});

test('修复回归:HTTP 200 中的永久 SSE 错误只试一次且日志不泄露正文', { timeout: 1500 }, async (t) => {
  const logs = [];
  t.mock.method(console, 'log', (line) => logs.push(JSON.parse(line)));
  const body = 'data: ' + JSON.stringify({ type: 'error', error: {
    code: 'invalid_request_error', message: 'secret-account-token instructions missing',
  } }) + '\n\n';
  const f = await mintBoundaryFixture(t, () => ({ body }));
  withEnv(t, { MINT_RETRY_COOLDOWN_MS: '1' });
  const result = await f.request();
  assert.equal(result.status, 502);
  assert.equal(f.hits.length, 1);
  assert.equal(result.body.error.last.reason, 'sse_error:invalid_request_error');
  assert.ok(!JSON.stringify(logs).includes('secret-account-token'));
  assert.ok(!JSON.stringify(result).includes('secret-account-token'));
});

test('修复回归:最后一次预算命中仍返回有效票', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '1' });
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.equal(result.body.attempts, 1);
});

test('修复回归:缓存票的补 pair 同样受总预算限制', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i === 0 ? { oailb: shortPair(1) } : { gateway: 'unified-125' });
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '2', MINT_RETRY_COOLDOWN_MS: '1' });
  assert.equal((await f.request()).status, 200);
  f.advance(2);
  const result = await f.request();
  assert.equal(result.status, 502);
  assert.equal(result.body.error.attempts, 2);
  assert.equal(f.hits.length, 3);
  assert.match(result.body.error.message, /no live target pair.*total_attempt_limit/);
});

test('修复回归:网关相同但无模型字段，有限失败且绝不伪造成功', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ served: null }));
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '2' });
  const result = await f.request();
  assert.equal(result.status, 502);
  assert.equal(result.body.error.last.why, 'no_model_field');
  assert.equal(f.hits.length, 2);
});

test('修复回归:失败请求的预算不会污染后续调用或有效缓存', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, (i) => i < 2 ? { gateway: 'unified-125' } : {});
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '2' });
  assert.equal((await f.request()).status, 502);
  assert.equal((await f.request()).status, 200);
  const cached = await f.request();
  assert.equal(cached.status, 200);
  assert.equal(cached.body.attempts, 0);
  assert.equal(f.hits.length, 3);
});

test('修复回归:成功返回后不遗留调用总截止计时器', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  withEnv(t, { MINT_TOTAL_TIMEOUT_MS: '73456' });
  const schedule = global.setTimeout, clear = global.clearTimeout;
  const timers = new Set();
  t.mock.method(global, 'setTimeout', (callback, delay, ...args) => {
    const timer = schedule(callback, delay, ...args);
    if (delay === 73456) timers.add(timer);
    return timer;
  });
  t.mock.method(global, 'clearTimeout', (timer) => { timers.delete(timer); clear(timer); });
  assert.equal((await f.request()).status, 200);
  assert.equal(timers.size, 0);
});

test('修复回归:模拟 FC 保留连接，外部调用方断开后仍由服务端预算终止', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ gateway: 'unified-125' }));
  withEnv(t, { MINT_TOTAL_TIMEOUT_MS: '50', MINT_RETRY_COOLDOWN_MS: '30000' });
  let started;
  const invoked = new Promise((resolve) => { started = resolve; });
  let ended;
  const completed = new Promise((resolve) => { ended = resolve; });
  const gateway = http.createServer((req, res) => {
    // 刻意不将外部 close 传给 relay，重现 HTTP 触发器保持内部请求的情形。
    const inner = http.request({ host: '127.0.0.1', port: f.port, method: 'POST', headers: {
      'x-relay-key': RELAY_KEY, 'x-relay-mint': 'unified-88', 'x-mint-model': 'gpt-6-sol',
      'x-mint-attempts': '1', authorization: f.auth,
    } }, (upstream) => {
      let body = '';
      upstream.on('data', (chunk) => { body += chunk; });
      upstream.on('end', () => { ended({ status: upstream.statusCode, body }); res.end(); });
    });
    inner.on('error', (error) => ended({ error: error.code }));
    inner.end();
    started();
  });
  const port = await serve(t, gateway);
  const outer = http.get({ host: '127.0.0.1', port });
  outer.on('error', () => {});
  await invoked;
  outer.destroy();
  const result = await completed;
  assert.equal(result.status, 502);
  assert.match(result.body, /total_timeout/);
  assert.equal(f.hits.length, 1);
});

for (const kind of ['deadline', 'attempts', 'terminal_event']) {
  test(`修复回归:WS 共用生命周期限制 ${kind}`, { timeout: 1500 }, async (t) => {
    const upstream = websocketMintUpstream(() => kind === 'deadline' ? { silent: true }
      : kind === 'attempts' ? { model: 'fallback' }
        : { event: { type: 'response.failed', response: { error: { code: 'invalid_request_error' } } } });
    const uport = await serve(t, upstream.server);
    const port = await startRelay(t);
    withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}`,
      MINT_MAX_TOTAL_ATTEMPTS: '2', MINT_TOTAL_TIMEOUT_MS: kind === 'deadline' ? '40' : '1000' });
    const result = await mintCall(port, { 'x-mint-transport': 'websocket' });
    assert.equal(result.status, 502);
    assert.equal(upstream.hits.length, kind === 'attempts' ? 2 : 1);
    const parsed = JSON.parse(result.body);
    if (kind === 'deadline') assert.match(parsed.error.message, /total_timeout/);
    if (kind === 'terminal_event') assert.equal(parsed.error.last.reason, 'ws_error:invalid_request_error');
    assert.equal(upstream.hits[0].payload.instructions, '');
  });
}

test('修复回归:SSE 错误发生在同包 created 之前，不能跳过错误验收', { timeout: 1500 }, async (t) => {
  const failed = { type: 'error', error: { code: 'invalid_request_error' } };
  const created = { type: 'response.created', response: { id: 'r', model: 'gpt-6-sol' } };
  const f = await mintBoundaryFixture(t, () => ({ body: `data: ${JSON.stringify(failed)}\n\ndata: ${JSON.stringify(created)}\n\n` }));
  assert.equal((await f.request()).status, 502);
  assert.equal(f.hits.length, 1);
});

test('修复回归:SSE 429 事件仍可重试，未知错误码不会泄露', { timeout: 1500 }, async (t) => {
  const logs = [];
  t.mock.method(console, 'log', (line) => logs.push(JSON.parse(line)));
  const body = 'data: ' + JSON.stringify({ type: 'error', status: 429, error: { code: 'SECRET_AS_ERROR_CODE' } }) + '\n\n';
  const f = await mintBoundaryFixture(t, (i) => i === 0 ? { body } : {});
  const result = await f.request();
  assert.equal(result.status, 200);
  assert.equal(f.hits.length, 2);
  assert.ok(!JSON.stringify(logs).includes('SECRET_AS_ERROR_CODE'));
});

test('修复回归:预算耗尽时尚未尝试的模型也有明确错误', { timeout: 1500 }, async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '1' });
  const result = await f.request({ 'x-mint-models': 'gpt-6-sol,gpt-6-luna,gpt-6-astra' });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body.tickets), ['gpt-6-sol']);
  assert.equal(result.body.errors['gpt-6-astra'].last.why, 'total_attempt_limit');
  assert.equal(result.body.errors['gpt-6-astra'].attempts, 0);
  assert.equal(f.hits.length, 1);
});

test('修复回归:调用总时限有安全默认及硬上限，请求头不能扩大', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({}));
  withEnv(t, { MINT_TOTAL_TIMEOUT_MS: undefined });
  const delays = [];
  const schedule = global.setTimeout;
  t.mock.method(global, 'setTimeout', (fn, delay, ...args) => {
    delays.push(delay);
    return schedule(fn, delay, ...args);
  });
  for (const [value, expected] of [[undefined, 75000], ['not-a-number', 75000], ['9999999999', 180000], ['0', 1]]) {
    if (value === undefined) delete process.env.MINT_TOTAL_TIMEOUT_MS;
    else process.env.MINT_TOTAL_TIMEOUT_MS = value;
    delays.length = 0;
    await f.request({ 'x-mint-total-timeout-ms': '9999999999' });
    assert.ok(delays.includes(expected), `总时限应为 ${expected}`);
  }
});

for (const transport of ['sse', 'websocket']) {
  test(`修复回归:无数值状态的认证错误也整单终止 ${transport}`, { timeout: 1500 }, async (t) => {
    const event = { type: 'error', error: { code: 'invalid_api_key' } };
    const upstream = transport === 'sse'
      ? mintUpstream(() => ({ body: `data: ${JSON.stringify(event)}\n\n` }))
      : websocketMintUpstream(() => ({ event }));
    const uport = await serve(t, upstream.server);
    const port = await startRelay(t);
    withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
    const result = await mintCall(port, { 'x-mint-transport': transport, 'x-mint-models': 'gpt-6-sol,gpt-6-luna' });
    assert.equal(result.status, 502);
    assert.equal(JSON.parse(result.body).error.code, 'mint_rejected');
    assert.equal(JSON.parse(result.body).error.upstream_status, 401);
    assert.equal(upstream.hits.length, 1);
  });
}

function testSeedCookie(gateway = 'unified-15', expires = Date.now() / 1000 + 300) {
  return `__cflb=seed-lb; __oailb=${fakeJwt({ exp: Math.floor(expires), aud: `chat.gateway.${gateway}.api.openai.com` })}`;
}

test('带 Cookie 打票:首发使用输入 pair，未返回新 pair 仍可验收且不泄露其他 Cookie', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ gateway: null }));
  const seed = testSeedCookie();
  const result = await f.request({ 'x-relay-mint': 'unified-15', cookie: seed + '; __cf_bm=private; session=secret' });
  assert.equal(result.status, 200);
  assert.equal(result.body.gateway, 'unified-15');
  assert.equal(f.hits.length, 1);
  assert.equal(f.hits[0].headers.cookie, seed);
  assert.equal(result.body.cookie_header, seed);
  assert.equal(result.body.attempt_log[0].sent_gateway, 'unified-15');
});

for (const [label, cookie] of [
  ['缺半对', '__cflb=seed'], ['过期', testSeedCookie('unified-15', 1)],
  ['非目标', testSeedCookie('unified-94')], ['无有效期', '__cflb=seed; __oailb=unified-15'],
  ['重复值', testSeedCookie() + '; __cflb=second'],
]) {
  test(`带 Cookie 打票:拒绝${label}，不偷偷裸打`, async (t) => {
    const f = await mintBoundaryFixture(t, () => ({}));
    const result = await f.request({ 'x-relay-mint': 'unified-15', cookie });
    assert.equal(result.status, 400);
    assert.equal(result.body.error.code, 'mint_bad_cookie');
    assert.equal(f.hits.length, 0);
    assert.ok(!JSON.stringify(result.body).includes(cookie));
  });
}

test('带 Cookie 打票:上游轮换到错误节点即停止，不退回裸打', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ gateway: 'unified-125' }));
  const result = await f.request({ 'x-relay-mint': 'unified-15', cookie: testSeedCookie() });
  assert.equal(result.status, 502);
  assert.equal(f.hits.length, 1);
  assert.equal(result.body.error.last.why, 'gateway:unified-125');
});

test('带 Cookie 打票:不同输入 pair 隔离缓存', async (t) => {
  const f = await mintBoundaryFixture(t, () => ({ gateway: null }));
  const seed = testSeedCookie();
  const first = await f.request({ 'x-relay-mint': 'unified-15', cookie: seed });
  const second = await f.request({ 'x-relay-mint': 'unified-15', cookie: seed.replace('seed-lb', 'other-lb') });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(f.hits.length, 2);
});

test('带 Cookie 打票:WS 首次握手同样带 pair，不要求重新签发路由 Cookie', async (t) => {
  const upstream = websocketMintUpstream(() => ({ pair: false }));
  const uport = await serve(t, upstream.server), port = await startRelay(t);
  withEnv(t, { RELAY_KEY, RELAY_UPSTREAM: `http://127.0.0.1:${uport}` });
  const cookie = testSeedCookie();
  const result = await mintCall(port, { 'x-relay-mint': 'unified-15', 'x-mint-transport': 'websocket', cookie });
  assert.equal(result.status, 200);
  assert.equal(upstream.hits[0].headers.cookie, cookie);
  assert.equal(JSON.parse(result.body).gateway, 'unified-15');
});

test('带 Cookie 打票:读取响应期间 seed 过期立即停止', async (t) => {
  const f = await mintBoundaryFixture(t, (i, hit, advance) => { advance(3); return { gateway: null }; });
  const result = await f.request({ 'x-relay-mint': 'unified-15', cookie: testSeedCookie('unified-15', Date.now()/1000+1) });
  assert.equal(result.status, 502);
  assert.equal(f.hits.length, 1);
});

test('带 Cookie 打票:模型声明缺失仍拒收，TTL=0 每次重新带 seed', async (t) => {
  const f = await mintBoundaryFixture(t, (i) => ({ gateway: null, served: i === 0 ? null : 'gpt-6-sol' }));
  withEnv(t, { MINT_MAX_TOTAL_ATTEMPTS: '1' });
  const cookie = testSeedCookie();
  const header = { 'x-relay-mint': 'unified-15', 'x-mint-ttl': '0', cookie };
  const rejected = await f.request(header);
  assert.equal(rejected.status, 502);
  assert.equal(rejected.body.error.last.why, 'no_model_field');
  assert.equal((await f.request(header)).status, 200);
  assert.equal((await f.request(header)).status, 200);
  assert.equal(f.hits.length, 3);
  assert.ok(f.hits.every(hit => hit.headers.cookie === cookie));
});
