# codex-turn-state-cloud-mint

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）原生插件 + 阿里云函数计算（FC）打票中继：为 Codex 业务请求在线铸取 `X-Codex-Turn-State` 票和 `__cflb`/`__oailb` 路由 Cookie，并在宿主选定凭据后注入。

**产品边界：有限取票＋路由复用＋协议校验。** 票长 780 仅是格式要求，`response.model` 仅是上游模型声明，`unified-N` 仅用于路由判断；这些信息均不证明模型实际能力，不提供"满血"鉴定或隐性降级过滤。

插件 ID：`codex-turn-state-cloud-mint`（由 .so 文件名派生）· 构建目标：`linux/amd64`、`linux/arm64` · 许可：[MIT](LICENSE)

---

## 架构总览

```text
                ┌─────────────────────────── CPA ───────────────────────────┐
 下游客户端 ───▶ │ 调度器选中 Codex 凭据                                     │
                │      │                                                    │
                │      ▼ request.intercept_after                            │
                │ codex-turn-state-cloud-mint.so                            │
                │   1. 归属判定：selected_auth_index/id → 宿主凭据目录       │
                │      校验 provider==codex（非 Codex 流量原样放行）         │
                │   2. 向 FC 打票（携带该凭据 access_token）                │
                │   3. 验收后注入 X-Codex-Turn-State + __cflb/__oailb       │
                │      票未就绪 → 503 cloud_mint_unavailable (Retry-After)  │
                └──────┼────────────────────────────────────────────────────┘
                       │ HTTPS + X-Relay-Key
                       ▼
              FC Web 函数（relay/index.js，零依赖 Node.js）
                │ 以 chatgpt.com 身份回源：SSE 或 WebSocket 发 codex ping
                │ 验收票长 / 目标网关 / response.created 模型声明 / 有效期
                ▼
              Cloudflare 边缘 ──▶ chatgpt.com
```

业务流量仍走 CPA 原有出口；FC 只是打票控制面，不在业务数据路径上。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `go/` | CPA 原生插件源码（CGO `c-shared`），构建产物 `codex-turn-state-cloud-mint.so` |
| `relay/` | FC 函数：[`index.js`](relay/index.js) 单文件零依赖，含打票端点与透明中继；[`s.yaml`](relay/s.yaml) Serverless Devs 部署描述 |
| `scripts/` | [`build.sh`](scripts/build.sh)（Docker 交叉编译）、[`mint_once.sh`](scripts/mint_once.sh)（手动打票诊断）、WS 续链探测与原生 ABI 验证脚本 |
| `tests/ui/` | 管理面板浏览器契约检查与切片单测 |
| `design/` | 面板设计稿与 UI 测试 fixture |
| `relay/CPA.md` | **插件接入与打票协议约定**（配置、503 恢复边界、日志） |
| `relay/README.md` | **FC 函数文档**（打票端点、传输、缓存、部署、平台约束） |
| `FINDINGS.md` | 路由 Cookie / 网关行为的实测记录 |
| `HANDOFF.md` | 复现与验证方法 |

## 快速开始

### 1. 部署 FC 打票函数

```bash
cd relay
export RELAY_KEY="$(openssl rand -hex 32)"
s deploy -y        # Serverless Devs 3.x；或按 relay/README.md 控制台手动部署
```

记下 HTTP 触发器地址。完整部署说明（地域、透明模式、固定出口 IP）：[relay/README.md](relay/README.md#部署)。

### 2. 构建插件

```bash
bash scripts/build.sh          # linux/<本机架构>
GOARCH=arm64 bash scripts/build.sh   # 交叉编译 arm64
```

产物：`build/linux/<arch>/codex-turn-state-cloud-mint.so`。只需 Docker，不需要本机 Go。

### 3. 安装并配置

把 `.so` 放进 CPA 插件目录，把 [config.example.yaml](config.example.yaml) 合并进 `plugins.configs`（键名必须是 `codex-turn-state-cloud-mint`），并把 `CPA_RELAY_KEY` 注入 **CPA 进程环境**——与 FC 的 `RELAY_KEY` 同值，配置里只写变量名。

建议顺序：`dry_run: true` 看决策日志确认归属判定 → `false` 生效。面板在 `/v0/resource/plugins/codex-turn-state-cloud-mint/dashboard`。

> **不要同时加载** `codex-turn-state.so` 与本插件：扫描目录只放一个，替换后受控重启 CPA。

### 4. 拦截判定（简述）

云端模式下，插件只动**已确认归属 Codex** 的请求：

- `selected_auth_index`/`selected_auth_id` → `host.auth.get_runtime` 校验 provider 为 `codex`；归属不明或非 Codex 一律原样放行——**不会**把凭据发到其他上游，也不借用其他账号的票。
- 请求已自带 `X-Codex-Turn-State` 或 `dry_run` → 放行。
- 已确认 Codex 但票未就绪 / 验收失败 → `503 cloud_mint_unavailable` + `Retry-After: 2`，不用别的票顶替。

`cloud_mint.enabled: false` 时退化为路由 Cookie 池模式：归属判定走同一套凭据目录校验（provider/type 优先，目录不可读才退回文件名约定），然后把池中存活最久的 `__cflb`/`__oailb` 合并进请求 `Cookie`。完整规则见 [relay/CPA.md](relay/CPA.md)。

## 安全边界

- **密钥**：`RELAY_KEY`/`CPA_RELAY_KEY` 只走环境变量；代理 URL 含密码时放 `CPA_MINT_PROXY` 环境变量，经 `proxy_env` 引用。不要写进 YAML、URL、日志或仓库。
- **凭据**：插件只读宿主已选中账号的凭据文件（`host.auth.get`），不刷新 OAuth、不写账号文件；FC 是凭据代理，`X-Relay-Key` 泄露即轮换。
- **SSRF/泄漏**：FC 只剥不放——剥 `x-fc-*`、身份头、中继控制头；`X-Edge-IP` 只收公网 IP 字面量。
- **凭据文件**：`codex-*.json` 已被 `.gitignore` 拦截，永远不入库。

## 测试

```bash
# 插件单测（Docker 内）
docker run --rm -v "$PWD/go":/src -v "$PWD/.gocache":/gocache -w /src \
  -e CGO_ENABLED=1 -e GOCACHE=/gocache/build -e GOMODCACHE=/gocache/mod \
  golang:1.26 go test ./...

# 原生 ABI 端到端（本地虚构宿主与 FC，不碰真实上游）
NATIVE_PLUGIN_PATH=build/linux/amd64/codex-turn-state-cloud-mint.so \
  python3 scripts/test_native_cloud_recovery.py

# FC 函数测试（零依赖，只连本机）
cd relay && node --test

# 面板（云打票 dashboard，Playwright headless）
node tests/ui/cloud-mint-production.test.cjs
node tests/ui/cloud-mint-example.test.cjs
```

## License

[MIT](LICENSE)
