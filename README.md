# codex-turn-state-cloud-mint

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）原生插件 + 阿里云函数计算（FC）打票中继：为 Codex 业务请求在线铸取 `X-Codex-Turn-State` 票和 `__cflb`/`__oailb` 路由 Cookie，并在宿主选定凭据后注入——场面看着像开武馆，正经营生却只是发门票。

**产品边界：有限取票＋路由复用＋协议校验。** 票长 780 仅是格式要求，`response.model` 仅是上游模型声明，`unified-N` 仅用于路由判断；这些信息只是门票与名牌,不是模型实际能力的武状元证书，不提供"满血"鉴定或隐性降级过滤——门票写着大侠，不等于持票人真会轻功；这里只查票，不替武功作保。

这位跑堂的名牌是插件 ID：`codex-turn-state-cloud-mint`（由 .so 文件名派生）· 构建目标：`linux/amd64`、`linux/arm64` · 许可：[MIT](LICENSE)

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

FC 把算盘拨得震天响，也只管取票这张小柜台；业务流量仍走 CPA 原有出口，
不经过 FC 这条控制面。厨子没有改行，酒菜也没有绕道。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `go/` | CPA 原生插件的后台剧本（CGO `c-shared`），构建产物 `codex-turn-state-cloud-mint.so` |
| `relay/` | FC 打票柜台：[`index.js`](relay/index.js) 单文件零依赖，含打票端点与透明中继；[`s.yaml`](relay/s.yaml) Serverless Devs 部署描述 |
| `scripts/` | [`build.sh`](scripts/build.sh)（Docker 交叉编译）、[`mint_once.sh`](scripts/mint_once.sh)（手动打票诊断）、WS 续链探测与原生 ABI 验证脚本 |
| `tests/ui/` | 管理面板的验票员：浏览器契约检查与切片单测 |
| `design/` | 面板定妆稿与 UI 测试 fixture 替身 |
| `relay/CPA.md` | **插件入场手续与打票协议约定**（配置、503 恢复边界、日志） |
| `relay/README.md` | **FC 柜台办事手册**（打票端点、传输、缓存、部署、平台约束） |
| `FINDINGS.md` | 路由 Cookie / 网关行为的实测记录——跑堂不靠记性，按实测留下流水账 |
| `HANDOFF.md` | 复现与验证的对戏方法 |

## 快速开始

### 1. 部署 FC 打票函数

```bash
cd relay
export RELAY_KEY="$(openssl rand -hex 32)"
s deploy -y        # Serverless Devs 3.x；或按 relay/README.md 控制台手动部署
```

先收好 HTTP 触发器地址：掌柜就算认得你，也得先找得到店门。完整部署说明（地域、透明模式、固定出口 IP）：[relay/README.md](relay/README.md#部署)。

### 2. 构建插件

```bash
bash scripts/build.sh          # linux/<本机架构>
GOARCH=arm64 bash scripts/build.sh   # 交叉编译 arm64
```

产物：`build/linux/<arch>/codex-turn-state-cloud-mint.so`。只需 Docker，不需要本机 Go——灶台借 Docker 的，本机不必另请 Go 大厨。

#### 用 GitHub Actions 构建

本机不想摆灶台，就让 GitHub 代班。[构建工作流](.github/workflows/build-plugin.yml) **仅手动触发**，一次分别构建 `linux/amd64` 和 `linux/arm64`；不会因 push / PR 自动开工，也不会发布 Release 或部署到服务器。

1. 将工作流随代码提交到 GitHub 仓库的**默认分支**，并启用 Actions；没有这张开工单，按钮不会凭空冒出来。默认分支要求见 [GitHub 手动运行说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)。
2. 打开仓库 **Actions → Build plugin → Run workflow**，选择要构建的分支，再点击 **Run workflow**。
3. 等对应架构的任务成功，在本次运行页面的 **Artifacts** 下载所需包：
   - `codex-turn-state-cloud-mint-linux-amd64`：x86-64 CPA 主机。
   - `codex-turn-state-cloud-mint-linux-arm64`：ARM64 CPA 主机。
4. 解压下载包，在其中执行校验，再按下一节安装 `.so`。两种架构的插件文件同名，别解压到一起让两位师傅抢一个工牌。

```bash
sha256sum --check SHA256SUMS
```

每份包只含 `codex-turn-state-cloud-mint.so` 和 `SHA256SUMS`，设置保留 **14 天**（受仓库保留策略约束）。工作流复用 `scripts/build.sh`：在 Ubuntu x86-64 runner 上用 Go 1.26 Docker 镜像构建，arm64 通过容器内交叉编译器生成，不依赖 ARM runner。amd64 任务先运行 Go 单测；arm64 任务只交叉构建，不冒充已在 ARM 主机验过货。

工作流只申请 `contents: read`，无需配置业务 token、relay key 或部署密钥；Action 版本固定到提交 SHA。不自动发布不等于不用算账：构建会占用 Actions 配额，最终仍需在目标 CPA 主机确认架构、动态库及原生 ABI 兼容性，下载到票不等于已经进场。

### 3. 安装并配置

把 `.so` 放进 CPA 插件目录，把 [config.example.yaml](config.example.yaml) 合并进 `plugins.configs`（键名必须是 `codex-turn-state-cloud-mint`），并把 `CPA_RELAY_KEY` 注入 **CPA 进程环境**——与 FC 的 `RELAY_KEY` 同值，配置里只写变量名，纸上只许写钥匙柜编号，不许把钥匙拓印一份。

建议顺序：`dry_run: true` 看决策日志确认归属判定 → `false` 生效——先让替身走位，确认没撞桌角再开拍。面板在 `/v0/resource/plugins/codex-turn-state-cloud-mint/dashboard`。

> **不要同时加载** `codex-turn-state.so` 与本插件：同一柜台别坐两个掌柜；扫描目录只放一个，替换后受控重启 CPA。

### 4. 拦截判定（简述）

云端模式下，插件只动**已确认归属 Codex** 的请求——身份没认准就不伸手，免得把送菜的当成来买票的：

- `selected_auth_index`/`selected_auth_id` → `host.auth.get_runtime` 校验 provider 为 `codex`；归属不明或非 Codex 一律原样放行——**不会**把凭据发到其他上游，也不借用其他账号的票，账本各记各的，不能拿隔壁桌的账单来结账。
- 请求已自带 `X-Codex-Turn-State` 或 `dry_run` → 放行——客人自己带了票，柜台就别抢着盖第二个章。
- 已确认 Codex 但票未就绪 / 验收失败 → `503 cloud_mint_unavailable` + `Retry-After: 2`，不用别的票顶替——柜台空了就亮停业牌，不能拿隔壁客人的票充数。

`cloud_mint.enabled: false` 时退化为路由 Cookie 池模式：归属判定走同一套凭据目录校验（provider/type 优先，目录不可读才退回文件名约定），然后把池中存活最久的 `__cflb`/`__oailb` 合并进请求 `Cookie`——房卡池先派活得最久的那位老伙计出门。完整规则见 [relay/CPA.md](relay/CPA.md)。

## 安全边界

- **密钥**：`RELAY_KEY`/`CPA_RELAY_KEY` 只走环境变量；代理 URL 含密码时放 `CPA_MINT_PROXY` 环境变量，经 `proxy_env` 引用。不要写进 YAML、URL、日志或仓库——钥匙不能当传单发，路过的鸽子也不该捡到一把。
- **凭据**：插件只读宿主已选中账号的凭据文件（`host.auth.get`），不刷新 OAuth、不写账号文件；FC 是凭据代理，`X-Relay-Key` 泄露即轮换——钥匙一旦走失，别问它想不想家，直接换锁。
- **SSRF/泄漏**：FC 只剥不放——剥 `x-fc-*`、身份头、中继控制头；`X-Edge-IP` 只收公网 IP 字面量——跑堂只送到公网，不能客人指着后院就把账房门撞开。
- **凭据文件**：`codex-*.json` 已被 `.gitignore` 拦截，不入仓库这道门，哪怕它自称来串门。

### 自己审核并推送 main

[`scripts/push_main.py`](scripts/push_main.py) 是送稿员，不是自动发货机：默认只做本地检查；只有显式加 `--push`，并在最后输入 `PUSH main`，才会向 `spumon1/SUCK_MY_ASTRA` 的 `main` 普通推送，绝不 force。

准备 Python 3、Git 和 [Gitleaks 8.19+](https://github.com/gitleaks/gitleaks#installing)，并准备好自己的 GitHub 推送权限。扫描器没装、报错或发现疑似秘密都会停工，不会改成“睁一只眼也算验票”。

```bash
# 先检查：不提交、不连接远端、不推送。
python3 scripts/push_main.py --check

# Gitleaks 不在 PATH 时，两个模式都可加 --gitleaks /path/to/gitleaks。
# 检查通过后自己执行；审核临时副本，最后输入 PUSH main 才真正推送。
python3 scripts/push_main.py --push
```

若提示 `git push` 的 HTTPS 认证凭据不可用，先自行执行 `gh auth login --hostname github.com --git-protocol https --web`，在浏览器完成授权，再用 `gh auth status --hostname github.com` 确认登录并重试。没有 GitHub CLI 时可配置自己的 Git 凭据助手；不要把 token 写进远端 URL、源码或命令参数。脚本会在最终确认前执行 `push --dry-run` 预检查，不更新远端；预检查通过也不等于绕过了分支保护或取得了所有写权限。

- 只导出白名单源码、文档和工作流；不新增上传账号文件、`.env`、构建缓存、二进制及截图，不自动同步删除。截图可能把钥匙拍进去，不能拿文本扫描当照妖镜。
- 不推当前分支的提交历史。脚本另建临时副本，以远端已有 `main` 为父提交，将当前选中文件覆盖为一个新提交；原工作区、分支与暂存区不动。远端 `main` 不存在或同时被别人推进，就停下来，不擅自创建、覆盖或强推。
- 默认提交署名为 `spumon1 <spumon1@users.noreply.github.com>`；可用 `--author-name`、`--author-email` 修改，邮箱只接受 GitHub noreply 地址。个人邮箱不必陪源码一起出门。
- 发布前后都扫描：先查导出快照，再查真正提交的文件及提交信息；报告只展示位置和规则，不回显秘密。固定的本机 TLS 测试私钥与 RFC WebSocket 示例 nonce 仅按**精确内容哈希及文件位置**认作公开道具，不豁免整个测试文件。
- 发现命中时先在本地审查并替换，再重新运行。临时审核目录保留供检查，里面可能有扫描命中的内容，不要上传它；远端已有图片和历史不属于清理范围。扫描无法保证发现所有凭据或隐私，最终推送前仍须人工审核差异。

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
