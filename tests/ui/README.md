# 云打票面板验收

面板不是另搭的戏台，而是插件内嵌的 `go/cloud_mint_ui.html`，宿主在 `/v0/resource/plugins/<plugin-id>/dashboard`
下服务，并在服务时把 `cpa-plugin-id` 的占位值重写为真实插件 id。以下请 Playwright
headless chromium 当验票员：加载真实页面、拦截并伪造管理接口，只查浏览器到接口的契约，CPA 和上游不来客串。

```bash
npm i -D playwright && npx playwright install --with-deps chromium
node tests/ui/cloud-mint-production.test.cjs
node tests/ui/cloud-mint-example.test.cjs
```

- `cloud-mint-production.test.cjs` 加载线上页面在本地对戏，即 `cloud_mint_ui.html`：能力边界文案、鉴权后取数、
  真实载荷渲染（票与任务、全局路由池、灌池状态、请求日志）、草稿保留、PATCH 浅合并、
  保存确认、校验、XSS、陈旧态、密钥清理、移动端不横向溢出。
- `cloud-mint-example.test.cjs` 校验设计稿有没有乱加戏，检查 `design/cloud-mint-example.html`：只保留云打票与设置，
  无无关导航；密钥只提供环境变量名，不出现密码/令牌输入框；筛选、前置代理互斥与校验等。

这套检查只给浏览器到接口的契约验票；真实 CPA 插件加载和线上上游测试另有考场，不能拿这张收据冒充。
