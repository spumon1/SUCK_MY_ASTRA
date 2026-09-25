'use strict';
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 try {
  const pluginID=process.env.CLOUD_PLUGIN_ID||'codex-turn-state';
  const page=await browser.newPage({viewport:{width:1440,height:1100},deviceScaleFactor:1.5});
  let config={enabled:true,role:'business',dry_run:false,other_plugin_field:'keep',cloud_mint:{enabled:true,url:'https://HOST/',proxy_env:'CPA_MINT_PROXY',future_field:'keep',transport:'sse',gateway:'unified-88',key_env:'CPA_RELAY_KEY',ticket_length:780,ttl_seconds:240,wait_ms:2000,timeout_ms:90000}};
  const logs=[{at:new Date().toISOString(),kind:'业务回源观测',message:'cookie-780 · 票长 780 · #hPdTPIqq · unified-199 · 得到 unified-88 · 票长 780 · #Y89E_-KZ · 这张票龄 22s · 未见模型 · 网关变化'}];
  const rows=[{account:'D2q8fLk1',model:'gpt-6-sol',transport:'sse',state:'ready',gateway:'unified-88',fingerprint:'Y89E_-KZ',length:780,seconds_left:218}];
  const errors=[],patches=[];let statusRequests=0,deny=false,omitCloudConfigOnce=true;
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(url.pathname.endsWith('/dashboard'))return route.fulfill({contentType:'text/html',body:fs.readFileSync(process.env.CLOUD_UI_HTML||path.resolve(__dirname,'../../go/cloud_mint_ui.html'),'utf8').replace('name="cpa-plugin-id" content="codex-turn-state"',`name="cpa-plugin-id" content="${pluginID}"`)});
   assert.equal(url.origin,'http://cpa.test');
   if(deny||req.headers().authorization!=='Bearer management-test-key')return route.fulfill({status:401,json:{error:'unauthorized'}});
   if(url.pathname.endsWith('/cloud-status')){
    assert.equal(url.pathname,'/v0/management/'+pluginID+'/cloud-status');
    statusRequests++;return route.fulfill({json:{build:'cloud-mint-ui-20260924-ws-chain',enabled:config.cloud_mint.enabled,dry_run:config.dry_run,role:'business',effective:config.cloud_mint,rows,logs,worker_limit:4}});
   }
   assert.equal(url.pathname,'/v0/management/plugins/'+pluginID+'/config');
   if(req.method()==='GET'&&omitCloudConfigOnce){
    omitCloudConfigOnce=false;
    return route.fulfill({json:{enabled:config.enabled,role:config.role,dry_run:config.dry_run,other_plugin_field:config.other_plugin_field}});
   }
   if(req.method()==='PATCH'){const body=req.postDataJSON();patches.push(body);config={...config,...body};}
   await route.fulfill({json:config});
  });
  await page.goto('http://cpa.test/v0/resource/plugins/'+pluginID+'/dashboard');
  assert.equal(await page.locator('#endpoint').isDisabled(),true);
  assert.equal(await page.locator('nav').count(),0);
  assert.equal(statusRequests,0);
  assert.match(await page.locator('#logsHelp').textContent(),/最近 80 条/);
  assert.match(await page.locator('#logsHelp').textContent(),/不等于已接受/);
  assert.match(await page.locator('#logsHelp').textContent(),/faster-model.*不是响应 model/);
  assert.equal(await page.locator('#capabilityScope').count(),1);
  const capabilityScope=await page.locator('#capabilityScope').textContent();
  for(const text of ['有限取票＋路由复用＋协议校验','780','上游模型声明','不证明模型实际能力'])assert.ok(capabilityScope.includes(text));
  assert.match(await page.locator('label[for="ticketLength"]').textContent(),/预期票长（格式）/);
  assert.match(await page.locator('label[for="gateway"]').textContent(),/目标网关（路由）/);
  assert.match(await page.locator('.note').last().textContent(),/总次数.*总时限.*FC/);
  await page.fill('#managementKey','wrong');await page.click('#connect');
  await page.waitForFunction(()=>document.querySelector('#settingsMessage').textContent.includes('鉴权失败'));
  await page.fill('#managementKey','management-test-key');await page.click('#connect');
  await page.waitForFunction(()=>!document.querySelector('#settingsFields').disabled);
  assert.equal(await page.locator('#gateway').inputValue(),'unified-88');
  assert.equal(await page.locator('#mintTransport').inputValue(),'sse');
  assert.equal(await page.locator('#ticketLength').inputValue(),'780');
  assert.equal(await page.locator('#readyCount').textContent(),'1');
  assert.match(await page.locator('#logs').textContent(),/网关变化/);
  assert.equal(await page.locator('#logs details summary').first().textContent(),'原始（脱敏）');
  assert.equal(await page.locator('#logs details pre').first().textContent(),JSON.stringify({at:logs[0].at,kind:logs[0].kind,message:logs[0].message},null,2));
  assert.equal(await page.locator('#managementKey').inputValue(),'');
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  await page.fill('#gateway','unified-199');
  // 后台轮询不能覆盖未保存草稿。
  await page.waitForTimeout(3200);
  assert.equal(await page.locator('#gateway').inputValue(),'unified-199');
  page.once('dialog',dialog=>dialog.dismiss());await page.click('#saveSettings');
  assert.equal(patches.length,0);
  page.once('dialog',dialog=>dialog.accept());await page.click('#saveSettings');
  await page.waitForFunction(()=>document.querySelector('#settingsMessage').textContent.includes('CPA 已保存'));
  assert.equal(patches.length,1);
  assert.equal(patches[0].cloud_mint.gateway,'unified-199');
  assert.equal(patches[0].cloud_mint.future_field,'keep');
  assert.deepEqual(Object.keys(patches[0]).sort(),['cloud_mint','dry_run']);
  assert.equal(config.other_plugin_field,'keep');
  await page.fill('#proxyURL','http://127.0.0.1:3128');await page.click('#saveSettings');
  assert.match(await page.locator('#settingsMessage').textContent(),/只能设置一个/);
  assert.equal(patches.length,1);
  await page.click('#discardSettings');
  logs.push({at:new Date().toISOString(),kind:'恶意样本',message:'<img src=x onerror=alert(1)>'});
  await page.click('#reset');await page.waitForFunction(()=>document.querySelector('#logs').textContent.includes('<img'));
  assert.equal(await page.locator('#logs img').count(),0);
  logs.pop();await page.click('#reset');await page.waitForTimeout(100);
  const originalLogs=[...logs];logs.length=0;
  for(let i=0;i<83;i++)logs.push({at:new Date(1700000000000+i*1000).toISOString(),kind:'沿用',message:'记录 '+i+'\ncookie unified-94 · 模型 gpt-6-sol → gpt-6-sol · 缓冲 gpt-6-luna · tier premium'});
  logs.reverse();await page.click('#reset');await page.waitForFunction(()=>document.querySelector('#logs').textContent.includes('记录 82'));
  assert.equal(await page.locator('#logs article').count(),80);
  assert.match(await page.locator('#logs article').first().textContent(),/记录 82/);
  assert.match(await page.locator('#logs article').last().textContent(),/记录 3/);
  logs.splice(0,logs.length,...originalLogs);await page.click('#reset');await page.waitForFunction(()=>document.querySelectorAll('#logs article').length===1);
  const screenshotDir=process.env.CLOUD_UI_SCREENSHOT_DIR||path.resolve(__dirname,'../../design');
  fs.mkdirSync(screenshotDir,{recursive:true});
  await page.screenshot({path:path.join(screenshotDir,'cloud-mint-production-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:path.join(screenshotDir,'cloud-mint-production-mobile.png'),fullPage:true});
  deny=true;await page.click('#reset');
  await page.waitForFunction(()=>document.querySelector('#connectionState').textContent.includes('最后一次数据'));
  await page.click('#disconnect');
  assert.equal(await page.locator('#endpoint').isDisabled(),true);
  assert.equal(await page.locator('#readyCount').textContent(),'—');
  assert.equal(await page.locator('#proxyEnv').inputValue(),'');
  assert.deepEqual(errors,[]);
  console.log('PASS production UI: capability boundaries / authenticated API / real payload rendering / draft preservation / PATCH merge / confirmation / validation / XSS / stale state / secret cleanup / mobile');
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
