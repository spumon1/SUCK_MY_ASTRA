async () => {
  // Run this function in either local preview page (/ or /baseline).
  // The fixture replaces fetch, so every tested mutation is local and synthetic.
  const results = [], traces = [];
  const check = (name, value) => { results.push({name, pass:!!value}); };
  const tick = () => new Promise(r=>setTimeout(r,30));
  const actions = () => __mock.requests.filter(r=>r.path!=='/status' && r.path!=='/ops/choices');
  const click = id => document.getElementById(id).click();
  const edit = (id,value) => {const n=document.getElementById(id);n.value=value;n.dispatchEvent(new Event('input',{bubbles:true}));};
  const tab = name => {const b=document.querySelector('[data-panel="'+name+'"]');if(b)b.click();};
  const reset = async () => {
    stopPolling(); state.paused=true; __mock.reset();
    scope.dirty=false;scope.extraModels=[];scope.acctSig='';scope.modelSig='';scope.choicesAt=0;scope.choices=null;
    clear(document.getElementById('notices'));
    await refresh(); stopPolling(); __mock.requests=[];
  };
  const confirm = async () => {check('Confirmation is visible',!document.getElementById('modal').hidden);click('modalOk');await tick();};
  const record = label => {traces.push({label,requests:actions().slice()});__mock.requests=[];};
  await reset();
  check('Initial matrix retains all 12 account/model cells',document.querySelectorAll('#matrix td.cell').length===12);
  check('Ready count is 8/12',document.getElementById('summary').textContent.includes('8/12'));
  check('Four original counters retained',document.querySelectorAll('#counters .counter').length===4);
  check('Missing buckets keep selftest but disable clear',Array.from(document.querySelectorAll('#matrix td.cell')).filter(c=>c.querySelector('button').disabled).every(c=>!c.querySelector('.cellprobe').disabled));

  // Cross-tab edits and subsequent polling must not overwrite a draft.
  tab('scope');const account=document.querySelector('#scopeAccounts input');account.click();
  tab('proxies');edit('scopeProxies','http://user:example@changed.example:8080');
  await refresh();tab('scope');
  check('Polling and tab switches preserve account draft',!account.checked && selectedAccounts().length===2);
  check('Polling preserves proxy draft',document.getElementById('scopeProxies').value.includes('changed.example'));
  click('btnScopeSave');await tick();click('modalCancel');await tick();
  check('Cancel save dispatches no mutation',actions().length===0);
  click('btnScopeSave');await tick();await confirm();
  let saved=actions().find(r=>r.path==='/ops/scope'),q=new URLSearchParams(saved ? saved.query : []);
  check('Save only patches changed fields',q.get('fields')==='accounts,proxies' && q.getAll('account').length===2 && !q.has('model') && !q.has('rotating_proxy') && q.get('confirm')==='1');record('scope-and-proxy-save');

  await reset();tab('proxies');edit('scopeRotating','');click('btnScopeSave');await tick();await confirm();
  saved=actions().find(r=>r.path==='/ops/scope');q=new URLSearchParams(saved?saved.query:[]);
  check('Empty rotating list is an explicit patch',q.get('fields')==='rotating' && !q.has('rotating_proxy'));record('clear-rotating-list');

  await reset();tab('proxies');edit('scopeProxies','socks5://***@invalid.example:1080');click('btnScopeSave');await tick();
  check('Masked credentials rejected without request',actions().length===0 && document.getElementById('notices').textContent.includes('***'));
  edit('scopeProxies','http://draft.example:8080');__mock.failNext='/ops/scope';click('btnScopeSave');await tick();await confirm();
  check('Save failure preserves draft',scope.dirty && document.getElementById('scopeProxies').value.includes('draft.example'));
  click('btnScopeReset');await tick();
  check('Discard restores stored proxy configuration',!scope.dirty && document.getElementById('scopeProxies').value.includes('static-01.example'));

  await reset();tab('overview');click('btnProbeCancel');await tick();await confirm();
  check('Cancel stops mock task',!__mock.status.probe_run.running);record('probe-cancel');
  await refresh();click('btnProbeStart');await tick();await confirm();
  check('Start resumes mock task',__mock.status.probe_run.running);record('probe-start');

  await reset();tab('settings');click('btnDryRun');await tick();
  check('Enabling dry_run preserves existing no-confirm behavior',__mock.status.dry_run);record('dry-run-on');
  click('btnDryRun');await tick();click('modalCancel');await tick();
  check('Cancel actual rewrite keeps dry_run enabled',__mock.status.dry_run && actions().length===0);
  click('btnDryRun');await tick();await confirm();record('dry-run-off');
  click('btnRole');await tick();await confirm();check('Role switch retains target value',__mock.status.role==='probe');record('role-switch');

  await reset();tab('overview');document.querySelector('#matrix .cellprobe').click();await tick();await confirm();
  let test=actions().find(r=>r.path==='/ops/selftest');q=new URLSearchParams(test?test.query:[]);
  check('Matrix selftest remains pinned to account and model',q.get('auth_id')==='codex-demo-a-pro.json' && q.get('model')==='gpt-5.5');record('targeted-selftest');
  document.querySelector('#matrix td.cell button:not(.cellprobe)').click();await tick();await confirm();
  check('Single clear removes only one bucket',__mock.status.buckets.length===11);record('single-clear');
  tab('settings');click('btnClearAll');await tick();click('modalCancel');await tick();
  check('Cancel bulk clear preserves templates',__mock.status.buckets.length===11 && actions().length===0);
  click('btnClearAll');await tick();await confirm();check('Bulk clear has explicit all flag',__mock.status.buckets.length===0);record('all-clear');

  await reset();tab('proxies');click('btnProxyCheck');await tick();
  check('Proxy results include success and failure rows',document.querySelectorAll('#proxyCheck .pcrow').length===2);record('proxy-check');
  await reset();__mock.failNext='/status';await refresh();
  check('Failed polling retains prior matrix and shows stale state',document.querySelectorAll('#matrix td.cell').length===12 && document.getElementById('freshness').classList.contains('stale'));
  __mock.status.buckets.push({auth_id:'codex-outside-pro.json',model:'outside-model',ready:true,seconds_left:500,len:292});await refresh();
  check('Outside-scope templates remain visible and excluded from denominator',document.getElementById('matrix').textContent.includes('outside-model') && document.getElementById('summary').textContent.includes('8/12') && document.getElementById('summary').textContent.includes('范围外'));
  await reset();__mock.status.probe_accounts=[];__mock.status.models=[];await refresh();
  check('Empty scope retains fallback matrix',document.getElementById('summary').textContent.includes('目标桶数') && document.querySelectorAll('#matrix td.cell').length===12);
  if(document.getElementById('overviewReady'))check('Summary does not invent a target for empty scope',document.getElementById('overviewReady').textContent==='—');
  await reset();delete __mock.status.probe_run;delete __mock.status.probe_proxies_rotating;await refresh();
  check('Old-server fallback disables unsupported probe actions',document.getElementById('btnProbeStart').disabled && document.getElementById('btnProbeCancel').disabled);
  check('Old-server fallback protects rotating editor',document.getElementById('scopeRotating').readOnly || document.getElementById('scopeRotating').disabled);
  await reset();tab('overview');
  return {passed:results.filter(r=>r.pass).length,total:results.length,failures:results.filter(r=>!r.pass),traces};
}
