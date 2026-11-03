// Actual HTTP document injection, real Chrome CSP, real WSGI stack. Loopback only.
// Server: python -m waf.tests.browser_wsgi_fixture --restaurant --csp --csp-probes
import assert from 'node:assert/strict';
const origin = 'http://127.0.0.1:8765';
const target = await fetch('http://127.0.0.1:9222/json/new?about:blank', {method:'PUT'}).then(r=>r.json());
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
let sequence=0, passed=0, environmentalRequestsBlocked=0;
const pending=new Map(), errors=[], unexpected=[];
function command(method,params={}) {
  return new Promise((resolve,reject)=>{
    const id=++sequence;
    const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method));},15000);
    pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));
  });
}
socket.addEventListener('message',({data})=>{
  const m=JSON.parse(data);
  if(m.id){const p=pending.get(m.id);pending.delete(m.id);if(p){clearTimeout(p.timer);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}}
  if(m.method==='Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.text);
  if(m.method==='Page.javascriptDialogOpening') {
    errors.push('Unexpected dialog: '+m.params.message);
    command('Page.handleJavaScriptDialog',{accept:true}).catch(e=>errors.push(e.message));
  }
  if(m.method==='Fetch.requestPaused') intercept(m.params).catch(e=>errors.push(e.message));
});
async function intercept(event) {
  const url=new URL(event.request.url);
  if(url.origin===origin) return command('Fetch.continueRequest',{requestId:event.requestId});
  // This workstation's antivirus injects this URL into HTTP browser documents.
  // Abort it explicitly; it is neither a project asset nor a CSP test probe.
  if(url.origin==='http://gc.kis.v2.scr.kaspersky-labs.com' && /^\/[A-F0-9-]+\/main\.js$/.test(url.pathname)) {
    environmentalRequestsBlocked++;
    return command('Fetch.failRequest',{requestId:event.requestId,errorReason:'BlockedByClient'});
  }
  if(url.href==='http://127.0.0.1:8766/forbidden.js') return command('Fetch.fulfillRequest',{
    requestId:event.requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'text/javascript'}],
    body:Buffer.from('window.__cspExternal=1').toString('base64')});
  if(url.origin==='https://images.unsplash.com') return command('Fetch.fulfillRequest',{
    requestId:event.requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'image/png'}],
    body:'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aM1cAAAAASUVORK5CYII='});
  unexpected.push(url.origin+url.pathname);
  return command('Fetch.failRequest',{requestId:event.requestId,errorReason:'BlockedByClient'});
}
async function evaluate(expression) {
  const r=await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
  if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;
}
async function waitFor(expression) {
  const until=Date.now()+15000;
  while(Date.now()<until){if(await evaluate(expression))return;await new Promise(r=>setTimeout(r,70));}
  throw Error('Timed out: '+expression);
}
async function navigate(path,ready) {await command('Page.navigate',{url:origin+path});await waitFor(ready);}
function pass(name){passed++;process.stdout.write('PASS '+name+'\n');}
let cookie;
async function operator(path='/waf-api/settings',method='GET',body,csrf) {
  const r=await fetch(origin+path,{method,headers:{Cookie:cookie,...(body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{})},body:body?JSON.stringify(body):undefined});
  assert.equal(r.status,200,path);return r.json();
}
async function setMode(mode,extra={}) {
  const s=await operator();return operator('/waf-api/settings','PUT',{
    revision:s.revision,policy:{...s.policy,...extra,csp:{...s.policy.csp,mode}}},s.csrf_token);
}
try {
  const page=await fetch(origin+'/dashboard/login');
  const csrf=/name="csrf_token" value="([^"]+)"/.exec(await page.text())[1];
  const login=await fetch(origin+'/dashboard/login',{method:'POST',redirect:'manual',headers:{
    Cookie:page.headers.getSetCookie().map(v=>v.split(';')[0]).join('; '),'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({username:'synthetic-operator',password:'synthetic-browser-password',csrf_token:csrf})});
  assert.equal(login.status,303);cookie=login.headers.getSetCookie().find(v=>v.startsWith('chillibek_waf_session=')).split(';')[0];
  await command('Page.enable');await command('Runtime.enable');await command('Network.enable');
  await command('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
  for(const [mode,blocked] of [['enforce',true],['report-only',false],['off',false]]) {
    await setMode(mode);
    await navigate('/index.html','window.__cspLegit===1 && document.querySelectorAll(".menu-item").length===15');
    // Click a real inline handler delivered in fixture HTML; no evaluated probe code.
    await evaluate('document.getElementById("csp-probe").click()');
    const result=await evaluate(`({inline:window.__cspInline||0,handler:window.__cspHandler||0,external:window.__cspExternal||0,
      eval:window.__cspEval||0,sink:!!window.__cspSinkAccepted,tt:!!window.trustedTypes,blocked:!!window.__cspSinkBlocked})`);
    for(const key of ['inline','handler','external','eval']) assert.equal(result[key],blocked?0:1,mode+' '+key);
    if(result.tt){assert.equal(result.sink,!blocked);assert.equal(result.blocked,blocked);}
    assert.equal(await evaluate('window.__storedXSS===undefined'),true);
    pass(`${mode}: HTML-delivered inline, event, external, eval and Trusted Types probes; menu remains functional`);
  }
  // Session cookie is used only to authenticate browser UI on this local origin.
  const split=cookie.indexOf('=');
  await command('Network.setCookie',{name:cookie.slice(0,split),value:cookie.slice(split+1),url:origin,httpOnly:true,sameSite:'Strict'});
  await navigate('/settings/','document.getElementById("cspSave") && !document.getElementById("cspSave").disabled');
  assert.ok((await evaluate('document.getElementById("cspCoverage").textContent')).includes('NOT COVERED'));
  await evaluate('document.getElementById("cspMode").value="report-only";document.getElementById("cspSave").click()');
  await waitFor('document.getElementById("cspEffective").textContent.includes("REPORT-ONLY") && !document.getElementById("cspSave").disabled');
  assert.equal((await operator()).policy.csp.mode,'report-only');
  await command('Page.reload');await waitFor('document.getElementById("cspMode")?.value==="report-only" && !document.getElementById("cspSave").disabled');
  pass('CSP controls save through authenticated PolicyStore API, survive reload, show Pages coverage truthfully');
  await evaluate('document.getElementById("cspMode").value="enforce";document.getElementById("cspSave").click()');
  await waitFor('document.getElementById("cspEffective").textContent.includes("ENFORCE") && !document.getElementById("cspSave").disabled');
  await navigate('/dashboard','document.querySelectorAll("#cspReports tr").length>0');
  const reports=await operator('/dashboard/api/csp');
  assert.ok(reports.reports.some(r=>r.disposition==='enforce'));
  assert.ok(reports.reports.some(r=>r.disposition==='report'));
  assert.ok(reports.reports.some(r=>r.directive==='script-src-attr'));
  assert.ok(reports.reports.some(r=>r.directive==='require-trusted-types-for'));
  assert.equal(await evaluate('document.querySelectorAll("#cspReports script,#cspReports [onclick]").length'),0);
  pass('Real browser reports arrive, retain disposition, and render safely in existing Dashboard');
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[]);
  process.stdout.write(`${passed} CSP browser checks passed; ${environmentalRequestsBlocked} antivirus injection requests aborted; all traffic stayed local or was fulfilled by fixtures.\n`);
} catch(error) {
  process.stderr.write(JSON.stringify({errors,unexpected})+'\n');throw error;
} finally {
  if(cookie)await setMode('enforce').catch(()=>{});
  await command('Browser.close').catch(()=>{});socket.close();
}
