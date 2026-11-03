// Serve the EXTRACTED pages-site.zip on loopback 8766; protected fixture on 8765.
// Browser sees fixed deployment URLs, but every such request is fulfilled using
// the disposable loopback WSGI stack. Nothing is forwarded to production.
import assert from 'node:assert/strict';
const local='http://127.0.0.1:8765', pages='http://127.0.0.1:8766', destination='https://kali.pythonanywhere.com';
const target=await fetch('http://127.0.0.1:9222/json/new?about:blank',{method:'PUT'}).then(r=>r.json());
const socket=new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
let sequence=0, passed=0, protectedRequests=0;
const pending=new Map(), errors=[], unexpected=[], headers=new Map();
function command(method,params={}) {
  return new Promise((resolve,reject)=>{
    const id=++sequence, timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method));},15000);
    pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));
  });
}
async function intercept(event) {
  const url=new URL(event.request.url);
  if(url.origin===pages) return command('Fetch.continueRequest',{requestId:event.requestId});
  if(url.origin===destination) {
    protectedRequests++;
    assert.equal(event.request.method,'GET');
    const r=await fetch(local+url.pathname+url.search,{redirect:'manual'});
    if(url.pathname.endsWith('.html') || url.pathname==='/dashboard/login') headers.set(url.pathname,r.headers.get('content-security-policy'));
    return command('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:r.status,
      responseHeaders:[...r.headers].filter(([name])=>!['content-length','transfer-encoding','connection'].includes(name)).map(([name,value])=>({name,value})),
      body:Buffer.from(await r.arrayBuffer()).toString('base64')});
  }
  if(url.origin==='https://images.unsplash.com') return command('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:200,
    responseHeaders:[{name:'Content-Type',value:'image/png'}],body:'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGP4DwQACfsD/fteaysAAAAASUVORK5CYII='});
  if(url.origin==='http://gc.kis.v2.scr.kaspersky-labs.com' && /^\/[A-F0-9-]+\/main\.js$/.test(url.pathname))
    return command('Fetch.failRequest',{requestId:event.requestId,errorReason:'BlockedByClient'});
  unexpected.push(url.origin+url.pathname);
  return command('Fetch.failRequest',{requestId:event.requestId,errorReason:'BlockedByClient'});
}
socket.addEventListener('message',({data})=>{
  const m=JSON.parse(data);
  if(m.id){const p=pending.get(m.id);pending.delete(m.id);if(p){clearTimeout(p.timer);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}}
  if(m.method==='Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.text);
  if(m.method==='Fetch.requestPaused') intercept(m.params).catch(e=>errors.push(e.message));
});
async function evaluate(expression) {
  const r=await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
  if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;
}
async function waitFor(expression) {
  const deadline=Date.now()+15000;
  while(Date.now()<deadline){if(await evaluate(expression))return;await new Promise(r=>setTimeout(r,60));}
  throw Error('Timed out: '+expression);
}
function pass(name){passed++;process.stdout.write('PASS '+name+'\n');}
try {
  await command('Page.enable');await command('Runtime.enable');
  await command('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
  for(const name of ['index','admin','kitchen']) {
    await command('Page.navigate',{url:pages+'/'+name+'.html?ignored=release-test#ignored'});
    await waitFor(`location.href===${JSON.stringify(destination+'/'+name+'.html')} && ${name==='index'?'document.querySelectorAll(".menu-item").length===15':'typeof login==="function"'}`);
    assert.ok(headers.get('/'+name+'.html')?.includes("script-src 'self'"));
    assert.equal(await evaluate('document.documentElement.dataset.apiBase'),'/api');
    pass(`${name} artifact gateway reaches WAF-served page with real CSP and matching assets; query/fragment dropped`);
  }
  await command('Page.navigate',{url:pages+'/settings/'});
  await waitFor(`location.origin===${JSON.stringify(pages)} && !!document.getElementById('manageLive')`);
  assert.equal(await evaluate('document.getElementById("manageLive").href'),destination+'/settings');
  pass('Published Settings artifact is a static gateway to the single authenticated interface');
  await command('Page.navigate',{url:pages+'/dashboard/'});
  await waitFor(`location.href===${JSON.stringify(destination+'/dashboard/login')} && !!document.querySelector('input[name="password"]')`);
  assert.ok(headers.get('/dashboard/login')?.includes("script-src 'self'"));
  pass('Published Dashboard gateway requires operator login at the protected origin');
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[]);
  process.stdout.write(`${passed} Pages release browser checks passed; ${protectedRequests} destination requests fulfilled from loopback, none sent to production.\n`);
} finally {await command('Browser.close').catch(()=>{});socket.close();}
