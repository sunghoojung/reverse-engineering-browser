// The integration runner uses these authored loopback fixtures with the real
// product actions. No test screenshot is substituted for product capture.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import element from '../apps/research-ui/element_screenshot.js';
export function elementScreenshotFixtureRoute(request,response) {
  const path = request.url.split('?')[0];
  if (!path.startsWith('/element-capture/')) return false;
  const kind = path.slice('/element-capture/'.length);
  const extras = {
    plain:'', changed:'<div style="position:absolute;left:220px;top:40px;width:60px;height:60px;background:#3a8">Changed</div>',
    scrolled:'<div style="height:1200px"></div><script>addEventListener("load",()=>scrollTo(0,120));</script>',
    private:'<input type="password" value="synthetic-private-only">',
    editable:'<div contenteditable>synthetic only</div>',
    marked:'<section data-reb-private>synthetic only</section>',
    frame:'<iframe src="/element-capture/plain"></iframe>',
    shadow:'<div id="shadow-host"></div><script>document.querySelector("#shadow-host").attachShadow({mode:"closed"}).innerHTML="<span>synthetic shadow</span>";</script>',
    many:Array.from({length:130},()=>'<div style="display:inline-block;width:4px;height:4px;background:#444"></div>').join('')
  };
  if (!Object.hasOwn(extras,kind)) { response.writeHead(404);response.end('Unknown synthetic fixture');return true; }
  response.setHeader('Content-Type','text/html');response.setHeader('Cache-Control','no-store');
  // The ordinary empty value exercises Blink's -1 string sentinel on the
  // successful path as well as the bare editable/private refusal fixtures.
  response.end(`<!doctype html><html><head><title>Authored element capture fixture</title><link rel="icon" href="data:,"><style>html,body{margin:0;background:#fff;color:#111}#box{position:absolute;left:20px;top:30px;width:160px;height:80px;background:#5b8;border:0}#fixed{position:fixed;left:8px;bottom:8px;width:40px;height:20px;background:#857}</style></head><body><div id="box">Authored local pixels</div><div id="fixed" data-note=""></div>${extras[kind]}</body></html>`);
  return true;
}
export async function checkElementScreenshotCapture({action,get,until,baseURL,fixtureURL}) {
  const post = async body => {
    const response = await fetch(baseURL+'/api/debugger/actions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(16000)});
    return {status:response.status,body:await response.json()};
  };
  const navigate = async kind => {
    const prior = await get();
    await action('navigate_object_experiment',{url:fixtureURL+'/element-capture/'+kind});
    return until(state=>state.state==='running' && state.element_document_epoch > prior.element_document_epoch && state.object_experiment.state==='loaded' && state.request_interception.pending_requests===0);
  };
  let state = await get();
  assert.equal((await post({action:'inspect_element_document',target_id:'not-the-owned-target'})).status,409);
  await navigate('plain');
  // Let authored load/font/viewport events settle before the explicit selection;
  // no command is auto-retried, including drift refusal.
  await new Promise(resolve=>setTimeout(resolve,150));
  state = await get();
  const inspected = await action('inspect_element_document',{target_id:state.target.id});
  assert(element.documentValid(inspected.document));
  const captured = await action('capture_element_screenshot',{selection:inspected.document.selection,confirm_sensitive:true});
  assert(element.captureValid(captured.capture));assert.deepEqual(captured.capture.document,inspected.document);
  const png=Buffer.from(captured.capture.image.base64,'base64');assert.deepEqual([...png.subarray(0,8)],[137,80,78,71,13,10,26,10]);
  assert.equal(png.readUInt32BE(16),captured.capture.image.width);assert.equal(png.readUInt32BE(20),captured.capture.image.height);
  assert.equal(createHash('sha256').update(png).digest('hex'),captured.capture.image.sha256);
  assert(inspected.document.elements.some(box=>box.x===20 && box.y===30 && box.width===160 && box.height===80),'Authored CSS geometry survives the actual capture path');
  assert(!JSON.stringify(inspected).includes('Authored local pixels'),'Text/attributes never enter geometry provenance');
  assert(!JSON.stringify(await get()).includes(captured.capture.image.base64),'PNG is not retained in debugger snapshots');
  assert.equal((await post({action:'capture_element_screenshot',selection:inspected.document.selection,confirm_sensitive:false})).status,400);
  await navigate('changed');
  const stale=await post({action:'capture_element_screenshot',selection:inspected.document.selection,confirm_sensitive:true});assert.equal(stale.status,409);assert(!stale.body.capture);
  for(const kind of ['private','editable','marked','frame','shadow','many']) {
    state=await navigate(kind);await new Promise(resolve=>setTimeout(resolve,100));
    const refused=await post({action:'inspect_element_document',target_id:state.target.id});assert.equal(refused.status,409,kind);assert(!refused.body.document);assert(!JSON.stringify(refused).includes('synthetic-private-only'));
  }
  state=await navigate('scrolled');await new Promise(resolve=>setTimeout(resolve,150));
  const scrolled=await action('inspect_element_document',{target_id:state.target.id});assert(scrolled.document.viewport.y>0);
  assert(scrolled.document.elements.every(box=>box.x>=0 && box.y>=0));
  const scrollCapture=await action('capture_element_screenshot',{selection:scrolled.document.selection,confirm_sensitive:true});assert(element.captureValid(scrollCapture.capture));
  console.log('PASS real product element capture: authored loopback PNG/geometry binding, private/editable/frame/shadow refusal, bounds, scroll, confirmation, stale navigation and no retained PNG');
}
