import assert from 'node:assert/strict';
import {selectRenderedOption} from './rendered-keyboard.mjs';
export async function checkWebSocketInteractions({evaluate,viewport,click,key,screenshot}) {
  const network={capture_enabled:true,instance_id:'ws-fixture',capture_epoch:1,target_id:'owned',websockets:{format:'reb-websocket-capture-v1',connections:[{id:1,protocol_request_id:'ws',target_id:'owned',url:'ws://127.0.0.1/authored',state:'open',handshake_status:101,error_count:0}],frames:[
    {sequence:1,connection_id:1,target_id:'owned',monotonic_seconds:1.25,direction:'received',opcode:1,encoding:'utf8',payload:'<img src=x onerror=alert(1)> inert authored text',truncated:false,payload_state:'available'},
    {sequence:2,connection_id:1,target_id:'owned',monotonic_seconds:1.5,direction:'sent',opcode:2,encoding:'base64',payload:'AP8=',truncated:false,payload_state:'available'}
  ],dropped_connections:0,dropped_frames:2,orphan_events:1,malformed_events:0}};
  await viewport(1440,900);
  await evaluate(`state.debuggerSession={...(state.debuggerSession??{}),network:${JSON.stringify(network)}};state.debuggerError=null;renderRequests();`);
  await click('#websocket-inspector > summary');
  assert.equal(await evaluate("document.querySelector('#websocket-inspector').open"),true);
  await key('Tab');assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"),'WebSocket connection');
  await key('Tab');assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"),'WebSocket direction');
  await selectRenderedOption({evaluate,click,key,selector:'#websocket-inspector [aria-label="WebSocket direction"]',index:1});
  assert.equal(await evaluate("document.querySelector('#websocket-inspector .websocket-frames').textContent.includes('AP8=')"),true);
  assert.equal(await evaluate("document.querySelector('#websocket-inspector .websocket-frames').textContent.includes('<img')"),false);
  await selectRenderedOption({evaluate,click,key,selector:'#websocket-inspector [aria-label="WebSocket direction"]',index:0});
  await click('#websocket-inspector .websocket-frames details > summary');
  assert.equal(await evaluate("document.querySelectorAll('#websocket-inspector img, #websocket-inspector script').length"),0);
  assert.equal(await evaluate("document.querySelector('#websocket-inspector pre').textContent.includes('<img src=x')"),true);
  await screenshot('websocket-wide.png');
  for(const [width,height] of [[600,800],[360,740]]) {
    await viewport(width,height);
    assert.equal(await evaluate("document.querySelector('#websocket-inspector').scrollWidth<=document.querySelector('#websocket-inspector').clientWidth+1"),true);
    assert.equal(await evaluate("document.querySelector('.traffic-grid').getBoundingClientRect().bottom<=innerHeight+1"),true);
    await screenshot(`websocket-${width}.png`);
  }
  await click('#websocket-inspector > summary');assert.equal(await evaluate("document.querySelector('#websocket-inspector').open"),false);
  await click('#websocket-inspector > summary');assert.equal(await evaluate("document.querySelector('#websocket-inspector').open"),true);
  await evaluate("state.debuggerSession.network.capture_epoch++;state.debuggerSession.network.websockets.connections=[];state.debuggerSession.network.websockets.frames=[];renderRequests();");
  assert.equal(await evaluate("document.querySelector('#websocket-inspector').textContent.includes('No retained connections')"),true);
  await evaluate("state.debuggerSession.network.capture_enabled=false;renderRequests();");
  assert.equal(await evaluate("document.querySelector('#websocket-inspector select').disabled"),true);
  await click('#websocket-inspector > summary');
  // Details toggle is queued by the browser after the click dispatch completes.
  // Observe its settled effect with a deadline; never mutate the inspected DOM.
  for(let attempt=0;attempt<100;attempt++) {
    if(await evaluate("document.querySelector('#websocket-inspector').hidden"))break;
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  assert.equal(await evaluate("document.querySelector('#websocket-inspector').open"),false);
  assert.equal(await evaluate("document.querySelector('#websocket-inspector').hidden"),true);
  return {status:'passed',checks:['connection/direction keyboard controls','inert raw text and binary base64','wide/narrow bounded layout','collapse/reopen','scope reset','capture disabled'],viewports:[[1440,900],[600,800],[360,740]]};
}
