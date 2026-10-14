#!/usr/bin/env node
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
const source=await readFile(new URL('../apps/research-ui/traffic_view.js',import.meta.url),'utf8');
const document={activeElement:null};
class Node {
 constructor(tag){this.tagName=tag;this.children=[];this.dataset={};this.events={};this.attributes={};this.text='';this.value='';}
 set textContent(value){this.text=String(value);this.children=[];}
 get textContent(){return this.text+this.children.map(child=>child.textContent).join('');}
 append(...children){this.children.push(...children);}
 replaceChildren(...children){this.children=children;this.text='';}
 setAttribute(key,value){this.attributes[key]=String(value);}
 addEventListener(name,handler){this.events[name]=handler;}
 focus(){document.activeElement=this;}
 contains(node){return node===this||this.children.some(child=>child.contains(node));}
}
document.createElement=tag=>new Node(tag);
const ui=runInNewContext(source+';({webSocketModel,renderWebSocketInspector})',{document,URL,TextEncoder,TextDecoder});
const net={capture_enabled:true,instance_id:'instance',capture_epoch:1,target_id:'owned',websockets:{format:'reb-websocket-capture-v1',connections:[{id:1,url:'ws://example.test/<script>',target_id:'owned',protocol_request_id:'ws-1',state:'open',handshake_status:101,error_count:0}],frames:[{sequence:1,connection_id:1,target_id:'owned',monotonic_seconds:1.5,direction:'received',opcode:1,encoding:'utf8',payload:'<img src=x onerror=alert(1)>',truncated:false,payload_state:'available'}],dropped_connections:0,dropped_frames:3,orphan_events:1,malformed_events:0}};
const clone=value=>JSON.parse(JSON.stringify(value)),root=new Node('details');
assert.equal(ui.webSocketModel(undefined).available,false);assert.equal(ui.webSocketModel({...net,capture_enabled:false}).available,false);
assert.equal(ui.webSocketModel(net).available,true);
for(const mutate of [v=>v.frames.push(v.frames[0]),v=>v.frames[0].payload='x'.repeat(5465),v=>v.frames[0].monotonic_seconds=NaN,v=>v.connections.push(v.connections[0]),v=>v.dropped_frames=-1]){const changed=clone(net);mutate(changed.websockets);assert.equal(ui.webSocketModel(changed).available,false);}
ui.renderWebSocketInspector(root,net);assert.equal(root.children.length,4);assert.equal(root._rebWebsocket.frames.children.length,0,'Collapsed panel does not render payloads');
root.open=true;root.events.toggle();const view=root._rebWebsocket;
assert(root.textContent.includes('<img src=x'));assert(root.textContent.includes('Dropped: 0 connections, 3 messages'));
assert.equal(view.frames.children[1].tagName,'details');assert.equal(view.frames.children[1].children[1].tagName,'pre');
view.frames.children[1].open=true;const focused=view.frames.children[1].children[1];focused.focus();
const next=clone(net);next.websockets.frames.push({...next.websockets.frames[0],sequence:2,direction:'sent',payload:'AP8=',encoding:'base64',opcode:2});
ui.renderWebSocketInspector(root,next);assert.equal(view.frames.children[1].open,true);assert.equal(document.activeElement,focused);
view.direction.value='sent';view.direction.events.change();assert.equal(view.frames.children.length,2);assert.equal(document.activeElement,view.select);
assert(view.frames.textContent.includes('AP8='));assert(!view.frames.textContent.includes('<img'));
ui.renderWebSocketInspector(root,next,true);assert(view.status.textContent.includes('last retained snapshot'));
const reset=clone(net);reset.capture_epoch=2;reset.websockets.frames=[];reset.websockets.connections=[];ui.renderWebSocketInspector(root,reset);assert(view.status.textContent.includes('No retained connections'));assert.equal(view.frames.children.length,1);
ui.renderWebSocketInspector(root,{capture_enabled:false});assert(view.select.disabled);assert.equal(view.frames.children.length,0);
const bounded=clone(net);bounded.websockets.frames=Array.from({length:200},(_,i)=>({...net.websockets.frames[0],sequence:i}));view.direction.value='all';ui.renderWebSocketInspector(root,bounded);assert.equal(view.frames.children.length,101);assert(view.frames.textContent.includes('100 of 200'));
const html=await readFile(new URL('../apps/research-ui/index.html',import.meta.url),'utf8'),app=await readFile(new URL('../apps/research-ui/app.js',import.meta.url),'utf8');
assert(html.includes('id="websocket-inspector"'));assert(app.includes("renderWebSocketInspector(document.querySelector('#websocket-inspector')"));
console.log('PASS WebSocket model/controller: disabled/malformed/empty/stale states, inert text/base64, selection/direction, bounded rows, expanded state and focus across refresh, scope reset. Not rendered UI acceptance.');
