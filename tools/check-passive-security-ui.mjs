import assert from 'node:assert/strict';

// Runs inside the existing synthetic loopback catalog/Traffic browser harness.
export async function checkPassiveSecurityInteractions({evaluate,send,click,key,shot,until}) {
  const raw=await evaluate('JSON.stringify(state.requests[0].captureRecord)');
  const originalSelection=await evaluate('JSON.stringify({selectedRequestId:state.selectedRequestId,selectedCaptureIdentity:state.selectedCaptureIdentity,trafficDetailOpen:state.trafficDetailOpen,inspectorTab:state.inspectorTab})');
  await click('#request-rows [role="option"]');
  await click('#traffic-capture-export > summary');
  // Intercept only while exercising the local report. The surrounding app's
  // regular debugger polling is suspended, not attributed to report analysis.
  await until(()=>evaluate("(()=>{if(state.refreshing||state.debuggerRefreshing)return false;state.refreshing=true;state.debuggerRefreshing=true;clearTimeout(state.debuggerRefreshTimer);window.passiveOriginalFetch=window.fetch;window.passiveFetchCalls=0;window.fetch=(...args)=>{passiveFetchCalls++;return passiveOriginalFetch(...args);};return true;})()"),'polling settled before local report');
  try {
    const reads=await evaluate('passiveFetchCalls');
    await click('#passive-security-open');
    await until(()=>evaluate("document.querySelector('#passive-security-status').textContent.includes('report ready')"),'passive report ready');
    assert.equal(await evaluate('document.activeElement.id'),'passive-security-close');
    await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.id'),'passive-security-content');
    assert.equal(await evaluate("document.querySelector('#passive-security-content').textContent.includes('synthetic-auth')"),false);
    assert.equal(await evaluate("document.querySelector('#passive-security-content').textContent.includes('credential-header')"),true);
    assert.equal(await evaluate("document.querySelectorAll('#passive-security-content img, #passive-security-content script').length"),0);
    for(const shortcut of [{key:'p',code:'KeyP',modifiers:2},{key:'ArrowLeft',code:'ArrowLeft',modifiers:1},{key:'F8',code:'F8'}]) {
      await send('Input.dispatchKeyEvent',{type:'keyDown',...shortcut});await send('Input.dispatchKeyEvent',{type:'keyUp',...shortcut});
      assert.equal(await evaluate("document.querySelector('#passive-security').open && !document.querySelector('#screen-traffic').hidden"),true);
    }
    for(const [width,height] of [[1440,900],[760,560],[360,740]]) {
      await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
      assert.equal(await evaluate("(()=>{const d=document.querySelector('#passive-security'),c=document.querySelector('#passive-security-content'),r=d.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth+1&&r.top>=0&&r.bottom<=innerHeight+1&&d.scrollWidth<=d.clientWidth+1&&c.scrollWidth<=c.clientWidth+1;})()"),true);
      await shot(`passive-security-${width}`);
    }
    assert.equal(await evaluate('passiveFetchCalls'),reads,'Report must not fetch');
    await key('Escape','Escape');assert.equal(await evaluate("document.querySelector('#passive-security').open"),false);
    assert.equal(await evaluate('document.activeElement.id'),'passive-security-open');
    await key('Enter','Enter');await until(()=>evaluate("document.querySelector('#passive-security-status').textContent.includes('report ready')"),'passive report reopened');
    await evaluate("state.requests[0].captureRecord.response.body.text += ' authored revision';passiveSecurityPanel.sync();");
    assert.equal(await evaluate("document.querySelector('#passive-security-content').textContent"),'');
    assert.equal(await evaluate("document.querySelector('#passive-security-status').textContent.includes('changed')"),true);
    await click('#passive-security-close');
    await evaluate(`state.requests[0].captureRecord=${raw};passiveSecurityPanel.sync();`);
    assert.equal(await evaluate('JSON.stringify(state.requests[0].captureRecord)'),raw);
    return {status:'passed',viewports:[[1440,900],[760,560],[360,740]],network_requests:0,
      checks:['Traffic action','inert count-only report','keyboard and modal shortcuts','narrow scrolling','Escape and reopen','same-identity source revision invalidation']};
  } finally {
    await evaluate(`state.refreshing=false;state.debuggerRefreshing=false;scheduleDebuggerRefresh();window.fetch=passiveOriginalFetch;delete window.passiveOriginalFetch;delete window.passiveFetchCalls;state.requests[0].captureRecord=${raw};document.querySelector('#passive-security').close();Object.assign(state,${originalSelection});renderRequests();renderInspector();document.querySelector('#traffic-capture-export').open=false;`);
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  }
}
