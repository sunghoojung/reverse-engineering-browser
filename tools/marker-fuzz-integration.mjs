// Invoked by the real backend/CDP gate, never a standalone external probe.
import assert from 'node:assert/strict';
import {markerPlan,runMarkerPlan,backendCall} from './marker-fuzz.mjs';
export async function checkMarkerFuzzIntegration({baseUrl,fixtureUrl,get,until}) {
  const before=await get();
  const input={format:'reb-marker-fuzz-input-v1',source_id:'authored-cdp-fixture',
    scope:{instance_id:before.network.instance_id,target_id:before.target.id,experiment_id:before.request_interception.experiment_id,session_id:before.repeater.session_id},
    request:{url:fixtureUrl+'/echo?q=REB_MARKER',method:'GET',headers:{accept:'*/*'},body:''},marker:{field:'query',literal:'REB_MARKER'},
    payloads:['snow 雪 & next=1','{{literal}}'],limits:{interval_ms:250,request_timeout_ms:1000,deadline_ms:5000,max_request_bytes:65536}};
  const plan=markerPlan(input),report=await runMarkerPlan(plan,{arm:plan.plan_sha256,baseUrl});
  assert.equal(report.state,'complete');assert.equal(report.attempted_cases,2);
  let s=await get();
  assert.equal(s.repeater.history.at(-2).resolved_request.url,plan.cases[0].request.url);
  assert.equal(s.repeater.history.at(-1).marker_fuzz.plan_sha256,plan.plan_sha256);
  assert.deepEqual(s.repeater.history.at(-1).variable_names,[]);
  // A wrong scope must fail before a request can enter history.
  const entry=s.repeater.history.at(-1),bad={action:'run_repeater_request',...plan.cases[1].request,timeout_ms:1000,
    marker_fuzz:{...entry.marker_fuzz,session_id:input.scope.session_id+1,expires_at_ms:Date.now()+5000}};
  await assert.rejects(()=>backendCall(baseUrl,bad));assert.equal((await get()).repeater.history.length,s.repeater.history.length);
  const post={...input,request:{url:fixtureUrl+'/slow',method:'POST',headers:{'content-type':'text/plain; charset=utf-8'},body:'雪:REB_MARKER'},marker:{field:'body',literal:'REB_MARKER'},payloads:['{{literal}}'],limits:{...input.limits,request_timeout_ms:3000}};
  const cancelPlan=markerPlan(post),control=new AbortController();
  const stopped=await runMarkerPlan(cancelPlan,{arm:cancelPlan.plan_sha256,baseUrl,signal:control.signal,call:async(base,action)=>{
    const result=await backendCall(base,action);
    if(action?.action==='run_repeater_request') {
      const active=result.repeater.active_execution;
      assert(active);assert.deepEqual(active.variable_names,[]);
      const wrong={...input.scope,execution_id:active.execution_id+1,plan_sha256:cancelPlan.plan_sha256,case_index:0};
      await assert.rejects(()=>backendCall(base,{action:'cancel_repeater_request',expected_execution:wrong}));
      assert.equal((await get()).repeater.active_execution.execution_id,active.execution_id);
      control.abort();
    }
    return result;
  }});
  assert.equal(stopped.state,'cancelled');assert.equal(stopped.cases[0].cancellation,'requested');
  s=await until(v=>!v.repeater.active_execution);
  assert.equal(s.repeater.history.at(-1).response.cancelled,true);assert.equal(s.repeater.history.at(-1).resolved_request.body,'雪:{{literal}}');
  const redirectInput={...post,request:{...post.request,url:fixtureUrl+'/marker-redirect'},payloads:['redirect']};
  const redirectPlan=markerPlan(redirectInput),redirectReport=await runMarkerPlan(redirectPlan,{arm:redirectPlan.plan_sha256,baseUrl});
  assert.equal(redirectReport.state,'error');assert.equal(redirectReport.attempted_cases,1);
  console.log('PASS real backend/CDP marker fuzz: exact query cases, literal variables, stale scope, full-tuple cancel and redirect refusal');
}
