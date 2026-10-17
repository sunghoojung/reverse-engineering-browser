// One-shot publication guard. This never starts a browser or makes requests.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const repository='sunghoojung/reverse-engineering-browser';
const ref='refs/heads/qa/public-demo-once-20261017';
const base='aef1b297b43f04b141dd2d3b2182c782293cb95f';
function accepts(env,event,parents) {
  return env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REPOSITORY===repository&&
    env.GITHUB_REF===ref&&env.GITHUB_RUN_NUMBER==='1'&&env.GITHUB_RUN_ATTEMPT==='1'&&
    event.repository?.full_name===repository&&event.ref===ref&&
    event.created===true&&event.deleted===false&&
    event.before==='0'.repeat(40)&&/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??'')&&
    event.after===env.GITHUB_SHA&&parents.length===2&&parents[0]===env.GITHUB_SHA&&parents[1]===base;
}
if(process.argv[2]==='--self-test') {
  const sha='1'.repeat(40);
  const env={GITHUB_EVENT_NAME:'push',GITHUB_REPOSITORY:repository,GITHUB_REF:ref,GITHUB_RUN_NUMBER:'1',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:sha};
  const event={repository:{full_name:repository},ref,created:true,deleted:false,before:'0'.repeat(40),after:sha};
  assert(accepts(env,event,[sha,base]));
  for(const [key,value] of Object.entries({GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'other/repo',GITHUB_REF:ref+'-extra',GITHUB_RUN_NUMBER:'2',GITHUB_RUN_ATTEMPT:'2',GITHUB_SHA:'bad'}))assert(!accepts({...env,[key]:value},event,[sha,base]));
  for(const mutation of [{created:false},{created:'true'},{deleted:true},{deleted:undefined},{before:base},{after:'2'.repeat(40)},{repository:{full_name:'other/repo'}},{ref:ref+'-extra'}])assert(!accepts(env,{...event,...mutation},[sha,base]));
  for(const parents of [[sha],[sha,'2'.repeat(40)],[sha,base,base],['2'.repeat(40),base]])assert(!accepts(env,event,parents));
  console.log('PASS one-shot creation guard: exact repository/ref/base, first run/attempt, no update/delete/dispatch/merge admission');
} else {
  try {
    const event=JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
    const parents=execFileSync('git',['rev-list','--parents','-n','1','HEAD'],{encoding:'utf8'}).trim().split(/\s+/);
    if(!accepts(process.env,event,parents))throw Error('refused');
    execFileSync('git',['diff','--exit-code',base,'--','tools/public-demo-passive-smoke.mjs','tools/check-public-demo-passive-smoke.mjs'],{stdio:'pipe'});
    console.log('One-shot creation and unchanged reviewed smoke verified.');
  } catch {
    console.error('One-shot public demo guard refused; no public navigation is authorized by this run.');
    process.exitCode=1;
  }
}
