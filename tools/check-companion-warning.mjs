// Cloud macOS acceptance of the production unverified-browser alert, with no real browser.
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {cp,mkdir,mkdtemp,readFile,readdir,realpath,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('..',import.meta.url));
assert.equal(process.platform,'darwin','Warning UI acceptance requires cloud macOS');
assert.equal(process.env.CI,'true','Run warning UI acceptance only on the disposable cloud CI runner');
const temporary=await mkdtemp(join(tmpdir(),'reb-companion-warning-'));
const report=join(root,'build/companion-warning-qa');
await mkdir(report,{recursive:true});
const app=join(temporary,'Origin Trace.app');
const browser=join(temporary,'Brave Browser Development.app');
const executable=join(browser,'Contents/MacOS/WarningFixture');
const result=join(report,'warning-ui.xcresult');
let log='',timer,exportError;
function failureSummary(output) {
  // Synthetic UI fixtures only. Keep CI exceptions small enough that Node does
  // not truncate the actual assertion behind compiler invocations.
  const failures=output.split('\n').filter(line=>/error:|failed|Failing tests:|Test Case|Executed |TEST FAILED|timed out/i.test(line));
  return (failures.length?failures.slice(-30).map(line=>line.slice(0,1000)).join('\n'):output.slice(-6000)).slice(-12000);
}

try {
  await cp(join(root,'build/Origin Trace.app'),app,{recursive:true});
  execFileSync('codesign',['--verify','--deep','--strict',app],{stdio:'pipe'});
  const plist=join(app,'Contents/Info.plist');
  assert.equal(execFileSync('/usr/libexec/PlistBuddy',['-c','Print :OriginTraceReleaseType',plist],{encoding:'utf8'}).trim(),'paired');
  await mkdir(join(browser,'Contents/MacOS'),{recursive:true});
  await writeFile(join(browser,'Contents/Info.plist'),`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.brave.Browser.development</string>
<key>CFBundleExecutable</key><string>WarningFixture</string><key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>Owned warning fixture</string></dict></plist>\n`);
  // This owned fixture never opens a network connection or starts an actual browser.
  await writeFile(executable,'#!/bin/sh\nset -eu\n: "${REB_COMPANION_WARNING_RECEIPT:?}"\nprintf "launched\\n" >> "$REB_COMPANION_WARNING_RECEIPT"\nexit 17\n',{mode:0o700});
  for(const scenario of ['keyboard-offline','button-offline','retry','modal-reopen']) {
    const stores=join(temporary,scenario,'stores');
    await mkdir(join(stores,'artifacts'),{recursive:true});
    await mkdir(join(temporary,scenario,'home'),{recursive:true});
    for(const name of ['events.jsonl','traces.jsonl','signals.jsonl'])await writeFile(join(stores,name),'');
  }
  const child=spawn('xcodebuild',['test','-project',join(root,'tools/companion-warning-ui/CompanionWarningUITests.xcodeproj'),
    '-scheme','CompanionWarningUITests','-destination','platform=macOS',
    '-derivedDataPath',join(temporary,'derived'),'-resultBundlePath',result,'-parallel-testing-enabled','NO'],
  {cwd:temporary,detached:true,env:{...process.env,TEST_RUNNER_REB_COMPANION_WARNING_APP:app,
    TEST_RUNNER_REB_COMPANION_WARNING_ROOT:temporary,TEST_RUNNER_REB_COMPANION_WARNING_BRAVE:executable}});
  for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{log=(log+chunk).slice(-512*1024);});
  try {
    await new Promise((done,reject)=>{
      timer=setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')log+='\n'+error;}reject(new Error('Cloud warning UI test timed out\n'+failureSummary(log)));},600000);
      child.once('error',reject);
      child.once('close',(code,signal)=>code===0?done():reject(new Error(`Cloud warning UI test exited ${code}/${signal}\n${failureSummary(log)}`)));
    });
  } finally {
    clearTimeout(timer);
    await writeFile(join(report,'xcodebuild.log'),log);
    try {
      execFileSync('xcrun',['xcresulttool','export','attachments','--path',result,
        '--output-path',join(report,'attachments')],{timeout:30000,stdio:'pipe'});
    } catch(error) {exportError=error;await writeFile(join(report,'attachment-export-error.log'),String(error));}
  }
  if(exportError)throw new Error('Native warning screenshots could not be exported',{cause:exportError});
  const screenshots=['keyboard-offline-initial-warning','keyboard-offline-after-return',
    'keyboard-offline-new-session-setup','keyboard-offline-later-session-warning',
    'keyboard-offline-later-session-offline','button-offline-initial-warning','button-offline-after-click',
    'retry-initial-warning','retry-real-startup-failure','retry-fresh-warning','retry-after-offline',
    'modal-reopen-initial-warning','modal-reopen-single-warning','modal-reopen-still-offline'];
  const manifest=JSON.parse(await readFile(join(report,'attachments/manifest.json'),'utf8'));
  assert(Array.isArray(manifest),'Expected XCTest attachment manifest');
  const attachments=manifest.flatMap(test=>Array.isArray(test.attachments)?test.attachments:[]);
  const seen=new Set();
  for(const name of screenshots) {
    const suffix=new RegExp('^'+name+'_[0-9]+_[0-9a-fA-F-]{36}\\.png$');
    const matching=attachments.filter(item=>item.suggestedHumanReadableName===name ||
      item.suggestedHumanReadableName===name+'.png' || suffix.test(item.suggestedHumanReadableName));
    assert.equal(matching.length,1,`Missing or duplicate named warning screenshot: ${name}`);
    const filename=matching[0].exportedFileName;
    assert(typeof filename==='string' && /^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.png$/.test(filename) && !seen.has(filename),'Unsafe or reused screenshot path');
    seen.add(filename);
    const bytes=await readFile(join(report,'attachments',filename));
    assert(bytes.length>8 && bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])),`Invalid PNG: ${name}`);
  }
  // Receipt expectations are checked here outside the UI-test runner sandbox.
  const receipts={};
  for(const [scenario,expected] of Object.entries({'keyboard-offline':0,'button-offline':0,retry:1,'modal-reopen':0})) {
    let receipt='';
    try {receipt=await readFile(join(temporary,scenario,'launches.txt'),'utf8');}
    catch(error) {if(error.code!=='ENOENT')throw error;}
    assert.equal(receipt,'launched\n'.repeat(expected),`Unexpected browser launch for ${scenario}`);
    receipts[scenario]=expected;
  }
  await writeFile(join(report,'result.json'),JSON.stringify({productionAlert:true,realXCTest:true,fakeBrowserOnly:true,screenshots,receipts},null,2)+'\n');
  console.log('PASS real unverified-browser warning decisions and launch receipts; owned unsigned fake browser only, no native-pair compatibility claim');
} finally {
  await writeFile(join(report,'xcodebuild.log'),log);
  // Match only this unique relocated bundle, including orphaned packaged helpers
  // and both /var and /private/var spellings used by Launch Services.
  const bundlePaths=[app];
  try {bundlePaths.push(await realpath(app));}catch(error){if(error.code!=='ENOENT')throw error;}
  let binaries=[];
  try {binaries=await readdir(join(app,'Contents/MacOS'));}catch(error){if(error.code!=='ENOENT')throw error;}
  const ownedCommands=bundlePaths.flatMap(bundle=>[
    ...binaries.map(name=>join(bundle,'Contents/MacOS',name)),
    ...['/bin/bash','bash','/bin/sh','sh'].map(shell=>shell+' '+join(bundle,'Contents/Resources/run-live-session.sh')),
  ]);
  const snapshot=()=>execFileSync('ps',['-axo','pid=,ppid=,command='],{encoding:'utf8'}).split('\n')
    .map(line=>/^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line)).filter(Boolean)
    .map(([,pid,parent,command])=>({pid:Number(pid),parent:Number(parent),command}));
  const selectOwned=processes=>{
    const owned=new Set(processes.filter(p=>ownedCommands.some(command=>p.command===command || p.command.startsWith(command+' '))).map(p=>p.pid));
    for(let previous=-1;previous!==owned.size;) {
      previous=owned.size;
      for(const child of processes)if(owned.has(child.parent))owned.add(child.pid);
    }
    return processes.filter(p=>owned.has(p.pid));
  };
  let pending=selectOwned(snapshot());
  for(const child of pending.reverse()) {
    try {process.kill(child.pid,'SIGTERM');}catch(error){if(error.code!=='ESRCH')throw error;}
  }
  for(let attempt=0;attempt<30 && pending.length;attempt++) {
    await new Promise(done=>setTimeout(done,100));
    const current=snapshot();
    // Retain a still-identical descendant even if termination reparented it.
    const currentOwned=new Set(selectOwned(current).map(child=>child.pid));
    pending=current.filter(child=>pending.some(old=>old.pid===child.pid && old.command===child.command)
      || currentOwned.has(child.pid));
  }
  for(const child of pending.reverse()) {
    try {process.kill(child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}
  }
  for(let attempt=0;attempt<20 && pending.length;attempt++) {
    await new Promise(done=>setTimeout(done,100));
    const current=snapshot();
    const currentOwned=new Set(selectOwned(current).map(child=>child.pid));
    pending=current.filter(child=>pending.some(old=>old.pid===child.pid && old.command===child.command)
      || currentOwned.has(child.pid));
  }
  assert.equal(pending.length,0,'Owned warning test processes did not stop; preserving fixtures');
  await rm(temporary,{recursive:true,force:true});
}
