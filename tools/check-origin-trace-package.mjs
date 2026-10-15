import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {access, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

// Check the existing explicit allowlists, not a second generated asset manifest.
export async function checkPackageContract() {
  const build = await readFile(join(root, 'scripts/build-research-app.sh'), 'utf8');
  const loops = [...build.matchAll(/for asset in ([^\n]+); do/g)];
  assert.equal(loops.length, 1, 'UI assets must have one packaging copy loop');
  const assets = loops[0][1].split(/\s+/);
  assert.equal(new Set(assets).size, assets.length);
  assert.match(build, /cp "\$\{repo_root\}\/apps\/research-ui\/\$\{asset\}" "\$\{research_ui_resources\}\/\$\{asset\}"/);
  assert.doesNotMatch(build, /"\$\{resources_path\}\/(?:\$\{asset\}|[^"/]+\.(?:js|css|html))"/);
  const html = await readFile(join(root, 'apps/research-ui/index.html'), 'utf8');
  const publicAssets = ['index.html', ...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match => match[1])];
  assert.deepEqual([...assets].sort(), [...publicAssets, 'analyst_runner_core.js', 'analyst_runner_node.js'].sort());
  for (const asset of assets) {
    assert.match(asset, /^[a-z][a-z0-9_]*\.(?:html|css|js)$/);
    assert((await stat(join(root, 'apps/research-ui', asset))).size > 0);
  }
  const native = await readFile(join(root, 'apps/research-ui/macos/OriginTraceApp.swift'), 'utf8');
  assert(build.includes('ClientProjectExportSmoke.swift'));
  const clientSmoke=await readFile(join(root,'apps/research-ui/macos/ClientProjectExportSmoke.swift'),'utf8');
  const clientUI=await readFile(join(root,'tools/client-project-ui/ClientProjectUITests.swift'),'utf8');
  assert(!clientSmoke.includes('panel.ok('),'Modern Save panels cannot be approved in process');
  assert(clientSmoke.includes('actual == expected') && clientSmoke.includes('children.isEmpty'));
  assert(clientUI.includes('XCUIApplication(url:') && clientUI.includes('save.click()'));
  assert(clientUI.includes('XCTAttachment(screenshot:') && !clientUI.includes('.write(to:'));
  assert(!clientUI.includes('Data(contentsOf:'),'Byte receipts are checked outside the UI-test sandbox');
  assert.equal([...native.matchAll(/func applicationWillTerminate\(/g)].length,1,'Keep one termination delegate');
  assert.match(native, /let researchUIURL = resourcesURL\.appendingPathComponent\("research-ui", isDirectory: true\)/);
  for (const asset of ['index.html', 'analyst_runner_core.js']) {
    assert(native.includes(`researchUIURL.appendingPathComponent("${asset}")`));
    assert(!native.includes(`resourcesURL.appendingPathComponent("${asset}")`));
  }
  const nativeRoutes = native.slice(native.indexOf('switch requestURL.path'), native.indexOf('case "/api/health"'));
  assert.deepEqual([...nativeRoutes.matchAll(/"\/([^"/]+\.(?:js|css|html))"/g)].map(match => match[1]).sort(), [...publicAssets].sort());
  const backend = await readFile(join(root, 'apps/origin-trace-backend/src/app.rs'), 'utf8');
  const backendCount = Number(backend.match(/const UI_ASSETS: \[&str; (\d+)\]/)[1]);
  assert.equal(backendCount, publicAssets.length, 'Backend asset array size matches packaged public assets');
  const backendRoutes = backend.match(/const UI_ASSETS:[\s\S]+?= \[([\s\S]+?)\];/)[1];
  assert.deepEqual([...backendRoutes.matchAll(/"([^"]+)"/g)].map(match => match[1]).sort(), [...publicAssets].sort());
  const config = await readFile(join(root, 'apps/origin-trace-backend/src/config.rs'), 'utf8');
  assert(config.includes('macos.join("../Resources/research-ui")'));
  const coordinator = await readFile(join(root, 'apps/research-ui/macos/LiveSessionCoordinator.swift'), 'utf8');
  assert(coordinator.includes('resourcesURL.appendingPathComponent("research-ui", isDirectory: true)'));
  assert(coordinator.includes('resourcesURL.appendingPathComponent("run-live-session.sh")'));
  assert(native.includes('resourcesURL.appendingPathComponent("OriginTrace.icns")'));
  const removedBytes = (await Promise.all([...publicAssets, 'analyst_runner_core.js'].map(async asset => (await stat(join(root, 'apps/research-ui', asset))).size))).reduce((a, b) => a + b, 0);
  await checkClientProjectScreenshotContract();
  console.log(`PASS packaging contract: ${assets.length} canonical assets; ${publicAssets.length + 1} redundant copies removed (${removedBytes} bytes)`);
  return {assets, publicAssets};
}

// Shared with the existing launcher check so the HTTP case uses its actual live
// session, not a fake server or a development-tree asset directory.
export async function runPackagedSmoke(app, directory, name, flags = [], environment = {}) {
  const stores = join(directory, name);
  await mkdir(stores, {recursive: true});
  const args = ['--store', join(stores, 'events.jsonl'), '--trace-store', join(stores, 'traces.jsonl'),
    '--signal-store', join(stores, 'signals.jsonl'), '--artifacts', join(stores, 'artifacts'),
    '--api-collection', join(stores, 'collection.json'), '--local-analyst', join(stores, 'analyst.json'), ...flags];
  const child = spawn(join(app, 'Contents/MacOS/OriginTrace'), args, {
    cwd: directory,
    env: {...process.env, REB_APP_SMOKE_TEST: '1', REB_APP_SMOKE_LOCAL_ANALYST_WRITE: '1',
      REB_APP_SMOKE_LIVE_FAILURE: '0', REB_DISABLE_AUTOMATIC_LIVE_SESSION: '1', ...environment},
  });
  let output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {output = (output + chunk).slice(-128 * 1024);});
  let timer;
  try {
    await new Promise((resolveExit, reject) => {
      timer = setTimeout(() => {child.kill('SIGKILL'); reject(new Error(`${name}: native smoke timed out\n${output}`));}, 60000);
      child.once('error', reject);
      child.once('exit', (code, signal) => code === 0 ? resolveExit() : reject(new Error(`${name}: app exited ${code}/${signal}\n${output}`)));
    });
  } finally {
    clearTimeout(timer);
    await writeFile(join(directory, `${name}.log`), output);
  }
  assert(!output.includes('SMOKE_ERROR'), output);
  const results = [...output.matchAll(/^SMOKE_OK (.+)$/gm)];
  assert.equal(results.length, 1, `${name}: missing or repeated completed WebKit result\n${output}`);
  const result = JSON.parse(results[0][1]);
  // renderShellStatus replaces the HTML bootstrap title after evidence loads.
  // Match the requested scenario, not whichever mode the app happened to report.
  const titles = {offline: 'Origin Trace', fallback: 'Origin Trace',
    demo: 'Origin Trace - Demo Evidence', live: 'Origin Trace - Live Session'};
  assert(Object.hasOwn(titles, name), `Unknown packaged smoke scenario: ${name}`);
  assert.equal(result.title, titles[name]);
  assert.equal(result.nativeShell, true);
  assert.deepEqual(result.nativeClientProject,{available:true,invalidPayloadRefused:true,subframeRefused:true});
  assert.equal(result.stylesLoaded, true);
  assert.equal(result.smokeExerciseError, null, output);
  assert.equal(result.debuggerContractValid, true);
  assert.equal(result.apiCollectionContractValid, true);
  assert.equal(result.localAnalystContractValid, true);
  assert.equal(result.localAnalystRunnerAvailable, true);
  assert.equal(result.localAnalystRunOutcome, 'completed');
  assert.deepEqual(JSON.parse(result.localAnalystRunResult), {seed: 'native-verified'});
  assert.equal(result.decoderTransformText, 'Hello');
  assertFloat32Smoke(name, result.float32);
  assert.equal(new URL(result.location).searchParams.get('native'), '1');
  const {publicAssets} = await checkPackageContract();
  assert.equal(result.packageAssetCount, publicAssets.length);
  assert.equal(result.packagePrivateAssetsBlocked, true);
  console.log(`PASS packaged WebKit ${name}: assets, native marker, API routes, Decoder and saved Analyst execution`);
  return {result, output};
}

export function assertFloat32Smoke(name, value) {
  assert(['offline','demo','fallback','live'].includes(name));
  const live=name==='live';
  assert.deepEqual(value, {module_ready:true,mode:live?'live_http':'stored_native',run_disabled:!live,
    output:live?{profile:'binary32-finite-steps-v1',input_sha256:'6d58692645c9d1cfaf13541cbd258f86193ef63c2f1d38f6bbca9617372d7bd6',reference_sha256:'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119',
      input_bits:'80000000',reference_bits:'00000000',input_sign_bit:1,reference_sign_bit:0,
      input_class:'zero',reference_class:'zero',raw_bytes_equal:false,all_bits_equal:false,all_numeric_equal:true,
      all_within_tolerance:true,finite_pairs:1,excluded_nonfinite_pairs:0,absolute_delta:0,relative_delta:0,ulp_distance:0,rms_delta:0}:null});
}

// xcresulttool names exported files by UUID; its manifest associates each
// file with the explicit XCTAttachment name. Auto screenshots are not evidence
// for a requested phase. See Apple's xcresulttool export attachments command.
export async function validateClientProjectScreenshots(manifest, directory) {
  assert(Array.isArray(manifest),'XCTest attachment manifest must be an array');
  const attachments=manifest.flatMap(test=>Array.isArray(test.attachments)?test.attachments:[]);
  const phases=['save','writeFailure','replacementSave'],used=new Set(),result=[];
  for(const phase of phases){
    const expected=phase+'-native-save-panel';
    const suffix=new RegExp('^'+expected+'_[0-9]+_[0-9a-fA-F-]{36}\\.png$');
    const matching=attachments.filter(item=>item.suggestedHumanReadableName===expected ||
      item.suggestedHumanReadableName===expected+'.png' || suffix.test(item.suggestedHumanReadableName));
    assert.equal(matching.length,1,'Expected one named XCTest screenshot for '+phase);
    const name=matching[0].exportedFileName;
    assert(typeof name==='string' && /^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.png$/.test(name) && !used.has(name),'Unsafe or reused screenshot filename');
    used.add(name);
    const bytes=await readFile(join(directory,name));
    assert(bytes.length>8 && bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])),'Missing, empty or invalid PNG for '+phase);
    result.push({phase,attachment:matching[0].suggestedHumanReadableName,exported_file:name,bytes:bytes.length});
  }
  return result;
}

async function checkClientProjectScreenshotContract(){
  const directory=await mkdtemp(join(tmpdir(),'reb-attachment-contract-'));
  const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=','base64');
  const phases=['save','writeFailure','replacementSave'];
  const attachments=phases.map((phase,index)=>({suggestedHumanReadableName:phase+'-native-save-panel_0_00000000-0000-0000-0000-00000000000'+index+'.png',exportedFileName:phase+'.png'}));
  try{
    for(const phase of phases)await writeFile(join(directory,phase+'.png'),png);
    assert.equal((await validateClientProjectScreenshots([{attachments}],directory)).length,3);
    const automatic=Array.from({length:4},(_,index)=>({suggestedHumanReadableName:'Automatic screenshot '+index,exportedFileName:'save.png'}));
    await assert.rejects(validateClientProjectScreenshots([{attachments:[...attachments.slice(0,2),...automatic]}],directory),/named XCTest screenshot/);
    await assert.rejects(validateClientProjectScreenshots([{attachments:[...attachments,attachments[0]]}],directory),/named XCTest screenshot/);
    await assert.rejects(validateClientProjectScreenshots([{attachments:attachments.map((item,index)=>index?item:{...item,exportedFileName:'../save.png'})}],directory),/Unsafe/);
    await assert.rejects(validateClientProjectScreenshots([{attachments:attachments.map(item=>({...item,exportedFileName:'save.png'}))}],directory),/reused/);
    await writeFile(join(directory,'save.png'),'');await assert.rejects(validateClientProjectScreenshots([{attachments}],directory),/invalid PNG/);
    await writeFile(join(directory,'save.png'),'not a PNG');await assert.rejects(validateClientProjectScreenshots([{attachments}],directory),/invalid PNG/);
  }finally{await rm(directory,{recursive:true,force:true});}
}

async function runClientProjectSmoke(app, directory) {
  const stores=join(directory,'client-project'),output=join(directory,'client-project-panels');
  await mkdir(stores);await mkdir(output);
  const child=spawn('xcodebuild',['test','-project',join(root,'tools/client-project-ui/ClientProjectUITests.xcodeproj'),
    '-scheme','ClientProjectUITests','-destination','platform=macOS',
    '-derivedDataPath',join(directory,'client-project-derived'),
    '-resultBundlePath',join(directory,'client-project-ui.xcresult'),
    '-parallel-testing-enabled','NO'],{cwd:directory,env:{...process.env,
      TEST_RUNNER_REB_CLIENT_PROJECT_APP:app,TEST_RUNNER_REB_CLIENT_PROJECT_OUTPUT:output,
      TEST_RUNNER_REB_CLIENT_PROJECT_STORES:stores}});
  let log='',timer,exportError=null;
  for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{log=(log+chunk).slice(-256*1024);});
  try {
    await new Promise((done,reject)=>{
      timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('Xcode native Save-panel test timed out\n'+log));},240000);
      child.once('error',reject);
      child.once('close',(code,signal)=>code===0?done():reject(new Error(`Xcode native Save-panel test exited ${code}/${signal}\n${log}`)));
    });
  } finally {
    clearTimeout(timer);await writeFile(join(directory,'client-project.log'),log);
    // Use Xcode's supported attachment export outside the UI-test sandbox.
    // Preserve the primary test failure if diagnostic export also fails.
    try {
      execFileSync('xcrun',['xcresulttool','export','attachments','--path',join(directory,'client-project-ui.xcresult'),
        '--output-path',join(output,'attachments')],{cwd:directory,timeout:30000,stdio:'pipe'});
    } catch(error) {exportError=error;await writeFile(join(output,'attachment-export-error.log'),String(error));}
  }
  if(exportError)throw new Error('XCTest screenshot export failed',{cause:exportError});
  const receipt=JSON.parse(await readFile(join(output,'result.json'),'utf8'));
  assert.deepEqual(receipt,{savedExactBytes:true,cancelNoWrite:true,busyRefused:true,
    navigationNoWrite:true,writeFailureRefused:true,replacementSaved:true,panelCount:5});
  const attachmentDirectory=join(output,'attachments');
  const manifest=JSON.parse(await readFile(join(attachmentDirectory,'manifest.json'),'utf8'));
  const screenshots=await validateClientProjectScreenshots(manifest,attachmentDirectory);
  for(const item of screenshots)await cp(join(attachmentDirectory,item.exported_file),join(output,item.phase+'-panel.png'));
  await writeFile(join(output,'phase-attachments.json'),JSON.stringify(screenshots,null,2)+'\n');
  console.log('PASS Xcode UI-tested real native Save panels, exact ZIP bytes, Cancel/no-write, pending refusal, navigation cancellation/retry and atomic-write failure; overwrite not exercised');
}

async function main() {
  const contract = await checkPackageContract();
  if (process.argv.includes('--contract-only')) return;
  assert.equal(process.platform, 'darwin', 'Packaged runtime checks require macOS; --contract-only does not validate native runtime');
  const temporary = await mkdtemp(join(tmpdir(), 'origin-trace-package-'));
  const app = join(temporary, 'relocated', 'Origin Trace.app');
  const reports = join(root, 'build/package-qa');
  await mkdir(reports, {recursive: true});
  try {
    // Relocate the signed product and use an unrelated cwd. No source UI override.
    await cp(join(root, 'build/Origin Trace.app'), app, {recursive: true});
    const resources = join(app, 'Contents/Resources');
    assert.deepEqual((await readdir(join(resources, 'research-ui'))).sort(), [...contract.assets].sort());
    for (const asset of contract.assets) {
      assert.deepEqual(await readFile(join(resources, 'research-ui', asset)), await readFile(join(root, 'apps/research-ui', asset)), asset);
      await assert.rejects(access(join(resources, asset)), {code: 'ENOENT'});
    }
    assert((await stat(join(resources, 'OriginTrace.icns'))).size > 0);
    await access(join(resources, 'run-live-session.sh'), constants.X_OK);
    execFileSync('codesign', ['--verify', '--deep', '--strict', app], {cwd: temporary, stdio: 'pipe'});
    execFileSync(join(app, 'Contents/MacOS/OriginTrace'), ['--check-native-ui-url'], {cwd: temporary, stdio: 'inherit'});
    const offline = await runPackagedSmoke(app, temporary, 'offline');
    assert.equal(new URL(offline.result.location).protocol, 'reb:');
    assert.equal(offline.result.captureMode, 'idle');
    await runClientProjectSmoke(app,temporary);
    const demo = join(temporary, 'demo');
    await mkdir(demo);
    const events = execFileSync(join(root, 'build/reb-event-producer'));
    execFileSync(join(app, 'Contents/MacOS/OriginTraceEventBroker'), ['--store', join(demo, 'events.jsonl'),
      '--trace-store', join(demo, 'traces.jsonl'), '--signal-store', join(demo, 'signals.jsonl')], {input: events});
    const sample = await runPackagedSmoke(app, temporary, 'demo', ['--demo-evidence']);
    assert.equal(sample.result.captureMode, 'demo');
    assert(sample.result.requests > 0, 'Demo must display the producer evidence');
    const fallback = await runPackagedSmoke(app, temporary, 'fallback', [], {REB_APP_SMOKE_LIVE_FAILURE: '1'});
    assert.match(fallback.output, /SMOKE_LIVE_FAILURE Brave Browser Development is not executable/);
    assert.equal(new URL(fallback.result.location).protocol, 'reb:');
    assert.equal(fallback.result.captureMode, 'idle');
    // Installed Chrome/Brave supplies only a disposable loopback debugger. It does
    // not stand in for native Brave capture instrumentation.
    const launcher = spawn(process.execPath, [join(root, 'tools/check-origin-trace-launcher.mjs'), root, app], {
      cwd: temporary, env: {...process.env, REB_CHECK_PACKAGED_APP_UI: '1'}, stdio: 'inherit',
    });
    await new Promise((resolveExit, reject) => {
      launcher.once('error', reject);
      launcher.once('exit', code => code === 0 ? resolveExit() : reject(new Error(`Packaged launcher check exited ${code}`)));
    });
    console.log('PASS relocated signed package: native offline/demo/startup-failure fallback, live HTTP WebKit and out-of-repository launcher');
  } finally {
    for (const name of ['offline', 'demo', 'fallback', 'client-project']) {
      const log = join(temporary, `${name}.log`);
      try {await cp(log, join(reports, `${name}.log`));} catch (error) {if (error.code !== 'ENOENT') throw error;}
    }
    try {await cp(join(temporary,'client-project-ui.xcresult'),join(reports,'client-project-ui.xcresult'),{recursive:true});}
    catch (error) {if(error.code!=='ENOENT')throw error;}
    try {await cp(join(temporary,'client-project-panels'),join(reports,'client-project-panels'),{recursive:true});}
    catch (error) {if(error.code!=='ENOENT')throw error;}
    await rm(temporary, {recursive: true, force: true});
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
