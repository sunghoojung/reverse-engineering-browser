#!/usr/bin/env node
// Deliberately interactive: real credentials belong to a local user handoff.
import {emitKeypressEvents} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {readCookieImport, CookieImportError} from './cookie-import.mjs';
import {launchCookieBrowser} from './cookie-import-browser.mjs';

const help='Usage: node tools/import-browser-cookies.mjs --browser /absolute/path/to/chromium\nRequires a local interactive terminal and Node.js 22+. Read protocol/cookie-import-v1.md.\nNo real credential import may be operated by an agent. There is no noninteractive mode.\n';

// Input is bounded and hidden, including file paths; nothing is saved to history.
function question(prompt,signal) {
  let answer='';
  return new Promise((resolve,reject)=>{
    const finish=(value,error)=>{
      process.stdin.off('keypress',onKey);process.stdin.off('end',onAbort);process.stdin.off('error',onAbort);signal?.removeEventListener('abort',onAbort);
      process.stdin.pause();process.stdout.write('\n');
      if(error)reject(error);else resolve(value);
    };
    const onAbort=()=>finish(null,new CookieImportError('cancelled'));
    const onKey=(text,key={})=>{
      if(key.ctrl&&(key.name==='c'||key.name==='d'))return onAbort();
      if(key.name==='return'||key.name==='enter')return finish(answer);
      if(key.name==='backspace'){answer=answer.slice(0,-1);return;}
      if(key.ctrl||key.meta||key.sequence?.startsWith('\x1b'))return;
      if(typeof text==='string'&&!/[\x00-\x1f\x7f]/.test(text)&&answer.length+text.length<=4096)answer+=text;
    };
    if(signal?.aborted)return onAbort();
    signal?.addEventListener('abort',onAbort,{once:true});
    process.stdin.once('end',onAbort);process.stdin.once('error',onAbort);
    process.stdin.setRawMode(true);process.stdin.resume();process.stdin.on('keypress',onKey);
    // Switch off terminal echo before publishing the prompt. A fast paste or
    // accessibility input can otherwise race the raw-mode transition.
    process.stdout.write(prompt);
  });
}

export async function runCookieImport({argv=process.argv.slice(2),interactive=Boolean(process.stdin.isTTY&&process.stdout.isTTY),ask=question,
  output=text=>process.stdout.write(text),read=readCookieImport,launch=launchCookieBrowser}={}) {
  if(argv.length===1&&['--help','-h'].includes(argv[0])){output(help);return 0;}
  if(argv.length!==2||argv[0]!=='--browser'||!interactive){output(help+'Refused: use the local user-operated terminal flow.\n');return 2;}
  let plan,session;const abort=new AbortController();let outcome;
  const wasRaw=process.stdin.isRaw===true;
  if(process.stdin.isTTY)process.stdin.setRawMode(true);
  const stop=()=>{abort.abort();void session?.dispose('interrupted');};
  process.once('SIGINT',stop);process.once('SIGTERM',stop);process.once('SIGHUP',stop);
  try {
    output('REB private cookie import\nOnly import cookies you are authorized to use. Keep this terminal private.\nAll input is hidden. No names, values, source filenames or source hashes are printed.\n');
    const path=await ask('Selected export file (absolute path): ',abort.signal);
    const format=await ask('Export format (chrome or firefox): ',abort.signal);
    const origin=await ask('Exact destination HTTPS origin (no trailing slash): ',abort.signal);
    const duration=await ask('Disposable lifetime in seconds (30–300): ',abort.signal);
    if(!/^[0-9]{2,3}$/.test(duration))throw new CookieImportError('duration');
    plan=await read(path,format,origin,Number(duration));
    output(JSON.stringify(plan.review(),null,2)+'\n');
    output('Destination: a new private off-record browser context. No existing profile is opened.\nIMPORT applies and verifies locally without opening a page. Source file stays unchanged.\n');
    if(await ask('Type IMPORT to apply, or anything else to cancel: ',abort.signal)!=='IMPORT'){output('Cancelled before browser launch.\n');return 0;}
    if(abort.signal.aborted)throw new CookieImportError('cancelled');
    session=await launch(argv[1],plan.review().destination,{signal:abort.signal});
    session.finished.then(value=>{outcome=value;abort.abort();});
    if(abort.signal.aborted)throw new CookieImportError('cancelled');
    await session.import(plan);plan=null;
    output('Imported and privately verified. No page has been opened.\n');
    output('OPEN hands this browser to you at the reviewed origin. This is NOT an origin firewall.\nCookies follow host/domain, path and SameSite rules, including subdomains where shown and other ports.\nPages, redirects and third parties may send data elsewhere. Only proceed within your authorization.\nThe browser closes at the deadline. CLEAR closes it now and clears/disposes its context.\n');
    const action=await ask('Type OPEN to browse, or anything else to CLEAR and close: ',abort.signal);
    if(action==='OPEN') {
      await session.openReviewedOrigin();
      output('Dedicated browser opened. REB Traffic capture is not attached.\n');
      await ask('Press Enter to CLEAR and close now (automatic close at the deadline): ',abort.signal);
    }
    outcome=await session.dispose('cleared');
    output(JSON.stringify(outcome)+'\n');return outcome.state==='disposed'?0:1;
  } catch(error) {
    if(session)outcome=await session.dispose(outcome?.reason??'interrupted');
    // Never forward arbitrary filesystem/browser/parser error text.
    if(outcome)output(JSON.stringify(outcome)+'\n');
    else output((error instanceof CookieImportError?error.message:'Cookie import failed. No source data is included in this diagnostic.')+'\n');
    return outcome?.state==='disposed'&&outcome.reason==='expired'?0:1;
  } finally {
    plan?.discard();process.off('SIGINT',stop);process.off('SIGTERM',stop);process.off('SIGHUP',stop);
    if(process.stdin.isTTY){process.stdin.setRawMode(wasRaw);process.stdin.pause();}
  }
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  emitKeypressEvents(process.stdin);
  process.exitCode=await runCookieImport();
}
