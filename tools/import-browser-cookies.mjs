// Compatibility entry point only: never reads private input or starts a browser.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

const removed='Cookie browser import has been removed. No CDP transport or fallback is available. No input was read and no browser was launched.';
export async function runCookieImport({argv=process.argv.slice(2),output=line=>console.log(line)}={}) {
  output(removed);
  return argv.length===1 && argv[0]==='--help' ? 0 : 2;
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  process.exitCode=await runCookieImport();
}
