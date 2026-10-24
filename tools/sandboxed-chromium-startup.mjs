// Shared headless Chromium launch for authored UI checks.
// A small /dev/shm can stall Chrome before DevToolsActivePort exists without
// the process exiting. --disable-dev-shm-usage avoids that stall. It does not
// disable the sandbox, and a failed launch is not retried.
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';

export const sandboxedChromiumStartupBudgetMs = 60000;

export function sandboxedChromiumArguments(profile) {
  return ['--headless=new', '--disable-dev-shm-usage', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-sync', 'about:blank'];
}

export function startSandboxedChromium(executable, profile, recordOutput = () => {}) {
  let output = '';
  const note = text => {output = text.slice(-8192); recordOutput(output);};
  const browser = spawn(executable, sandboxedChromiumArguments(profile), {
    detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'pipe']});
  browser.on('error', error => note(output + String(error)));
  browser.stderr.on('data', chunk => note(output + chunk));
  const ready = async (budgetMs = sandboxedChromiumStartupBudgetMs) => {
    const active = join(profile, 'DevToolsActivePort');
    const deadline = Date.now() + budgetMs;
    let portState = 'not checked';
    while (Date.now() < deadline) {
      if (browser.exitCode !== null || browser.signalCode !== null) {
        throw Error(`Sandboxed Chromium startup failed (${browser.exitCode ?? browser.signalCode}): ${output || '(no process output)'}`);
      }
      try {
        const text = await readFile(active, 'utf8');
        const port = text.split('\n')[0];
        portState = port ? 'ready' : `incomplete (${Buffer.byteLength(text)} bytes)`;
        if (port) return port;
      } catch (error) {
        portState = error?.code === 'ENOENT' ? 'missing' : String(error?.code ?? error?.message ?? error).slice(0, 80);
      }
      await new Promise(resolve => setTimeout(resolve, 40));
    }
    const state = browser.exitCode === null && browser.signalCode === null ? 'alive' : (browser.signalCode ?? browser.exitCode);
    throw Error(`Timed out: sandboxed Chromium startup after ${budgetMs}ms pid=${browser.pid ?? 'unknown'} ${state} DevToolsActivePort=${portState} output=${output || '(no process output)'}`);
  };
  return {browser, ready};
}
