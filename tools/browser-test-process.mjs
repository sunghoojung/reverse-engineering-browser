// Browser fixtures must reap owned subprocesses before removing their profiles.
export async function waitForClose(closed, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      closed.then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function stopBrowserTestProcess({child, closed}, timeoutMs = 3000) {
  const running = () => child.exitCode === null && child.signalCode === null;
  if (running()) child.kill('SIGTERM');
  if (await waitForClose(closed, timeoutMs)) return;
  if (running()) child.kill('SIGKILL');
  if (!await waitForClose(closed, timeoutMs)) {
    throw new Error(`Browser fixture process ${child.pid} did not close; preserving its profile`);
  }
}
