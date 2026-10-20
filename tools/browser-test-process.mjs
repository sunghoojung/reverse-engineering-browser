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
  // A failed spawn has no PID. On macOS, signaling its native handle can target
  // the caller's process group instead of an owned child.
  const running = () => Number.isInteger(child.pid) && child.pid > 0 &&
    child.exitCode === null && child.signalCode === null;
  if (running()) child.kill('SIGTERM');
  if (await waitForClose(closed, timeoutMs)) return;
  if (running()) child.kill('SIGKILL');
  if (!await waitForClose(closed, timeoutMs)) {
    throw new Error(`Browser fixture process ${child.pid} did not close; preserving its profile`);
  }
}
