import {spawnSync} from 'node:child_process';

// Shared local-check watchdog. SIGKILL also terminates a child that ignores
// SIGTERM, so a blocked file open cannot leave make lint waiting forever.
export function checkedSpawnSync(command, args = [], options = {}) {
  const result = spawnSync(command, args, {...options, timeout: 600_000, killSignal: 'SIGKILL'});
  if (result.error) {
    throw new Error(`Child command failed: ${[command, ...args].join(' ')}: ${result.error.code === 'ETIMEDOUT' ? '10-minute watchdog expired' : result.error.message}`, {cause: result.error});
  }
  return result;
}
