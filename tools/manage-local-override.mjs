#!/usr/bin/env node
// Fail before reading action files, stdin, or contacting any backend.
const removed = 'Local override execution was removed with CDP. Offline preview and preparation remain available; no native override replacement exists.';
if (process.argv.length === 3 && process.argv[2] === '--help') {
  console.log(removed);
} else {
  console.error(removed);
  process.exitCode = 2;
}
