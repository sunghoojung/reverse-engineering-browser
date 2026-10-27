#!/usr/bin/env node
// Retired entry point: refuse before reading plans, writing reports, or loading transport.
console.error('Marker execution is unavailable: the CDP/Repeater runner was removed. Use prepare-marker-fuzz.mjs for offline planning only; no fallback is provided.');
process.exitCode=1;
