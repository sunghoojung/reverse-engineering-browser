#!/usr/bin/env node
// Install this reviewed example as examples/check-stock.mjs after project export.
import {readFile} from 'node:fs/promises';
import {sendRequest} from '../src/client.mjs';
import {checkStock, StockcheckError} from '../src/stockcheck.mjs';

try {
  const args = process.argv.slice(2), options = {};
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!['--input', '--origin', '--send'].includes(flag) || Object.hasOwn(options, flag)) throw new StockcheckError('INVALID_INPUT');
    if (flag === '--send') options[flag] = true;
    else {
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new StockcheckError('INVALID_INPUT');
      options[flag] = value;
    }
  }
  if (!options['--input'] || !options['--origin']) throw new StockcheckError('INVALID_INPUT');
  let selection;
  try {
    const bytes = await readFile(options['--input']);
    if (bytes.length > 4096) throw new Error();
    selection = JSON.parse(bytes.toString('utf8'));
  } catch {throw new StockcheckError('INVALID_INPUT');}
  console.log(JSON.stringify(await checkStock(selection, {sendRequest, allowedOrigin: options['--origin'], send: options['--send'] === true})));
} catch (error) {
  const code = error instanceof StockcheckError ? error.code : 'CLIENT_ERROR';
  console.log(JSON.stringify({ok: false, error: {code}}));
  process.exitCode = ['INVALID_INPUT', 'INVALID_ORIGIN', 'MISSING_EXPORTED_TRANSPORT'].includes(code) ? 2 :
    ['LOGIN_REQUIRED', 'CATALOG_EXPIRED', 'RATE_LIMITED', 'TARGET_ERROR', 'REDIRECT_REFUSED'].includes(code) ? 3 :
      ['SCHEMA_CHANGED', 'MALFORMED_RESPONSE', 'INCOMPLETE_RESPONSE'].includes(code) ? 4 : 5;
}
