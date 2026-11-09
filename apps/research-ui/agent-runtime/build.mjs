#!/usr/bin/env node
// Bundles the agent loop and its pinned LangChain packages into one minified
// browser asset. `platform: 'browser'` selects the packages' browser builds, so
// a dependency that needs a Node built-in fails here instead of in the app.
// Usage: node build.mjs <output directory>
import {build} from 'esbuild';
import {mkdir, readFile, stat, writeFile} from 'node:fs/promises';
import {join, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const output = process.argv[2];
if (!output) throw new Error('usage: node build.mjs <output directory>');
await mkdir(output, {recursive: true});
const outfile = join(output, 'agent_runtime.js');
const result = await build({
  entryPoints: [join(here, 'src/entry.mjs')],
  bundle: true, minify: true, format: 'iife', platform: 'browser', target: 'safari16',
  outfile, legalComments: 'none', metafile: true, logLevel: 'warning',
  // Deterministic output for the same lockfile.
  sourcemap: false, charset: 'utf8',
});
const inputs = Object.keys(result.metafile.inputs);
const forbidden = inputs.filter(path => /(^|\/)node:|async_hooks/.test(path));
if (forbidden.length) throw new Error(`The agent bundle must not include Node built-ins: ${forbidden.join(', ')}`);
// One notice file per bundled package, from the package's own license file.
const lock = JSON.parse(await readFile(join(here, 'package-lock.json'), 'utf8'));
const used = [...new Set(inputs.map(path => /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(path)?.[1]).filter(Boolean))].sort();
const notices = [];
for (const name of used) {
  const entry = lock.packages[`node_modules/${name}`];
  let text = '';
  for (const file of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'license', 'LICENCE']) {
    text = await readFile(join(here, 'node_modules', name, file), 'utf8').catch(() => '');
    if (text) break;
  }
  notices.push(`${name}@${entry?.version ?? 'unknown'} (${entry?.license ?? 'see package'})\n\n${text.trim() || 'No license file in the package; see its package.json.'}\n`);
}
await writeFile(join(output, 'agent_runtime.LICENSES.txt'),
  `Third-party packages bundled into agent_runtime.js, pinned by apps/research-ui/agent-runtime/package-lock.json.\n\n${notices.join('\n---\n\n')}`);
const {size} = await stat(outfile);
console.log(`Built ${outfile}: ${size} bytes, ${used.length} packages`);
