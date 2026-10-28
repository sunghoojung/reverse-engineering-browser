// Build a dev-only browser-glue bundle; the official Wasm is never transformed.
import {build} from 'esbuild';
import {createHash} from 'node:crypto';
import {mkdir, readFile, writeFile, copyFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root = path.dirname(fileURLToPath(import.meta.url));
const output = path.resolve(process.argv[2] || path.join(root, 'native-hook-build'));
const wasm = path.join(root, 'node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/emscripten-module.wasm');
const bytes = await readFile(wasm);
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (sha256 !== '4d2f9f8adf28c48ed273515b815e05ae9a698b54955f7348e951faf43b1febc3') throw new Error('Unrecognized public QuickJS binary');
await mkdir(output, {recursive: true});
await build({
  absWorkingDir: root,
  entryPoints: ['native-hook-entry.mjs'],
  outfile: path.join(output, 'quickjs-native-hook.js'),
  bundle: true,
  platform: 'browser',
  conditions: ['browser'],
  format: 'iife',
  target: 'es2022',
  loader: {'.map': 'json'},
  define: {'import.meta.url': '"https://reb.invalid/quickjs-native-hook.js"'},
  legalComments: 'eof',
});
const bundle = await readFile(path.join(output, 'quickjs-native-hook.js'));
if (bundle.length > 16 * 1024 * 1024 || bytes.length > 16 * 1024 * 1024) throw new Error('Native fixture exceeds cctest file limit');
const bundle_sha256 = createHash('sha256').update(bundle).digest('hex');
await copyFile(wasm, path.join(output, 'quickjs.wasm'));
for (const [name, packageName] of [['quickjs', '@jitl/quickjs-wasmfile-debug-sync'], ['core', 'quickjs-emscripten-core']]) {
  await copyFile(path.join(root, 'node_modules', packageName, 'LICENSE'), path.join(output, `LICENSE-${name}`));
}
await writeFile(path.join(output, 'input-receipt.json'), JSON.stringify({sha256, bundle_sha256, native_capture_validated: false}, null, 2) + '\n');
console.log(output);
