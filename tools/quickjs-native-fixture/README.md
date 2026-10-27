# Real public QuickJS native target

Development-only official QuickJS-WASM debug-sync 0.32.0, not a toy interpreter
or a page-side sampler. The lockfile pins three MIT-licensed packages; install
scripts are disabled. Preserve downloaded LICENSE files when redistributing.
Do not commit node_modules.

    npm ci --ignore-scripts --prefix tools/quickjs-native-fixture
    node tools/quickjs-native-fixture/verify.mjs
    node tools/quickjs-native-fixture/exercise-quickjs.mjs
    REB_QUICKJS_WASM="$PWD/tools/quickjs-native-fixture/node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/emscripten-module.wasm" cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml --lib native_guest_binding::tests::pinned_public_module_and_corruption -- --ignored

These establish identity, reviewed compiled PC mapping, and normal interpreter
behavior (eight synchronous callbacks), NOT live native capture.
browser-acceptance.html additionally calls real canvas.measureText during each
synchronous Wasm import. Its JavaScript never inspects interpreter memory or
reports PCs/events. Serve this directory on loopback and open the page in the
rebuilt instrumented Brave session:

    python3 -m http.server 8766 --bind 127.0.0.1 --directory tools/quickjs-native-fixture
    # Another shell, with rebuilt Brave configured through the normal launcher:
    REB_NATIVE_WASM_DISPATCH=1 REB_NATIVE_WASM_GUEST_ADAPTER="$PWD/tools/quickjs-native-fixture/adapter.json" REB_CAPTURE_CATEGORY_MASK=1537 scripts/run-live-session.sh

Mask1537 enables Canvas+VM+Artifacts. The adapter is immutable startup config;
changing it requires a new browser process. Its JSON is sorted-key compact
canonical JSON with NO trailing newline. Native parsing rejects ambiguous
encodings and duplicate keys.

VM Lab must show retained exact module/adapter/bytecode identities and byte-offset
PCs, plus retained direct dispatch parents for Canvas host rows. A successful page
result alone is not native capture proof. Missing patches, exhausted budgets and
missing parents remain explicit omissions. Limit256 samples,64KiB per snapshot.
Workers/shared memory/async callbacks/cross-process network ancestry are not
established. Failed initial module/adapter admission requires a new capture
configuration; IPC enqueue is not delivery and no automatic retry is promised.

## Reviewed source and binary

Upstream: https://github.com/justjake/quickjs-emscripten
Source revision: df4efb9ef2cb25c417ecb57986da462d11b244ed
Module SHA256: 4d2f9f8adf28c48ed273515b815e05ae9a698b54955f7348e951faf43b1febc3

Function414 / offset0x20677 has244 explicit br_table arms. Selector is
load8_u(local320): the ORIGINAL opcode address. Local322 is postincrement and
must not replace320. Local10 is the C-stack frame base. Checked LE memory0
pointer chains[1708,20] and[1708,24] give current bytecode base and length.
Guest PC=local320-base, adjustment0, units byte offsets. Host import0 callsite
0x6816 is in a helper; native attribution validates it AND the exact live
dispatcher ancestor, not merely the nearest Wasm frame.

The Rust verifier checks exact digest AND compiled instruction/type dataflow.
Unknown builds cannot gain semantic verification from a caller label.
This is not hCaptcha support or universal guest-PC discovery.
