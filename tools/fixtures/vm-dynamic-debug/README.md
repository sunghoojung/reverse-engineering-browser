# VM Dynamic Debug fixtures

These source-owned fixtures exercise cold-path analysis only. Tests read the
JavaScript as inert bytes and never execute it.

- `stack-vm.js` is a small stack machine with push, add, jump, and halt cases.
- `xor-decoded/` decodes into a new typed array. Its fake artifact store links
  the post-decode bytes to the interpreter instead of treating the ciphertext
  string as guest bytecode.
- `register-vm.js` mutates a `regs` array.
- `packed-non-vm.js` is a minified long-switch negative without a dispatch
  loop.

The `bytecode_buffer` record in the fake manifest uses the native artifact
kind and `runtime_typed_array` capture origin. Workspace snapshot origin
labels stay `runtime-typed-array` in `vm-opcode-workspace-v2`.

`wasm-dispatch.json` contains authored WASM modules as hex: single and repeated
`br_table` loops, a `call_indirect` loop, and a non-VM constant/drop function.
These are decoded statically, never instantiated. Dispatch source ranges identify
the instruction, not a recovered guest handler body. Dynamic/default arms retain
unknown opcodes. Repeated selectors remain scoped to their dispatch source site.
Functions reached by a direct call or by a `call_indirect` table element can
contribute more sites. Unrelated functions do not.
