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
