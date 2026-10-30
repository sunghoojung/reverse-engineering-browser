# Native JavaScript dispatch fixtures

`two-level-vm.js` is a repository-owned synthetic program for the native
JavaScript dispatch probe ([contract](../../../protocol/native-js-dispatch-v1.md)).
An outer `switch (program[pc++])` interpreter calls, from its opcode 3
handler, an inner `ops[code[pc++]](s)` handler-table interpreter, and its
opcode 4 handler dispatches `ext[program[pc++]](s)`. Non-ASCII comment
characters before every site make UTF-8 and UTF-16 offsets differ.

`tools/native-js-dispatch-golden.cc` names this exact text: its UTF-16LE
SHA-256, UTF-16 length and the UTF-16 anchors of the outer `switch` keyword,
the inner `[` and the extended `[`. Change the file only together with those
constants.
