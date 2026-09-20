# VM deobfuscation spike

This is a dependency-free feasibility prototype for a narrow but difficult
JavaScript tactic: a custom bytecode array interpreted by an embedded VM.

## Question

Can a bounded static pass recover useful pseudo-code from a common VM shape
without executing the captured JavaScript?

## What it recognizes

- a numeric literal bytecode array;
- an optional `opcode = bytecode[pc++] ^ key` decode step;
- a `switch (opcode)` dispatcher;
- allowlisted stack operations: push immediate, push bytecode immediate,
  binary arithmetic/bitwise operations, and return;
- a bounded concrete trace over the recovered bytecode.

The analyzer rejects missing or ambiguous pieces and reports uncertainty. It
does not import a JavaScript runtime, evaluate expressions, call `eval`, or
execute source supplied to it.

## Run

```sh
python3 vm_deob.py fixtures/xor-stack-vm.js
python3 -m unittest -v test_vm_deob.py
```

## Verdict

**PARTIAL / VALIDATED for the fixture shape.** The POC recovers a readable
instruction stream and result from an XOR-encoded stack VM. It is not a
general VM devirtualizer. The next production step would be parser-backed
handler extraction, provenance ranges, and a pluggable ISA registry rather
than adding more regular expressions.

## Research basis

- [webcrack](https://github.com/j4k0xb/webcrack) demonstrates AST-aware
  handling of obfuscator.io and bundles.
- [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
  documents control-flow flattening and VM bytecode as separate protection
  layers.
- [de4js](https://github.com/lelinhtinh/de4js) is useful historical prior art
  for unpackers, but its repository is archived.

This spike is intentionally bounded and non-executing.
