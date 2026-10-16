# Owned workspace effect declarations

These are inert, repository-authored declarations used to exercise opcode
workspaces. The analyzer never executes these JavaScript files. It attaches
metadata only when the exact complete source SHA-256 matches the bundled
metadata. Similar handler text, an opcode number, a filename, a URL, or a
changed snapshot cell cannot authorize that association.

`stack.js` and `register.js` describe separate owned, byte-encoded programs.
Their `stack.json` / `register.json` metadata uses one-byte literal opcodes and
unsigned little-endian operands. Program entry and branch targets are byte
offsets. Arithmetic is explicitly modulo 2^64. Both branch successors are
static possibilities; the analysis neither evaluates conditions nor reports
which edge executed.

`native-stack.json` and `native-register.json` instead bind the exact inert
reference sources under `../native-vm-dispatch/` and the exact
`protocol/owned-vm-programs-v1.json` digest. These are declared mappings to the
repository's fixed native fixtures, not captured JavaScript interpreter
execution. Their PCs are instruction indices. Instruction sizes, operand byte
locations, and byte entry are null. They cannot supply guest-byte attribution
or byte-offset traversal, and native dispatch samples cannot silently fill
those gaps.

Each handler has a bounded array of declarative effects. Distinct incompatible
rows are retained, and no row wins merely because it was first or had a sample.
All shipped effects are `inferred`; none are automatically `confirmed` or
promoted by dispatch occurrence. `reads` and `writes` describe declared access
sets, not deductions from differences between snapshots. A null cell value is
unknown, including popped native stack cells; it is never rewritten as zero.
Atomic groups and fused superoperators remain explicitly null/unknown.

`tools/check-owned-vm-helper.py` checks the native declarations against the
independent transition goldens used by the existing owned semantics acceptance
before running the actual fixed native helper. Workspace Rust tests compare
operation vocabularies and exact-source binding. These checks do not prove any
site's instruction set or authorize captured-code execution.
