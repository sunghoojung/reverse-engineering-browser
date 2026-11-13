# WASM Laboratory: value flow v1

To trace a request field back into WebAssembly, an analyst needs to know where
a value inside a function comes from and where it goes. **Trace value** answers
that for one instruction, one of its operands, or one local, from the captured
module's bytes alone.

In Sources, choose **Inspect** on a captured module and select an instruction
row (click it or Tab to its offset). The **Trace value** panel under the listing
names the row; choose an operand and a direction, then **Trace value**. The
panel lists the slice by direction and distance, each row with its original
byte offset, role (seed, source, sink, step, or depth cap), kind and
instruction. A join shows every incoming edge with the branch that carried it.
Selecting a row, or Enter on it, shows that instruction in Inspect; the slice's
rows are marked in the listing by role. **×** clears the trace, and Hex hides
the panel. While the block graph is open the panel is hidden; seeding from a
graph block is not supported in v1.

Backward, the slice reaches the params, locals, globals, constants, memory
loads (with the instructions that compute their address) and call and import
call results that feed the value. Forward, it reaches stores (address or value
side), call and `call_indirect` arguments, import calls (where the value
crosses into JavaScript), `br_table`, `br_if`, `if` and `select` selectors,
globals and returns. One optional step maps a parameter or return to direct
call sites in the same module. Memory is conservative: a load equals an earlier
store only for the same constant address in the same block with nothing in
between.

Agents call `get_wasm_value_flow`. Kinds, offsets, indices and edges are
readable at every permission level; instruction text is content and needs Full
access. The analysis is static and bounded: nothing is executed, every result
names its truncation, and raw evidence is unchanged. The
[versioned contract](../../protocol/wasm-value-flow-v1.md) defines the seed,
joins, memory rule, document and limits.

This is the intra-function increment of "Search for values moving between WASM,
JavaScript, browser APIs, and network requests" in the
[WASM Laboratory roadmap](feature-list.md#webassembly-laboratory). Linking a
slice to observed calls, request fields and JavaScript values remains planned.
The def-use simulation is separate from the readable lifted view's expression
lifter; unifying them is follow-up work.
