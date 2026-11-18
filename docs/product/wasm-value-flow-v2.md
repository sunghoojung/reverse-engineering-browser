# WASM Laboratory: value flow v2

To trace a request field back into WebAssembly, an analyst needs to know where
a value inside a function comes from and where it goes. **Trace value** answers
that for one instruction, one of its operands, or one local, from the captured
module's bytes alone, and it answers completely: the slice has no node, depth
or edge cap, calls are entered rather than stopped at, and what the panel shows
is a page of a whole it names exactly.

In Sources, choose **Inspect** on a captured module and select an instruction
row (click it or Tab to its offset). The **Trace value** panel under the listing
names the row; choose an operand, a direction and whether to follow control
dependence, then **Trace value**. The panel is a path view rooted at the seed:
**Comes from** groups the sources by kind with exact counts (loads, params,
constants, import call results, calls in other functions), **Goes to** groups
the sinks the same way, and opening one row shows its path to the seed, with
the locals the value passed through, the join that merged it (and the branch
that carried it there), the memory cell it may have gone through, the call it
crossed and the decision that chose its path named on each connector. Every row
says which class it is: the value itself, an address it only computed, a
possible value through memory, or a decision. Rows link to their Inspect
instruction, in this function or in a callee; the slice's rows are marked in
the listing by role. The panel takes its height from a resizable split, and
long lists are virtualized, so a slice of a million nodes and a slice of ten
read the same way.

Backward, the slice reaches the params, locals, globals, constants, memory
loads (with the instructions that compute their address), the stores a load
provably or possibly reads, and, through the calls it meets, the sources inside
the functions they name; a call's result is tied to the arguments it depends on
by the callee's summary, so the path stays exact. Forward, it reaches stores,
call arguments and the sinks inside the callee, import calls (where the value
crosses into JavaScript), `br_table`, `br_if`, `if` and `select` selectors,
globals and returns. **Show callers** lists every direct call site of the
function, paged, with what else can reach it.

Agents call `get_wasm_value_flow` and `get_wasm_call_sites`. Kinds, offsets,
indices, classes and edges are readable at every permission level; instruction
text is content and needs Full access. Results are paged, and the MCP
projection shrinks a page until it fits rather than cutting a document. The
analysis is static: nothing is executed, every omission is named, the only
bound is the machine's memory, and raw evidence is unchanged. The
[versioned contract](../../protocol/wasm-value-flow-v2.md) defines the seed,
simulation, classes, calls, document and paging.

This is the intra-module increment of "Search for values moving between WASM,
JavaScript, browser APIs, and network requests" in the
[WASM Laboratory roadmap](feature-list.md#webassembly-laboratory). Linking a
slice to observed calls, request fields and JavaScript values remains planned.
The def-use simulation and the readable lifted view's expression lifter share
one stack and control-frame layer, `wasm_stack.rs`, and each keeps its own
payload, so an operator or proposal is modeled once for both.
