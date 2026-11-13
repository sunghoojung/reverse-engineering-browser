# WASM Laboratory: module diff v1

Sites rotate their WebAssembly builds. **Compare with**, in the Sources **More**
menu of a captured WebAssembly module, matches that module's functions (A,
the build already understood) with those of another captured module (B) and
shows the match table in place of the code view.

Each row has a status (**Changed**, **Added**, **Removed**, **Ambiguous**,
**Renumbered** or **Identical**, and **Unclassified** when a limit stopped the
comparison), each side's function name and index, the match method and a
score. Each member of a tie is its own **Ambiguous** row with the tie's size.
Filters narrow the table by status; **Show more rows** pages it. Every
function opens in **Graph** on its own module, and Back returns to the
comparison's module.

Matching runs from strongest to weakest evidence: identical bytes, a
normalized body that ignores call targets, renumbered locals and globals and
moved static data, import and export names, the name section, the call graph,
and finally structural similarity. Two equally good candidates stay
**Ambiguous**; nothing is paired by guess, and a step the four-second bound
stops leaves its functions **Unclassified**. **Renumbered** means the bodies
differ only by renumbering and relocation as far as the contract can tell; it
cannot tell apart two globals of the same type. The comparison is static, reads
only verified captured bytes, never runs either module, and shows no
instruction text. Fingerprints, bounds and statuses are defined by the
[versioned contract](../../protocol/wasm-module-diff-v1.md); agents use
`get_wasm_module_diff` (recipe 26 in the
[agent cookbook](../development/agent-cookbook.md)).

Remaining work: carrying analyst names and notes from A to B across matched
rows, and using the fingerprints as library signatures.
