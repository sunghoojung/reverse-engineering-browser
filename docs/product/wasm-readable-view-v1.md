# WASM Laboratory: readable view of one function v1

**Readable** in Sources shows one function of a captured WebAssembly module as
folded expressions instead of stack instructions, beside **Inspect**, **Hex**
and **Graph**:

```text
loop L1 {
  l1 = i32.load(p0, offset 8) + 1
  env.log(l1)
  br_if L1 (l1 < p0)
}
```

Every line shows the byte offset where it starts and names the module byte
ranges it covers, so choosing a line by pointer or with Enter reveals that byte
in the disassembly or the hex below. Calls use only names the module carries
(its name section, exports and imports). An instruction the view does not fold,
such as code after a `return`, stays its disassembly text on a line marked
**raw**, and the header counts those lines. Arrow keys, Page Up and Page Down
move through lines and read the next or previous window of a long function.
The function is chosen by index or with the previous and next controls, and
Readable opens on the function Graph last showed.

Agents read the same lift through `get_wasm_pseudocode` (see the
[agent cookbook](../development/agent-cookbook.md)). Line structure, byte
ranges, counts and callee names are available at every permission level; the
lifted text is captured content and needs Full access.

The lift is a static reading of declared stack effects: nothing runs the
module. Folding keeps calls, memory, globals, traps and branches in their
byte order, and local writes in order with whatever can throw to a handler
in the same function. The tests check this on generated code, and a check
runs generated modules in V8 and compares their values with the listing. Bounds,
fallback reasons, names and the document are defined by the
[versioned contract](../../protocol/wasm-pseudocode-v1.md). Type recovery,
value provenance and analyst names for functions remain outside this
increment of the [WASM Laboratory](feature-list.md#webassembly-laboratory).
