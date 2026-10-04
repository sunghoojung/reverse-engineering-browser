# WASM Laboratory: captured module inspection v1

Sources now provides **Inspect** for captured WebAssembly artifacts. Researchers
can inspect sections, function signatures, imports, exports, memories, tables,
globals, data and custom sections, then read function disassembly with original
byte offsets. Every instruction keeps its function index, including imported
function numbering. Selecting an enabled offset returns to the original hex.
**Hex** preserves the existing evidence view; **Find** searches either view.

Inspection is an explicit static action. It uses the existing pinned
`wasmparser` dependency, verifies artifact integrity, and never executes the
module or contacts its origin. Resource bounds, partial coverage, malformed
input, and retry behavior follow the
[versioned contract](../../protocol/wasm-inspection-v1.md).

This completes the bounded section-inspection and disassembly increment in the
[WASM Laboratory roadmap](feature-list.md#webassembly-laboratory). Remaining
work includes runtime compile/instantiate/call/trap/memory-growth evidence,
JS/WASM crossing and value relationships, complete GC layouts, higher-level
semantic reconstruction and WASM VM hypothesis confirmation. Static inspection
cannot establish those relationships.
