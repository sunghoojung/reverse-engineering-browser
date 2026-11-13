# WASM Pseudocode v1

`GET /api/wasm/pseudocode?artifact_id=<id>&function=<index>[&line_offset=<n>][&line_limit=<n>]`
returns `wasm-pseudocode-v1`: a readable lifted listing of one defined function of
a captured core WebAssembly module. The operation ID is `get_wasm_pseudocode`.
The native `reb://app/api/wasm/pseudocode` route and
`origin-trace-wasm --artifacts DIR --artifact-id ID --pseudocode-function N
[--line-offset N] [--line-limit N]` use the same Rust provider
(`apps/origin-trace-backend/src/wasm_pseudocode.rs`). Any other query parameter
is refused with 400. The [OpenAPI schema](openapi.json) defines `WasmPseudocode`.

The artifact passes the same identity, size and SHA-256 checks as
[WASM inspection](wasm-inspection-v1.md). Nothing runs the module, calls an
import, fetches anything or writes analysis files. The lift is derived on
request and never stored, so captured bytes and their hash stay the only
evidence.

## What a line is

The lift simulates the operand stack with each operator's declared effect and
folds instructions into nested expressions, as `wasm2wat --fold-exprs` and
WABT `wasm-decompile` do. Declared effects come from wasmparser's own
`operator_arity` table through `wasm_stack.rs`, so every operator the pinned
wasmparser 0.240 decodes has one. A function reads like this:

```text
func run(p0: i32) -> i32 {
  var l1: i32
  loop L1 {
    l1 = i32.load(p0, offset 8) + 1
    env.log(l1)
    br_if L1 (l1 < p0)
  }
  return l1
}
```

- Parameters are `p<index>`, other locals `l<index>`, globals `g<index>`, using
  the Wasm local and global indexes. `tN` is a temporary the lift introduced.
- Labels are `L<n>`, numbered by frame in opening order, and shown only on a
  frame some branch targets. A branch to the function's own frame is `return`.
- A branch that carries values names the label's temporaries:
  `br L3 with t5 = l1 + 1`. A frame whose end is reached by more than one path
  assigns its results to the same temporaries; a `block` whose end is reached
  only by falling through keeps its result as a pending value instead.
- Integer division, remainder, comparison and shift operators that depend on
  signedness carry a `u` suffix when unsigned (`/u`, `%u`, `<u`, `>u`, `<=u`,
  `>=u`); `>>` is `shr_s` and `>>>` is `shr_u`. An `i64` constant ends in `L`,
  an `f32` constant in `f`, and a non-finite float is written by its bits.
- Loads read `i32.load(addr, offset 8)`; stores read
  `i32.store(addr, offset 8) = value`. The offset is the memory argument's
  static offset, never an addition. Alignment is shown only when it is not
  natural, and a memory index only when it is not zero.
- Calls read `name(args)`. `call_indirect(args; index i, type 3, table 0)` names
  its callee index, type and table, and `call_ref` names its reference and type.
  A tail call reads `return f(args)`.
- `br_table` reads as `switch (selector) { case 0-3: br L2 ... default: br L0 }`,
  with cases grouped by target in order of first appearance. A case list longer
  than 240 bytes ends with `... (+N cases)`; the line still covers the whole
  instruction.
- A run of plain `block` openers with nothing between them (a dispatcher's)
  reads as one line, `block x32 L1..L32 {`.
- Other operators read as their mnemonic called with their operands and named
  immediates: `i32x4.extract_lane(v, lane: 2)`. A zero memory or table index is
  not printed.

### Names

Names come only from the module, in this order: the name section, an export,
an import's `module.field`, then `f<index>`. One function, `display_name`,
chooses every function name the lift prints and the callee table returns, so a
later name source is added there. A name that is not a plain identifier, or
that looks like a lift variable (`p0`, `l3`, `t9`, `g1`, `L2`, `f4`), is printed
quoted with control characters escaped, bounded to 64 bytes. Names never come
from guesses about what a function does.

### Effect order

Folding never reorders effects. A pending value is assigned to a temporary on
its own line before a line it could conflict with: two effects that order
matters for (calls, memory, tables, globals, traps), or a local one writes and
the other reads. Values a frame boundary would carry unassigned, a value a
conditional branch both carries and leaves on the stack, and an expression
deeper than 12 levels or longer than 200 bytes are assigned too. `spill_count`
counts these temporaries.

## Byte mapping and fallbacks

Every decoded instruction is owned by exactly one line, so the `instructions`
column of the lines sums to `lifted_instructions`, which equals
`instruction_count` when `status` is `complete`. Each line's `ranges` are the
module byte ranges (exclusive end) of the instructions it owns and those it
names without owning (a switch's case lines name their `br_table`), merged
where they touch. The header and `var` lines map to the body header and each
local declaration group. A value a branch discards is still a line, so no
instruction disappears.

What the lift does not model stays the instruction's disassembly text
(the same text as an `inspect_wasm` row) on a line of kind `fallback`, counted
by reason in `fallbacks`:

| Reason | When |
| --- | --- |
| `unreachable_code` | Instructions after an unconditional transfer, up to the frame's `else`, `catch` or `end`. |
| `unknown_effect` | An operator whose effect needs a type or label this module does not resolve. Pending values are assigned first, and later operands of that frame read `?` (`unknown_operands`). |
| `exception_handler` | A `try_table` with catch clauses: the clauses are listed, but the values they deliver are not assigned to the target's temporaries. |
| `gc_branch` | `br_on_null`, `br_on_non_null`, `br_on_cast`, `br_on_cast_fail`. |
| `stack_switching` | `resume`, `resume_throw`, `switch`, `suspend`. |
| `label_out_of_range` | A branch label past the open frames. |

A fallback with a declared effect binds it on the line:
`t4 = br_on_null { relative_depth: 0 } (t3)`. Fallbacks never make a lift
partial; they are counted and `omissions` says how many there are.

## Document

- Identity: `artifact_id`, `sha256`, `byte_size`, `function_index`, `name`,
  `name_source` (`name_section`, `export`, `import` or `index`), `byte_offset`
  and `byte_end` of the body, `type_index`, `params`, `results`, `locals`.
- `evidence` is always `static_lift`. `status` is `complete` or `partial`.
- Counts: `instruction_count`, `lifted_instructions`, `line_count`,
  `fallback_count`, `fallbacks`, `spill_count`, `unknown_operands`.
- `nesting`: `max_depth` and counts of `block`, `loop`, `if`, `else`, `try`,
  `try_table` and `br_table`.
- `frames` (`frame_fields`: `open_line`, `close_line`, `depth`, `kind`, `label`,
  `byte_offset`): control frames open in or around the window, at most 256,
  with `truncation.frames` when more exist. `close_line` is null for a frame a
  limit left open.
- `lines` (`line_fields`: `depth`, `kind`, `instructions`, `ranges`), where
  `kind` indexes `line_kinds`: `header`, `statement`, `open`, `middle` (`else`,
  `catch`), `close`, `case`, `fallback`.
- `text`: the window's lines, newline terminated, two spaces of indent per
  depth up to 24 levels and `[depth N]` beyond. It has exactly one row per
  entry of `lines`.
- `callees` (`callee_fields`: `function_index`, `name`, `name_source`): each
  function called on a line in the window.
- `window`: `line_offset`, `line_limit`, `lines` returned and
  `next_line_offset`, null at the end.
- `truncation`: `instructions`, `lines` and `deadline` (a limit stopped the
  lift), `clipped_lines` (lines whose text was cut at 2,048 bytes and marked
  `[text limited]`), `window_bytes` (the window stopped early to fit),
  `frames`.
- `omissions`, `limits` and `notice`.

## Permission levels

The lifted `text` is captured content, like an `inspect_wasm` row's text:
through `reb-api mcp` it is omitted below `--allow-content` (`--permission
full`), as `--omit-content` omits every `text` field. Everything else is
structure and is returned at every level, read-only included: counts, the
nesting summary and frames, each line's depth, kind, owned count and byte
ranges, and the callee table. Callee names are module names, which
`get_wasm_functions` also returns at every level.

## Bounds

| Bound | Value | Why |
| --- | --- | --- |
| Input | 64 MiB | The block graph's limit, above the artifact receiver's default 16 MiB. |
| Function body | 7,654,321 bytes | Web engines reject a longer body, so it cannot have run. |
| Instructions lifted | 250,000 | Keeps one request's offsets and lines in tens of megabytes. |
| Lines | 300,000, and 24 MiB of line text | The same, for line storage. |
| Line text | 2,048 bytes | One line stays readable; `clipped_lines` counts cuts. |
| Expression depth and text | 12 levels, 200 bytes | Deeper operands become temporaries. |
| Window | 1 to 2,000 lines (default 400), about 96 KiB | One page fits the 128 KiB MCP inline limit. |
| Deadline | 3 seconds | Checked every 1,024 instructions. |

A limit stops the lift at a named byte, sets the matching `truncation` field
and `status: partial`, and names the byte in `omissions`; later instructions
are not lifted. The lift is recomputed for each window. An imported or
undefined function returns 404, a malformed body or unterminated control
structure 422, a window past `line_count` or a `line_limit` outside 1 to 2,000
400. The native route runs the packaged helper with the block graph's queue,
output limit and five-second process deadline.

## What it does not establish

A readable line is a reading of declared stack effects, not observed
execution, value provenance or semantics. It does not validate types,
recover high-level types, or claim that a fallback line is unreachable at run
time beyond what the binary declares. The intra-function stack layer in
`wasm_stack.rs` (`ModuleTypes`, `Label`, `arity`, `block_arity`,
`branch_arity`) is the interface a value-flow analysis can share.
