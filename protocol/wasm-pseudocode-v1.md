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
  `br L3 with t5 = l1 + 1`. A frame's results reach its end in temporaries of
  their own, assigned before its closing brace: a `loop` has separate ones,
  because a branch to a loop carries its parameters back to its start. Only a
  `block` whose end is reached solely by falling through keeps its result as a
  pending value instead; a `try_table`'s result is always assigned inside it,
  so a value computed in the protected region never reads as computed after
  it.
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
quoted with control characters escaped. A name longer than 96 bytes keeps its
start and its end around `...`, because overloads and numbered clones of one
demangled name differ at the end, and is followed by its function index:
`"std::__2::__function::__func<...>::operator()()"#123`. The index keeps
names that differ only in a long middle apart. The raw name is cut on whole
characters and each kept character is escaped as a unit, so a cut never
splits an escape and nothing inside the quotes can close them early. Names
never come from guesses about what a function does.

### What folding guarantees

Read the lines in order, and within a line read an expression's operands
before the expression itself (left to right, as written). That reading
evaluates the instructions in an order with these properties. The tests check
them on fixtures and on two generators.
`folding_keeps_effect_order_and_owns_every_byte_once` runs 5,000 untyped
programs mixing calls, loads, stores, globals, locals, trapping division and
`br_if`. `typed_generated_modules_validate_and_keep_effect_order` runs 2,000
modules that wasmparser validates, with nested `block`, `loop`, `if`/`else`
and `try_table`, `br`, `br_if` and `br_table` at depth, `return_call`,
`select`, `local.tee`, `memory.grow`, a multi-value call and `throw`, and
`try_table` handlers that read a local the try body writes. A third,
`every_partial_assignment_keeps_the_guarantees`, puts a conflicting value
below every place that assigns only part of the pending stack. Beyond these
static checks, `make wasm-readable-values-check` (part of `make check`) runs
3,000 generated modules in V8 with imports that log their calls and throw
into handlers, interprets each listing with the same imports, and requires
the same results, traps, escaping exceptions, call log, global and memory for
five inputs.

1. The instructions with an effect (calls, loads, stores and every other
   memory or table operation, global reads and writes, trapping arithmetic,
   throws, `unreachable`) and the branches (`if`, `br`, `br_if`, `br_table`,
   `return`) keep their byte order.
2. No read or write of a local moves across a write of that local.
3. While a catching frame of this function is open (a legacy `try` body
   before its first catch arm, or a `try_table` with catch clauses), a local
   write keeps its byte order with every instruction that can throw: calls of
   every kind, `throw`, `throw_ref` and `rethrow`. A handler in the function
   reads the local as it was when control left.
4. When `status` is `complete`, every decoded instruction, and so every code
   byte, is owned by exactly one line.

So two kinds of instruction may read at a different place than their bytes.
A pure value (a constant, a local read, arithmetic that cannot trap) may read
later, where nothing above can change what it reads. A local write may move
across a call or a throw where no catching frame of this function is open: a
throw there leaves the function, and its locals are never read again.
To keep these properties, a pending value is assigned to a temporary `tN` on
its own line, deepest first, before a line it conflicts with. Two values
conflict when both have effects, when one writes a local the other reads or
writes, or, inside a catching frame, when one writes a local and the other
can throw. Values are marked from the top of
the stack down, and each marked value's effects join what later values are
checked against, so a value below a marked one that conflicts with it is
assigned before it. At a `br_if`, every pending value with an effect or a
local write is marked, because it runs whether or not the branch is taken,
and so is anything below that it conflicts with (a read of the local it
writes). A pending pure value with no such conflict may wait, since on the
taken path it is discarded unseen. Values a frame boundary would carry unassigned,
a value a conditional branch both carries and leaves on the stack, and an
expression deeper than 12 levels or longer than 200 bytes are assigned too.
`spill_count` counts these temporaries.

## Byte mapping and fallbacks

Every decoded instruction is owned by exactly one line. This is checked on
every lift, not assumed: `unowned_instructions` and `repeated_instructions`
count instructions owned by no line or by more than one, and `status` is
`complete` only when both are zero and no limit stopped the lift. The
`instructions` column of the lines then sums to `lifted_instructions`, which
equals `instruction_count`. Each line's `ranges` are the
module byte ranges (exclusive end) of the instructions it owns and those it
names without owning (a switch's case lines name their `br_table`), merged
where they touch. A line lists at most 64 ranges: past that, its 64th range
is one span covering every later one, which also covers bytes other lines
own, and `truncation.merged_ranges` counts such lines in the window. The
header and `var` lines map to the body header and each local declaration
group. A value a branch discards is still a line, so no
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
- Counts: `instruction_count`, `lifted_instructions`,
  `unowned_instructions`, `repeated_instructions`, `line_count`,
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
  `frames`, and `merged_ranges` (lines whose ranges were merged into a
  covering span).
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
| Function body | 7,654,321 bytes | Web engines reject a longer body, so it cannot have run. Module validation enforces it for every body, so one oversized function makes every function of its module return 422. |
| Instructions lifted | 250,000 | Keeps one request's offsets and lines in tens of megabytes. |
| Lines | 300,000, and 24 MiB of line text | The same, for line storage. Checked before each instruction and before each `br_table` case line, so one table with many targets cannot overshoot. |
| Line text | 2,048 bytes | One line stays readable; `clipped_lines` counts cuts. |
| Expression depth and text | 12 levels, 200 bytes | Deeper operands become temporaries. |
| Window | 1 to 2,000 lines (default 400), cut until the whole document is at most 120 KiB both compact and pretty-printed | `reb-api mcp` inlines a result only when both forms are at most 131,072 bytes; the cut is measured on the serialized document, callees and frames included, and `truncation.window_bytes` says it happened. |
| Deadline | 3 seconds | Checked every 1,024 instructions and every 65,536 pending values visited while ordering effects, so a deep operand stack cannot run far past it. |

A limit stops the lift at a named byte, sets the matching `truncation` field
and `status: partial`, and names the byte in `omissions`; later instructions
are not lifted. The lift is recomputed for each window. An imported or
undefined function returns 404. A module whose sections do not validate, or
a requested function whose body does not validate with wasmparser's
validator (every feature enabled), returns 422 with a named error rather
than a listing. The validator's own message can quote captured text (a
duplicate export name, say), so it is cut at 512 bytes on a character
boundary and marked `[text limited]`. The lift reads declared stack effects and assumes a body that
type checks, so an invalid one would read as plausible junk. A malformed
body or unterminated control structure also returns 422, a window past `line_count` or a `line_limit` outside 1 to 2,000
400. The native route runs the packaged helper with the block graph's queue,
output limit and five-second process deadline.

## What it does not establish

A readable line is a reading of declared stack effects, not observed
execution, value provenance or semantics. It does not validate types,
recover high-level types, or claim that a fallback line is unreachable at run
time beyond what the binary declares. The intra-function stack layer in
`wasm_stack.rs` (`ModuleTypes`, `Label`, `arity`, `block_arity`,
`branch_arity`) is the interface a value-flow analysis can share.
