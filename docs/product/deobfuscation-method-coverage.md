# Deobfuscation method coverage

This comparison covers the JavaScript deobfuscation series on
[ReverseJS](https://steakenthusiast.github.io/), reviewed September 21, 2026.
It describes the shipped Rust worker, not the experimental Babel pipeline.
Deobfuscation remains an alternate representation inside Sources. Original
artifact bytes and byte-range provenance remain available.

| Article technique | Production behavior | Deliberate limits |
| --- | --- | --- |
| [Constant folding](https://steakenthusiast.github.io/2022/05/28/Deobfuscating-Javascript-via-AST-Manipulation-Constant-Folding/) | Recursive primitive arithmetic, bitwise operations, comparisons and string concatenation | Non-finite values, mixed string coercion and non-exact exponentiation remain unresolved |
| [Constant propagation](https://steakenthusiast.github.io/2022/05/31/Deobfuscating-Javascript-via-AST-Replacing-References-to-Constant-Variables-with-Their-Actual-Value/) | Earlier primitive `const` initializers in the same statement list | No cross-scope, mutable binding, destructuring or closure propagation; declarations stay intact |
| [String concealing](https://steakenthusiast.github.io/2022/05/22/Deobfuscating-Javascript-via-AST-Manipulation-Various-String-Concealing-Techniques/) | Escape normalization, literal concatenation, own literal array/string indices, non-escaping local constant tables | No global script tables, mutable/aliased tables, sparse indices, custom cipher execution or general decoder interpretation |
| [Bracket to dot](https://steakenthusiast.github.io/2022/05/28/Deobfuscating-Javascript-via-AST-Manipulation-Converting-Bracket-Notation-Dot-Notation-for-Property-Accessors/) | Literal ASCII identifier properties, including optional access | Numeric receivers retain brackets; non-identifier and Unicode property names remain bracketed |
| [Dead code](https://steakenthusiast.github.io/2022/06/04/Deobfuscating-Javascript-via-AST-Removing-Dead-or-Unreachable-Code/) | Known primitive conditional/logical expressions; literal-condition `if` arms without declarations | No general control-flow analysis or removal of declarations that might affect hoisting; surviving blocks retain scope |
| [JSFuck-style expressions](https://steakenthusiast.github.io/2022/06/14/Deobfuscating-Javascript-via-AST-Deobfuscating-a-Peculiar-JSFuck-style-Case/) | Primitive unary chains, boolean arithmetic, negative zero and bounded bitwise operations | Array/object coercion, sparse-array tricks and constructor-generated code remain unresolved |

The restricted evaluator never invokes `eval`, `Function`, Node's `vm`, Babel's
`path.evaluate`, analyzed functions, getters or coercion hooks. The site's
[Babel execution vulnerability investigation](https://steakenthusiast.github.io/2023/10/11/CVE-2023-45133-Finding-an-Arbitrary-Code-Execution-Vulnerability-In-Babel/)
shows why a static analyzer must not substitute host execution for proof.

There is intentionally no claim of complete deobfuscation. Custom XOR/base64
functions, rotated tables, dynamic proxy calls, sparse JSFuck arrays and general
control-flow flattening require additional bounded interpreters or separately
captured runtime evidence. In particular, replacing array holes with explicit
`undefined` changes property-existence and prototype-lookup behavior. Unknown
code stays visible, and Sources reports these omissions.

## Bounds and correctness

The evaluator has a depth limit of 64, a 250,000-step budget, a 16 KiB value
limit, and at most 4,096 rewrites with 512 KiB total replacement text. Constant
storage is capped at 64 primitive bindings and 16 local tables of at most 256
entries per statement list. Table recovery rejects all non-index references,
mutations, duplicate binding names, dynamic scope and global script bindings.
It never assumes that `const` makes an array immutable.

Each rewrite uses original UTF-8 byte ranges. Replacements are parenthesized to
preserve precedence, member syntax and directive prologues. The worker chooses
a non-overlapping outer expression when recursive evaluation succeeds, without
reparsing generated nodes or looping to a fixed point. Exhausted rewrite, work or evaluation-depth budgets mark
the representation truncated and retain the remaining source.

A heap-backed Tree-sitter preflight iteratively checks syntax-tree depth before
Oxc parsing. Sources above depth 128 or 500,000 syntax nodes are rejected with a
recoverable diagnostic; preflight also has a one-second deadline. Error-recovery
trees are rejected rather than used to infer a depth bound. This adds a
conservative grammar admission boundary: syntax accepted by Oxc but unsupported
by the preflight grammar remains unavailable. Literal/comment punctuation does
not count as nesting. The worker preserves the source and can process the next
framed request after rejection. Adapter wall-clock deadlines remain five seconds.

## Validation and engines

`tests/research_ui/test_deobfuscation_methods.py` exercises the worker protocol,
reconstructs every source map, checks positive and negative technique cases,
and compares observable results of repository-owned fixtures in Node. The
production worker never runs Node or any captured JavaScript. Native service
tests verify the packaged response boundary, errors and deadline.

The browser development server uses the same Rust worker when built, preferring
`target/debug` then `target/release`, or an explicit
`REB_DEOBFUSCATOR_WORKER` path. Without a worker it retains the separately
labelled `python-lexical` classifier/formatter. An available worker's error
never silently falls back. Native builds always bundle Rust. Python heuristic
classification and table previews remain supplementary evidence, not proof
that a Rust rewrite is valid.

## Proxy calls

Literal calls through preceding immutable function/arrow bindings and immediate
functions can be reduced when the body is one return expression and all arguments
are statically known primitives. Non-escaping local function declarations are
also supported after their declaration. All supplied arguments must be pure,
including unused arguments. Rest/default/destructured parameters, async/generator
functions, captures, `this`, host calls and recursive/nested proxy evaluation are
left unresolved. Templates are limited to 4 KiB, 16 parameters and 64 bindings
per statement list. Declarations remain in place; each call maps to its original
call range. No analyzed function is executed by a JavaScript runtime.
