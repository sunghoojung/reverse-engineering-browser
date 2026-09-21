# AST deobfuscation pipeline spike

This prototype applies the useful parts of the ReverseJS material as a safe,
iterative AST pipeline:

- static constant folding without calling JavaScript or Babel's general
  evaluator;
- scope-aware replacement of immutable literal bindings;
- literal string-array index recovery;
- simple pure proxy-function inlining;
- statically provable dead-branch removal;
- safe bracket-to-dot conversion;
- pass counts and source-range transform provenance in a machine-readable report.

The input is parsed as JavaScript, but it is never executed. Unknown or
dynamic expressions remain unchanged. This is intentionally a spike, not yet
the production Research UI analyzer.

## Run

```sh
npm install
npm test
node deobfuscator.js fixtures/mixed.js
```

The pipeline runs passes to a fixed point with a maximum iteration count. Each
replacement is restricted to values proven by the local static evaluator.

The evaluator deliberately treats sparse-array holes, non-finite arithmetic,
dynamic identifiers, calls, and unsupported object semantics as unknown. It
does handle safe `void`/`typeof` results and finite negative numeric values.
Unknown cases remain in the generated output rather than being guessed. Every
recorded rewrite includes the original AST byte range so a future production
adapter can attach the result to REB's evidence map.

This spike is intentionally bounded and non-executing.
