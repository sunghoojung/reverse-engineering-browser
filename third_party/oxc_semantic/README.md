# Pinned Oxc semantic analysis

This is the MIT-licensed `oxc_semantic` 0.155.0 source from crates.io, with its
required examples for documentation. `Cargo.toml` is a repository-maintained
manifest with exact Oxc dependencies. `LICENSE` preserves the upstream notice.
The application pins the other Oxc crates to 0.155.0 and commits its lockfile.

The only behavioral patch is in `src/builder.rs`: after Oxc finishes creating
scopes, bindings and references, JavaScript reference resolution traverses those
scopes once. An active stack per name answers each reference in constant time.
Scope entry/exit visits every binding once, and implicit non-arrow `arguments`
uses a boundary marker. Named function expressions preserve upstream's special
arguments rule. Hoisting, Annex B, default parameters, class scopes, early errors
and symbol creation remain Oxc's implementation. TypeScript keeps the upstream
resolver and is not accepted by the application.

Upstream resolves each reference by walking its complete ancestor chain. Deep
scopes with many identifiers therefore perform quadratic work even after the
application stops rescanning function source. The small scheduling change here
removes that work without replacing Oxc's binding rules. The `reference-audit`
feature independently resolves each reference again through the original Oxc
algorithm and asserts identical symbol identities. The application's
`semantic-audit` feature enables it for differential validation; keep it disabled
for production and scaling measurements. Comments use plain dashes to follow
this repository's writing policy.

To update: obtain the new exact crates.io release, review binder and reference
semantics, port this one resolver change, run `semantic-audit` against the full
retention ledger and mutation suite, and rerun parser memory and scope scaling
measurements before changing all exact versions and the lockfile together.
Do not copy a registry-generated Cargo manifest or lockfile into this directory.
