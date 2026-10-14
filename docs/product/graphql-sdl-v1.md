# Saved GraphQL introspection to SDL

Convert an explicitly selected local introspection result into reviewable SDL:

```sh
node tools/export-graphql-sdl.mjs --input introspection.json --output schema.graphql
```

Use Node.js 22+. Input is a complete JSON response with `data.__schema`, or an
object with `__schema`. A saved REB `reb-network-request-v1` exact-request
response is also accepted directly: select the captured introspection HTTP
request in Traffic, obtain its five exact selectors with the existing
`get_network_request` API/`reb-api` workflow, save that response as JSON, and pass
it as --input. The exporter reuses REB's exact-response validator, requires a
complete retained HTTP 200 JSON body, and records the exact source identity in
an SDL comment. No second file read can substitute a different captured body.
A truncated/missing body must be recaptured in an authorized session; it is not
repaired or fetched automatically. A response carrying GraphQL errors is refused. This tool
never sends an introspection query, accesses an endpoint, follows a scalar URL,
loads resolvers, evaluates descriptions/defaults, or reads browser credentials.
If the schema is unavailable, obtain it through your own separately authorized
workflow; the exporter does not guess it from observed requests.

The output covers explicit query/mutation/subscription roots; scalars, objects,
interfaces and interface inheritance, unions, enums and input objects; nested
list/non-null wrappers; field and argument descriptions; literal default values;
deprecation; custom directive definitions, locations and repeatability; scalar
specifiedByURL and OneOf input objects when present. Standard introspection types
and built-in scalar/directive definitions are omitted. Source order is stable.
Definitions and references are checked for bounded valid names and compatible
input/output kinds. Repeated names, missing referenced types, malformed wrappers,
empty definitions, duplicate object literal fields and source-text injection are
refused. Default values are parsed as bounded constant literals, never appended
as unchecked SDL or evaluated as JavaScript.

## Scope and honest unknowns

This is structural reconstruction, not full semantic GraphQL schema validation.
In particular, interface covariance/implementation obligations, every default's
input coercion, non-null input cycles and custom scalar semantics need a full
GraphQL validator. CI independently compares an authored projection with
GraphQL.js 16.11.0's parser, validator and buildClientSchema/printSchema result.
The production exporter has no GraphQL package dependency.

The input query must include type fields, arguments/defaultValue, interfaces,
union members, enum values, input fields, roots and directive definitions. It
cannot recover fields omitted by server permissions, omitted deprecated members,
applied custom directives, resolvers, auth policy, federation implementation or
runtime behavior. The output begins with these limitations. Missing optional
isOneOf, isRepeatable or scalar specifiedByURL information adds a limitation
comment rather than claiming those semantics are known. Request these optional
introspection fields when the server supports them. Description text is inert.

Constant defaults support strings and block strings, numbers, booleans/null,
enums, lists and input objects. Comments in defaults and unsupported syntax are
refused. Original numeric literal spelling is preserved without binary64 numeric
conversion. No operation document, variable reference or directive application
can be smuggled in as a default.

## Files and bounds

Input must be a regular, non-symlink UTF-8 JSON file of at most 1 MiB, with no
duplicate keys, malformed Unicode or excessive JSON nesting. The converter caps
4096 types/members per list, 20000 total fields/arguments, 256 directives, 32 type
wrapper/default nesting levels, 4096 nodes per literal, 16 KiB descriptions and
literal defaults, and 1 MiB SDL text. Existing output paths are never replaced;
publication is atomic and private (0600). The source file SHA-256 is recorded in a
comment and returned in a count-only CLI receipt. These limits preserve usable
failure behavior, not evidence of complete server coverage.

Schema names, descriptions and defaults may be private. Output is raw local data,
not an automatically redacted artifact; review before sharing. No target data is
printed on errors. The original JSON is unchanged and remains the source evidence.

`node tools/check-graphql-sdl.mjs` exercises all projected type kinds, malformed
and partial inputs, bounds, injection refusal, deterministic output and the real
private/no-overwrite CLI. Set REB_GRAPHQL_REFERENCE to an installed GraphQL.js
16.11.0 module path to run the independent reference check (CI does this).

Reference: [GraphQL September 2025 introspection and type system](https://spec.graphql.org/September2025/#sec-Schema-Introspection).
