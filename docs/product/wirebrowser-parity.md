# WireBrowser Parity Inventory

This inventory pins the external comparison to WireBrowser commit
`77e1e48ceb4acaef0356877ee2d09391763613cc` from 2026-04-17. The source of
truth is the upstream repository at
<https://github.com/fcavallarin/wirebrowser>. A feature is complete here only
when the equivalent researcher workflow works through REB's local-first,
bounded evidence architecture. Matching a panel name is not sufficient.

## Browser and source workflow

| WireBrowser capability | REB status | Evidence or remaining work |
| --- | --- | --- |
| Managed browser and page selection | Implemented | `make live` launches an isolated Brave profile, and the debugger target selector supports page and webview targets. |
| Global or page-specific action scope | Partial | Capture sessions and debugger actions are scoped, but mutable rules do not yet have a shared global-versus-target policy model. |
| Parsed-script catalog and source viewer | Implemented | Sources provides page, frame, and captured-artifact trees, quick open, search, line navigation, source maps, and bounded source loading. |
| Debug console and breakpoint controls | Implemented | Pause, resume, step, line, conditional, log, XHR/fetch, event, watch, scope, and async stack workflows are live. |

## Memory and runtime control

| WireBrowser capability | REB status | Evidence or remaining work |
| --- | --- | --- |
| Live object search | Implemented, read-only | Property, primitive, class, regular-expression, and structural similarity criteria are bounded and do not invoke getters. |
| Heap snapshot search | Implemented | Native C++ search covers root-reachable and unreachable nodes, retaining paths, hidden references, and weak references. |
| Heap comparison | REB extension | Exact dominators and retained-size change comparison go beyond the pinned WireBrowser workflow. |
| Breakpoint-driven origin trace | Implemented | [Memory Origin Trace v1](./memory-origin-trace-v1.md) adds bounded click-driven temporal heap probing and source-function mapping. |
| Expose or patch a live object | Implemented | [Live Object Experiment v1](./live-object-experiment-v1.md) adds bounded live-object search and confirmed typed own-property set/delete operations inside the disposable Experiment BrowserContext, with metadata-only audit records and no arbitrary code execution. |
| Runtime hooks and return overrides | Implemented | [Runtime Hooks v1](./runtime-hooks-v1.md) adds bounded function-entry and synchronous-return hooks, local binding capture, conditional logic, and typed return replacement inside the disposable Experiment BrowserContext. |
| Expose or patch a live object | Missing | Must be restricted to a visibly isolated Experiment session with explicit mutation audit records. |
| Runtime hooks and return overrides | Partial | REB has breakpoints and logpoints. Function-call hooks, argument capture, injected logic, and synchronous return overrides remain. |

## Network workflow

| WireBrowser capability | REB status | Evidence or remaining work |
| --- | --- | --- |
| Request inspection and filtering | Implemented | Traffic provides normalized request lifecycle, headers, payload metadata, timing, initiator, response, and signal inspection. |
| Request interception | Implemented | [Request Interception v1](./request-interception-v1.md) provides continue, block, drop, bounded request rewrite, and bounded synthetic-response rules only inside a disposable credential-free BrowserContext, with a metadata-only mutation audit. |
| Repeater | Implemented | [Repeater v1](./repeater-v1.md) adds editable credential-free requests, immediate cancellation, bounded session history, scoped variables, resolved-request copying, and response comparison inside the disposable request-lab BrowserContext. |
| API Collection | Implemented | [API Collection v1](./api-collection-v1.md) adds atomic local persistence, a bounded folder tree, inherited root/folder/request variables, safe Traffic import, editable saved requests, and execution history scoped through the isolated Repeater context. |
| Request interception | Missing | Continue, block, drop, request rewrite, and synthetic response controls must be Experiment-only and auditable. |
| Repeater | Missing | Editable requests, cancellation, bounded history, scoped variables, and response comparison remain. |
| API Collection | Missing | Folders, scoped variables, saved requests, and execution history remain. |

## Automation and tools

| WireBrowser capability | REB status | Evidence or remaining work |
| --- | --- | --- |
| Browser-context scripts | Implemented | [Automation Recipes v1](./automation-recipes-v1.md) adds a bounded recipe library, private variables, manual execution, and explicitly armed created, before-load, and after-load triggers inside the disposable Experiment BrowserContext. |
| Local Node-style analyst scripts | Implemented | [Local Analyst Workspace v1](./local-analyst-workspace-v1.md) adds reusable async scripts over frozen, bounded evidence snapshots, private variables, text-only logs and results, isolated helper processes, cancellation, timeout recovery, and visible limits. MCP remains deferred by project policy. |
| Decoder chains | Missing | Add local byte, text, URL, Base64, hex, compression, and structured-data transforms without automatic execution. |
| JWT inspection | Missing | Add bounded local decoding and claim inspection without signature or trust claims unless explicitly verified. |
| Scratchpad and reusable files | Implemented | Local Analyst Workspace adds a permission-restricted, atomically replaced folder and file library with stable IDs, generation conflicts, four scratchpad languages, and non-executable notes. |

## Delivery order

Local Analyst Workspace is the current completed parity increment. The next
implementation sequence is local decoding tools and JWT inspection.
Each increment must preserve immutable baseline evidence, make mutation
visible, and pass the repository's full native and UI gates.
Memory Origin Trace is the current completed parity increment. The next
implementation sequence is network interception, Repeater, API Collection,
Experiment-only live object mutation, runtime hooks, automation recipes, and
local decoding tools. Each increment must preserve immutable baseline evidence,
make mutation visible, and pass the repository's full native and UI gates.
