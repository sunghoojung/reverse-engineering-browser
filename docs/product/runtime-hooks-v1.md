# Runtime Hooks v1

Runtime Hooks extends the disposable Experiment BrowserContext with bounded
function-entry and synchronous-return instrumentation. It provides the useful
runtime workflow from the pinned WireBrowser comparison without granting a
baseline target a persistent code-execution channel.

The Chrome DevTools Protocol primitives are `Debugger.getPossibleBreakpoints`,
`Debugger.evaluateOnCallFrame`, and the experimental
`Debugger.setReturnValue`. A return replacement is available only at a return
break position, so Promise and other asynchronous continuations are outside
this contract.

## Safety boundary

- Hooks may be armed only on the target owned by the disposable Experiment
  BrowserContext.
- The user must confirm that entry logic, return logic, and return replacement
  may mutate that isolated page before each arm operation.
- Arming is atomic. If any breakpoint cannot be installed, every breakpoint
  installed by that attempt is removed.
- A hook pause is handled internally and always resumes. It never becomes an
  interactive debugger pause.
- Navigation, target detach, context disposal, bridge shutdown, and the hit
  limit disarm every hook and invalidate paused-frame and object references.
- Hook definitions, captured values, and audit records are ephemeral. They do
  not enter the normalized evidence store.
- Captured bindings come only from own data properties of the local scope.
  Accessors are described but never invoked.

## Hook definition

Each definition contains:

- a session-scoped hook identifier and researcher label;
- the selected live script identifier and display URL;
- a zero-based runtime line and column inside the function;
- independently enabled entry and return phases;
- an optional side-effect-free condition;
- optional entry and return logic evaluated in the paused top frame; and
- an optional synchronous return replacement, either a typed JSON value or an
  expression evaluated in that return frame.

At arm time, REB asks V8 for breakable locations restricted to the selected
function. The first location is the entry point. Locations classified as
`return` become return points. A definition that requests a return phase but
has no return point is rejected.

## Bounds

| Resource | Limit |
| --- | ---: |
| Definitions per session | 8 |
| Active breakpoint points | 64 |
| Return points per definition | 32 |
| Retained hit records | 128 |
| Total hits before automatic disarm | 512 |
| Captured local bindings per hit | 32 |
| Binding preview | 512 UTF-8 bytes |
| Condition | 1 KiB |
| Logic per phase | 8 KiB |
| Return expression or JSON | 8 KiB |
| Evaluation timeout | 100 ms |

Definitions and breakpoints are bounded before DevTools receives an arm
command. Hit records use bounded, by-value previews. Objects retain only type,
subtype, class, and description metadata.

## Return replacement

Typed JSON supports JSON null, booleans, finite numbers, strings, arrays, and
objects. Expression mode can reference the return frame and uses the exact
`Runtime.CallArgument` representation returned by DevTools. A Promise result
or Promise return value is rejected visibly and the original return value is
preserved. Exceptions and timeouts also preserve the original value.

## Lifecycle and audit

The public state is one versioned `runtime_hooks` object containing the
session state, definitions, active point count, hit usage, retained hits,
eviction count, last failure, and documented limits. Every hit row exposes:

- timestamp;
- source and function;
- entry or return category;
- observed, logic-run, return-overridden, or failed operation;
- session, hook, hit, and target correlation identifiers;
- bounded argument or local previews;
- original and replacement return metadata when applicable.

Stopping a session removes its DevTools breakpoints but retains bounded hit
records until they are cleared or the disposable context is erased.

## Performance

The feature is entirely cold-path debugger control. No C++ event, queue,
probe, browser bridge, protocol ABI, or evidence-storage hot path changes.
When no hook session is armed, runtime work is limited to one branch while
dispatching an already-received debugger pause event.
