# Native proxy containers v1

Status: preparation-only native C++ foundation and typed Chromium adapter.
No proxy settings, group badge, browser routing hook, credential store,
persistent state, or external connection
is enabled by this change. `kRuntimeIntegrated` is false and the GN target is
not a dependency of the browser. Passing its offline tests is not proof of
network routing, storage isolation, or browser lifecycle coverage.

`NativeProxyPartitionAdapter` is owned by the real BrowserContext through its
user-data lifetime, uses that context's process-lifetime token, and runs on the
browser UI sequence. The adapter prepares native params only; there is no
StoragePartition creation hook calling it. `GetNativePartitionAdmission` has
only `kNotOwned` and `kBlocked` results. Successful preparation returns
`kPreparedRuntimeBlocked`, never permission to create a network context.

## Authority and ownership

The browser process owns a `PolicyRegistry` on its UI sequence, scoped to the
complete opaque Profile/BrowserContext token. This is a native in-process
contract, not a raw-byte IPC, on-disk format, or renderer-authorized API.
`version == 1` is mandatory; unknown versions fail closed.

- A container key contains the profile token, a browser-generated opaque
  lowercase alphanumeric/hyphen ID (1–64 bytes), and a nonzero generation.
- Each key has exactly one immutable endpoint. Identical registration is
  idempotent. A changed endpoint needs a new generation and a new partition.
- A native group key contains a window-lifetime ID and both halves of the
  tab-group token. A label/color is never an identity. One generation cannot be
  assigned to two different groups implicitly, including after its first group
  is removed or rebound. Its first group owner is retained for this registry's
  lifetime because old tabs/workers may still exist.
- Group bindings are creation intents only. An already loaded tab keeps its
  actual container when a binding changes; no live tab is silently relabeled.
- Group removal invalidates pending plans but does not erase policies. Storage,
  service workers, shared workers, and network-service recreation can outlive
  both a group and its visible tabs.
- Admission is bounded to 128 generations and 64 group bindings per registry.
  Exhaustion is an explicit failure, never default-profile fallback. This
  foundation intentionally has no eviction or storage deletion API.

The registry is not copyable. It is not thread-safe; the native adapter must
keep all operations on the browser UI sequence. Tokens and document epochs
must come from authoritative browser objects, not page-supplied numbers.

## Bounded restore input

`PolicySnapshot` restores endpoint records atomically, with no runtime Profile
token or group binding in the input. Duplicate identities, including identical
duplicates, invalidate the entire restore. Ownership is derived afresh from the
actual BrowserContext; merely restoring endpoints never authorizes new tabs.
No file store, registered preference, encoder, or startup restore hook exists yet.

The typed adapter accepts a strict dictionary for a future per-profile store:

```json
{
  "version": 1,
  "policies": [
    {"id": "opaque-id", "generation": "1", "scheme": "https", "host": "proxy.example.test", "port": 443}
  ]
}
```

These are the only permitted fields. Generations are canonical nonzero decimal
uint64 strings, preserving precision beyond JSON's interoperable number range.
The existing ID/endpoint bounds and 128-record limit apply. Restore is one-shot
per BrowserContext, including failed attempts; corrupt input leaves policy
unavailable and cannot be repaired by substituting a second snapshot in place.
An empty valid snapshot is allowed and authorizes no protected partition.

Preparation matches the complete `containers` domain and original
`reb-proxy-<id>-g<generation>` name; a relative/hash-derived disk path is never
an identity. Storage mode must match BrowserContext off-the-record status, and
blob fallback to the parent domain is forbidden. Unknown reserved names remain
blocked. Unowned partitions and every rejected preparation leave params intact.
After complete validation, the adapter installs a typed single-proxy config,
subtracts implicit bypasses, detaches profile/custom proxy update and observer
pipes, and disallows default OS credentials. Unrelated network settings survive.
This does not create or exercise any socket or enforce the transport guards below.

## Endpoint and routing plan

V1 accepts one explicit HTTP, HTTPS, or unauthenticated SOCKS5 endpoint. The
input consists of scheme, ASCII DNS host/canonical IPv4 literal, and a nonzero
16-bit port. Unicode input requires IDNA conversion before validation. IPv6
endpoint literals, SOCKS4, PAC/WPAD, bypass destinations, fallback lists, and
proxy authentication are not supported in this stage.

Credentials are never accepted in host fields, URLs, logs, labels, or plans.
No username/password or secret-storage API exists here. A future authenticated
HTTP/HTTPS implementation needs an exact endpoint/partition-scoped challenge
flow and separate secure secret handling. Chromium SOCKS5 does not implement
SOCKS authentication; do not imply that adding a password field enables it.

`MakeNetworkPlan` returns exactly one manual proxy URI and the subtract-implicit-
bypass rule `<-loopback>`, plus requirements to detach the profile proxy monitor
and disable ambient OS HTTP authentication. It cannot return DIRECT or a PAC
URL. These are preparation requirements, not applied NetworkContext settings.
The later adapter must verify the parsed native config and fail before creating
loaders if the policy is absent or invalid. It must not clear both the initial
proxy config and config receiver: Chromium interprets that pair as DIRECT.

Removing implicit bypasses is not permission to send local/privileged URLs to a
remote proxy. V1 activation additionally requires browser-side blocking of
local/privileged destinations and their redirects, using Chromium's canonical
URL/IP classification. The offline hostname validator validates a proxy endpoint,
not destination safety. Certificate errors must keep their normal failure
behavior; no certificate bypass is part of this feature.

## Creation and explicit reopen

`PlanNewTab(group)` produces a profile/container/generation-bound plan before
WebContents creation. Its partition name is `reb-proxy-<id>-g<generation>` in
Brave's native container partition domain. The later adapter must register the
identity with ContainersService, prepare the real partition's network policy,
and use `SiteInstance::CreateForFixedStoragePartition`. Missing group/policy
produces no plan, never a default-partition plan.

`PlanReopen(source, destination)` is deliberately separate from ordinary
TabStrip group membership. It snapshots source tab identity, document epoch,
and actual container, plus the destination binding revision. The native UI
must warn that unsaved work, page state, sessions, and in-flight work will not
move. A positive warning choice does not override a page's beforeunload veto.
Even an about:blank tab requires fresh creation when changing owner: its
existing context may already have performed work.

`ValidateReopen` checks the entire current snapshot, exact destination plan,
explicit warning acceptance, and beforeunload acceptance. Navigation, tab
replacement, source group/window move, binding change, group deletion/recreation,
or ABA rebinding makes
the old approval unusable. Same-container group moves return `kSameContainer`
and require no proxy/storage change.

`PlanGroupTransfer` and `CommitGroupTransfer` model a separate whole-group
cross-window move. The native group token and Profile must stay the same. Commit
moves the creation binding and all retained generation owners, preserving the
actual storage/proxy identities of tabs and workers. A fresh revision invalidates
old creation/reopen plans even if the group later returns to its original window.
Source removal/rebinding or an occupied destination rejects the plan. This only
changes registry intent; no TabStrip, WebContents, or native group is moved.

Validation is a side-effect-free preparation result, not a consumed approval
or proof of an executed move. The later adapter must own a one-shot transaction:
create and verify a new partition-bound WebContents without issuing the target
request, revalidate before commit, preserve the original on cancellation or
failure, then reopen the approved safe URL and remove the original only through
the normal close lifecycle. Never transplant NavigationController/PageState,
POST bodies, opener references, credentials, or live connections into the new
owner. Do not auto-retry a navigation or replay a submitted form.

## Explicit traffic requirements

`RequiredHandling` describes the intended activation gate. It reports no
measured traffic and contains no implementation of those transports.

| Surface | Required v1 behavior before activation | Current verification |
| --- | --- | --- |
| HTTP/HTTPS | Native fixed proxy in the owning partition; outage is an error | Policy only |
| ws/wss | Same partition and single proxy rule; no live socket migration | Policy only |
| Dedicated/shared/service-worker fetch | Owner's partition, including tabless worker lifetime | Policy only |
| Destination DNS | Proxy-side resolution for supported URL requests | Policy only |
| Proxy endpoint DNS | Explicitly disclosed system resolver bootstrap, unless IP literal | Policy only |
| Speculative DNS/preconnect/prewarm/prerender | Block or prove owner propagation; no default-context escape | Policy only |
| WebRTC | Block native P2P socket binding for protected partitions | Policy only |
| QUIC/HTTP3 | Disable/block for protected context; never mutate global/profile settings | Policy only |
| WebTransport | Block browser-side creation, including workers | Policy only |
| Browser services/extensions/updates | Outside tab-container scope; no all-traffic assertion | Explicitly excluded |

The HTTPS proxy scheme describes TLS to the proxy. HTTPS destination requests
can also use an HTTP proxy via CONNECT. SOCKS5 supports TCP URL requests, not
arbitrary UDP. Separate StoragePartitions do not imply a private DNS manager,
OS network stack, password manager, client-certificate store, permissions,
history, bookmarks, or other Profile services.

## Browser activation gates

All of the following remain incomplete and must be tested at the pinned
Brave boundary before enabling a badge/settings action or claiming routing:

1. Persistent profile-scoped group/container/generation ownership loaded before
   session restore or partition recreation; unknown/corrupt/deleted policies
   block. Preserve tombstones or carry the full StoragePartitionConfig into the
   network hook. Chromium's 48-bit partition-directory hash is not sufficient
   identity; reject any path collision and never infer ownership from a hash.
2. Creation-time native NetworkContext override, detached profile/extension/OS
   proxy updates, single route/no DIRECT, implicit-bypass subtraction, ambient
   auth denial, and network-service crash recreation under the same policy.
3. P2P/WebRTC, WebTransport, QUIC, speculation and local-destination controls,
   with no browser-global setting changes. Audit auxiliary network consumers,
   certificate-related fetches, downloads and extension traffic separately.
4. Native group create/new-tab/popup/noopener, drag in/out, regroup/ungroup,
   duplicate/discard, cross-window move, group close/reopen, crash/session
   restore and feature-disabled restore. Preserve ownership before the first
   request and reject old approvals after any intervening change.
5. Policy retention while workers/partitions exist; saved closed-group references
   participate in native container cleanup. Explicit disposal must stop workers,
   close active factories/connections and retain deny metadata until no stale
   reference can recreate a direct context. Closing idle sockets is insufficient.
6. Local synthetic proxy/browser tests for every included transport and every
   denial, proxy outage/407/TLS error, cookie/localStorage/IndexedDB/CacheStorage/
   service-worker separation, policy update, restored missing policy, and
   unauthorized fallback. No real proxy credentials or external service needed.
7. UI states reflect the actual tab owner and observed readiness: unavailable,
   pending, mismatched/reopen-needed, failed, and verified. A group label or
   successful plan validation must never render as protected/active.

## Available checks

`make native-proxy-policy-check` compiles the exact dependency-free C++ policy
implementation and exercises endpoint rejection, version/ownership checks,
immutable generations, exclusive bindings, bounds, stale plans, cancelled
reopens, no DIRECT construction and the explicit traffic matrix. `make check`
includes it; `make sanitize` also runs this check with the configured sanitizers.
The offline suite also covers exact partition lookup, atomic snapshot restore,
and whole-group transfers, including retained generations and stale plans.
No socket or browser is opened by these tests.

The separate GN `proxy_partition_adapter_unittests` target exercises real
Chromium dictionaries, partition configs and native proxy-rule evaluation. It
covers malformed restore, denied preparation without mutation, context lifetime,
storage mode and blob fallback, profile/custom-proxy detachment, ambient-auth
denial and continued blocked admission. It requires the initialized pinned
Chromium toolchain and is not run by `make native-proxy-policy-check` or ordinary
repository CI. Neither suite substitutes for real browser/network acceptance.
See the [Brave integration instructions](../browser/integration/brave/README.md)
for the explicit native test command.

See [pinned architecture and implementation seams](../docs/architecture/native-proxy-containers.md)
for source evidence and the distinction between existing Brave behavior and
the new, preparation-only implementation.
