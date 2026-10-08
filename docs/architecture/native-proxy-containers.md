# Native proxy containers controlled by tab groups

## Decision and stage boundary

Use Brave's existing native Containers system: one Browser/Profile may contain
several real fixed StoragePartitions. Bind native groups to immutable container
proxy generations. A group is a control surface, not a security boundary. Do
not put multiple Profile objects into one tab strip, use CDP request routing,
or pretend relabeling loaded tabs moves their storage or connections.

This draft implements the dependency-free native preparation/controller
contract, atomic endpoint restore and whole-group transfer, plus a typed
BrowserContext-owned preparation adapter and native unit-test target. Browser
network interception, persistent configuration,
native group UI, and real browser/proxy tests are not implemented. The source
constant remains `kRuntimeIntegrated = false`; the separate GN target is not
linked into the browser. See [the versioned contract](../../protocol/native-proxy-containers-v1.md).

Research pins are Chromium `151.0.7922.108` and Brave `v1.95.52`, matching
`browser/config/`. Findings below are pinned-source inspection, not a claim
that a full pinned browser was compiled or tested in this task.

## Supported same-window storage ownership

Chromium exposes [CreateForFixedStoragePartition](https://github.com/chromium/chromium/blob/151.0.7922.108/content/public/browser/site_instance.h#L252-L258)
for a non-default partition that survives navigation. Its
[implementation](https://github.com/chromium/chromium/blob/151.0.7922.108/content/browser/site_instance_impl.cc#L243-L255)
constructs a fixed-partition BrowsingInstance. All SiteInstances in that
BrowsingInstance must retain one partition; group membership cannot change it.
[NavigationRequest](https://github.com/chromium/chromium/blob/151.0.7922.108/content/browser/renderer_host/navigation_request.cc#L4660-L4675)
preserves the fixed partition, including child-frame ownership.

Brave already implements desktop native containers and
[enables the feature by default](https://github.com/brave/brave-core/blob/v1.95.52/components/containers/core/common/features.cc).
Its [navigation adapter](https://github.com/brave/brave-core/blob/v1.95.52/chromium_src/chrome/browser/ui/navigator/browser_navigator.cc#L43-L82)
accepts explicit partition configuration or inherits the source container.
Its [noopener patch](https://github.com/brave/brave-core/blob/v1.95.52/chromium_src/content/browser/web_contents/web_contents_impl.cc#L25-L31)
retains container identity even when Chromium would otherwise create an
unrelated default SiteInstance. Raw Chromium alone gives an incomplete answer.

Existing [OpenTabUrlsInContainer](https://github.com/brave/brave-core/blob/v1.95.52/browser/ui/browser_commands.cc#L1206-L1243)
opens new tabs from the originals' URLs instead of mutating their live owners.
That is the right ownership model, but a group move needs its own explicit
unsaved-work warning, beforeunload handling, safe-URL checks and transaction.
Same-container tabs intentionally share state; each isolated proxy group needs
an exclusive container-generation identity.

There is no justification here for relaxing a Browser/Profile assertion. The
inspected [discard path](https://github.com/chromium/chromium/blob/151.0.7922.108/chrome/browser/ui/tabs/tab_model.cc#L459-L462)
requires the same BrowserContext, and Brave's
[cross-window helper](https://github.com/brave/brave-core/blob/v1.95.52/browser/ui/browser_commands.cc#L148-L151)
requires matching Profiles. The proposed design keeps those constraints.

## Restore and lifetime are part of the boundary

Brave [serializes container identity](https://github.com/brave/brave-core/blob/v1.95.52/components/containers/content/browser/session_utils.h#L18-L64)
into virtual URLs and PageState. This preserves ownership and makes
feature-disabled restore fail to unsupported URLs rather than leaking default
cookies. [Discard tracking](https://github.com/brave/brave-core/blob/v1.95.52/browser/containers/container_tab_tracker.cc#L37-L45)
also retains the identity. Existing
[browser tests](https://github.com/brave/brave-core/blob/v1.95.52/browser/containers/containers_browsertest.cc)
cover native storage isolation, service workers, restore/history, mixed tabs,
pinned tabs, and feature-disabled restoration. Reading those tests is not
executing them, and they do not establish the new group/proxy invariants.

Two reuse hazards need explicit extensions:

- [Container-specifier lookup](https://github.com/brave/brave-core/blob/v1.95.52/browser/containers/container_specifier_utils.cc#L54-L84)
  returns no config when unavailable; ordinary navigation may then default.
  Protected-group creation must instead block.
- [Container cleanup](https://github.com/brave/brave-core/blob/v1.95.52/components/containers/core/browser/containers_service.cc#L177-L235)
  and [reference discovery](https://github.com/brave/brave-core/blob/v1.95.52/browser/containers/containers_service_delegate.cc)
  inspect live tabs, session and tab-restore records. Saved closed-group policy
  and tabless worker references need retention too. Removing a group must not
  remove an immutable policy while its partition can still issue requests.

## Creation-time network configuration

Each StoragePartition exposes its own
[NetworkContext](https://github.com/chromium/chromium/blob/151.0.7922.108/content/public/browser/storage_partition.h#L101-L108).
But [ProfileNetworkContextService](https://github.com/chromium/chromium/blob/151.0.7922.108/chrome/browser/net/profile_network_context_service.cc#L1475)
attaches the Profile's proxy monitor to every context. The
[monitor](https://github.com/chromium/chromium/blob/151.0.7922.108/chrome/browser/net/proxy_config_monitor.cc#L81-L123)
broadcasts updates, including DIRECT. A one-time initial proxy setting without
disconnecting that monitor is not isolation.

The typed adapter now prepares creation params only for an authoritative
protected partition using its complete original StoragePartitionConfig. It
replaces initial configuration, detaches proxy monitor and poller/custom-proxy
pipes, and denies ambient credentials, without touching other network settings.
Strict one-shot dictionary restore supplies an immutable BrowserContext-owned
registry; it neither reads a store nor restores group bindings. It rejects
unknown policies, wrong storage mode and blob-domain fallback without changing
params. There is deliberately no native call site or allowing admission result.
A future hook must run after normal Brave/Chrome setup and before the context is
exposed to loaders, and must safely deny creation on every failure.
The [normal Profile configuration](https://github.com/chromium/chromium/blob/151.0.7922.108/chrome/browser/net/profile_network_context_service.cc#L1366-L1376)
can allow default OS authentication; a new cookie store does not disable it.
Profile password-manager filling, client certificates and other Profile services
are separate concerns and are not promised isolated by this design.

The network hook receives a relative path. Chromium
[hashes partition names to six bytes](https://github.com/chromium/chromium/blob/151.0.7922.108/content/browser/storage_partition_impl_map.cc#L292-L310).
Never authorize ownership from that 48-bit hash alone. An authoritative
profile-scoped mapping with collision rejection and persistent deny/tombstone
state must exist before restore/recreation, or an earlier hook must pass the
original config. A missing record must not turn a formerly protected container
into an ordinary container using the Profile proxy.

## Transport gaps that block activation

Chromium's [proxy specification](https://github.com/chromium/chromium/blob/151.0.7922.108/net/docs/proxy.md)
distinguishes HTTP, HTTPS and SOCKS5 proxies, ws/wss rule selection, SOCKS5 remote
DNS, unsupported SOCKS authentication/UDP, and implicit bypass destinations.
An empty bypass list still sends localhost/link-local directly. The required
manual plan subtracts those implicit bypasses and has no DIRECT alternative;
separate native destination guards must block privileged/local destinations.
Proxy hostname bootstrap may still use system DNS and must be disclosed.

Further context-specific hooks are necessary:

- [P2PSocketDispatcherHost](https://github.com/chromium/chromium/blob/151.0.7922.108/content/browser/renderer_host/p2p/socket_dispatcher_host.cc#L72-L86)
  can identify the process StoragePartition before creating the P2P manager.
  Deny protected-container P2P binding; URL proxy settings do not proxy UDP.
- [WillCreateWebTransport](https://github.com/chromium/chromium/blob/151.0.7922.108/content/public/browser/content_browser_client.h#L2197)
  is a browser denial seam; workers require process/partition attribution too.
- [NetworkContextParams](https://github.com/chromium/chromium/blob/151.0.7922.108/services/network/public/mojom/network_context.mojom)
  has no simple per-context `enable_quic` member. Do not change the Profile's
  QUIC preference or globally disable QUIC as a shortcut. Native proxy routing
  gates ordinary forced HTTP/3, but that is not a substitute for the promised
  context-specific denial and browser tests.
- [PreconnectManagerImpl](https://github.com/chromium/chromium/blob/151.0.7922.108/content/browser/preloading/preconnect/preconnect_manager_impl.cc#L461-L474)
  uses the default partition for an absent config. Loading-predictor and omnibox
  paths need explicit partition propagation or scoped blocking. Prerender and
  prewarm must not create a default SiteInstance for protected navigation.
- A separate partition does not imply an independent DNS manager: ordinary
  contexts share the NetworkService resolver manager. Speculative DNS must be
  covered, not inferred from SOCKS5 destination resolution.

The complete acceptance matrix and staged activation requirements live in the
[v1 contract](../../protocol/native-proxy-containers-v1.md#browser-activation-gates).
Until those gates pass, a native settings entry/badge must remain unavailable;
there is no supported promise that all browser or OS traffic uses this proxy.
