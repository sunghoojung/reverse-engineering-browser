// The production NativeTabRegistry, NativeFactoryScopeOf and factory owner
// hook against narrow content stand-ins (chromium_stubs.h): how content's
// scoped owner becomes a factory's tab, flags and exclusion, how a
// service-worker job's note becomes a version's registrant, and how the
// worker services feed NativeTabResolver (protocol/native-network-v3.md).
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "brave/components/reverse_engineering_browser/browser/native_factory_scope.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_registry.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_resolver.h"
#include "brave/components/reverse_engineering_browser/common/native_factory_owner_hook.h"

namespace {

int failures = 0;

void Check(const bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL " << message << '\n';
    ++failures;
  }
}

using Cause = reb::NativeFactoryOwnerCause;
using Factory = reb::NativeUrlLoaderFactoryKind;
constexpr std::uint64_t kSession = 7;

base::UnguessableToken Token(std::uint64_t high, std::uint64_t low) {
  return {high, low};
}

reb::NativeToken128 Native(const base::UnguessableToken& token) {
  return {token.high, token.low};
}

reb::NativeFactoryScope ScopeOf(content::BrowserContext& context,
                                content::RenderFrameHost* frame,
                                const Factory kind,
                                const url::Origin& initiator = url::Origin("https", "a.test")) {
  return reb::NativeFactoryScopeOf(&context, frame, 1, static_cast<int>(kind), initiator);
}

void OwnerHook() {
  Check(reb::CurrentNativeFactoryOwner().frame_process_id == -1 &&
            reb::CurrentNativeFactoryOwner().cause == Cause::kNamed,
        "With no scope the owner names nothing");
  {
    const reb::ScopedNativeFactoryOwner outer({.frame_process_id = 1, .frame_routing_id = 2});
    {
      const reb::ScopedNativeFactoryOwner inner({.cause = Cause::kPrefetchWithoutPage});
      Check(reb::CurrentNativeFactoryOwner().cause == Cause::kPrefetchWithoutPage &&
                reb::CurrentNativeFactoryOwner().frame_process_id == -1,
            "An inner scope replaces the owner");
    }
    Check(reb::CurrentNativeFactoryOwner().frame_routing_id == 2,
          "Leaving a scope restores the outer owner");
  }
  Check(reb::CurrentNativeFactoryOwner().frame_routing_id == -2, "The thread owner is reset");
  std::cout << "PASS factory owner hook: scopes nest and restore\n";
}

void Factories() {
  content::BrowserContext owned(true), other(false);
  auto& resolver = reb::NativeTabResolver::Get();
  // A version note before the registry exists reaches nobody.
  reb::NoteNativeServiceWorkerVersion(&owned, 300, {.frame_process_id = 1, .frame_routing_id = 5});
  Check(resolver.ServiceWorkerHasNoPage(300), "A note before the registry observes is dropped");

  content::RenderFrameHost page(1, 5, Token(0x11, 0x12), 40);
  Check(ScopeOf(other, &page, Factory::kDocumentSubResource).tab_id == 0,
        "A profile outside capture gets no scope");
  const auto document = ScopeOf(owned, &page, Factory::kDocumentSubResource);
  Check(document.tab_id == 40 && document.exclusion == 0 &&
            !document.owner.service_worker_without_caller,
        "A frame's factory takes the frame's tab");

  {
    // Early hints: no frame is passed, the navigation's main frame is scoped.
    const reb::ScopedNativeFactoryOwner owner({.frame_process_id = 1, .frame_routing_id = 5});
    Check(ScopeOf(owned, nullptr, Factory::kEarlyHints).tab_id == 40,
          "A frameless factory takes its scoped frame's tab");
  }
  {
    const reb::ScopedNativeFactoryOwner owner({.cause = Cause::kPrefetchWithoutPage});
    const auto prefetch = ScopeOf(owned, nullptr, Factory::kPrefetch);
    Check(prefetch.exclusion == reb::kNativeBrowserPrefetchExclusion && prefetch.tab_id == 0,
          "A prefetch with no page is class 69");
    const auto counted = reb::NativeProxyRequestExclusion(
        prefetch, static_cast<int>(Factory::kPrefetch), "https", {1, 1});
    Check(counted.exclusion_class == 69 && counted.counted_here,
          "The proxy counts class 69 itself");
  }
  {
    // A browser-initiated registration: a job with no caller and no active version.
    const reb::ScopedNativeFactoryOwner owner({.cause = Cause::kServiceWorker});
    const auto script = ScopeOf(owned, nullptr, Factory::kServiceWorkerScript);
    Check(script.tab_id == 0 && script.owner.service_worker_without_caller &&
              script.owner.service_worker_version == -1,
          "A job with no caller sets the no-caller flag");
    Check(!script.worker_script_requests, "A job's script factory is no worker's import bundle");
    const auto counted = reb::NativeProxyRequestExclusion(
        script, static_cast<int>(Factory::kServiceWorkerScript), "https", {1, 2});
    Check(counted.exclusion_class == 68 && counted.counted_here,
          "Its script fetch is class 68, counted by the proxy");
  }
  {
    // The register() caller's frame is gone before the factory is created.
    const reb::ScopedNativeFactoryOwner owner({.frame_process_id = 1,
                                               .frame_routing_id = 99,
                                               .service_worker_version_id = 301,
                                               .cause = Cause::kServiceWorker});
    const auto script = ScopeOf(owned, nullptr, Factory::kServiceWorkerScript);
    Check(script.tab_id == 0 && !script.owner.service_worker_without_caller &&
              script.owner.service_worker_version == 301,
          "A named caller whose frame is gone is no no-page job");
  }
  std::cout << "PASS factory scope: frames, scoped frames, prefetch class 69, service-worker jobs "
               "with and without a caller\n";

  // The registry is observing now, so a job's note reaches the resolver.
  {
    const content::RenderFrameHost caller(1, 6, Token(0x21, 0x22), 41);
    reb::NoteNativeServiceWorkerVersion(&owned, 302,
                                        {.frame_process_id = 1, .frame_routing_id = 6});
  }
  const auto registered = resolver.ResolveVersion(302, kSession);
  Check(registered.status == reb::NativeTabResolution::Status::kLinked &&
            registered.kind == reb::NativeTabLinkKind::kServiceWorkerRegistrant &&
            registered.tabs.size() == 1 && registered.tabs[0] == 41,
        "A version links to the tab its register() caller had when the job started it");
  // An update whose caller is gone takes the active version's tabs.
  resolver.ServiceWorkerControlleeAdded(303, "client", std::vector<std::uint32_t>{42});
  reb::NoteNativeServiceWorkerVersion(&owned, 304,
                                      {.frame_process_id = 1,
                                       .frame_routing_id = 77,
                                       .service_worker_version_id = 303,
                                       .cause = Cause::kServiceWorker});
  const auto updated = resolver.ResolveVersion(304, kSession);
  Check(updated.kind == reb::NativeTabLinkKind::kServiceWorkerRegistrant &&
            updated.tabs.size() == 1 && updated.tabs[0] == 42,
        "With the caller's frame gone the registrant is the updated version's clients");
  reb::NoteNativeServiceWorkerVersion(&owned, 305, {.frame_process_id = 1, .frame_routing_id = 78});
  Check(resolver.ResolveVersion(305, kSession).status ==
                reb::NativeTabResolution::Status::kUnresolved &&
            !resolver.ServiceWorkerHasNoPage(305),
        "A gone caller with nothing to fall back on is unresolved, never counted as no page");
  reb::NoteNativeServiceWorkerVersion(&other, 306, {.frame_process_id = 1, .frame_routing_id = 5});
  Check(resolver.ServiceWorkerHasNoPage(306), "Another profile's job note is ignored");
  // A registration installed in an earlier run: a register() of its current
  // script, or an identical update(), starts no version, so patch 0045 notes
  // the caller for the active version it found.
  const reb::NativeToken128 installed_token{0x27, 0x28};
  resolver.ServiceWorkerStarted(309, installed_token, {}, "https://installed.test/");
  Check(resolver.ServiceWorkerHasNoPage(309), "An installed version no page used yet is pageless");
  {
    const content::RenderFrameHost again(1, 9, Token(0x29, 0x2a), 44);
    reb::NoteNativeServiceWorkerVersion(&owned, 309,
                                        {.frame_process_id = 1,
                                         .frame_routing_id = 9,
                                         .service_worker_version_id = 309,
                                         .cause = Cause::kServiceWorker});
  }
  const auto found =
      resolver.Resolve(reb::NativeLoaderKind::kServiceWorker, installed_token.fold(), kSession);
  Check(!resolver.ServiceWorkerHasNoPage(309) &&
            found.status == reb::NativeTabResolution::Status::kLinked &&
            found.kind == reb::NativeTabLinkKind::kServiceWorkerRegistrant &&
            found.tabs.size() == 1 && found.tabs[0] == 44,
        "The active version's later fetches link to the caller that found it");
  std::cout << "PASS service-worker job notes: registrant from the caller, from the updated "
               "version when the caller is gone, from a job that started no version, unresolved "
               "otherwise, other profiles ignored\n";

  // A starting worker's factories name it before its first fetch.
  const auto worker_token = Token(0x31, 0x32);
  {
    const reb::ScopedNativeFactoryOwner owner({.service_worker_version_id = 307,
                                               .cause = Cause::kServiceWorker,
                                               .service_worker_token_high = worker_token.high,
                                               .service_worker_token_low = worker_token.low});
    const auto subresource = ScopeOf(owned, nullptr, Factory::kServiceWorkerSubResource);
    Check(subresource.owner.service_worker_without_caller &&
              subresource.owner.service_worker_version == 307 &&
              !subresource.worker_script_requests,
          "A starting worker's subresource factory knows its version");
    // Its new-scripts bundle carries the renderer's request ids, so an import
    // shares the drain's answer and the drain alone counts it.
    const auto scripts = ScopeOf(owned, nullptr, Factory::kServiceWorkerScript);
    Check(scripts.worker_script_requests && scripts.owner.service_worker_version == 307,
          "A starting worker's new-scripts factory is its import bundle");
    const auto imported = reb::NativeProxyRequestExclusion(
        scripts, static_cast<int>(Factory::kServiceWorkerScript), "https", {1, 3});
    Check(imported.exclusion_class == 68 && !imported.counted_here,
          "An import of a pageless starting worker is left out for the drain to count");
  }
  Check(
      resolver.Resolve(reb::NativeLoaderKind::kServiceWorker, Native(worker_token).fold(), kSession)
              .status == reb::NativeTabResolution::Status::kNoPage,
      "The drain finds the worker before OnVersionStartedRunning, and it has no page");
  // A page arrives before the import's renderer record drains: the record still
  // takes the proxy's answer, so the import is left out whole and counted once.
  resolver.ServiceWorkerControlleeAdded(307, "late", std::vector<std::uint32_t>{50});
  const reb::NativeTabResolver::RendererRequest import_record{1, 3}, later_record{1, 5};
  Check(resolver.Resolve(reb::NativeLoaderKind::kServiceWorker, Native(worker_token).fold(),
                         kSession, &import_record)
                    .status == reb::NativeTabResolution::Status::kNoPage &&
            resolver.Resolve(reb::NativeLoaderKind::kServiceWorker, Native(worker_token).fold(),
                             kSession, &later_record)
                    .status == reb::NativeTabResolution::Status::kLinked,
        "The import's renderer record takes the proxy's answer; a later request has the page");
  const auto extension_token = Token(0x41, 0x42);
  {
    const reb::ScopedNativeFactoryOwner owner({.service_worker_version_id = 308,
                                               .cause = Cause::kServiceWorker,
                                               .service_worker_token_high = extension_token.high,
                                               .service_worker_token_low = extension_token.low});
    const auto excluded = ScopeOf(owned, nullptr, Factory::kServiceWorkerSubResource,
                                  url::Origin("chrome-extension", std::string(32, 'd')));
    Check(excluded.exclusion == reb::kNativeExtensionWorkerExclusion,
          "An extension worker's factory is class 65");
    const auto scripts = ScopeOf(owned, nullptr, Factory::kServiceWorkerScript,
                                 url::Origin("chrome-extension", std::string(32, 'd')));
    const auto imported = reb::NativeProxyRequestExclusion(
        scripts, static_cast<int>(Factory::kServiceWorkerScript), "https", {1, 4});
    Check(
        imported.exclusion_class == reb::kNativeExtensionWorkerExclusion && !imported.counted_here,
        "An extension worker's import is class 65, counted by the drain with its record");
  }
  Check(resolver.Resolve(reb::NativeLoaderKind::kServiceWorker, Native(extension_token).fold(),
                         kSession)
                .status == reb::NativeTabResolution::Status::kExtension,
        "An excluded extension worker is still named, so its records are counted as 65");
  std::cout << "PASS starting service workers: named with their factories, extension ones too\n";
}

void Observers() {
  content::BrowserContext owned(true);
  auto* partition = owned.GetDefaultStoragePartition();
  // Enumeration in token order: the child comes before its parent.
  const content::RenderFrameHost creator(1, 7, Token(0x51, 0x52), 43);
  const blink::DedicatedWorkerToken child{Token(0x61, 0x62)}, parent{Token(0x63, 0x64)};
  partition->dedicated.existing = {{child, parent},
                                   {parent, content::GlobalRenderFrameHostId(1, 7)}};
  // Any frameless factory in the profile starts observing it.
  static_cast<void>(ScopeOf(owned, nullptr, Factory::kWorkerMainResource));
  auto& resolver = reb::NativeTabResolver::Get();
  const auto nested = resolver.Resolve(reb::NativeLoaderKind::kDedicatedWorker,
                                       Native(child.value()).fold(), kSession);
  Check(nested.status == reb::NativeTabResolution::Status::kLinked && nested.tabs.size() == 1 &&
            nested.tabs[0] == 43,
        "A nested worker enumerated before its parent links to the root document's tab");
  Check(partition->dedicated.observers.size() == 1 && partition->shared.observers.size() == 1 &&
            partition->service.observers.size() == 1,
        "Each worker service is observed once");
  static_cast<void>(ScopeOf(owned, nullptr, Factory::kWorkerMainResource));
  Check(partition->dedicated.observers.size() == 1, "A second factory observes nothing again");

  // Shared worker clients.
  const blink::SharedWorkerToken shared{Token(0x71, 0x72)};
  auto* shared_observer = partition->shared.observers.front();
  shared_observer->OnWorkerCreated(shared, content::ChildProcessId(1),
                                   url::Origin("https", "a.test"), {});
  const content::RenderFrameHost first(1, 8, Token(0x81, 0x82), 44),
      second(1, 9, Token(0x83, 0x84), 45);
  shared_observer->OnClientAdded(shared, {1, 8});
  shared_observer->OnClientAdded(shared, {1, 9});
  Check(resolver.Resolve(reb::NativeLoaderKind::kSharedWorker, Native(shared.value()).fold(),
                         kSession)
                .tabs.size() == 2,
        "A shared worker links to both client tabs");
  shared_observer->OnClientRemoved(shared, {1, 8});
  shared_observer->OnClientRemoved(shared, {1, 9});
  const auto last = resolver.Resolve(reb::NativeLoaderKind::kSharedWorker,
                                     Native(shared.value()).fold(), kSession);
  Check(last.last_clients && last.tabs.size() == 1 && last.tabs[0] == 45,
        "Without clients it links to the client that left last");

  // Service worker controllees: a window client gets its tab at commit.
  auto* service_observer = *partition->service.observers.begin();
  const blink::ServiceWorkerToken service{Token(0x91, 0x92)};
  service_observer->OnVersionStartedRunning(
      400, {GURL("https", "sw.test"), GURL("https", "sw.test"), service});
  service_observer->OnControlleeAdded(400, "window", content::GlobalRenderFrameHostId());
  Check(!resolver.ServiceWorkerHasNoPage(400), "A client before its commit already names a page");
  const content::RenderFrameHost committed(1, 10, Token(0xa1, 0xa2), 46);
  service_observer->OnControlleeNavigationCommitted(400, "window", {1, 10});
  const auto controlled = resolver.Resolve(reb::NativeLoaderKind::kServiceWorker,
                                           Native(service.value()).fold(), kSession);
  Check(controlled.kind == reb::NativeTabLinkKind::kServiceWorkerClients &&
            controlled.tabs.size() == 1 && controlled.tabs[0] == 46,
        "The committed window client's tab is the version's client");
  service_observer->OnDestruct(&partition->service);
  Check(partition->service.observers.empty(), "A destroyed context loses the observer");
  std::cout << "PASS worker services: enumeration order, shared clients and last clients, "
               "service-worker controllees from commit, context destruction\n";
}

}  // namespace

int main() {
  OwnerHook();
  Factories();
  Observers();
  if (failures != 0) {
    std::cerr << failures << " native tab registry checks failed\n";
    return 1;
  }
  return 0;
}
