#include "components/reverse_engineering_browser/browser/native_proxy_policy.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>

namespace {

using namespace reb::proxy;

void Check(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << "Native proxy policy failure: " << message << '\n';
    std::exit(1);
  }
}

constexpr ProfileToken kProfile{7, 19};
constexpr ProfileToken kOtherProfile{7, 20};
constexpr GroupKey kGroup{11, 13, 17};
constexpr GroupKey kOtherGroup{11, 13, 18};

Policy SamplePolicy() {
  return Policy{kPolicyVersion,
                {kProfile, "opaque-container", 1},
                {Scheme::kHttps, "proxy.example.test", 443}};
}

void CheckEndpoints() {
  auto policy = SamplePolicy();
  Check(ValidatePolicy(policy) == Error::kOk, "valid HTTPS endpoint");
  for (const auto scheme : {Scheme::kHttp, Scheme::kHttps, Scheme::kSocks5}) {
    policy.endpoint.scheme = scheme;
    const auto plan = MakeNetworkPlan(policy);
    Check(plan.has_value(), "supported fixed proxy scheme");
    const auto prefix = scheme == Scheme::kHttp    ? "http://"
                        : scheme == Scheme::kHttps ? "https://"
                                                   : "socks5://";
    Check(plan->proxy_rules == std::string(prefix) + "proxy.example.test:443",
          "one URI applies to HTTP, HTTPS, ws and wss");
    Check(plan->bypass_rules == "<-loopback>", "implicit direct bypasses removed");
    Check(plan->disallow_ambient_auth, "no ambient OS credentials");
    Check(plan->detach_profile_proxy_monitor, "profile updates cannot inject DIRECT");
  }
  policy.endpoint.scheme = static_cast<Scheme>(99);
  Check(ValidatePolicy(policy) == Error::kUnsupportedScheme, "unknown schemes fail closed");
  Check(!MakeNetworkPlan(policy), "no plan for unsupported SOCKS/other scheme");
  policy = SamplePolicy();
  for (const std::string host : {"",
                                 "http://proxy.test",
                                 "name:secret@proxy.test",
                                 "proxy.test:80",
                                 "proxy.test/path",
                                 "proxy.test?x=y",
                                 "proxy.test#fragment",
                                 "proxy.test,direct://",
                                 "proxy;DIRECT",
                                 "*.example.test",
                                 " proxy.test",
                                 "proxy.test\n",
                                 "proxy..test",
                                 "proxy.test.",
                                 ".proxy.test",
                                 "-proxy.test",
                                 "proxy-.test",
                                 "[::1]",
                                 "::1",
                                 "a_b.test",
                                 "127.1",
                                 "0177.0.0.1",
                                 "127.0.0.256",
                                 "2130706433",
                                 "1.2.3.04",
                                 "0x7f000001",
                                 "0X7f.0.0.1",
                                 "127.0.0.0x1",
                                 "proxy.123",
                                 "proxy.0x"}) {
    policy.endpoint.host = host;
    Check(ValidatePolicy(policy) == Error::kInvalidEndpoint, "unsafe host syntax rejected");
    Check(!MakeNetworkPlan(policy), "unsafe input cannot reach proxy rule construction");
  }
  for (unsigned int byte = 0; byte <= 255; ++byte) {
    const auto character = static_cast<char>(static_cast<unsigned char>(byte));
    const bool allowed = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                         (byte >= '0' && byte <= '9') || byte == '-';
    if (allowed) {
      continue;
    }
    // Includes embedded NUL, every control byte, UTF-8 bytes, and URL metacharacters.
    policy.endpoint.host = "proxy" + std::string(1, character) + "label.test";
    if (character != '.') {
      Check(!MakeNetworkPlan(policy), "non-ASCII/URL/control bytes rejected");
    }
  }
  policy.endpoint.host = std::string(64, 'a') + ".test";
  Check(!MakeNetworkPlan(policy), "DNS label length bound");
  policy.endpoint.host = std::string(254, 'a');
  Check(!MakeNetworkPlan(policy), "DNS total length bound");
  for (const std::string host : {"127.0.0.1", "192.0.2.9", "proxy", "xn--bcher-kva.test",
                                 "Proxy.EXAMPLE.test", "proxy-1.example.test"}) {
    policy.endpoint.host = host;
    Check(ValidatePolicy(policy) == Error::kOk, "explicit ASCII name or IPv4");
  }
  policy.endpoint.port = 0;
  Check(!MakeNetworkPlan(policy), "missing port rejected instead of defaulting");
  policy.endpoint.port = std::numeric_limits<std::uint16_t>::max();
  Check(MakeNetworkPlan(policy).has_value(), "maximum explicit port");
}

void CheckVersionAndOwnership() {
  auto policy = SamplePolicy();
  policy.version = 0;
  Check(ValidatePolicy(policy) == Error::kUnsupportedVersion, "zero version rejected");
  policy.version = 2;
  Check(ValidatePolicy(policy) == Error::kUnsupportedVersion, "future version rejected");
  policy = SamplePolicy();
  policy.key.profile = {};
  Check(ValidatePolicy(policy) == Error::kInvalidProfile, "missing profile rejected");
  policy = SamplePolicy();
  policy.key.generation = 0;
  Check(ValidatePolicy(policy) == Error::kInvalidContainer, "missing generation rejected");
  policy = SamplePolicy();
  for (const auto& id : {std::string(), std::string("group label"), std::string("../outside"),
                         std::string("ID"), std::string(65, 'a')}) {
    policy.key.id = id;
    Check(ValidatePolicy(policy) == Error::kInvalidContainer, "opaque key validation");
  }
  policy = SamplePolicy();
  PolicyRegistry invalid({});
  Check(invalid.Register(policy) == Error::kInvalidProfile, "unowned registry rejects policies");
  PolicyRegistry registry(kProfile);
  Check(registry.Register(policy) == Error::kOk, "register immutable generation");
  Check(registry.Register(policy) == Error::kOk, "idempotent exact registration");
  auto changed = policy;
  changed.endpoint.host = "another.example.test";
  Check(registry.Register(changed) == Error::kImmutableConflict, "no live route mutation");
  Check(registry.Find(policy.key)->endpoint == policy.endpoint, "rejected update preserves route");
  changed.key.generation = 2;
  Check(registry.Register(changed) == Error::kOk,
        "changed route requires fresh partition generation");
  changed.key.profile = kOtherProfile;
  Check(registry.Register(changed) == Error::kCrossProfile, "profile ownership is exact");
  Check(registry.BindGroup(kGroup, changed.key) == Error::kCrossProfile,
        "foreign group binding rejected");
  changed.key.profile = kProfile;
  changed.key.id = "unknown";
  Check(registry.BindGroup(kGroup, changed.key) == Error::kUnknownContainer,
        "missing route fails closed");
  Check(!registry.PlanNewTab(kGroup), "unknown group cannot default to unproxied partition");
  Check(registry.BindGroup({}, policy.key) == Error::kInvalidGroup, "empty group rejected");
  Check(registry.BindGroup({0, 1, 2}, policy.key) == Error::kInvalidGroup,
        "missing window rejected");
  Check(registry.BindGroup(kGroup, policy.key) == Error::kOk, "bind first native group");
  Check(registry.BindGroup(kOtherGroup, policy.key) == Error::kContainerAlreadyBound,
        "distinct groups cannot silently share one storage identity");
  const auto plan = registry.PlanNewTab(kGroup);
  Check(plan.has_value(), "group new-tab intent inherited before creation");
  Check(plan->partition_name == "reb-proxy-opaque-container-g1", "opaque generation partition key");
  Check(registry.ValidateCreation(*plan) == Error::kOk, "current creation plan valid");
  auto forged = *plan;
  forged.partition_name = "default";
  Check(registry.ValidateCreation(forged) == Error::kStalePlan, "partition substitution rejected");
  forged = *plan;
  forged.version = 2;
  Check(registry.ValidateCreation(forged) == Error::kUnsupportedVersion,
        "creation version checked");
  forged = *plan;
  forged.container.profile = kOtherProfile;
  Check(registry.ValidateCreation(forged) == Error::kCrossProfile, "creation profile checked");
  Check(registry.BindGroup(kGroup, policy.key) == Error::kOk, "repeat binding harmless");
  Check(registry.ValidateCreation(*plan) == Error::kOk, "repeat binding preserves intent revision");
  auto generation2 = policy.key;
  generation2.generation = 2;
  Check(registry.BindGroup(kGroup, generation2) == Error::kOk,
        "intent changed to fresh generation");
  Check(registry.ValidateCreation(*plan) == Error::kStalePlan, "old creation receipt invalidated");
  Check(registry.BindGroup(kGroup, policy.key) == Error::kOk,
        "intent can return to prior generation");
  Check(registry.ValidateCreation(*plan) == Error::kStalePlan, "ABA binding cannot revive receipt");
  const auto before_remove = registry.PlanNewTab(kGroup);
  Check(registry.RemoveGroup(kGroup) == Error::kOk, "group removal");
  Check(registry.BindGroup(kOtherGroup, policy.key) == Error::kContainerAlreadyBound,
        "deleted group cannot donate a still-live storage identity to a different group");
  Check(registry.RemoveGroup(kGroup) == Error::kUnknownGroup, "repeat removal visible");
  Check(registry.ValidateCreation(*before_remove) == Error::kStalePlan,
        "removed group fails closed");
  Check(registry.BindGroup(kGroup, policy.key) == Error::kOk, "recreated group");
  Check(registry.ValidateCreation(*before_remove) == Error::kStalePlan,
        "recreation cannot replay intent");
  Check(registry.Find(policy.key) != nullptr,
        "group deletion does not delete referenced storage policy");
}

void CheckReopenTransactions() {
  PolicyRegistry registry(kProfile);
  const auto policy = SamplePolicy();
  auto other = policy;
  other.key.id = "other-container";
  other.endpoint.scheme = Scheme::kSocks5;
  Check(registry.Register(policy) == Error::kOk, "register source");
  Check(registry.Register(other) == Error::kOk, "register target");
  Check(registry.BindGroup(kGroup, policy.key) == Error::kOk, "bind source");
  Check(registry.BindGroup(kOtherGroup, other.key) == Error::kOk, "bind target");
  const TabSnapshot source{kProfile, 101, 4, policy.key};
  ReopenPlan plan;
  Check(registry.PlanReopen(source, kOtherGroup, plan) == Error::kOk,
        "explicit cross-container reopen");
  Check(plan.source == source, "planning cannot relabel loaded tab");
  Check(plan.destination.container == other.key, "fresh owner selected before navigation");
  Check(registry.ValidateReopen(plan, source, false, false) == Error::kConfirmationRequired,
        "unsaved work warning must be accepted");
  Check(registry.ValidateReopen(plan, source, true, false) == Error::kUnloadCancelled,
        "beforeunload veto preserved");
  Check(registry.ValidateReopen(plan, source, true, true) == Error::kOk,
        "confirmed plan passes only preparation validation");
  auto current = source;
  ++current.document_epoch;
  Check(registry.ValidateReopen(plan, current, true, true) == Error::kStalePlan,
        "navigation during confirmation invalidates transaction");
  current = source;
  ++current.tab;
  Check(registry.ValidateReopen(plan, current, true, true) == Error::kStalePlan,
        "replacement source invalidates transaction");
  auto forged = plan;
  forged.destination.partition_name = "default";
  Check(registry.ValidateReopen(forged, source, true, true) == Error::kStalePlan,
        "confirmation cannot authorize altered partition");
  auto third = other;
  third.key.generation = 2;
  Check(registry.Register(third) == Error::kOk, "prepare another immutable destination");
  Check(registry.BindGroup(kOtherGroup, third.key) == Error::kOk,
        "target intent changes while waiting");
  Check(registry.ValidateReopen(plan, source, true, true) == Error::kStalePlan,
        "old confirmation cannot move against newer intent");
  Check(registry.BindGroup(kOtherGroup, other.key) == Error::kOk, "target intent returns");
  Check(registry.ValidateReopen(plan, source, true, true) == Error::kStalePlan,
        "ABA target rebind cannot reuse old confirmation");
  Check(registry.PlanReopen(source, kGroup, plan) == Error::kSameContainer,
        "same-container ordinary group move needs no new context");
  Check(plan.source.tab == 0, "failed planning clears previous transaction");
  const TabSnapshot baseline{kProfile, 102, 1, std::nullopt};
  Check(registry.PlanReopen(baseline, kOtherGroup, plan) == Error::kOk,
        "baseline tab needs explicit fresh-container reopen");
  Check(registry.ValidateReopen(plan, baseline, false, true) == Error::kConfirmationRequired,
        "blank/default origin does not exempt confirmation");
  current = baseline;
  current.profile = kOtherProfile;
  Check(registry.PlanReopen(current, kOtherGroup, plan) == Error::kCrossProfile,
        "cross-profile insertion rejected");
  current = baseline;
  current.tab = 0;
  Check(registry.PlanReopen(current, kOtherGroup, plan) == Error::kInvalidTab,
        "missing tab rejected");
  current = baseline;
  current.document_epoch = 0;
  Check(registry.PlanReopen(current, kOtherGroup, plan) == Error::kInvalidTab,
        "missing epoch rejected");
  current = source;
  current.container->id = "missing";
  Check(registry.PlanReopen(current, kOtherGroup, plan) == Error::kUnknownContainer,
        "lost owner cannot silently become direct");
  Check(registry.PlanReopen(source, {}, plan) == Error::kUnknownGroup, "lost group fails closed");
}

void CheckBoundsAndCoverage() {
  PolicyRegistry registry(kProfile);
  auto policy = SamplePolicy();
  for (std::size_t index = 0; index < kMaximumContainers; ++index) {
    policy.key.generation = index + 1;
    Check(registry.Register(policy) == Error::kOk, "bounded policy admission");
  }
  Check(registry.Register(policy) == Error::kOk, "idempotency at capacity");
  ++policy.key.generation;
  Check(registry.Register(policy) == Error::kCapacity, "container limit visible");
  policy.key.generation = 1;
  for (std::size_t index = 0; index < kMaximumGroups; ++index) {
    policy.key.generation = index + 1;
    Check(registry.BindGroup({1, 1, index + 1}, policy.key) == Error::kOk,
          "bounded group admission");
  }
  policy.key.generation = 1;
  Check(registry.BindGroup({1, 1, 1}, policy.key) == Error::kOk, "idempotent group at capacity");
  policy.key.generation = kMaximumGroups + 1;
  Check(registry.BindGroup({1, 2, 1}, policy.key) == Error::kCapacity, "group limit visible");
  for (const auto traffic : {Traffic::kHttp, Traffic::kHttps, Traffic::kWebSocket,
                             Traffic::kSecureWebSocket, Traffic::kDedicatedWorkerFetch,
                             Traffic::kSharedWorkerFetch, Traffic::kServiceWorkerFetch}) {
    Check(RequiredHandling(traffic) == Requirement::kContainerProxy, "URL traffic must use owner");
  }
  Check(RequiredHandling(Traffic::kDestinationDns) == Requirement::kProxySideResolution,
        "no destination DNS escape");
  Check(RequiredHandling(Traffic::kProxyEndpointDns) == Requirement::kDisclosedSystemResolution,
        "proxy endpoint bootstrap DNS explicitly disclosed");
  for (const auto traffic : {Traffic::kSpeculativeDns, Traffic::kWebRtc, Traffic::kQuic,
                             Traffic::kWebTransport, static_cast<Traffic>(999)}) {
    Check(RequiredHandling(traffic) == Requirement::kBlocked, "unsupported transports fail closed");
  }
  Check(RequiredHandling(Traffic::kBrowserService) == Requirement::kOutsideContainerScope,
        "browser-wide services are not falsely claimed as tab traffic");
  static_assert(!std::is_copy_constructible_v<PolicyRegistry>);
  static_assert(!std::is_copy_assignable_v<PolicyRegistry>);
  static_assert(!kRuntimeIntegrated);
}

void CheckWholeGroupTransfer() {
  PolicyRegistry registry(kProfile);
  auto first = SamplePolicy();
  auto current = first;
  current.key.generation = 2;
  current.endpoint.host = "next.example.test";
  Check(registry.Register(first) == Error::kOk, "transfer retired generation registered");
  Check(registry.Register(current) == Error::kOk, "transfer current generation registered");
  Check(registry.BindGroup(kGroup, first.key) == Error::kOk, "first generation owner");
  Check(registry.BindGroup(kGroup, current.key) == Error::kOk, "retire earlier generation");
  const GroupKey destination{99, kGroup.high, kGroup.low};
  const auto original_plan = *registry.PlanNewTab(kGroup);
  GroupTransferPlan transfer;
  Check(registry.PlanGroupTransfer(kGroup, destination, transfer) == Error::kOk,
        "whole group cross-window plan");
  auto foreign = transfer;
  foreign.profile = kOtherProfile;
  Check(registry.CommitGroupTransfer(foreign) == Error::kCrossProfile,
        "whole-group transfer remains profile-bound");
  Check(registry.ValidateCreation(original_plan) == Error::kOk, "planning does not mutate owners");
  auto stale = transfer;
  --stale.source_revision;
  Check(registry.CommitGroupTransfer(stale) == Error::kStalePlan, "stale transfer rejected");
  Check(registry.PlanNewTab(kGroup).has_value() && !registry.PlanNewTab(destination),
        "failed transfer leaves source and destination unchanged");
  Check(registry.CommitGroupTransfer(transfer) == Error::kOk, "atomic whole-group commit");
  Check(!registry.PlanNewTab(kGroup), "old window binding removed");
  const auto moved = registry.PlanNewTab(destination);
  Check(moved && moved->container == current.key &&
            moved->partition_name == original_plan.partition_name,
        "whole-group transfer preserves partition and proxy generation");
  Check(registry.ValidateCreation(original_plan) == Error::kStalePlan,
        "source creation and reopen plans invalidated");
  Check(registry.CommitGroupTransfer(transfer) == Error::kUnknownGroup,
        "committed transfer is not replayable");
  Check(registry.Find(first.key) && registry.Find(current.key),
        "workers retain all generation policies");
  Check(registry.BindGroup(kGroup, first.key) == Error::kContainerAlreadyBound,
        "old window cannot reclaim retired worker owner");
  Check(registry.BindGroup(destination, first.key) == Error::kOk,
        "retired generation owner moved with whole group");
  Check(registry.BindGroup(destination, current.key) == Error::kOk, "restore current generation");
  Check(registry.PlanGroupTransfer(destination, kGroup, transfer) == Error::kOk,
        "return whole group to first window");
  Check(registry.CommitGroupTransfer(transfer) == Error::kOk, "return transfer commits");
  Check(registry.ValidateCreation(original_plan) == Error::kStalePlan,
        "window ABA cannot revive old plan");
  Check(registry.PlanGroupTransfer(kGroup, kOtherGroup, transfer) == Error::kInvalidTransfer,
        "different group token cannot masquerade as window transfer");
  Check(registry.PlanGroupTransfer(kGroup, kGroup, transfer) == Error::kInvalidTransfer,
        "same window cannot be transferred");
  Check(registry.PlanGroupTransfer(kGroup, destination, transfer) == Error::kOk,
        "prepare competing transfer");
  Check(registry.BindGroup(kGroup, first.key) == Error::kOk,
        "source intent changes while transfer pending");
  Check(registry.CommitGroupTransfer(transfer) == Error::kStalePlan,
        "source rebind invalidates transfer");
  auto unrelated = first;
  unrelated.key.id = "unrelated";
  Check(registry.Register(unrelated) == Error::kOk, "destination conflict identity");
  Check(registry.BindGroup(destination, unrelated.key) == Error::kOk,
        "destination becomes occupied");
  Check(registry.PlanGroupTransfer(kGroup, destination, transfer) == Error::kGroupExists,
        "cannot overwrite destination group");
}

void CheckTransferBoundsAndRemoval() {
  PolicyRegistry registry(kProfile);
  auto first = SamplePolicy();
  Check(registry.Register(first) == Error::kOk, "bounded transfer policy");
  Check(registry.BindGroup(kGroup, first.key) == Error::kOk, "bounded transfer owner");
  const GroupKey destination{99, kGroup.high, kGroup.low};
  GroupTransferPlan transfer;
  Check(registry.PlanGroupTransfer(kGroup, destination, transfer) == Error::kOk,
        "prepare before group removal");
  Check(registry.RemoveGroup(kGroup) == Error::kOk, "source removed before transfer");
  Check(registry.CommitGroupTransfer(transfer) == Error::kUnknownGroup,
        "removed source cannot commit");
  Check(registry.BindGroup(kGroup, first.key) == Error::kOk, "source recreated with same owner");
  Check(registry.CommitGroupTransfer(transfer) == Error::kStalePlan,
        "source removal and recreation cannot revive approval");
  for (std::uint64_t index = 1; index < kMaximumGroups; ++index) {
    auto policy = first;
    policy.key.id = "bounded-" + std::to_string(index);
    Check(registry.Register(policy) == Error::kOk, "fill group transfer policies");
    Check(registry.BindGroup({1000 + index, 1000 + index, 1}, policy.key) == Error::kOk,
          "fill groups to capacity");
  }
  Check(registry.PlanGroupTransfer(kGroup, destination, transfer) == Error::kOk,
        "full registry can prepare a move");
  Check(registry.CommitGroupTransfer(transfer) == Error::kOk,
        "full registry transfer replaces rather than adds a group");
  Check(registry.PlanNewTab(destination).has_value() && !registry.PlanNewTab(kGroup),
        "capacity transfer preserves exactly one binding");
  auto extra = first;
  extra.key.id = "extra";
  Check(registry.Register(extra) == Error::kOk, "extra generation within policy bound");
  Check(registry.BindGroup({2000, 2000, 1}, extra.key) == Error::kCapacity,
        "transfer does not bypass group bound");
}

void CheckRestoreIdentity() {
  const auto policy = SamplePolicy();
  PolicySnapshot snapshot{kPolicyVersion,
                          {{policy.key.id, policy.key.generation, policy.endpoint}}};
  Error error;
  auto restored = RestorePolicyRegistry(snapshot, kOtherProfile, error);
  Check(restored && error == Error::kOk, "bounded snapshot restored atomically");
  auto new_key = policy.key;
  new_key.profile = kOtherProfile;
  Check(restored->Find(new_key) && !restored->Find(policy.key),
        "restore derives current process profile ownership");
  Check(!restored->PlanNewTab(kGroup), "policy restore does not authorize group navigation");
  const std::string name = "reb-proxy-opaque-container-g1";
  Check(restored->FindPartition(kOtherProfile, name) != nullptr,
        "full original partition identity resolved");
  Check(!restored->FindPartition(kProfile, name), "foreign profile cannot look up owned partition");
  for (const auto& bad : {"Storage/ext/containers/123ABC", "reb-proxy-opaque-container-g01",
                          "reb-proxy-opaque-container-g2", "reb-proxy-unknown-g1", "default"}) {
    Check(!restored->FindPartition(kOtherProfile, bad),
          "hash, alias and missing generation fail closed");
  }
  snapshot.policies.push_back(snapshot.policies.front());
  Check(!RestorePolicyRegistry(snapshot, kProfile, error) && error == Error::kInvalidSnapshot,
        "identical duplicate stored identity is corruption");
  snapshot.policies.back().endpoint.host = "conflict.example.test";
  Check(!RestorePolicyRegistry(snapshot, kProfile, error) && error == Error::kInvalidSnapshot,
        "conflicting duplicate stored identity is corruption");
  snapshot.policies.back().id = "another";
  snapshot.policies.back().endpoint.host = "username:password@proxy.test";
  Check(!RestorePolicyRegistry(snapshot, kProfile, error) && error == Error::kInvalidEndpoint,
        "one corrupt record prevents partial restore");
  snapshot.version = 2;
  Check(!RestorePolicyRegistry(snapshot, kProfile, error) && error == Error::kUnsupportedVersion,
        "unsupported stored version blocked");
  snapshot.version = kPolicyVersion;
  snapshot.policies.resize(kMaximumContainers + 1);
  Check(!RestorePolicyRegistry(snapshot, kProfile, error) && error == Error::kCapacity,
        "oversized snapshot rejected before admission");
  snapshot.policies.clear();
  Check(!RestorePolicyRegistry(snapshot, {}, error) && error == Error::kInvalidProfile,
        "restore requires actual browser ownership");
}

}  // namespace

int main() {
  CheckEndpoints();
  CheckVersionAndOwnership();
  CheckReopenTransactions();
  CheckBoundsAndCoverage();
  CheckWholeGroupTransfer();
  CheckRestoreIdentity();
  CheckTransferBoundsAndRemoval();
  std::cout
      << "Native proxy policy v1 checks passed (preparation only; browser routing unavailable)\n";
}
