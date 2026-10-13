// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROXY_POLICY_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROXY_POLICY_H_

#include <compare>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace reb::proxy {

// Native browser-process preparation contract, not a serialized IPC ABI.
inline constexpr std::uint32_t kPolicyVersion = 1;
inline constexpr std::size_t kMaximumContainers = 128;
inline constexpr std::size_t kMaximumGroups = 64;

// No enabled UI or browser network hook consumes these plans in this stage.
inline constexpr bool kRuntimeIntegrated = false;

struct ProfileToken {
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  auto operator<=>(const ProfileToken&) const = default;
};

enum class Scheme { kHttp, kHttps, kSocks5 };

struct Endpoint {
  Scheme scheme = Scheme::kHttp;
  // ASCII DNS name or canonical IPv4 literal. No URL, userinfo, or port here.
  std::string host;
  std::uint16_t port = 0;
  bool operator==(const Endpoint&) const = default;
};

struct ContainerKey {
  ProfileToken profile;
  // Browser-generated opaque ID, never a group name or a proxy credential.
  std::string id;
  std::uint64_t generation = 0;
  auto operator<=>(const ContainerKey&) const = default;
};

struct Policy {
  std::uint32_t version = kPolicyVersion;
  ContainerKey key;
  Endpoint endpoint;
  bool operator==(const Policy&) const = default;
};

struct GroupKey {
  // Window lifetime ID and full opaque native tab-group token, scoped to profile.
  std::uint64_t window = 0;
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  auto operator<=>(const GroupKey&) const = default;
};

enum class Error {
  kOk,
  kUnsupportedVersion,
  kInvalidProfile,
  kInvalidContainer,
  kInvalidEndpoint,
  kUnsupportedScheme,
  kCrossProfile,
  kUnknownContainer,
  kImmutableConflict,
  kContainerAlreadyBound,
  kCapacity,
  kInvalidGroup,
  kUnknownGroup,
  kInvalidTab,
  kStalePlan,
  kConfirmationRequired,
  kUnloadCancelled,
  kSameContainer,
  kSequenceExhausted,
  kInvalidSnapshot,
  kGroupExists,
  kInvalidTransfer,
};

Error ValidatePolicy(const Policy& policy);

// Returns no plan on invalid input. A single fixed route has no PAC, bypass
// destination, or DIRECT fallback. Subtracting Chromium's implicit bypasses is
// necessary but does not itself block privileged/local destinations.
struct NetworkPlan {
  std::string proxy_rules;
  std::string bypass_rules;
  bool disallow_ambient_auth = true;
  bool detach_profile_proxy_monitor = true;
};
std::optional<NetworkPlan> MakeNetworkPlan(const Policy& policy);

// This is a required implementation/test matrix, NOT an observed traffic result.
enum class Traffic {
  kHttp,
  kHttps,
  kWebSocket,
  kSecureWebSocket,
  kDedicatedWorkerFetch,
  kSharedWorkerFetch,
  kServiceWorkerFetch,
  kDestinationDns,
  kProxyEndpointDns,
  kSpeculativeDns,
  kWebRtc,
  kQuic,
  kWebTransport,
  kBrowserService,
};
enum class Requirement {
  kContainerProxy,
  kProxySideResolution,
  kDisclosedSystemResolution,
  kBlocked,
  kOutsideContainerScope,
};
Requirement RequiredHandling(Traffic traffic);

// Browser-generated observation. document_epoch changes on navigation,
// beforeunload-state changes, replacement, or source group/window moves.
// The adapter must invalidate pending confirmation before accepting those changes.
struct TabSnapshot {
  ProfileToken profile;
  std::uint64_t tab = 0;
  std::uint64_t document_epoch = 0;
  std::optional<ContainerKey> container;
  bool operator==(const TabSnapshot&) const = default;
};

struct CreationPlan {
  std::uint32_t version = kPolicyVersion;
  ContainerKey container;
  GroupKey group;
  std::uint64_t binding_revision = 0;
  // Reuse Brave's container partition domain with this opaque name. Register it
  // in ContainersService before creating a fixed-partition SiteInstance.
  std::string partition_name;
  bool operator==(const CreationPlan&) const = default;
};

struct ReopenPlan {
  TabSnapshot source;
  CreationPlan destination;
  bool operator==(const ReopenPlan&) const = default;
};

struct GroupTransferPlan {
  std::uint32_t version = kPolicyVersion;
  ProfileToken profile;
  GroupKey source;
  GroupKey destination;
  std::uint64_t source_revision = 0;
  bool operator==(const GroupTransferPlan&) const = default;
};

// Restore records omit process-lifetime Profile and window identities. Restoring
// policies alone never restores group admission or creates a browsing context.
struct StoredPolicy {
  std::string id;
  std::uint64_t generation = 0;
  Endpoint endpoint;
};

struct PolicySnapshot {
  std::uint32_t version = kPolicyVersion;
  std::vector<StoredPolicy> policies;
};

// Single-sequence, profile-owned registry of immutable policies and group
// intents. It never changes WebContents, opens sockets, or marks routing active.
// The later native adapter must prepare a fresh WebContents before navigation.
// Copying would fork revision ownership and permit stale plan reuse.
class PolicyRegistry {
 public:
  explicit PolicyRegistry(ProfileToken profile);
  ~PolicyRegistry();
  PolicyRegistry(const PolicyRegistry&) = delete;
  PolicyRegistry& operator=(const PolicyRegistry&) = delete;

  Error Register(Policy policy);
  const Policy* Find(const ContainerKey& key) const;
  const Policy* FindPartition(ProfileToken profile, std::string_view partition_name) const;

  // Rebinding only changes the intent for future creation/reopen. Existing tabs
  // remain in their original container and must show a mismatch in any later UI.
  Error BindGroup(const GroupKey& group, const ContainerKey& container);
  Error RemoveGroup(const GroupKey& group);
  std::optional<CreationPlan> PlanNewTab(const GroupKey& group) const;
  Error ValidateCreation(const CreationPlan& plan) const;

  // Explicit whole-group transfer only: same opaque native group token, different
  // window, same profile. All retired generation owners move together. No tab,
  // worker, partition, or network resource is replaced or reconfigured here.
  Error PlanGroupTransfer(GroupKey source, GroupKey destination, GroupTransferPlan& plan) const;
  Error CommitGroupTransfer(const GroupTransferPlan& plan);

  // Always requires a fresh WebContents, explicit unsaved-work warning, and the
  // source's beforeunload result. Even an about:blank tab may have used a context.
  Error PlanReopen(const TabSnapshot& source, const GroupKey& destination, ReopenPlan& plan) const;
  Error ValidateReopen(const ReopenPlan& plan,
                       const TabSnapshot& current_source,
                       bool warning_accepted,
                       bool beforeunload_accepted) const;

 private:
  struct Binding {
    ContainerKey container;
    std::uint64_t revision = 0;
  };

  ProfileToken profile_;
  std::uint64_t next_binding_revision_ = 1;
  std::map<ContainerKey, Policy> policies_;
  // Keep ownership after group removal/rebinding: old tabs and workers may live.
  std::map<ContainerKey, GroupKey> container_owners_;
  std::map<GroupKey, Binding> groups_;
};

// All-or-nothing, bounded restore. Duplicate records are corruption, including
// identical duplicates. Runtime profile ownership is supplied by the browser.
std::unique_ptr<PolicyRegistry> RestorePolicyRegistry(const PolicySnapshot& snapshot,
                                                      ProfileToken profile,
                                                      Error& error);

}  // namespace reb::proxy

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROXY_POLICY_H_
