// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_proxy_policy.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace reb::proxy {
namespace {

bool IsValidProfile(ProfileToken token) {
  return token.high != 0 || token.low != 0;
}

bool IsAsciiDigit(char value) {
  return value >= '0' && value <= '9';
}

bool IsAsciiAlpha(char value) {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
}

bool IsValidContainerKey(const ContainerKey& key) {
  return IsValidProfile(key.profile) && key.generation != 0 && !key.id.empty() &&
         key.id.size() <= 64 && std::all_of(key.id.begin(), key.id.end(), [](char value) {
           return (value >= 'a' && value <= 'z') || IsAsciiDigit(value) || value == '-';
         });
}

bool IsValidHost(std::string_view host) {
  if (host.empty() || host.size() > 253) {
    return false;
  }
  bool digits_and_dots = true;
  std::size_t labels = 0;
  for (std::size_t start = 0; start < host.size();) {
    const auto dot = host.find('.', start);
    const auto end = dot == std::string_view::npos ? host.size() : dot;
    const auto label = host.substr(start, end - start);
    if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
      return false;
    }
    for (const char value : label) {
      if (!IsAsciiAlpha(value) && !IsAsciiDigit(value) && value != '-') {
        return false;
      }
      digits_and_dots = digits_and_dots && IsAsciiDigit(value);
    }
    ++labels;
    if (end == host.size()) {
      break;
    }
    start = end + 1;
    if (start == host.size()) {
      return false;
    }
  }
  if (!digits_and_dots) {
    // Chromium treats a numeric final label as an IPv4 attempt, including hex.
    // Reject DNS-looking input that its parser can reinterpret as an address.
    const auto final_dot = host.rfind('.');
    const auto final_label =
        final_dot == std::string_view::npos ? host : host.substr(final_dot + 1);
    const bool numeric_suffix = std::all_of(final_label.begin(), final_label.end(), IsAsciiDigit);
    const bool hex_suffix = final_label.size() >= 2 && final_label[0] == '0' &&
                            (final_label[1] == 'x' || final_label[1] == 'X') &&
                            std::all_of(final_label.begin() + 2, final_label.end(), [](char value) {
                              return IsAsciiDigit(value) || (value >= 'a' && value <= 'f') ||
                                     (value >= 'A' && value <= 'F');
                            });
    return !numeric_suffix && !hex_suffix;
  }
  // Reject shorthand, octal, overflow, and other ambiguous numeric addresses.
  if (labels != 4) {
    return false;
  }
  for (std::size_t start = 0; start < host.size();) {
    const auto dot = host.find('.', start);
    const auto end = dot == std::string_view::npos ? host.size() : dot;
    const auto label = host.substr(start, end - start);
    if (label.size() > 3 || (label.size() > 1 && label.front() == '0')) {
      return false;
    }
    unsigned int value = 0;
    for (const char digit : label) {
      value = value * 10U + static_cast<unsigned int>(digit - '0');
    }
    if (value > 255U) {
      return false;
    }
    start = end + 1;
  }
  return true;
}

bool IsValidGroup(const GroupKey& group) {
  return group.window != 0 && (group.high != 0 || group.low != 0);
}

std::string PartitionName(const ContainerKey& key) {
  return "reb-proxy-" + key.id + "-g" + std::to_string(key.generation);
}

}  // namespace

Error ValidatePolicy(const Policy& policy) {
  if (policy.version != kPolicyVersion) {
    return Error::kUnsupportedVersion;
  }
  if (!IsValidProfile(policy.key.profile)) {
    return Error::kInvalidProfile;
  }
  if (!IsValidContainerKey(policy.key)) {
    return Error::kInvalidContainer;
  }
  switch (policy.endpoint.scheme) {
    case Scheme::kHttp:
    case Scheme::kHttps:
    case Scheme::kSocks5:
      break;
    default:
      return Error::kUnsupportedScheme;
  }
  if (policy.endpoint.port == 0 || !IsValidHost(policy.endpoint.host)) {
    return Error::kInvalidEndpoint;
  }
  return Error::kOk;
}

std::optional<NetworkPlan> MakeNetworkPlan(const Policy& policy) {
  if (ValidatePolicy(policy) != Error::kOk) {
    return std::nullopt;
  }
  std::string_view scheme;
  switch (policy.endpoint.scheme) {
    case Scheme::kHttp:
      scheme = "http";
      break;
    case Scheme::kHttps:
      scheme = "https";
      break;
    case Scheme::kSocks5:
      scheme = "socks5";
      break;
    default:
      return std::nullopt;
  }
  return NetworkPlan{std::string(scheme) + "://" + policy.endpoint.host + ":" +
                         std::to_string(policy.endpoint.port),
                     "<-loopback>", true, true};
}

Requirement RequiredHandling(Traffic traffic) {
  switch (traffic) {
    case Traffic::kHttp:
    case Traffic::kHttps:
    case Traffic::kWebSocket:
    case Traffic::kSecureWebSocket:
    case Traffic::kDedicatedWorkerFetch:
    case Traffic::kSharedWorkerFetch:
    case Traffic::kServiceWorkerFetch:
      return Requirement::kContainerProxy;
    case Traffic::kDestinationDns:
      return Requirement::kProxySideResolution;
    case Traffic::kProxyEndpointDns:
      return Requirement::kDisclosedSystemResolution;
    case Traffic::kBrowserService:
      return Requirement::kOutsideContainerScope;
    case Traffic::kSpeculativeDns:
    case Traffic::kWebRtc:
    case Traffic::kQuic:
    case Traffic::kWebTransport:
    default:
      return Requirement::kBlocked;
  }
}

PolicyRegistry::PolicyRegistry(ProfileToken profile) : profile_(profile) {}

Error PolicyRegistry::Register(Policy policy) {
  if (!IsValidProfile(profile_)) {
    return Error::kInvalidProfile;
  }
  const auto error = ValidatePolicy(policy);
  if (error != Error::kOk) {
    return error;
  }
  if (policy.key.profile != profile_) {
    return Error::kCrossProfile;
  }
  if (const auto* existing = Find(policy.key)) {
    return *existing == policy ? Error::kOk : Error::kImmutableConflict;
  }
  if (policies_.size() == kMaximumContainers) {
    return Error::kCapacity;
  }
  const auto key = policy.key;
  policies_.emplace(key, std::move(policy));
  return Error::kOk;
}

const Policy* PolicyRegistry::Find(const ContainerKey& key) const {
  const auto found = policies_.find(key);
  return found == policies_.end() ? nullptr : &found->second;
}

const Policy* PolicyRegistry::FindPartition(ProfileToken profile,
                                            std::string_view partition_name) const {
  if (profile != profile_) {
    return nullptr;
  }
  for (const auto& [key, policy] : policies_) {
    if (PartitionName(key) == partition_name) {
      return &policy;
    }
  }
  return nullptr;
}

Error PolicyRegistry::BindGroup(const GroupKey& group, const ContainerKey& container) {
  if (!IsValidGroup(group)) {
    return Error::kInvalidGroup;
  }
  if (container.profile != profile_) {
    return Error::kCrossProfile;
  }
  if (!Find(container)) {
    return Error::kUnknownContainer;
  }
  const auto existing = groups_.find(group);
  if (existing != groups_.end() && existing->second.container == container) {
    return Error::kOk;
  }
  const auto owner = container_owners_.find(container);
  if (owner != container_owners_.end() && owner->second != group) {
    return Error::kContainerAlreadyBound;
  }
  if (existing == groups_.end() && groups_.size() == kMaximumGroups) {
    return Error::kCapacity;
  }
  if (next_binding_revision_ == std::numeric_limits<std::uint64_t>::max()) {
    return Error::kSequenceExhausted;
  }
  container_owners_.emplace(container, group);
  groups_.insert_or_assign(group, Binding{container, next_binding_revision_++});
  return Error::kOk;
}

Error PolicyRegistry::RemoveGroup(const GroupKey& group) {
  return groups_.erase(group) == 0 ? Error::kUnknownGroup : Error::kOk;
}

std::optional<CreationPlan> PolicyRegistry::PlanNewTab(const GroupKey& group) const {
  const auto found = groups_.find(group);
  if (found == groups_.end()) {
    return std::nullopt;
  }
  return CreationPlan{kPolicyVersion, found->second.container, group, found->second.revision,
                      PartitionName(found->second.container)};
}

Error PolicyRegistry::ValidateCreation(const CreationPlan& plan) const {
  if (plan.version != kPolicyVersion) {
    return Error::kUnsupportedVersion;
  }
  if (plan.container.profile != profile_) {
    return Error::kCrossProfile;
  }
  const auto current = PlanNewTab(plan.group);
  return current && *current == plan ? Error::kOk : Error::kStalePlan;
}

Error PolicyRegistry::PlanGroupTransfer(GroupKey source,
                                        GroupKey destination,
                                        GroupTransferPlan& plan) const {
  plan = {};
  if (!IsValidGroup(source) || !IsValidGroup(destination) || source.window == destination.window ||
      source.high != destination.high || source.low != destination.low) {
    return Error::kInvalidTransfer;
  }
  const auto found = groups_.find(source);
  if (found == groups_.end()) {
    return Error::kUnknownGroup;
  }
  if (groups_.contains(destination)) {
    return Error::kGroupExists;
  }
  plan = GroupTransferPlan{kPolicyVersion, profile_, source, destination, found->second.revision};
  return Error::kOk;
}

Error PolicyRegistry::CommitGroupTransfer(const GroupTransferPlan& plan) {
  if (plan.version != kPolicyVersion) {
    return Error::kUnsupportedVersion;
  }
  if (plan.profile != profile_) {
    return Error::kCrossProfile;
  }
  GroupTransferPlan expected;
  const auto error = PlanGroupTransfer(plan.source, plan.destination, expected);
  if (error != Error::kOk) {
    return error;
  }
  if (plan != expected) {
    return Error::kStalePlan;
  }
  if (next_binding_revision_ == std::numeric_limits<std::uint64_t>::max()) {
    return Error::kSequenceExhausted;
  }
  const auto binding = groups_.find(plan.source)->second;
  // Single UI sequence, no callbacks/yields. Insert first so an allocation
  // failure cannot leave a normally recoverable, partially transferred owner.
  groups_.emplace(plan.destination, Binding{binding.container, next_binding_revision_++});
  for (auto& [container, owner] : container_owners_) {
    if (owner == plan.source) {
      owner = plan.destination;
    }
  }
  groups_.erase(plan.source);
  return Error::kOk;
}

Error PolicyRegistry::PlanReopen(const TabSnapshot& source,
                                 const GroupKey& destination,
                                 ReopenPlan& plan) const {
  // Failed preparation cannot accidentally leave a previously valid plan.
  plan = {};
  if (source.profile != profile_ || (source.container && source.container->profile != profile_)) {
    return Error::kCrossProfile;
  }
  if (source.tab == 0 || source.document_epoch == 0) {
    return Error::kInvalidTab;
  }
  if (source.container && !Find(*source.container)) {
    return Error::kUnknownContainer;
  }
  const auto target = PlanNewTab(destination);
  if (!target) {
    return Error::kUnknownGroup;
  }
  if (source.container == target->container) {
    return Error::kSameContainer;
  }
  plan = ReopenPlan{source, *target};
  return Error::kOk;
}

Error PolicyRegistry::ValidateReopen(const ReopenPlan& plan,
                                     const TabSnapshot& current_source,
                                     bool warning_accepted,
                                     bool beforeunload_accepted) const {
  if (plan.source != current_source) {
    return Error::kStalePlan;
  }
  ReopenPlan expected;
  const auto error = PlanReopen(current_source, plan.destination.group, expected);
  if (error != Error::kOk) {
    return error;
  }
  if (plan != expected) {
    return Error::kStalePlan;
  }
  if (!warning_accepted) {
    return Error::kConfirmationRequired;
  }
  return beforeunload_accepted ? Error::kOk : Error::kUnloadCancelled;
}

std::unique_ptr<PolicyRegistry> RestorePolicyRegistry(const PolicySnapshot& snapshot,
                                                      ProfileToken profile,
                                                      Error& error) {
  error = Error::kOk;
  if (snapshot.version != kPolicyVersion) {
    error = Error::kUnsupportedVersion;
    return nullptr;
  }
  if (!IsValidProfile(profile)) {
    error = Error::kInvalidProfile;
    return nullptr;
  }
  if (snapshot.policies.size() > kMaximumContainers) {
    error = Error::kCapacity;
    return nullptr;
  }
  auto restored = std::make_unique<PolicyRegistry>(profile);
  for (const auto& record : snapshot.policies) {
    Policy policy{kPolicyVersion, {profile, record.id, record.generation}, record.endpoint};
    if (restored->Find(policy.key)) {
      error = Error::kInvalidSnapshot;
      return nullptr;
    }
    error = restored->Register(std::move(policy));
    if (error != Error::kOk) {
      return nullptr;
    }
  }
  return restored;
}

}  // namespace reb::proxy
