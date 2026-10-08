// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_proxy_partition_adapter.h"

#include <charconv>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/storage_partition_config.h"
#include "net/base/proxy_server.h"
#include "net/http/http_auth_preferences.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/mojom/network_context.mojom.h"

namespace reb::proxy {
namespace {

constexpr char kAdapterUserDataKey[] = "reb.native-proxy-partition-adapter";
// Exact pinned Brave Containers domain, not a second partition namespace.
constexpr std::string_view kContainerDomain = "containers";
constexpr std::string_view kProtectedNamePrefix = "reb-proxy-";

static_assert(!kRuntimeIntegrated,
              "Bind the guarded native lifecycle only after browser validation");

constexpr auto kProxyTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("reb_native_proxy_container",
                                        R"(semantics {
      sender: "Native research proxy container"
      description: "Prepares a single fixed proxy for a native storage container."
      trigger: "Not currently enabled. A future explicit native group action is required."
      data: "The destination and permitted browser request data use the selected proxy."
      destination: OTHER
      destination_other: "A user-selected proxy endpoint"
    }
    policy {
      cookies_allowed: YES
      cookies_store: "The container StoragePartition"
      setting: "Unavailable until native lifecycle and transport tests are complete."
      policy_exception_justification: "Disabled experimental integration without a user-facing setting."
    })");

ProfileToken GetProfileToken(content::BrowserContext& context) {
  const auto& token = context.UniqueToken();
  return {token.GetHighForSerialization(), token.GetLowForSerialization()};
}

bool IsProtectedPartition(const content::StoragePartitionConfig& config) {
  return config.partition_domain() == kContainerDomain &&
         std::string_view(config.partition_name()).starts_with(kProtectedNamePrefix);
}

std::optional<Scheme> ParseScheme(std::string_view scheme) {
  if (scheme == "http") {
    return Scheme::kHttp;
  }
  if (scheme == "https") {
    return Scheme::kHttps;
  }
  if (scheme == "socks5") {
    return Scheme::kSocks5;
  }
  return std::nullopt;
}

Error DecodeSnapshot(const base::DictValue& value, PolicySnapshot& snapshot) {
  const auto version = value.FindInt("version");
  if (!version || *version != static_cast<int>(kPolicyVersion)) {
    return Error::kUnsupportedVersion;
  }
  const auto* records = value.FindList("policies");
  if (value.size() != 2 || !records) {
    return Error::kInvalidSnapshot;
  }
  if (records->size() > kMaximumContainers) {
    return Error::kCapacity;
  }
  snapshot.version = kPolicyVersion;
  for (const auto& entry : *records) {
    const auto* record = entry.GetIfDict();
    if (!record || record->size() != 5) {
      return Error::kInvalidSnapshot;
    }
    const auto* id = record->FindString("id");
    const auto* generation_text = record->FindString("generation");
    const auto* scheme_text = record->FindString("scheme");
    const auto* host = record->FindString("host");
    const auto port = record->FindInt("port");
    if (!id || id->empty() || id->size() > 64 || !generation_text || generation_text->empty() ||
        generation_text->size() > 20 || generation_text->front() == '0' || !scheme_text || !host ||
        host->empty() || host->size() > 253 || !port || *port < 1 || *port > 65535) {
      return Error::kInvalidSnapshot;
    }
    std::uint64_t generation = 0;
    const auto* generation_end = std::to_address(generation_text->cend());
    const auto parsed = std::from_chars(generation_text->data(), generation_end, generation);
    const auto scheme = ParseScheme(*scheme_text);
    if (parsed.ec != std::errc() || parsed.ptr != generation_end || generation == 0 || !scheme) {
      return Error::kInvalidSnapshot;
    }
    snapshot.policies.push_back(
        StoredPolicy{*id, generation, {*scheme, *host, static_cast<std::uint16_t>(*port)}});
  }
  return Error::kOk;
}

std::optional<net::ProxyConfigWithAnnotation> BuildProxyConfig(const Policy& policy) {
  if (ValidatePolicy(policy) != Error::kOk) {
    return std::nullopt;
  }
  net::ProxyServer::Scheme scheme = net::ProxyServer::SCHEME_INVALID;
  switch (policy.endpoint.scheme) {
    case Scheme::kHttp:
      scheme = net::ProxyServer::SCHEME_HTTP;
      break;
    case Scheme::kHttps:
      scheme = net::ProxyServer::SCHEME_HTTPS;
      break;
    case Scheme::kSocks5:
      scheme = net::ProxyServer::SCHEME_SOCKS5;
      break;
    default:
      return std::nullopt;
  }
  const auto server = net::ProxyServer::FromSchemeHostAndPort(
      scheme, policy.endpoint.host, std::optional<std::uint16_t>(policy.endpoint.port));
  if (!server.is_valid()) {
    return std::nullopt;
  }
  net::ProxyConfig config;
  config.proxy_rules().type = net::ProxyConfig::ProxyRules::Type::PROXY_LIST;
  config.proxy_rules().single_proxies.SetSingleProxyServer(server);
  config.proxy_rules().bypass_rules.AddRulesToSubtractImplicit();
  return net::ProxyConfigWithAnnotation(config, kProxyTrafficAnnotation);
}

}  // namespace

NativePartitionAdmission GetNativePartitionAdmission(
    const content::StoragePartitionConfig& config) {
  return IsProtectedPartition(config) ? NativePartitionAdmission::kBlocked
                                      : NativePartitionAdmission::kNotOwned;
}

NativeProxyPartitionAdapter& NativeProxyPartitionAdapter::GetOrCreate(
    content::BrowserContext& context) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  auto* existing =
      static_cast<NativeProxyPartitionAdapter*>(context.GetUserData(kAdapterUserDataKey));
  if (existing) {
    return *existing;
  }
  auto adapter =
      std::unique_ptr<NativeProxyPartitionAdapter>(new NativeProxyPartitionAdapter(context));
  auto& reference = *adapter;
  context.SetUserData(kAdapterUserDataKey, std::move(adapter));
  return reference;
}

NativeProxyPartitionAdapter::NativeProxyPartitionAdapter(content::BrowserContext& context)
    : profile_(GetProfileToken(context)), off_the_record_(context.IsOffTheRecord()) {}

NativeProxyPartitionAdapter::~NativeProxyPartitionAdapter() = default;

Error NativeProxyPartitionAdapter::Restore(const base::DictValue& value) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (restore_attempted_) {
    return Error::kImmutableConflict;
  }
  restore_attempted_ = true;
  PolicySnapshot snapshot;
  auto error = DecodeSnapshot(value, snapshot);
  if (error != Error::kOk) {
    return error;
  }
  registry_ = RestorePolicyRegistry(snapshot, profile_, error);
  return error;
}

NativePreparation NativeProxyPartitionAdapter::Prepare(
    const content::StoragePartitionConfig& config,
    network::mojom::NetworkContextParams& params) const {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (!IsProtectedPartition(config)) {
    return NativePreparation::kNotOwned;
  }
  if (config.in_memory() != off_the_record_) {
    return NativePreparation::kWrongStorageMode;
  }
  if (config.fallback_to_partition_domain_for_blob_urls() !=
      content::StoragePartitionConfig::FallbackMode::kNone) {
    return NativePreparation::kBlobFallbackForbidden;
  }
  const auto* policy =
      registry_ ? registry_->FindPartition(profile_, config.partition_name()) : nullptr;
  if (!policy) {
    return NativePreparation::kPolicyUnavailable;
  }
  auto proxy_config = BuildProxyConfig(*policy);
  if (!proxy_config) {
    return NativePreparation::kInvalidNativeEndpoint;
  }

  // Mutate only after complete validation. Never clear both proxy fields and
  // leave Chromium's implicit DIRECT default. SSL/cookie/cache settings survive.
  params.initial_proxy_config = std::move(*proxy_config);
  params.proxy_config_client_receiver.reset();
  params.proxy_config_poller_client.reset();
  params.proxy_error_client.reset();
  params.initial_custom_proxy_config.reset();
  params.custom_proxy_config_client_receiver.reset();
  params.custom_proxy_connection_observer_remote.reset();
  if (!params.http_auth_static_network_context_params) {
    params.http_auth_static_network_context_params =
        network::mojom::HttpAuthStaticNetworkContextParams::New();
  }
  params.http_auth_static_network_context_params->allow_default_credentials =
      net::HttpAuthPreferences::DISALLOW_DEFAULT_CREDENTIALS;
  return NativePreparation::kPreparedRuntimeBlocked;
}

}  // namespace reb::proxy
