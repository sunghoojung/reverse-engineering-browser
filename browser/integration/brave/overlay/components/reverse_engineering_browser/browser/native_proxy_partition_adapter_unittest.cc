// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_proxy_partition_adapter.h"

#include <string>
#include <utility>

#include "content/public/browser/storage_partition_config.h"
#include "content/public/test/browser_task_environment.h"
#include "content/public/test/test_browser_context.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/base/proxy_server.h"
#include "net/http/http_auth_preferences.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "services/network/public/mojom/cookie_manager.mojom.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/ssl_config.mojom.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace reb::proxy {
namespace {

base::DictValue Snapshot(std::string scheme = "https") {
  base::DictValue record;
  record.Set("id", "test");
  record.Set("generation", "1");
  record.Set("scheme", std::move(scheme));
  record.Set("host", "proxy.example.test");
  record.Set("port", 443);
  base::ListValue records;
  records.Append(std::move(record));
  base::DictValue snapshot;
  snapshot.Set("version", 1);
  snapshot.Set("policies", std::move(records));
  return snapshot;
}

// A preexisting profile config, with all update/observer pipes present. Merely
// checking null default params would miss accidental mutation on a denial.
network::mojom::NetworkContextParamsPtr ExistingParams() {
  auto params = network::mojom::NetworkContextParams::New();
  params->user_agent = "preserved-test-agent";
  params->accept_language = "test-language";
  params->enable_brotli = false;
  params->http_cache_enabled = false;
  params->initial_ssl_config = network::mojom::SSLConfig::New();
  params->initial_ssl_config->rev_checking_enabled = true;
  params->cookie_manager_params = network::mojom::CookieManagerParams::New();
  params->cookie_manager_params->block_third_party_cookies = true;
  params->initial_proxy_config = net::ProxyConfigWithAnnotation(
      net::ProxyConfig::CreateAutoDetect(), TRAFFIC_ANNOTATION_FOR_TESTS);
  mojo::PendingRemote<network::mojom::ProxyConfigClient> client;
  params->proxy_config_client_receiver = client.InitWithNewPipeAndPassReceiver();
  auto poller_receiver = params->proxy_config_poller_client.InitWithNewPipeAndPassReceiver();
  auto error_receiver = params->proxy_error_client.InitWithNewPipeAndPassReceiver();
  params->initial_custom_proxy_config = network::mojom::CustomProxyConfig::New();
  mojo::PendingRemote<network::mojom::CustomProxyConfigClient> custom_client;
  params->custom_proxy_config_client_receiver = custom_client.InitWithNewPipeAndPassReceiver();
  auto observer_receiver =
      params->custom_proxy_connection_observer_remote.InitWithNewPipeAndPassReceiver();
  params->http_auth_static_network_context_params =
      network::mojom::HttpAuthStaticNetworkContextParams::New();
  return params;
}

void ExpectUnchanged(const network::mojom::NetworkContextParams& params) {
  ASSERT_TRUE(params.initial_proxy_config);
  EXPECT_TRUE(params.initial_proxy_config->value().auto_detect());
  EXPECT_TRUE(params.proxy_config_client_receiver.is_valid());
  EXPECT_TRUE(params.proxy_config_poller_client.is_valid());
  EXPECT_TRUE(params.proxy_error_client.is_valid());
  EXPECT_TRUE(params.initial_custom_proxy_config);
  EXPECT_TRUE(params.custom_proxy_config_client_receiver.is_valid());
  EXPECT_TRUE(params.custom_proxy_connection_observer_remote.is_valid());
  ASSERT_TRUE(params.http_auth_static_network_context_params);
  EXPECT_EQ(params.http_auth_static_network_context_params->allow_default_credentials,
            net::HttpAuthPreferences::ALLOW_DEFAULT_CREDENTIALS);
  EXPECT_EQ(params.user_agent, "preserved-test-agent");
  EXPECT_EQ(params.accept_language, "test-language");
  EXPECT_FALSE(params.enable_brotli);
  EXPECT_FALSE(params.http_cache_enabled);
  ASSERT_TRUE(params.initial_ssl_config);
  EXPECT_TRUE(params.initial_ssl_config->rev_checking_enabled);
  ASSERT_TRUE(params.cookie_manager_params);
  EXPECT_TRUE(params.cookie_manager_params->block_third_party_cookies);
}

class NativeProxyPartitionAdapterTest : public testing::Test {
 protected:
  content::StoragePartitionConfig Config(std::string name = "reb-proxy-test-g1",
                                         std::string domain = "containers",
                                         bool in_memory = false) {
    return content::StoragePartitionConfig::Create(&context_, domain, name, in_memory);
  }

  NativeProxyPartitionAdapter& adapter() {
    return NativeProxyPartitionAdapter::GetOrCreate(context_);
  }

  // Destruction of the BrowserContext and its adapter occurs before task teardown.
  content::BrowserTaskEnvironment environment_;
  content::TestBrowserContext context_;
};

TEST_F(NativeProxyPartitionAdapterTest, AdmissionNeverEnablesProtectedNetworking) {
  static_assert(!kRuntimeIntegrated);
  EXPECT_EQ(GetNativePartitionAdmission(Config()), NativePartitionAdmission::kBlocked);
  EXPECT_EQ(GetNativePartitionAdmission(Config("reb-proxy-missing-g1")),
            NativePartitionAdmission::kBlocked);
  EXPECT_EQ(GetNativePartitionAdmission(Config("reb-proxy-")), NativePartitionAdmission::kBlocked);
  EXPECT_EQ(GetNativePartitionAdmission(Config("ordinary")), NativePartitionAdmission::kNotOwned);
  EXPECT_EQ(GetNativePartitionAdmission(Config("reb-proxy-test-g1", "other")),
            NativePartitionAdmission::kNotOwned);
  EXPECT_EQ(GetNativePartitionAdmission(content::StoragePartitionConfig::CreateDefault(&context_)),
            NativePartitionAdmission::kNotOwned);
}

TEST_F(NativeProxyPartitionAdapterTest, RejectionsPreserveExistingParams) {
  auto params = ExistingParams();
  EXPECT_EQ(adapter().Prepare(Config(), *params), NativePreparation::kPolicyUnavailable);
  ExpectUnchanged(*params);
  ASSERT_EQ(adapter().Restore(Snapshot()), Error::kOk);
  EXPECT_EQ(adapter().Prepare(Config("ordinary"), *params), NativePreparation::kNotOwned);
  ExpectUnchanged(*params);
  EXPECT_EQ(adapter().Prepare(Config("reb-proxy-test-g1", "other"), *params),
            NativePreparation::kNotOwned);
  ExpectUnchanged(*params);
  EXPECT_EQ(adapter().Prepare(Config("reb-proxy-test-g01"), *params),
            NativePreparation::kPolicyUnavailable);
  ExpectUnchanged(*params);
  EXPECT_EQ(adapter().Prepare(Config("reb-proxy-test-g1", "containers", true), *params),
            NativePreparation::kWrongStorageMode);
  ExpectUnchanged(*params);
  auto config = Config();
  config.set_fallback_to_partition_domain_for_blob_urls(
      content::StoragePartitionConfig::FallbackMode::kFallbackPartitionOnDisk);
  EXPECT_EQ(adapter().Prepare(config, *params), NativePreparation::kBlobFallbackForbidden);
  ExpectUnchanged(*params);
}

TEST_F(NativeProxyPartitionAdapterTest, SingletonAndRestoreAreContextOwnedAndOneShot) {
  EXPECT_EQ(&adapter(), &NativeProxyPartitionAdapter::GetOrCreate(context_));
  ASSERT_EQ(adapter().Restore(Snapshot()), Error::kOk);
  EXPECT_EQ(adapter().Restore(Snapshot("http")), Error::kImmutableConflict);
  content::TestBrowserContext other;
  auto& other_adapter = NativeProxyPartitionAdapter::GetOrCreate(other);
  EXPECT_NE(&adapter(), &other_adapter);
  auto params = ExistingParams();
  EXPECT_EQ(other_adapter.Prepare(Config(), *params), NativePreparation::kPolicyUnavailable);
  ExpectUnchanged(*params);
}

TEST_F(NativeProxyPartitionAdapterTest, CorruptRestoreCannotAdmitPartialPoliciesOrRetry) {
  auto snapshot = Snapshot();
  snapshot.FindList("policies")->Append(snapshot.FindList("policies")->front().Clone());
  EXPECT_EQ(adapter().Restore(snapshot), Error::kInvalidSnapshot);
  EXPECT_EQ(adapter().Restore(Snapshot()), Error::kImmutableConflict);
  auto params = ExistingParams();
  EXPECT_EQ(adapter().Prepare(Config(), *params), NativePreparation::kPolicyUnavailable);
  ExpectUnchanged(*params);
}

TEST_F(NativeProxyPartitionAdapterTest, StrictSnapshotSchemaAndGenerationStrings) {
  for (const std::string generation :
       {"", "0", "01", "-1", "+1", "1 ", "1.0", "18446744073709551616"}) {
    SCOPED_TRACE(generation);
    content::TestBrowserContext context;
    auto snapshot = Snapshot();
    snapshot.FindList("policies")->front().GetDict().Set("generation", generation);
    EXPECT_EQ(NativeProxyPartitionAdapter::GetOrCreate(context).Restore(snapshot),
              Error::kInvalidSnapshot);
  }
  for (int corruption = 0; corruption < 7; ++corruption) {
    SCOPED_TRACE(corruption);
    content::TestBrowserContext context;
    auto snapshot = Snapshot();
    auto& record = snapshot.FindList("policies")->front().GetDict();
    switch (corruption) {
      case 0:
        snapshot.Set("profile_token", "untrusted");
        break;
      case 1:
        record.Set("credential", "unsupported");
        break;
      case 2:
        record.Set("generation", 1);
        break;
      case 3:
        record.Set("scheme", "direct");
        break;
      case 4:
        record.Set("port", 0);
        break;
      case 5:
        record.Set("port", 65536);
        break;
      case 6:
        snapshot.Set("policies", "not-a-list");
        break;
    }
    EXPECT_EQ(NativeProxyPartitionAdapter::GetOrCreate(context).Restore(snapshot),
              Error::kInvalidSnapshot);
  }
}

TEST_F(NativeProxyPartitionAdapterTest, UnsupportedVersionAndOversizedSnapshotsAreRejected) {
  auto snapshot = Snapshot();
  snapshot.Set("version", 2);
  EXPECT_EQ(adapter().Restore(snapshot), Error::kUnsupportedVersion);
  content::TestBrowserContext other;
  snapshot = Snapshot();
  auto* records = snapshot.FindList("policies");
  while (records->size() <= kMaximumContainers) {
    records->Append(records->front().Clone());
  }
  EXPECT_EQ(NativeProxyPartitionAdapter::GetOrCreate(other).Restore(snapshot), Error::kCapacity);
}

TEST_F(NativeProxyPartitionAdapterTest, EmptyAndMaximumGenerationSnapshotsRemainPreparationOnly) {
  auto empty = Snapshot();
  empty.FindList("policies")->clear();
  ASSERT_EQ(adapter().Restore(empty), Error::kOk);
  auto params = ExistingParams();
  EXPECT_EQ(adapter().Prepare(Config(), *params), NativePreparation::kPolicyUnavailable);
  ExpectUnchanged(*params);
  content::TestBrowserContext other;
  auto snapshot = Snapshot();
  snapshot.FindList("policies")->front().GetDict().Set("generation", "18446744073709551615");
  auto& restored = NativeProxyPartitionAdapter::GetOrCreate(other);
  ASSERT_EQ(restored.Restore(snapshot), Error::kOk);
  auto config = Config("reb-proxy-test-g18446744073709551615");
  EXPECT_EQ(restored.Prepare(config, *params), NativePreparation::kPreparedRuntimeBlocked);
  EXPECT_EQ(GetNativePartitionAdmission(config), NativePartitionAdmission::kBlocked);
}

TEST_F(NativeProxyPartitionAdapterTest, OneInvalidEndpointPreventsPartialRestore) {
  auto snapshot = Snapshot();
  auto invalid = snapshot.FindList("policies")->front().Clone();
  invalid.GetDict().Set("id", "other");
  invalid.GetDict().Set("host", "userinfo@proxy.example.test");
  snapshot.FindList("policies")->Append(std::move(invalid));
  EXPECT_EQ(adapter().Restore(snapshot), Error::kInvalidEndpoint);
  auto params = ExistingParams();
  EXPECT_EQ(adapter().Prepare(Config(), *params), NativePreparation::kPolicyUnavailable);
  ExpectUnchanged(*params);
}

TEST_F(NativeProxyPartitionAdapterTest, FixedNativeRulesReplaceProfileConfigAndStayBlocked) {
  for (const std::string scheme : {"http", "https", "socks5"}) {
    SCOPED_TRACE(scheme);
    content::TestBrowserContext context;
    auto& prepared = NativeProxyPartitionAdapter::GetOrCreate(context);
    ASSERT_EQ(prepared.Restore(Snapshot(scheme)), Error::kOk);
    auto params = ExistingParams();
    EXPECT_EQ(prepared.Prepare(Config(), *params), NativePreparation::kPreparedRuntimeBlocked);
    ASSERT_TRUE(params->initial_proxy_config);
    const auto& config = params->initial_proxy_config->value();
    EXPECT_FALSE(config.HasAutomaticSettings());
    EXPECT_TRUE(config.proxy_override_rules().empty());
    EXPECT_EQ(config.proxy_rules().type, net::ProxyConfig::ProxyRules::Type::PROXY_LIST);
    EXPECT_EQ(config.proxy_rules().single_proxies.size(), 1U);
    // Rule evaluation, including implicit bypass subtraction, is not socket or
    // destination-safety coverage. Local URLs must still be blocked at runtime.
    for (const char* url :
         {"http://example.test", "https://example.test", "ws://example.test", "wss://example.test",
          "http://localhost", "http://127.0.0.1", "http://169.254.1.1"}) {
      SCOPED_TRACE(url);
      net::ProxyInfo result;
      config.proxy_rules().Apply(GURL(url), &result);
      EXPECT_FALSE(result.is_direct());
      EXPECT_EQ(result.proxy_list().size(), 1U);
      const std::string prefix = scheme == "http"    ? "PROXY"
                                 : scheme == "https" ? "HTTPS"
                                                     : "SOCKS5";
      EXPECT_EQ(result.ToPacString(), prefix + " proxy.example.test:443");
    }
    EXPECT_FALSE(params->proxy_config_client_receiver.is_valid());
    EXPECT_FALSE(params->proxy_config_poller_client.is_valid());
    EXPECT_FALSE(params->proxy_error_client.is_valid());
    EXPECT_FALSE(params->initial_custom_proxy_config);
    EXPECT_FALSE(params->custom_proxy_config_client_receiver.is_valid());
    EXPECT_FALSE(params->custom_proxy_connection_observer_remote.is_valid());
    ASSERT_TRUE(params->http_auth_static_network_context_params);
    EXPECT_EQ(params->http_auth_static_network_context_params->allow_default_credentials,
              net::HttpAuthPreferences::DISALLOW_DEFAULT_CREDENTIALS);
    EXPECT_EQ(params->user_agent, "preserved-test-agent");
    EXPECT_EQ(params->accept_language, "test-language");
    EXPECT_FALSE(params->enable_brotli);
    EXPECT_FALSE(params->http_cache_enabled);
    ASSERT_TRUE(params->initial_ssl_config);
    EXPECT_TRUE(params->initial_ssl_config->rev_checking_enabled);
    ASSERT_TRUE(params->cookie_manager_params);
    EXPECT_TRUE(params->cookie_manager_params->block_third_party_cookies);
    EXPECT_EQ(GetNativePartitionAdmission(Config()), NativePartitionAdmission::kBlocked);
    // A fresh params object models repeated preparation for service recreation.
    auto recreated = network::mojom::NetworkContextParams::New();
    EXPECT_EQ(prepared.Prepare(Config(), *recreated), NativePreparation::kPreparedRuntimeBlocked);
    ASSERT_TRUE(recreated->initial_proxy_config);
    EXPECT_TRUE(config.Equals(recreated->initial_proxy_config->value()));
    ASSERT_TRUE(recreated->http_auth_static_network_context_params);
    EXPECT_EQ(recreated->http_auth_static_network_context_params->allow_default_credentials,
              net::HttpAuthPreferences::DISALLOW_DEFAULT_CREDENTIALS);
  }
}

TEST_F(NativeProxyPartitionAdapterTest, IncognitoOnlyAcceptsInMemoryPartitions) {
  content::TestBrowserContext incognito;
  incognito.set_is_off_the_record(true);
  auto& incognito_adapter = NativeProxyPartitionAdapter::GetOrCreate(incognito);
  ASSERT_EQ(incognito_adapter.Restore(Snapshot()), Error::kOk);
  auto params = ExistingParams();
  EXPECT_EQ(incognito_adapter.Prepare(Config(), *params), NativePreparation::kWrongStorageMode);
  ExpectUnchanged(*params);
  auto config =
      content::StoragePartitionConfig::Create(&incognito, "containers", "reb-proxy-test-g1", false);
  ASSERT_TRUE(config.in_memory());
  EXPECT_EQ(incognito_adapter.Prepare(config, *params), NativePreparation::kPreparedRuntimeBlocked);
}

TEST_F(NativeProxyPartitionAdapterTest, BothBlobFallbackModesRemainBlocked) {
  ASSERT_EQ(adapter().Restore(Snapshot()), Error::kOk);
  for (const auto fallback :
       {content::StoragePartitionConfig::FallbackMode::kFallbackPartitionOnDisk,
        content::StoragePartitionConfig::FallbackMode::kFallbackPartitionInMemory}) {
    auto config = Config();
    config.set_fallback_to_partition_domain_for_blob_urls(fallback);
    auto params = ExistingParams();
    EXPECT_EQ(adapter().Prepare(config, *params), NativePreparation::kBlobFallbackForbidden);
    EXPECT_EQ(GetNativePartitionAdmission(config), NativePartitionAdmission::kBlocked);
    ExpectUnchanged(*params);
  }
}

}  // namespace
}  // namespace reb::proxy
