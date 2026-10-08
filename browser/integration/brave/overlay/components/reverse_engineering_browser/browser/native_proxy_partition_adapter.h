// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROXY_PARTITION_ADAPTER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROXY_PARTITION_ADAPTER_H_

#include <memory>

#include "base/supports_user_data.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/browser/native_proxy_policy.h"
#include "services/network/public/mojom/network_context.mojom-forward.h"

namespace content {
class BrowserContext;
class StoragePartitionConfig;
}  // namespace content

namespace reb::proxy {

// There is intentionally no "allow protected networking" enumerator. This
// interface is not bound to StoragePartitionImpl until safe denial lifecycle,
// transport guards and real browser tests exist. kNotOwned delegates to the
// ordinary embedder; it is not an assertion that other contexts are safe.
enum class NativePartitionAdmission { kNotOwned, kBlocked };
NativePartitionAdmission GetNativePartitionAdmission(const content::StoragePartitionConfig& config);

enum class NativePreparation {
  kNotOwned,
  kPolicyUnavailable,
  kWrongStorageMode,
  kBlobFallbackForbidden,
  kInvalidNativeEndpoint,
  kPreparedRuntimeBlocked,
};

// BrowserContext-owned, UI-sequence, immutable once restored. No renderer IPC,
// prefs registration, file I/O, loader, SiteInstance, or NetworkContext creation.
// Each process-lifetime owner token is derived from the actual BrowserContext;
// it is never accepted from persisted data. Records and workers may outlive UI.
class NativeProxyPartitionAdapter final : public base::SupportsUserData::Data {
 public:
  static NativeProxyPartitionAdapter& GetOrCreate(content::BrowserContext& context);
  ~NativeProxyPartitionAdapter() override;

  NativeProxyPartitionAdapter(const NativeProxyPartitionAdapter&) = delete;
  NativeProxyPartitionAdapter& operator=(const NativeProxyPartitionAdapter&) = delete;

  // One-shot restore from a per-profile store supplied by a future startup
  // adapter. Failure remains unavailable for this context; it never substitutes
  // defaults or partially admits valid records from a corrupt snapshot.
  Error Restore(const base::DictValue& snapshot);

  // Full domain/name/storage mode, never a hash-derived relative disk path.
  // Only successful preparation changes params. The return value still denies
  // runtime creation; this is a typed adapter, not a network admission hook.
  NativePreparation Prepare(const content::StoragePartitionConfig& config,
                            network::mojom::NetworkContextParams& params) const;

 private:
  explicit NativeProxyPartitionAdapter(content::BrowserContext& context);

  const ProfileToken profile_;
  const bool off_the_record_;
  bool restore_attempted_ = false;
  std::unique_ptr<PolicyRegistry> registry_;
};

}  // namespace reb::proxy

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROXY_PARTITION_ADAPTER_H_
