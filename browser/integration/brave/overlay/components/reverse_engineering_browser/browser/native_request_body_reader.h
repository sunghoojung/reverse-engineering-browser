// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_REQUEST_BODY_READER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_REQUEST_BODY_READER_H_

#include <cstddef>
#include <cstdint>

#include "base/functional/callback.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_stream.h"

namespace network {
class ResourceRequestBody;
}

namespace reb {

enum class NativeRequestBodyReadEnd : std::uint8_t {
  kComplete,
  // A part failed or changed, the upload was cancelled, or capture ended.
  kIncomplete,
  // The kept bytes reached the allowance the session budget gave the read.
  kBudget,
  // The in-flight pool stayed full.
  kRefused,
};

struct NativeRequestBodyReadResult final {
  NativeArtifactStream stream;
  NativeRequestBodyReadEnd end = NativeRequestBodyReadEnd::kIncomplete;
  // Every byte of every part; exact when complete, a lower bound otherwise.
  std::uint64_t body_length = 0;
};

// Reads a request body's parts in order on its own background sequence into
// `stream` (protocol/native-network-v3.md). In-memory parts are copied, file
// parts are read only while unchanged since the page attached them, and blob
// parts through a clone of their getter; past 16 MiB a part is sized, not
// read. A stream part is consumed once by the network, so its getter is
// replaced by one that forwards every byte unchanged through a tee.
class NativeRequestBodyReader final {
 public:
  using Done = base::OnceCallback<void(NativeRequestBodyReadResult)>;

  // Whether the body has a file, blob or stream part and no part this reader
  // cannot identify.
  [[nodiscard]] static bool CanRead(const network::ResourceRequestBody& body) noexcept;
  // `done` runs once on the calling sequence. False, with nothing started,
  // when no background sequence is available.
  [[nodiscard]] static bool Start(network::ResourceRequestBody& body,
                                  NativeArtifactStream stream,
                                  std::size_t allowance,
                                  Done done);
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_REQUEST_BODY_READER_H_
