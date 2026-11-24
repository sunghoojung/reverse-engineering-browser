// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_REQUEST_BODY_READER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_REQUEST_BODY_READER_H_

#include <cstddef>
#include <cstdint>

#include "base/functional/callback.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_stream.h"
#include "brave/components/reverse_engineering_browser/common/native_tab_link.h"

namespace network {
class ResourceRequestBody;
}

namespace reb {

enum class NativeRequestBodyReadEnd : std::uint8_t {
  kComplete,
  // A part failed or changed, the upload was cancelled, or capture ended.
  kIncomplete,
};

struct NativeRequestBodyReadResult final {
  NativeArtifactStream stream;
  NativeRequestBodyReadEnd end = NativeRequestBodyReadEnd::kIncomplete;
  // Every byte of every part; exact when complete, a lower bound otherwise.
  std::uint64_t body_length = 0;
};

// Reads a request body's parts in order, whole, on its own background sequence
// into `stream` (protocol/native-network-v3.md). In-memory parts are copied,
// file parts are read only while unchanged since the page attached them, and
// blob parts through a clone of their getter. A stream part is consumed once
// by the network, so its getter is replaced by one that forwards every byte
// unchanged through a tee. When the in-flight pool is full the read waits for
// room, and a stream part's upload waits with it.
class NativeRequestBodyReader final {
 public:
  using Done = base::OnceCallback<void(NativeRequestBodyReadResult)>;

  // Whether the body has a part, every part is one this reader can identify,
  // and a stream part is the only part.
  [[nodiscard]] static bool CanRead(const network::ResourceRequestBody& body) noexcept;
  // UI sequence. Whether every file part may be read for `owner`; a renderer
  // must not get a file it could not upload itself read into the evidence store.
  [[nodiscard]] static bool MayReadFiles(const network::ResourceRequestBody& body,
                                         const NativeBrowserRequestOwner& owner) noexcept;
  // `done` runs once on the calling sequence. False, with nothing started,
  // when no background sequence is available.
  [[nodiscard]] static bool Start(network::ResourceRequestBody& body,
                                  NativeArtifactStream stream,
                                  Done done);
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_REQUEST_BODY_READER_H_
