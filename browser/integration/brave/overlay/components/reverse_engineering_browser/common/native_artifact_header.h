// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_HEADER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_HEADER_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace reb {

inline constexpr std::uint32_t kNativeArtifactMagic = 0x41424552U;
inline constexpr std::uint16_t kNativeArtifactProtocolVersion = 1;
inline constexpr std::size_t kNativeArtifactHeaderSize = 128;
inline constexpr std::uint16_t kNativeArtifactFlagSensitive = 1U << 0U;

enum class NativeArtifactKind : std::uint16_t {
  kUnknown = 0,
  kJavaScript = 1,
  kWasm = 2,
  kSourceMap = 3,
  kResponseBody = 4,
};

struct NativeArtifactHeader final {
  std::uint32_t magic = kNativeArtifactMagic;
  std::uint16_t protocol_version = kNativeArtifactProtocolVersion;
  std::uint16_t header_size = static_cast<std::uint16_t>(kNativeArtifactHeaderSize);
  NativeArtifactKind kind = NativeArtifactKind::kUnknown;
  std::uint16_t flags = 0;
  std::uint32_t reserved0 = 0;
  std::uint64_t session_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t artifact_id = 0;
  std::uint64_t parent_artifact_id = 0;
  std::uint64_t creator_event_id = 0;
  std::uint64_t content_size = 0;
  std::uint32_t url_size = 0;
  std::uint32_t mime_type_size = 0;
  std::array<std::uint8_t, 32> expected_sha256{};
  std::array<std::uint8_t, 16> reserved1{};
};

static_assert(sizeof(NativeArtifactHeader) == kNativeArtifactHeaderSize);
static_assert(std::is_standard_layout_v<NativeArtifactHeader>);
static_assert(std::is_trivially_copyable_v<NativeArtifactHeader>);
static_assert(std::has_unique_object_representations_v<NativeArtifactHeader>);
#define REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(member, expected) \
  static_assert(offsetof(NativeArtifactHeader, member) == expected)
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(magic, 0);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(protocol_version, 4);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(header_size, 6);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(kind, 8);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(flags, 10);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(reserved0, 12);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(session_id, 16);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(navigation_id, 24);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(frame_id, 32);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(artifact_id, 40);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(parent_artifact_id, 48);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(creator_event_id, 56);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(content_size, 64);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(url_size, 72);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(mime_type_size, 76);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(expected_sha256, 80);
REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET(reserved1, 112);
#undef REB_ASSERT_NATIVE_ARTIFACT_HEADER_OFFSET

// Only the browser-process bridge owns this channel. Renderer probes must use
// the fixed event transport and must never stream bytes, write files, or open
// the receiver connection.

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_HEADER_H_
