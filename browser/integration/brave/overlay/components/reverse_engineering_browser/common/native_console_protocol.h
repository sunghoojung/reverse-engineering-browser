// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_PROTOCOL_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_PROTOCOL_H_

#include <array>
#include <bit>
#include <cstdint>
#include <type_traits>

namespace reb {

inline constexpr std::uint32_t kNativeConsoleMagic = 0x43424552;
inline constexpr std::uint16_t kNativeConsoleVersion = 2;
inline constexpr std::uint32_t kNativeConsoleSourceLimit = 8192;
inline constexpr std::uint32_t kNativeConsoleTextLimit = 8192;
inline constexpr std::uint32_t kNativeConsoleTargetLimit = 64;
inline constexpr std::uint32_t kNativeConsolePayloadLimit = 65536;
inline constexpr int kNativeConsoleExecutionMillis = 200;
inline constexpr int kNativeConsoleReplyMillis = 2000;
inline constexpr char kNativeConsoleSwitch[] = "reb-native-console";

enum class NativeConsoleOperation : std::uint16_t { kTargets = 1, kEvaluate = 2, kRuntime = 3 };
enum class NativeConsoleStatus : std::uint16_t {
  kOk,
  kMalformed,
  kStaleTarget,
  kForbidden,
  kException,
  kTimeout,
  kDisconnected,
};
enum class NativeConsoleType : std::uint16_t {
  kUndefined,
  kNull,
  kBoolean,
  kNumber,
  kString,
  kBigInt,
  kSymbol,
  kFunction,
  kObject,
  kPromise,
  kTargets,
  kRuntime,
};
inline constexpr std::uint16_t kNativeConsoleTruncated = 1;

// Same-machine, little-endian records. No pointers, padding-dependent payloads,
// JSON parsing, or allocation based on unchecked peer lengths.
struct NativeConsoleRequest final {
  std::uint32_t magic = kNativeConsoleMagic;
  std::uint16_t version = kNativeConsoleVersion;
  NativeConsoleOperation operation = NativeConsoleOperation::kTargets;
  std::uint64_t request_id = 0;
  std::uint64_t target_id = 0;
  std::uint32_t source_bytes = 0;
  std::uint32_t reserved = 0;
};

struct NativeConsoleResponse final {
  std::uint32_t magic = kNativeConsoleMagic;
  std::uint16_t version = kNativeConsoleVersion;
  NativeConsoleStatus status = NativeConsoleStatus::kOk;
  std::uint64_t request_id = 0;
  NativeConsoleType type = NativeConsoleType::kUndefined;
  std::uint16_t flags = 0;
  std::uint32_t item_count = 0;
  std::uint32_t payload_bytes = 0;
  std::uint32_t reserved = 0;
};

struct NativeConsoleTarget final {
  std::uint64_t id = 0;
  std::uint16_t origin_bytes = 0;
  std::uint16_t flags = 0;
  std::uint32_t reserved = 0;
  std::array<char, 256> origin{};
  std::uint16_t label_bytes = 0;
  std::uint16_t url_bytes = 0;
  std::array<char, 128> label{};
  std::array<char, 512> url{};
  std::uint32_t tail_reserved = 0;
};

[[nodiscard]] inline bool IsNativeConsoleRequest(const NativeConsoleRequest& request) noexcept {
  if (request.magic != kNativeConsoleMagic || request.version != kNativeConsoleVersion ||
      request.request_id == 0 || request.reserved != 0) {
    return false;
  }
  if (request.operation == NativeConsoleOperation::kTargets) {
    return request.target_id == 0 && request.source_bytes == 0;
  }
  return (request.operation == NativeConsoleOperation::kEvaluate ||
          request.operation == NativeConsoleOperation::kRuntime) &&
         request.target_id != 0 && request.source_bytes > 0 &&
         request.source_bytes <= (request.operation == NativeConsoleOperation::kRuntime
                                      ? kNativeConsolePayloadLimit
                                      : kNativeConsoleSourceLimit);
}

[[nodiscard]] inline bool IsNativeConsoleResponse(const NativeConsoleResponse& response,
                                                  std::uint64_t request_id) noexcept {
  if (response.magic != kNativeConsoleMagic || response.version != kNativeConsoleVersion ||
      response.request_id != request_id || response.reserved != 0 ||
      response.status > NativeConsoleStatus::kDisconnected ||
      response.type > NativeConsoleType::kRuntime ||
      (response.flags & ~kNativeConsoleTruncated) != 0) {
    return false;
  }
  if (response.type == NativeConsoleType::kTargets) {
    return response.status == NativeConsoleStatus::kOk &&
           response.item_count <= kNativeConsoleTargetLimit &&
           response.payload_bytes == response.item_count * sizeof(NativeConsoleTarget);
  }
  return response.item_count == 0 &&
         response.payload_bytes <= (response.type == NativeConsoleType::kRuntime
                                        ? kNativeConsolePayloadLimit
                                        : kNativeConsoleTextLimit);
}

[[nodiscard]] inline bool IsNativeConsoleResponseFor(const NativeConsoleResponse& response,
                                                     const NativeConsoleRequest& request) noexcept {
  if (!IsNativeConsoleResponse(response, request.request_id))
    return false;
  if (response.status != NativeConsoleStatus::kOk)
    return response.type == NativeConsoleType::kUndefined;
  if (request.operation == NativeConsoleOperation::kTargets)
    return response.type == NativeConsoleType::kTargets;
  if (request.operation == NativeConsoleOperation::kRuntime)
    return response.type == NativeConsoleType::kRuntime;
  return response.type < NativeConsoleType::kTargets;
}

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(NativeConsoleRequest) == 32);
static_assert(sizeof(NativeConsoleResponse) == 32);
static_assert(sizeof(NativeConsoleTarget) == 920);
static_assert(std::is_trivially_copyable_v<NativeConsoleRequest>);
static_assert(std::is_trivially_copyable_v<NativeConsoleResponse>);
static_assert(std::is_trivially_copyable_v<NativeConsoleTarget>);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_PROTOCOL_H_
