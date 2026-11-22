// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_PROTOCOL_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_PROTOCOL_H_

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>

namespace reb {

inline constexpr std::uint32_t kNativeConsoleMagic = 0x43424552;
// Version 3 added operation 5 (Stop) and status 7 (Stopped). Version 4 drops
// every command, reply and listing bound and makes target records variable
// length, so a source, a value, a message or a listing of any size crosses
// whole.
inline constexpr std::uint16_t kNativeConsoleVersion = 4;
// The one bound left is the record format's own: a header names its payload
// with 32 bits. Every hop reads a payload as its bytes arrive and Mojo carries
// it as a BigString, which moves anything large to shared memory, so neither
// a socket buffer nor Mojo's message limit bounds a record below this. V8
// cannot build a string whose UTF-8 form comes near it.
inline constexpr std::uint64_t kNativeConsoleRecordLimit = 0xffffffffu;
// A reply that drains a queue (a message poll, a document-start read) carries
// at least one record and stops adding them past this many bytes, then says
// that more remain, so a large backlog arrives as several replies instead of
// one that every hop holds whole. It is a page size: nothing is refused or
// dropped because of it.
inline constexpr std::size_t kNativeConsolePageBytes = 8 * 1024 * 1024;
// A command runs until it returns or the owner sends Stop; there is no
// execution budget. These bound only the hand-offs around it: the renderer
// must start a command this soon after the browser posts it, a header's
// payload must follow it this soon, and a Stop must end the command this
// soon, or the exchange is ambiguous and the session retires.
inline constexpr int kNativeConsoleDispatchMillis = 500;
inline constexpr int kNativeConsoleTransferMillis = 2000;
inline constexpr int kNativeConsoleStopMillis = 5000;
inline constexpr char kNativeConsoleSwitch[] = "reb-native-console";
// Binds this protocol to the browser a live capture is already using.
// Remote debugging may stay enabled. Losing the socket must not exit that browser.
inline constexpr char kNativeConsoleLiveBindingSwitch[] = "reb-native-console-live-binding";
// Permits the separately armed document-start script experiment in this browser
// session. The switch alone arms nothing: it only lets the owner register
// scripts later, and its absence makes an arm request fail closed.
inline constexpr char kNativeConsoleDocumentStartSwitch[] = "reb-native-console-document-start";

enum class NativeConsoleOperation : std::uint16_t {
  kTargets = 1,
  kEvaluate = 2,
  kRuntime = 3,
  kDocumentStart = 4,
  // Sent only while a request is in flight, naming that request. It has no
  // reply of its own: the running request answers kStopped, or its own result
  // when it finished first.
  kStop = 5,
};
enum class NativeConsoleStatus : std::uint16_t {
  kOk,
  kMalformed,
  kStaleTarget,
  kForbidden,
  kException,
  kTimeout,
  kDisconnected,
  kStopped,
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
  kDocumentStart,
};
// On a target listing: a listed document did not describe itself in time, so
// the listing is partial. Nothing is ever truncated to fit a record.
inline constexpr std::uint16_t kNativeConsoleTruncated = 1;
// Set only on a target listing, and only when this browser session was launched
// with the document-start switch. An older browser leaves it clear, so the owner
// refuses to send operation 4 instead of breaking a working v2 session.
inline constexpr std::uint16_t kNativeConsoleDocumentStartSupported = 2;
inline constexpr std::uint16_t kNativeConsoleResponseFlags =
    kNativeConsoleTruncated | kNativeConsoleDocumentStartSupported;

// Same-machine, little-endian records. No pointers or padding-dependent
// payloads, and a payload is stored only as its bytes arrive, never allocated
// up front from a length the peer declared.
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

// A target listing is `item_count` of these, each followed directly by its
// origin, label and URL bytes, with no padding. The metadata is whatever the
// browser holds, however long: nothing is cut to fit a fixed field.
struct NativeConsoleTarget final {
  std::uint64_t id = 0;
  std::uint32_t origin_bytes = 0;
  std::uint32_t label_bytes = 0;
  std::uint32_t url_bytes = 0;
  std::uint16_t flags = 0;
  std::uint16_t reserved = 0;
};
inline constexpr std::uint16_t kNativeConsoleTargetTopFrame = 2;

// Reads the target that starts at `offset` and moves `offset` past its bytes,
// or returns false when the record or any of its strings would run past
// `payload`. The views point into `payload`.
[[nodiscard]] inline bool ReadNativeConsoleTarget(std::span<const std::byte> payload,
                                                  std::size_t& offset,
                                                  NativeConsoleTarget& target,
                                                  std::string_view& origin,
                                                  std::string_view& label,
                                                  std::string_view& url) noexcept {
  if (offset > payload.size() || payload.size() - offset < sizeof(target))
    return false;
  std::memcpy(&target, payload.data() + offset, sizeof(target));
  const std::uint64_t bytes = std::uint64_t{target.origin_bytes} + target.label_bytes +
                              target.url_bytes;
  if (payload.size() - offset - sizeof(target) < bytes)
    return false;
  const auto* text = reinterpret_cast<const char*>(payload.data() + offset + sizeof(target));
  origin = std::string_view(text, target.origin_bytes);
  label = std::string_view(text + target.origin_bytes, target.label_bytes);
  url = std::string_view(text + target.origin_bytes + target.label_bytes, target.url_bytes);
  offset += sizeof(target) + static_cast<std::size_t>(bytes);
  return true;
}

[[nodiscard]] inline bool IsNativeConsoleRequest(const NativeConsoleRequest& request) noexcept {
  if (request.magic != kNativeConsoleMagic || request.version != kNativeConsoleVersion ||
      request.request_id == 0 || request.reserved != 0) {
    return false;
  }
  if (request.operation == NativeConsoleOperation::kTargets ||
      request.operation == NativeConsoleOperation::kStop) {
    return request.target_id == 0 && request.source_bytes == 0;
  }
  // Document-start scripts belong to the session, not to one selected document,
  // so operation 4 carries no target and can never be pinned to a stale one.
  if (request.operation == NativeConsoleOperation::kDocumentStart) {
    return request.target_id == 0 && request.source_bytes > 0;
  }
  return (request.operation == NativeConsoleOperation::kEvaluate ||
          request.operation == NativeConsoleOperation::kRuntime) &&
         request.target_id != 0 && request.source_bytes > 0;
}

[[nodiscard]] inline bool IsNativeConsoleResponse(const NativeConsoleResponse& response,
                                                  std::uint64_t request_id) noexcept {
  if (response.magic != kNativeConsoleMagic || response.version != kNativeConsoleVersion ||
      response.request_id != request_id || response.reserved != 0 ||
      response.status > NativeConsoleStatus::kStopped ||
      response.type > NativeConsoleType::kDocumentStart ||
      (response.flags & ~kNativeConsoleResponseFlags) != 0) {
    return false;
  }
  // Both flags describe a listing. Nothing else is ever cut to fit a record.
  if (response.flags != 0 && response.type != NativeConsoleType::kTargets) {
    return false;
  }
  // Each target's own lengths are checked as it is read; the count can only
  // be as large as the fixed headers the payload has room for.
  if (response.type == NativeConsoleType::kTargets) {
    return response.status == NativeConsoleStatus::kOk &&
           std::uint64_t{response.item_count} * sizeof(NativeConsoleTarget) <=
               response.payload_bytes;
  }
  return response.item_count == 0;
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
  if (request.operation == NativeConsoleOperation::kDocumentStart)
    return response.type == NativeConsoleType::kDocumentStart;
  return response.type < NativeConsoleType::kTargets;
}

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(NativeConsoleRequest) == 32);
static_assert(sizeof(NativeConsoleResponse) == 32);
static_assert(sizeof(NativeConsoleTarget) == 24);
static_assert(std::is_trivially_copyable_v<NativeConsoleRequest>);
static_assert(std::is_trivially_copyable_v<NativeConsoleResponse>);
static_assert(std::is_trivially_copyable_v<NativeConsoleTarget>);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_PROTOCOL_H_
