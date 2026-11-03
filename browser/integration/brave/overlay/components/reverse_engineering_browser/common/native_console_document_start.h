// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_DOCUMENT_START_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_DOCUMENT_START_H_

// Dependency-free so the browser process, the renderer and the offline
// document-start check all decide "does this document match" with exactly the
// same bytes. A rule never contains a pattern, wildcard or host suffix: the
// browser matches one exact serialized origin, one frame kind and an optional
// literal path prefix, so a declared rule can never widen to another origin.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

#include "native_console_protocol.h"

namespace reb {

inline constexpr std::size_t kNativeConsoleDocumentStartOriginLimit = 256;
inline constexpr std::size_t kNativeConsoleDocumentStartPathLimit = 256;
inline constexpr std::uint16_t kNativeConsoleDocumentStartTopFrame = 1;
inline constexpr std::uint16_t kNativeConsoleDocumentStartChildFrame = 2;

// One rule selects exactly one origin and one frame kind. Both bits set, or
// neither set, is refused: "any frame" must be requested as two rules so the
// armed set always states which frames it reaches.
struct NativeConsoleDocumentStartRule final {
  std::uint16_t origin_bytes = 0;
  std::uint16_t path_bytes = 0;
  std::uint16_t frame_flags = 0;
  std::uint16_t reserved = 0;
  std::array<char, kNativeConsoleDocumentStartOriginLimit> origin{};
  std::array<char, kNativeConsoleDocumentStartPathLimit> path{};
};

struct NativeConsoleDocumentStartScript final {
  std::uint64_t script_id = 0;
  std::uint32_t source_bytes = 0;
  std::uint32_t reserved = 0;
  NativeConsoleDocumentStartRule rule;
  std::array<char, kNativeConsoleDocumentStartSourceLimit> source{};
};

static_assert(sizeof(NativeConsoleDocumentStartRule) == 520);
static_assert(sizeof(NativeConsoleDocumentStartScript) == 4632);
static_assert(std::is_trivially_copyable_v<NativeConsoleDocumentStartRule>);
static_assert(std::is_trivially_copyable_v<NativeConsoleDocumentStartScript>);
// No padding: the fixed records cross Mojo and the offline check as exact bytes.
static_assert(sizeof(NativeConsoleDocumentStartRule) ==
              8 + kNativeConsoleDocumentStartOriginLimit + kNativeConsoleDocumentStartPathLimit);
static_assert(sizeof(NativeConsoleDocumentStartScript) ==
              16 + sizeof(NativeConsoleDocumentStartRule) + kNativeConsoleDocumentStartSourceLimit);

inline constexpr std::size_t kNativeConsoleDocumentStartSetBytes =
    kNativeConsoleDocumentStartScriptLimit * sizeof(NativeConsoleDocumentStartScript);

// Snippet output is one bounded string per record. Reading an object would
// require touching page-controlled property access, so `report` accepts only
// primitives; a snippet that wants structure formats its own text.
inline constexpr std::size_t kNativeConsoleDocumentStartReportLimit = 512;
inline constexpr std::uint32_t kNativeConsoleDocumentStartRecordsPerDocument = 64;
inline constexpr std::size_t kNativeConsoleDocumentStartTrackedDocuments = 32;
inline constexpr std::size_t kNativeConsoleDocumentStartOutputCapacity = 128;
inline constexpr std::size_t kNativeConsoleDocumentStartOutputPage = 32;
// Document creation is on the critical path of every navigation, so the
// injection budget is much tighter than an explicit console command's.
inline constexpr int kNativeConsoleDocumentStartExecutionMillis = 50;

// Why a record exists. The agent needs the gap kinds, not only the snippet's
// own output, to tell "the snippet said nothing" from "nothing ran".
enum class NativeConsoleDocumentStartRecord : std::uint32_t {
  kInjected = 1,     // The snippet compiled in a matching document and was about to run.
  kReport = 2,       // The snippet called report(value).
  kScriptError = 3,  // The snippet failed to compile, threw, or exceeded its budget.
  kRefused = 4,      // A report argument, per-document budget or stale generation.
};

[[nodiscard]] inline constexpr bool IsNativeConsoleDocumentStartRecord(
    std::uint32_t kind) noexcept {
  return kind >= static_cast<std::uint32_t>(NativeConsoleDocumentStartRecord::kInjected) &&
         kind <= static_cast<std::uint32_t>(NativeConsoleDocumentStartRecord::kRefused);
}

[[nodiscard]] inline constexpr const char* NativeConsoleDocumentStartRecordName(
    std::uint32_t kind) noexcept {
  switch (static_cast<NativeConsoleDocumentStartRecord>(kind)) {
    case NativeConsoleDocumentStartRecord::kInjected:
      return "injected";
    case NativeConsoleDocumentStartRecord::kReport:
      return "report";
    case NativeConsoleDocumentStartRecord::kScriptError:
      return "script_error";
    case NativeConsoleDocumentStartRecord::kRefused:
      return "refused";
  }
  return "";
}

namespace native_console_document_start_detail {

// Shortest-form UTF-8 without NUL, surrogates or over-long encodings. Bounded
// text crosses Mojo and JSON, so an invalid sequence must be refused at arming
// rather than truncated into a different string later.
[[nodiscard]] inline constexpr bool Utf8(std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    const auto lead = static_cast<unsigned char>(text[index]);
    std::size_t length = 0;
    std::uint32_t point = 0;
    if (lead == 0) {
      return false;
    } else if (lead < 0x80) {
      length = 1;
      point = lead;
    } else if (lead >= 0xc2 && lead <= 0xdf) {
      length = 2;
      point = lead & 0x1fu;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      length = 3;
      point = lead & 0x0fu;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      length = 4;
      point = lead & 0x07u;
    } else {
      return false;
    }
    if (index + length > text.size())
      return false;
    for (std::size_t offset = 1; offset < length; ++offset) {
      const auto continuation = static_cast<unsigned char>(text[index + offset]);
      if (continuation < 0x80 || continuation > 0xbf)
        return false;
      point = (point << 6) | (continuation & 0x3fu);
    }
    if ((length == 3 && point < 0x800) || (length == 4 && point < 0x10000) || point > 0x10ffff ||
        (point >= 0xd800 && point <= 0xdfff))
      return false;
    index += length;
  }
  return true;
}

[[nodiscard]] inline constexpr std::string_view Text(const char* data, std::size_t size) noexcept {
  return std::string_view(data, size);
}

}  // namespace native_console_document_start_detail

// `scheme://host[:port]` exactly as url::Origin::Serialize writes it: lowercase
// ASCII, no path, no credentials, no trailing slash, no default port.
[[nodiscard]] inline bool IsValidNativeConsoleDocumentStartOrigin(
    std::string_view origin) noexcept {
  std::string_view host = origin;
  if (host.starts_with("http://"))
    host.remove_prefix(7);
  else if (host.starts_with("https://"))
    host.remove_prefix(8);
  else
    return false;
  if (host.empty() || host.size() > 255)
    return false;
  const auto colon = host.rfind(':');
  if (colon != std::string_view::npos) {
    const auto port = host.substr(colon + 1);
    if (port.empty() || port.size() > 5 || port.front() == '0')
      return false;
    unsigned value = 0;
    for (char digit : port) {
      if (digit < '0' || digit > '9')
        return false;
      value = value * 10 + static_cast<unsigned>(digit - '0');
    }
    if (value == 0 || value > 65535)
      return false;
    host = host.substr(0, colon);
  }
  if (host.empty() || host.front() == '.' || host.front() == '-' || host.back() == '-')
    return false;
  bool previous_dot = false;
  for (char character : host) {
    const bool letter = character >= 'a' && character <= 'z';
    const bool digit = character >= '0' && character <= '9';
    if (!letter && !digit && character != '.' && character != '-' && character != '[' &&
        character != ']' && character != ':')
      return false;
    if (character == '.' && previous_dot)
      return false;
    previous_dot = character == '.';
  }
  return !previous_dot;
}

// A literal prefix of the committed path. Query and fragment are deliberately
// outside the rule: they are not part of the document's path identity.
[[nodiscard]] inline bool IsValidNativeConsoleDocumentStartPath(std::string_view path) noexcept {
  if (path.empty())
    return true;
  if (path.front() != '/' || path.size() > kNativeConsoleDocumentStartPathLimit)
    return false;
  for (char character : path) {
    const auto value = static_cast<unsigned char>(character);
    if (value <= 0x20 || value >= 0x7f || character == '?' || character == '#')
      return false;
  }
  return true;
}

[[nodiscard]] inline std::string_view NativeConsoleDocumentStartOrigin(
    const NativeConsoleDocumentStartRule& rule) noexcept {
  return native_console_document_start_detail::Text(rule.origin.data(), rule.origin_bytes);
}

[[nodiscard]] inline std::string_view NativeConsoleDocumentStartPath(
    const NativeConsoleDocumentStartRule& rule) noexcept {
  return native_console_document_start_detail::Text(rule.path.data(), rule.path_bytes);
}

[[nodiscard]] inline std::string_view NativeConsoleDocumentStartSource(
    const NativeConsoleDocumentStartScript& script) noexcept {
  return native_console_document_start_detail::Text(script.source.data(), script.source_bytes);
}

[[nodiscard]] inline bool IsValidNativeConsoleDocumentStartRule(
    const NativeConsoleDocumentStartRule& rule) noexcept {
  if (rule.reserved != 0 || rule.origin_bytes == 0 ||
      rule.origin_bytes > kNativeConsoleDocumentStartOriginLimit ||
      rule.path_bytes > kNativeConsoleDocumentStartPathLimit)
    return false;
  if (rule.frame_flags != kNativeConsoleDocumentStartTopFrame &&
      rule.frame_flags != kNativeConsoleDocumentStartChildFrame)
    return false;
  for (std::size_t index = rule.origin_bytes; index < rule.origin.size(); ++index)
    if (rule.origin[index] != '\0')
      return false;
  for (std::size_t index = rule.path_bytes; index < rule.path.size(); ++index)
    if (rule.path[index] != '\0')
      return false;
  return IsValidNativeConsoleDocumentStartOrigin(NativeConsoleDocumentStartOrigin(rule)) &&
         IsValidNativeConsoleDocumentStartPath(NativeConsoleDocumentStartPath(rule));
}

[[nodiscard]] inline bool IsValidNativeConsoleDocumentStartScript(
    const NativeConsoleDocumentStartScript& script) noexcept {
  if (script.script_id == 0 || script.reserved != 0 || script.source_bytes == 0 ||
      script.source_bytes > kNativeConsoleDocumentStartSourceLimit)
    return false;
  for (std::size_t index = script.source_bytes; index < script.source.size(); ++index)
    if (script.source[index] != '\0')
      return false;
  return IsValidNativeConsoleDocumentStartRule(script.rule) &&
         native_console_document_start_detail::Utf8(NativeConsoleDocumentStartSource(script));
}

// Exact origin equality, exact frame kind, literal path prefix. No normalizing,
// no suffix match and no scheme relaxation: a document that is not covered by a
// declared rule is never injected.
[[nodiscard]] inline bool NativeConsoleDocumentStartMatches(
    const NativeConsoleDocumentStartRule& rule,
    std::string_view origin,
    std::string_view path,
    bool top_frame) noexcept {
  if (!IsValidNativeConsoleDocumentStartRule(rule))
    return false;
  const auto required =
      top_frame ? kNativeConsoleDocumentStartTopFrame : kNativeConsoleDocumentStartChildFrame;
  return rule.frame_flags == required && origin == NativeConsoleDocumentStartOrigin(rule) &&
         path.starts_with(NativeConsoleDocumentStartPath(rule));
}

// Stable, order-independent per-script label so the panel and an agent can
// confirm which exact snippet is armed without echoing its source. FNV-1a is a
// labeling digest, not a security claim.
[[nodiscard]] inline std::uint64_t NativeConsoleDocumentStartDigest(
    std::string_view source) noexcept {
  std::uint64_t hash = 0xcbf29ce484222325ull;
  for (char character : source) {
    hash ^= static_cast<unsigned char>(character);
    hash *= 0x100000001b3ull;
  }
  return hash;
}

[[nodiscard]] inline std::size_t EncodeNativeConsoleDocumentStartScripts(
    std::span<const NativeConsoleDocumentStartScript> scripts,
    std::span<std::uint8_t> out) noexcept {
  if (scripts.size() > kNativeConsoleDocumentStartScriptLimit ||
      out.size() < scripts.size() * sizeof(NativeConsoleDocumentStartScript))
    return 0;
  std::size_t offset = 0;
  for (const auto& script : scripts) {
    if (!IsValidNativeConsoleDocumentStartScript(script))
      return 0;
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&script);
    for (std::size_t index = 0; index < sizeof(script); ++index)
      out[offset + index] = bytes[index];
    offset += sizeof(script);
  }
  return offset;
}

// Returns the decoded count, or 0 for any refusal. A partially valid set arms
// nothing: a renderer must never run a subset the browser did not approve.
[[nodiscard]] inline std::size_t DecodeNativeConsoleDocumentStartScripts(
    std::span<const std::uint8_t> bytes,
    std::span<NativeConsoleDocumentStartScript> out) noexcept {
  constexpr auto record = sizeof(NativeConsoleDocumentStartScript);
  if (bytes.empty() || bytes.size() % record != 0)
    return 0;
  const auto count = bytes.size() / record;
  if (count > kNativeConsoleDocumentStartScriptLimit || count > out.size())
    return 0;
  std::size_t total = 0;
  for (std::size_t index = 0; index < count; ++index) {
    NativeConsoleDocumentStartScript script;
    auto* destination = reinterpret_cast<std::uint8_t*>(&script);
    for (std::size_t offset = 0; offset < record; ++offset)
      destination[offset] = bytes[index * record + offset];
    if (!IsValidNativeConsoleDocumentStartScript(script))
      return 0;
    for (std::size_t previous = 0; previous < index; ++previous)
      if (out[previous].script_id == script.script_id)
        return 0;
    total += script.source_bytes;
    if (total > kNativeConsoleDocumentStartTotalSourceLimit)
      return 0;
    out[index] = script;
  }
  return count;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_DOCUMENT_START_H_
