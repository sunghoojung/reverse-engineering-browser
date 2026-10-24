// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"

#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_finding.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>

#include "base/compiler_specific.h"
#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

namespace reb {

namespace {

std::uint64_t MonotonicTimeNs() noexcept {
  return static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
}

bool IsFingerprintSurfaceCategory(const NativeProbeCategory category) noexcept {
  switch (category) {
    case NativeProbeCategory::kCanvas:
    case NativeProbeCategory::kWebGl:
    case NativeProbeCategory::kWebAudio:
    case NativeProbeCategory::kNavigator:
    case NativeProbeCategory::kPermissions:
    case NativeProbeCategory::kStorage:
    case NativeProbeCategory::kWebRtc:
    case NativeProbeCategory::kRuntime:
      return true;
    case NativeProbeCategory::kUnknown:
    case NativeProbeCategory::kWasm:
    case NativeProbeCategory::kNetwork:
    case NativeProbeCategory::kVm:
    case NativeProbeCategory::kArtifact:
      return false;
  }
  return false;
}

// Origin Trace reads artifact content through a bounded 2 MiB local response.
// Keep Canvas data URLs within that exact limit so an accepted image is always
// complete enough to validate and display instead of becoming a partial base64
// preview. Other generated artifact kinds retain their 16 MiB transport cap.
constexpr std::size_t kCanvasDataUrlMaxBytes = 2U * 1024U * 1024U;
constexpr std::size_t kRuntimeTypedArrayMinBytes = 32;
constexpr std::size_t kRuntimeTypedArrayMaxSnapshots = 16;

struct RuntimeScriptCache final {
  std::uint64_t generation = 0;
  std::array<std::pair<std::uint64_t, std::uint64_t>, kRuntimeTypedArrayMaxSnapshots> keys{};
  std::size_t count = 0;
};
thread_local RuntimeScriptCache runtime_script_cache;

struct RuntimeObservation final {
  std::uint64_t context = 0;
  std::uint64_t script = 0;
  bool candidate = false;
  bool dispatch = false;
};
struct RuntimeObservationCache final {
  std::uint64_t generation = 0;
  std::array<RuntimeObservation, 64> observations{};
  std::size_t count = 0;
  bool no_signal_reported = false;
};
thread_local RuntimeObservationCache runtime_observations;

// Bounded, allocation-free metadata sanitization. Ambiguous/control-containing
// URLs are unavailable; data/javascript URLs must never become source metadata.
std::string_view SanitizeRuntimeSourceUrl(
    std::string_view input,
    std::array<char, kNativeArtifactMaxUrlBytes>& output) noexcept {
  if (input.empty() || input.size() > output.size())
    return {};
  for (const char character : input) {
    const auto ch = static_cast<unsigned char>(character);
    if (ch <= 0x20 || ch == 0x7f || ch == '\\')
      return {};
  }
  input = input.substr(0, input.find_first_of("?#"));
  const auto scheme = input.find("://");
  if (scheme == std::string_view::npos || scheme > 7)
    return {};
  std::array<char, 8> scheme_storage{};
  for (std::size_t index = 0; index < scheme; ++index) {
    const auto ch = input[index];
    scheme_storage[index] = ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + ('a' - 'A')) : ch;
  }
  const std::string_view scheme_name(scheme_storage.data(), scheme);
  if (scheme_name != "http" && scheme_name != "https" && scheme_name != "fixture")
    return {};
  std::size_t cut_begin = 0;
  std::size_t cut_end = 0;
  if (scheme != std::string_view::npos) {
    cut_begin = scheme + 3;
    const auto authority_end = input.find('/', cut_begin);
    const auto authority = input.substr(cut_begin, authority_end - cut_begin);
    const auto at = authority.rfind('@');
    if (at != std::string_view::npos)
      cut_end = cut_begin + at + 1;
    if (authority.empty() || cut_end == cut_begin + authority.size())
      return {};
  }
  std::size_t length = 0;
  for (std::size_t index = 0; index < input.size(); ++index) {
    if (cut_end != 0 && index >= cut_begin && index < cut_end)
      continue;
    output[length++] = input[index];
  }
  return {output.data(), length};
}

// Same structural weights as the offline JavaScript detector. Anti-bot lexical
// rules are relevance only and do not admit a buffer. The scan never executes
// source. One malloc/free pair keeps this path noexcept under -fno-exceptions.
constexpr std::size_t kRuntimeSourceScanBytes = 256U * 1024U;
constexpr std::size_t kRuntimeSourceMaxFunctions = 256;
constexpr int kRuntimeCandidateScore = 20;
constexpr int kRuntimeLikelyScore = 60;
constexpr int kRuntimeLikelyFamilies = 3;

struct RuntimeSourceTier final {
  bool likely = false;
  bool candidate = false;
  bool dispatch = false;
};

struct RuntimeRegion final {
  std::size_t start = 0;
  std::size_t end = 0;
  std::uint16_t id = 0;
};

constexpr bool IsAsciiWord(const unsigned char c) noexcept {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

constexpr bool IsIdentStart(const unsigned char c) noexcept {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '$';
}

constexpr bool IsIdentCont(const unsigned char c) noexcept {
  return IsIdentStart(c) || (c >= '0' && c <= '9');
}

constexpr bool IsAsciiSpace(const unsigned char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

constexpr char AsciiLower(const unsigned char c) noexcept {
  return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
}

constexpr std::size_t AlignUp(const std::size_t value, const std::size_t alignment) noexcept {
  return (value + alignment - 1U) & ~(alignment - 1U);
}

void MaskScriptSource(const std::span<char> text, const std::size_t length) noexcept {
  bool line = false;
  bool block = false;
  bool escaped = false;
  char quote = 0;
  for (std::size_t index = 0; index < length; ++index) {
    const char current = text[index];
    const char next = index + 1 < length ? text[index + 1] : '\0';
    if (line) {
      if (current == '\n') {
        line = false;
      } else {
        text[index] = ' ';
      }
    } else if (block) {
      text[index] = ' ';
      if (current == '*' && next == '/') {
        text[index + 1] = ' ';
        ++index;
        block = false;
      }
    } else if (quote != 0) {
      text[index] = ' ';
      if (escaped) {
        escaped = false;
      } else if (current == '\\') {
        escaped = true;
      } else if (current == quote) {
        quote = 0;
      }
    } else if (current == '/' && (next == '/' || next == '*')) {
      text[index] = ' ';
      text[index + 1] = ' ';
      ++index;
      line = next == '/';
      block = next == '*';
    } else if (current == '"' || current == '\'' || current == '`') {
      text[index] = ' ';
      quote = current;
    }
  }
}

std::size_t MatchFunctionBrace(const std::span<const char> text,
                               const std::size_t length,
                               const std::size_t index) noexcept {
  constexpr std::string_view kWord = "function";
  constexpr std::size_t kLen = kWord.size();
  if (index + kLen > length ||
      (index > 0 && IsAsciiWord(static_cast<unsigned char>(text[index - 1]))) ||
      !std::ranges::equal(text.subspan(index, kLen), kWord) ||
      (index + kLen < length && IsAsciiWord(static_cast<unsigned char>(text[index + kLen])))) {
    return length;
  }
  std::size_t cursor = index + kLen;
  const std::size_t limit = std::min(length, index + kLen + 1024U + 1U);
  while (cursor < limit && text[cursor] != '{' && text[cursor] != '}') {
    ++cursor;
  }
  if (cursor <= index + kLen + 1024U && cursor < length && text[cursor] == '{') {
    return cursor;
  }
  return length;
}

std::size_t MatchParenArrowBrace(const std::span<const char> text,
                                 const std::size_t length,
                                 const std::size_t index) noexcept {
  if (index >= length || text[index] != '(') {
    return length;
  }
  std::size_t cursor = index + 1U;
  const std::size_t limit = std::min(length, index + 1U + 1024U);
  while (cursor < limit && text[cursor] != '(' && text[cursor] != ')' && text[cursor] != '{' &&
         text[cursor] != '}') {
    ++cursor;
  }
  if (cursor >= length || text[cursor] != ')') {
    return length;
  }
  ++cursor;
  while (cursor < length && IsAsciiSpace(static_cast<unsigned char>(text[cursor]))) {
    ++cursor;
  }
  if (cursor + 1U >= length || text[cursor] != '=' || text[cursor + 1U] != '>') {
    return length;
  }
  cursor += 2U;
  while (cursor < length && IsAsciiSpace(static_cast<unsigned char>(text[cursor]))) {
    ++cursor;
  }
  return cursor < length && text[cursor] == '{' ? cursor : length;
}

std::size_t MatchIdentArrowBrace(const std::span<const char> text,
                                 const std::size_t length,
                                 const std::size_t index) noexcept {
  if (index >= length || !IsIdentStart(static_cast<unsigned char>(text[index])) ||
      (index > 0 && IsIdentCont(static_cast<unsigned char>(text[index - 1])))) {
    return length;
  }
  std::size_t cursor = index + 1U;
  while (cursor < length && IsIdentCont(static_cast<unsigned char>(text[cursor]))) {
    ++cursor;
  }
  while (cursor < length && IsAsciiSpace(static_cast<unsigned char>(text[cursor]))) {
    ++cursor;
  }
  if (cursor + 1U >= length || text[cursor] != '=' || text[cursor + 1U] != '>') {
    return length;
  }
  cursor += 2U;
  while (cursor < length && IsAsciiSpace(static_cast<unsigned char>(text[cursor]))) {
    ++cursor;
  }
  return cursor < length && text[cursor] == '{' ? cursor : length;
}

std::size_t MatchSignatureBrace(const std::span<const char> text,
                                const std::size_t length,
                                const std::size_t index) noexcept {
  const std::size_t function_brace = MatchFunctionBrace(text, length, index);
  if (function_brace < length) {
    return function_brace;
  }
  const std::size_t paren_brace = MatchParenArrowBrace(text, length, index);
  if (paren_brace < length) {
    return paren_brace;
  }
  return MatchIdentArrowBrace(text, length, index);
}

struct RegionScan final {
  std::span<const char> text;
  std::span<const std::uint16_t> owner;
  std::uint16_t id = 0;
  std::size_t begin = 0;
  std::size_t end = 0;

  [[nodiscard]] char At(const std::size_t index) const noexcept {
    if (index >= end || owner[index] != id) {
      return ' ';
    }
    return text[index];
  }

  [[nodiscard]] bool WordBefore(const std::size_t index) const noexcept {
    return index > begin && IsAsciiWord(static_cast<unsigned char>(At(index - 1U)));
  }

  [[nodiscard]] bool WordAfter(const std::size_t index) const noexcept {
    return index < end && IsAsciiWord(static_cast<unsigned char>(At(index)));
  }
};

bool EqualsAt(const RegionScan& scan,
              const std::size_t index,
              const std::string_view word,
              const bool ignore_case) noexcept {
  const std::size_t length = word.size();
  if (index + length > scan.end) {
    return false;
  }
  for (std::size_t offset = 0; offset < length; ++offset) {
    const char current = scan.At(index + offset);
    const char expected =
        ignore_case ? AsciiLower(static_cast<unsigned char>(word[offset])) : word[offset];
    const char actual = ignore_case ? AsciiLower(static_cast<unsigned char>(current)) : current;
    if (actual != expected) {
      return false;
    }
  }
  return true;
}

bool ContainsBoundedWord(const RegionScan& scan,
                         const std::string_view word,
                         const bool ignore_case) noexcept {
  const std::size_t length = word.size();
  if (length == 0 || scan.end - scan.begin < length) {
    return false;
  }
  for (std::size_t index = scan.begin; index + length <= scan.end; ++index) {
    if (!scan.WordBefore(index) && EqualsAt(scan, index, word, ignore_case) &&
        !scan.WordAfter(index + length)) {
      return true;
    }
  }
  return false;
}

bool ContainsLoop(const RegionScan& scan) noexcept {
  constexpr char kWhile[] = "while";
  constexpr char kFor[] = "for";
  constexpr std::size_t kWhileLen = sizeof(kWhile) - 1U;
  constexpr std::size_t kForLen = sizeof(kFor) - 1U;
  for (std::size_t index = scan.begin; index < scan.end; ++index) {
    const std::size_t length = EqualsAt(scan, index, kWhile, false) ? kWhileLen
                               : EqualsAt(scan, index, kFor, false) ? kForLen
                                                                    : 0U;
    if (length == 0 || scan.WordBefore(index) || scan.WordAfter(index + length)) {
      continue;
    }
    std::size_t cursor = index + length;
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == '(') {
      return true;
    }
  }
  return false;
}

bool ContainsIndexedCall(const RegionScan& scan) noexcept {
  for (std::size_t index = scan.begin; index < scan.end; ++index) {
    if (scan.WordBefore(index) || !IsIdentStart(static_cast<unsigned char>(scan.At(index)))) {
      continue;
    }
    std::size_t cursor = index + 1U;
    while (cursor < scan.end && IsIdentCont(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor >= scan.end || scan.At(cursor) != '[') {
      continue;
    }
    ++cursor;
    bool any = false;
    bool bad = false;
    while (cursor < scan.end && scan.At(cursor) != ']') {
      any = true;
      if (scan.At(cursor) == '[') {
        ++cursor;
        while (cursor < scan.end && scan.At(cursor) != ']' && scan.At(cursor) != '[') {
          ++cursor;
        }
        if (cursor >= scan.end || scan.At(cursor) != ']') {
          bad = true;
          break;
        }
      }
      ++cursor;
    }
    if (bad || !any || cursor >= scan.end || scan.At(cursor) != ']') {
      continue;
    }
    ++cursor;
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == '(') {
      return true;
    }
  }
  return false;
}

bool ContainsSwitch(const RegionScan& scan) noexcept {
  constexpr char kSwitch[] = "switch";
  constexpr std::size_t kLen = sizeof(kSwitch) - 1U;
  for (std::size_t index = scan.begin; index + kLen <= scan.end; ++index) {
    if (scan.WordBefore(index) || !EqualsAt(scan, index, kSwitch, false) ||
        scan.WordAfter(index + kLen)) {
      continue;
    }
    std::size_t cursor = index + kLen;
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == '(') {
      return true;
    }
  }
  return false;
}

bool ContainsIpUpdate(const RegionScan& scan) noexcept {
  constexpr std::array<std::string_view, 5> kWords = {"instructionPointer", "offset", "cursor",
                                                      "pc", "ip"};
  for (std::size_t index = scan.begin; index < scan.end; ++index) {
    if (scan.WordBefore(index)) {
      continue;
    }
    std::size_t matched = 0;
    for (std::size_t word = 0; word < 5U; ++word) {
      if (EqualsAt(scan, index, kWords[word], false) &&
          !scan.WordAfter(index + kWords[word].size())) {
        matched = kWords[word].size();
        break;
      }
    }
    if (matched == 0) {
      continue;
    }
    std::size_t cursor = index + matched;
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor + 1U < scan.end && ((scan.At(cursor) == '+' && scan.At(cursor + 1U) == '+') ||
                                   (scan.At(cursor) == '-' && scan.At(cursor + 1U) == '-'))) {
      return true;
    }
    if (cursor < scan.end && (scan.At(cursor) == '+' || scan.At(cursor) == '-')) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == '=') {
      return true;
    }
  }
  return false;
}

bool ContainsNamedBracket(const RegionScan& scan,
                          const std::span<const std::string_view> words) noexcept {
  for (std::size_t index = scan.begin; index < scan.end; ++index) {
    if (scan.WordBefore(index)) {
      continue;
    }
    for (std::size_t word = 0; word < words.size(); ++word) {
      if (!EqualsAt(scan, index, words[word], true) || scan.WordAfter(index + words[word].size())) {
        continue;
      }
      std::size_t cursor = index + words[word].size();
      while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
        ++cursor;
      }
      if (cursor >= scan.end || scan.At(cursor) != '[') {
        continue;
      }
      ++cursor;
      const std::size_t content = cursor;
      while (cursor < scan.end && scan.At(cursor) != ']') {
        ++cursor;
      }
      if (cursor > content && cursor < scan.end && scan.At(cursor) == ']') {
        return true;
      }
    }
  }
  return false;
}

bool ContainsBytecodeRead(const RegionScan& scan) noexcept {
  constexpr std::array<std::string_view, 6> kWords = {"instructions", "bytecode", "opcodes",
                                                      "program",      "bytes",    "code"};
  if (ContainsNamedBracket(scan, kWords) || ContainsBoundedWord(scan, "Uint8Array", false) ||
      ContainsBoundedWord(scan, "DataView", false)) {
    return true;
  }
  return false;
}

bool ContainsDotMutation(const RegionScan& scan) noexcept {
  constexpr std::array<std::string_view, 4> kNames = {".unshift", ".shift", ".push", ".pop"};
  for (std::size_t index = scan.begin; index < scan.end; ++index) {
    for (std::size_t name = 0; name < 4U; ++name) {
      if (!EqualsAt(scan, index, kNames[name], false)) {
        continue;
      }
      std::size_t cursor = index + kNames[name].size();
      while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
        ++cursor;
      }
      if (cursor < scan.end && scan.At(cursor) == '(') {
        return true;
      }
    }
  }
  return false;
}

bool ContainsStateWord(const RegionScan& scan) noexcept {
  constexpr std::array<std::string_view, 5> kWords = {"accumulator", "registers", "register",
                                                      "memory", "stack"};
  for (std::size_t index = scan.begin; index < scan.end; ++index) {
    if (scan.WordBefore(index)) {
      continue;
    }
    std::size_t matched = 0;
    for (std::size_t word = 0; word < 5U; ++word) {
      if (EqualsAt(scan, index, kWords[word], true) &&
          !scan.WordAfter(index + kWords[word].size())) {
        matched = kWords[word].size();
        break;
      }
    }
    if (matched == 0) {
      continue;
    }
    std::size_t cursor = index + matched;
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == '[') {
      return true;
    }
    if (cursor < scan.end &&
        (scan.At(cursor) == '+' || scan.At(cursor) == '-' || scan.At(cursor) == '^' ||
         scan.At(cursor) == '|' || scan.At(cursor) == '&')) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == '=') {
      return true;
    }
  }
  return false;
}

bool ContainsCaseLabel(const RegionScan& scan) noexcept {
  constexpr char kCase[] = "case";
  constexpr std::size_t kLen = sizeof(kCase) - 1U;
  for (std::size_t index = scan.begin; index + kLen <= scan.end; ++index) {
    if (scan.WordBefore(index) || !EqualsAt(scan, index, kCase, true) ||
        scan.WordAfter(index + kLen)) {
      continue;
    }
    std::size_t cursor = index + kLen;
    if (cursor >= scan.end || !IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      continue;
    }
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor + 1U < scan.end && scan.At(cursor) == '0' &&
        (scan.At(cursor + 1U) == 'x' || scan.At(cursor + 1U) == 'X')) {
      std::size_t hex = cursor + 2U;
      const auto hex_digit = [](const char character) noexcept {
        const auto value = static_cast<unsigned char>(character);
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
               (value >= 'A' && value <= 'F');
      };
      if (hex < scan.end && hex_digit(scan.At(hex))) {
        while (hex < scan.end && hex_digit(scan.At(hex))) {
          ++hex;
        }
        cursor = hex;
      }
    } else {
      const auto digit = [](const char character) noexcept {
        const auto value = static_cast<unsigned char>(character);
        return value >= '0' && value <= '9';
      };
      if (cursor < scan.end && digit(scan.At(cursor))) {
        while (cursor < scan.end && digit(scan.At(cursor))) {
          ++cursor;
        }
      }
    }
    while (cursor < scan.end && IsAsciiSpace(static_cast<unsigned char>(scan.At(cursor)))) {
      ++cursor;
    }
    if (cursor < scan.end && scan.At(cursor) == ':') {
      return true;
    }
  }
  return false;
}

bool ContainsHandler(const RegionScan& scan) noexcept {
  constexpr std::array<std::string_view, 4> kWords = {"handlers", "handler", "opcodes", "opcode"};
  return ContainsCaseLabel(scan) || ContainsNamedBracket(scan, kWords);
}

bool ContainsExit(const RegionScan& scan) noexcept {
  return ContainsBoundedWord(scan, "return", false) || ContainsBoundedWord(scan, "break", false) ||
         ContainsBoundedWord(scan, "throw", false);
}

struct RegionScore final {
  int score = 0;
  int families = 0;
  bool dispatch = false;
};

RegionScore ScoreRegion(const RegionScan& scan) noexcept {
  const bool dispatch = ContainsLoop(scan) && (ContainsSwitch(scan) || ContainsIndexedCall(scan));
  const bool ip = ContainsIpUpdate(scan);
  const bool bytecode = ContainsBytecodeRead(scan);
  const bool state = ContainsDotMutation(scan) || ContainsStateWord(scan);
  const bool handler = ContainsHandler(scan);
  const bool exit = ContainsExit(scan);
  RegionScore scored;
  scored.dispatch = dispatch;
  if (dispatch) {
    scored.score += 20;
    ++scored.families;
  }
  if (ip) {
    scored.score += 20;
    ++scored.families;
  }
  if (bytecode) {
    scored.score += 20;
    ++scored.families;
  }
  if (state) {
    scored.score += 15;
    ++scored.families;
  }
  if (handler) {
    scored.score += 15;
    ++scored.families;
  }
  if (exit) {
    scored.score += 5;
    ++scored.families;
  }
  return scored;
}

[[nodiscard]] RuntimeSourceTier ClassifyRuntimeSource(
    const std::span<const std::uint8_t> source) noexcept {
  if (source.empty()) {
    return {};
  }
  const bool truncated = source.size() > kRuntimeSourceScanBytes;
  const std::size_t length = truncated ? kRuntimeSourceScanBytes : source.size();
  const std::size_t owner_off = AlignUp(length, alignof(std::uint16_t));
  const std::size_t marks_off = owner_off + length * sizeof(std::uint16_t);
  const std::size_t stack_off = AlignUp(marks_off + length, alignof(std::size_t));
  const std::size_t total = stack_off + length * sizeof(std::size_t);
  void* const block = std::malloc(total);
  if (block == nullptr) {
    return {};
  }
  // SAFETY: malloc returned exactly total bytes. All subsequent partitions
  // are bounded subspans; owner/stack offsets are aligned for their value type.
  const auto storage = UNSAFE_BUFFERS(std::span(static_cast<std::byte*>(block), total));
  std::ranges::fill(storage, std::byte{0});
  const auto typed = []<typename T>(const std::span<std::byte> bytes) {
    // SAFETY: callers supply an aligned partition containing whole T objects
    // in this malloc allocation. No unbounded pointer escapes the partition.
    return UNSAFE_BUFFERS(std::span(reinterpret_cast<T*>(bytes.data()), bytes.size() / sizeof(T)));
  };
  const auto text = typed.template operator()<char>(storage.first(length));
  const auto owner = typed.template operator()<std::uint16_t>(
      storage.subspan(owner_off, length * sizeof(std::uint16_t)));
  const auto marks = typed.template operator()<unsigned char>(storage.subspan(marks_off, length));
  const auto brace_stack = typed.template operator()<std::size_t>(
      storage.subspan(stack_off, length * sizeof(std::size_t)));
  std::ranges::copy(std::as_bytes(source.first(length)), std::as_writable_bytes(text).begin());
  MaskScriptSource(text, length);

  std::size_t opening_count = 0;
  std::size_t cursor = 0;
  bool too_many_functions = false;
  while (cursor < length) {
    const std::size_t brace = [&]() {
      for (std::size_t index = cursor; index < length; ++index) {
        const std::size_t found = MatchSignatureBrace(text, length, index);
        if (found < length) {
          return found;
        }
      }
      return length;
    }();
    if (brace >= length) {
      break;
    }
    if (opening_count == kRuntimeSourceMaxFunctions) {
      too_many_functions = true;
      break;
    }
    marks[brace] = 1U;
    ++opening_count;
    cursor = brace + 1U;
  }
  if (too_many_functions) {
    std::free(block);
    return {};
  }

  std::array<RuntimeRegion, kRuntimeSourceMaxFunctions + 1U> regions{};
  regions[0] = {0U, length, 0U};
  std::size_t region_count = 1;
  std::size_t depth = 0;
  std::size_t closed = 0;
  std::size_t earliest_unclosed = length;
  for (std::size_t index = 0; index < length; ++index) {
    if (text[index] == '{') {
      brace_stack[depth++] = index;
    } else if (text[index] == '}' && depth > 0) {
      const std::size_t start = brace_stack[--depth];
      if (marks[start] != 0U) {
        const auto id = static_cast<std::uint16_t>(region_count);
        regions[region_count] = {start + 1U, index, id};
        ++region_count;
        ++closed;
      }
    }
  }
  if (closed != opening_count) {
    if (!truncated) {
      std::free(block);
      return {};
    }
    for (std::size_t index = 0; index < depth; ++index) {
      if (marks[brace_stack[index]] != 0U && brace_stack[index] < earliest_unclosed) {
        earliest_unclosed = brace_stack[index];
      }
    }
  }

  // Larger function bodies first so an inner function overwrites its parent.
  for (std::size_t start = 1; start < region_count; ++start) {
    std::size_t largest = start;
    for (std::size_t index = start + 1U; index < region_count; ++index) {
      const std::size_t largest_size = regions[largest].end - regions[largest].start;
      const std::size_t index_size = regions[index].end - regions[index].start;
      if (index_size > largest_size) {
        largest = index;
      }
    }
    const RuntimeRegion swap = regions[start];
    regions[start] = regions[largest];
    regions[largest] = swap;
  }
  for (std::size_t index = 1; index < region_count; ++index) {
    const RuntimeRegion& region = regions[index];
    for (std::size_t byte = region.start; byte < region.end; ++byte) {
      owner[byte] = region.id;
    }
  }
  if (earliest_unclosed < length) {
    for (std::size_t byte = earliest_unclosed; byte < length; ++byte) {
      owner[byte] = static_cast<std::uint16_t>(0xFFFFU);
    }
  }

  RuntimeSourceTier best_tier;
  int best_score = -1;
  int best_families = -1;
  std::size_t best_start = 0;
  for (std::size_t index = 0; index < region_count; ++index) {
    const RegionScan scan{text, owner, regions[index].id, regions[index].start, regions[index].end};
    const RegionScore scored = ScoreRegion(scan);
    if (scored.score > best_score ||
        (scored.score == best_score &&
         (scored.families > best_families ||
          (scored.families == best_families && regions[index].start < best_start)))) {
      best_score = scored.score;
      best_families = scored.families;
      best_start = regions[index].start;
      best_tier.dispatch = scored.dispatch;
      best_tier.candidate = scored.score >= kRuntimeCandidateScore;
      best_tier.likely = scored.dispatch && scored.score >= kRuntimeLikelyScore &&
                         scored.families >= kRuntimeLikelyFamilies;
    }
  }
  std::free(block);
  return best_tier;
}

void SetPayload(NativeProbeEvent& event,
                const std::string_view first,
                const std::string_view second = {}) noexcept {
  std::size_t written = 0;
  const auto append = [&event, &written](const std::string_view value) {
    const std::size_t available = event.inline_payload.size() - written;
    const std::size_t size = std::min(value.size(), available);
    std::transform(value.begin(), value.begin() + static_cast<std::ptrdiff_t>(size),
                   event.inline_payload.begin() + static_cast<std::ptrdiff_t>(written),
                   [](const char character) {
                     return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    written += size;
    return size == value.size();
  };

  const bool complete = append(first) && append(second);
  event.header.payload_size = static_cast<std::uint32_t>(written);
  if (!complete) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
  }
}

}  // namespace

NativeProbeSink::NativeProbeSink() noexcept = default;

NativeProbeSink& NativeProbeSink::Get() {
  static NativeProbeSink sink;
  return sink;
}

void NativeProbeSink::SetEmitters(const NativeRendererProbeEmitter emitter,
                                  const NativeGeneratedArtifactEmitter artifact_emitter,
                                  const std::uint64_t session_id,
                                  const std::uint64_t category_mask,
                                  const std::uint64_t expires_at_monotonic_ns,
                                  const bool capture_canvas_images,
                                  const NativeProbeFrameIdProvider frame_id_provider) noexcept {
  // Flush dispatch losses into the configuration that observed them before
  // the emitter and generation change. A replacement session must opt in again.
  PublishVmDispatchBudgetGap();
  DisableOwnedRegisterSampling();
  // SetEmitters is serialized by NativeProbeTransport's bound sequence. Stop
  // new readers before marking the independently atomic configuration fields
  // unstable. The completed even generation release-publishes the relaxed
  // policy fields and emitter together. Active readers acquire an even
  // generation, snapshot those fields, and accept only an unchanged final
  // generation.
  emitter_.store(nullptr, std::memory_order_release);
  artifact_emitter_.store(nullptr, std::memory_order_release);
  // Claims rely on generation ordering. Fail closed instead of ever reusing a
  // generation if the serialized control sequence exhausts the counter.
  if (config_generation_.load(std::memory_order_relaxed) >=
      std::numeric_limits<std::uint64_t>::max() - 1) {
    config_generation_.store(std::numeric_limits<std::uint64_t>::max(), std::memory_order_release);
    return;
  }
  config_generation_.fetch_add(1, std::memory_order_acq_rel);
  // If a reader sees any replacement policy field, its acquire fence also
  // observes the preceding odd generation and rejects the mixed snapshot.
  std::atomic_thread_fence(std::memory_order_release);
  const bool active = emitter && artifact_emitter;
  session_id_.store(active ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(active ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(active ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  capture_canvas_images_.store(active && capture_canvas_images, std::memory_order_relaxed);
  runtime_typed_array_count_.store(0, std::memory_order_relaxed);
  frame_id_provider_.store(active ? frame_id_provider : nullptr, std::memory_order_relaxed);
  emitter_.store(emitter, std::memory_order_relaxed);
  artifact_emitter_.store(artifact_emitter, std::memory_order_relaxed);
  config_generation_.fetch_add(1, std::memory_order_release);
}

bool NativeProbeSink::CanAdmitEvent(const NativeProbeEvent& event,
                                    const std::uint64_t config_generation) const noexcept {
  if ((config_generation & 1U) != 0 ||
      config_generation_.load(std::memory_order_acquire) != config_generation) {
    return false;
  }
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeRendererProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  return config_generation_.load(std::memory_order_acquire) == config_generation && emitter &&
         session_id != 0 && event.header.session_id == session_id &&
         (category_mask & NativeProbeCategoryMask(event.header.category)) != 0 &&
         MonotonicTimeNs() < expires_at;
}

bool NativeProbeSink::IsCanvasImageCaptureEnabled() const noexcept {
  return capture_canvas_images_.load(std::memory_order_acquire) && IsArtifactCaptureEnabled();
}

bool NativeProbeSink::IsArtifactCaptureEnabled() const noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire)) [[likely]] {
    return false;
  }
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return false;
  }
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeGeneratedArtifactEmitter artifact_emitter =
      artifact_emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  return config_generation_.load(std::memory_order_acquire) == generation && artifact_emitter &&
         (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kArtifact)) != 0 &&
         MonotonicTimeNs() < expires_at;
}

bool NativeProbeSink::IsVmCaptureEnabled() const noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire)) [[likely]] {
    return false;
  }
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return false;
  }
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeGeneratedArtifactEmitter artifact_emitter =
      artifact_emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  return config_generation_.load(std::memory_order_acquire) == generation && artifact_emitter &&
         (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kVm)) != 0 &&
         MonotonicTimeNs() < expires_at;
}

bool NativeProbeSink::RuntimeScriptSourceNeeded(const std::uint64_t execution_context_id,
                                                const std::uint64_t script_id) const noexcept {
  const auto generation = config_generation_.load(std::memory_order_acquire);
  if (runtime_script_cache.generation != generation) {
    runtime_script_cache = {};
    runtime_script_cache.generation = generation;
  }
  const auto key = std::pair{execution_context_id, script_id};
  return std::find(runtime_script_cache.keys.begin(),
                   runtime_script_cache.keys.begin() +
                       static_cast<std::ptrdiff_t>(runtime_script_cache.count),
                   key) == runtime_script_cache.keys.begin() +
                               static_cast<std::ptrdiff_t>(runtime_script_cache.count);
}

std::uint64_t NativeProbeSink::RuntimeCaptureGeneration() const noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire)) [[likely]]
    return 0;
  const auto generation = config_generation_.load(std::memory_order_acquire);
  return IsVmCaptureEnabled() && config_generation_.load(std::memory_order_acquire) == generation
             ? generation
             : 0;
}

bool NativeProbeSink::RegisterRuntimeScriptObservation(
    const std::uint64_t generation,
    const std::uint64_t execution_context_id,
    const std::uint64_t script_id,
    const NativeRuntimeScriptObservation observation) noexcept {
  if (generation == 0 || generation != RuntimeCaptureGeneration() || execution_context_id == 0 ||
      script_id == 0)
    return false;
  if (observation != NativeRuntimeScriptObservation::kCapturedVmCandidate &&
      observation != NativeRuntimeScriptObservation::kCapturedLikelyVm &&
      observation != NativeRuntimeScriptObservation::kStaticDispatchLoop)
    return false;
  if (runtime_observations.generation != generation) {
    runtime_observations = {};
    runtime_observations.generation = generation;
  }
  auto* entry = static_cast<RuntimeObservation*>(nullptr);
  for (std::size_t index = 0; index < runtime_observations.count; ++index) {
    auto& current = runtime_observations.observations[index];
    if (current.context == execution_context_id && current.script == script_id)
      entry = &current;
  }
  if (!entry) {
    if (runtime_observations.count == runtime_observations.observations.size())
      return false;
    entry = &runtime_observations.observations[runtime_observations.count++];
    entry->context = execution_context_id;
    entry->script = script_id;
  }
  if (observation == NativeRuntimeScriptObservation::kStaticDispatchLoop)
    entry->dispatch = true;
  else
    entry->candidate = true;
  return true;
}

bool NativeProbeSink::RuntimeBufferHasSignal(const std::uint64_t generation,
                                             const std::uint64_t execution_context_id,
                                             const std::uint64_t frame_id,
                                             const std::size_t bytes,
                                             const std::uint64_t script_id,
                                             const bool is_eval) noexcept {
  if (generation == 0 || generation != RuntimeCaptureGeneration() || bytes < 32 ||
      bytes > kNativeArtifactMaxContentBytes || execution_context_id == 0 || script_id == 0)
    return false;
  bool candidate = false;
  bool dispatch = false;
  if (runtime_observations.generation == generation) {
    for (std::size_t index = 0; index < runtime_observations.count; ++index) {
      const auto& observation = runtime_observations.observations[index];
      if (observation.context == execution_context_id && observation.script == script_id) {
        candidate = observation.candidate;
        dispatch = observation.dispatch;
      }
    }
  }
  if (!candidate && !is_eval && !(bytes >= 256 && dispatch)) {
    if (runtime_observations.generation != generation) {
      runtime_observations = {};
      runtime_observations.generation = generation;
    }
    if (!runtime_observations.no_signal_reported) {
      runtime_observations.no_signal_reported =
          RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                                   "runtime_buffer_no_vm_signal", generation) != 0;
    }
    return false;
  }
  auto count = runtime_typed_array_count_.load(std::memory_order_relaxed);
  if (count >= kRuntimeTypedArrayMaxSnapshots) {
    if (count == kRuntimeTypedArrayMaxSnapshots &&
        RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                                 "runtime_typed_array_session_limit", generation) != 0) {
      runtime_typed_array_count_.compare_exchange_strong(count, count + 1,
                                                         std::memory_order_relaxed);
    }
    return false;
  }
  return true;
}

void NativeProbeSink::RecordRuntimeBufferOmission(const std::uint64_t generation,
                                                  const std::uint64_t frame_id,
                                                  const std::string_view reason) noexcept {
  if (generation != 0 && generation == RuntimeCaptureGeneration()) {
    RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id, reason, generation);
  }
}

void NativeProbeSink::CaptureRuntimeTypedArray(const std::uint64_t execution_context_id,
                                               const std::uint64_t frame_id,
                                               const std::string_view source_url,
                                               const std::span<const std::uint8_t> content,
                                               const NativeRuntimeScript& script) noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire)) [[likely]] {
    return;
  }
  if (content.size() < kRuntimeTypedArrayMinBytes ||
      content.size() > kNativeArtifactMaxContentBytes) {
    return;
  }
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0 ||
      (script.capture_generation != 0 && script.capture_generation != generation)) {
    return;
  }
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeGeneratedArtifactEmitter artifact_emitter =
      artifact_emitter_.load(std::memory_order_relaxed);
  const NativeRendererProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != generation || !artifact_emitter ||
      !emitter || (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kVm)) == 0 ||
      MonotonicTimeNs() >= expires_at) {
    return;
  }
  if (script.script_id == 0 ||
      (script.source.empty() &&
       RuntimeScriptSourceNeeded(execution_context_id, script.script_id)) ||
      script.source.size() > kNativeArtifactMaxContentBytes) {
    RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                             "allocating_script_unavailable", generation);
    return;
  }
  std::array<char, kNativeArtifactMaxUrlBytes> sanitized_storage{};
  const auto sanitized_url = SanitizeRuntimeSourceUrl(source_url, sanitized_storage);
  if (execution_context_id == 0 || sanitized_url.empty()) {
    RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                             "allocating_script_url_unavailable", generation);
    return;
  }
  // Source is present only on the first observed copy of this script. Register
  // that structural result before the keep-list read so later empty copies of
  // the same script still match. The winning region supplies every flag.
  if (!script.source.empty()) {
    const RuntimeSourceTier tier = ClassifyRuntimeSource(script.source);
    if (tier.likely) {
      (void)RegisterRuntimeScriptObservation(generation, execution_context_id, script.script_id,
                                             NativeRuntimeScriptObservation::kCapturedLikelyVm);
    } else if (tier.candidate) {
      (void)RegisterRuntimeScriptObservation(generation, execution_context_id, script.script_id,
                                             NativeRuntimeScriptObservation::kCapturedVmCandidate);
    }
    if (tier.dispatch) {
      (void)RegisterRuntimeScriptObservation(generation, execution_context_id, script.script_id,
                                             NativeRuntimeScriptObservation::kStaticDispatchLoop);
    }
  }
  if (!RuntimeBufferHasSignal(generation, execution_context_id, frame_id, content.size(),
                              script.script_id, script.is_eval))
    return;
  const std::size_t snapshot_index =
      runtime_typed_array_count_.fetch_add(1, std::memory_order_relaxed);
  if (snapshot_index >= kRuntimeTypedArrayMaxSnapshots) {
    if (snapshot_index == kRuntimeTypedArrayMaxSnapshots) {
      RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                               "runtime_typed_array_session_limit", generation);
    }
    return;
  }
  NativeRuntimeScript scoped_script = script;
  scoped_script.session_id = session_id_.load(std::memory_order_relaxed);
  if (config_generation_.load(std::memory_order_acquire) != generation) {
    return;
  }
  const std::uint64_t creator_event_id =
      RecordRuntimeBufferEvent(NativeProbeType::kApiCall, frame_id,
                               "runtime_typed_array_task_checkpoint_snapshot", generation);
  artifact_emitter(NativeArtifactKind::kBytecodeBuffer,
                   NativeArtifactCaptureOrigin::kRuntimeTypedArray, creator_event_id,
                   execution_context_id, frame_id, sanitized_url, content, scoped_script);
  if (!script.source.empty() && RuntimeScriptSourceNeeded(execution_context_id, script.script_id) &&
      runtime_script_cache.count < runtime_script_cache.keys.size()) {
    runtime_script_cache.keys[runtime_script_cache.count++] = {execution_context_id,
                                                               script.script_id};
  }
}

std::uint64_t NativeProbeSink::RecordRuntimeBufferEvent(const NativeProbeType type,
                                                        const std::uint64_t frame_id,
                                                        const std::string_view reason,
                                                        const std::uint64_t generation) noexcept {
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = type;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.monotonic_time_ns = MonotonicTimeNs();
  event.header.session_id = session_id_.load(std::memory_order_relaxed);
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  SetPayload(event, reason);
  const auto emitter = emitter_.load(std::memory_order_acquire);
  return emitter && CanAdmitEvent(event, generation) && emitter(event, generation)
             ? event.header.sequence_number
             : 0;
}

void NativeProbeSink::CaptureGeneratedArtifact(
    const NativeArtifactKind kind,
    const NativeArtifactCaptureOrigin capture_origin,
    const std::uint64_t creator_event_id,
    const std::uint64_t execution_context_id,
    const std::uint64_t frame_id,
    const std::string_view source_url,
    const std::span<const std::uint8_t> content) noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire) || source_url.empty() ||
      source_url.size() > kNativeArtifactMaxUrlBytes || content.empty() ||
      content.size() > kNativeArtifactMaxContentBytes) [[likely]] {
    return;
  }
  const bool valid_kind_and_origin =
      (kind == NativeArtifactKind::kJavaScript &&
       capture_origin == NativeArtifactCaptureOrigin::kDynamicJavaScript) ||
      (kind == NativeArtifactKind::kWasm &&
       (capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyCompile ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyModule ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyInstantiate)) ||
      (kind == NativeArtifactKind::kCanvasDataUrl &&
       capture_origin == NativeArtifactCaptureOrigin::kCanvasToDataUrl && creator_event_id != 0 &&
       execution_context_id == 0) ||
      (kind == NativeArtifactKind::kBytecodeBuffer &&
       capture_origin == NativeArtifactCaptureOrigin::kRuntimeTypedArray);
  if (!valid_kind_and_origin ||
      (kind != NativeArtifactKind::kCanvasDataUrl && execution_context_id == 0)) {
    return;
  }
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return;
  }
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeGeneratedArtifactEmitter artifact_emitter =
      artifact_emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != generation || !artifact_emitter ||
      (category_mask & NativeProbeCategoryMask(kind == NativeArtifactKind::kBytecodeBuffer
                                                   ? NativeProbeCategory::kVm
                                                   : NativeProbeCategory::kArtifact)) == 0 ||
      MonotonicTimeNs() >= expires_at) {
    return;
  }
  artifact_emitter(kind, capture_origin, creator_event_id, execution_context_id, frame_id,
                   source_url, content, {});
}

void NativeProbeSink::RecordApiCall(const NativeProbeCategory category,
                                    const std::string_view operation) noexcept {
  static_cast<void>(RecordSurfaceOperation(category, NativeProbeType::kApiCall, operation));
}

void NativeProbeSink::RecordPropertyRead(const NativeProbeCategory category,
                                         const std::string_view operation) noexcept {
  static_cast<void>(RecordSurfaceOperation(category, NativeProbeType::kPropertyRead, operation));
}

void NativeProbeSink::RecordApiCallOnce(const NativeProbeCategory category,
                                        const std::string_view operation,
                                        std::atomic<std::uint64_t>& observed_generation) noexcept {
  static_cast<void>(
      RecordSurfaceOperation(category, NativeProbeType::kApiCall, operation, &observed_generation));
}

void NativeProbeSink::RecordPropertyReadOnce(
    const NativeProbeCategory category,
    const std::string_view operation,
    std::atomic<std::uint64_t>& observed_generation) noexcept {
  static_cast<void>(RecordSurfaceOperation(category, NativeProbeType::kPropertyRead, operation,
                                           &observed_generation));
}

std::uint64_t NativeProbeSink::RecordSurfaceOperation(
    const NativeProbeCategory category,
    const NativeProbeType type,
    const std::string_view operation,
    std::atomic<std::uint64_t>* const observed_generation) noexcept {
  if (!emitter_.load(std::memory_order_acquire)) [[likely]] {
    return 0;
  }
  if (!IsFingerprintSurfaceCategory(category) ||
      (type != NativeProbeType::kApiCall && type != NativeProbeType::kPropertyRead) ||
      operation.empty()) {
    return 0;
  }
  const std::uint64_t config_generation = config_generation_.load(std::memory_order_acquire);
  if ((config_generation & 1U) != 0) {
    return 0;
  }
  const std::uint64_t monotonic_time_ns = MonotonicTimeNs();
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at_monotonic_ns =
      expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const NativeRendererProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != config_generation || !emitter ||
      (category_mask & NativeProbeCategoryMask(category)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns) {
    return 0;
  }

  if (observed_generation) {
    std::uint64_t observed = observed_generation->load(std::memory_order_relaxed);
    // Even values claim an in-flight or accepted observation. A failed claim
    // releases to generation - 1, preserving a watermark above every older
    // configuration. One CAS bounds work under competing same-site callers.
    if (observed >= config_generation ||
        !observed_generation->compare_exchange_strong(observed, config_generation,
                                                      std::memory_order_relaxed)) {
      return 0;
    }
  }

  NativeProbeEvent event;
  event.header.category = category;
  event.header.type = type;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.session_id = session_id;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  const NativeProbeFrameIdProvider frame_id_provider =
      frame_id_provider_.load(std::memory_order_relaxed);
  event.header.frame_id = frame_id_provider ? frame_id_provider() : 0;
  SetPayload(event, operation);
  if (!emitter(event, config_generation)) {
    if (observed_generation) {
      std::uint64_t claimed = config_generation;
      // Never erase a newer configuration's claim or its failure watermark.
      observed_generation->compare_exchange_strong(claimed, config_generation - 1,
                                                   std::memory_order_relaxed);
    }
    return 0;
  }
  return event.header.sequence_number;
}

void NativeProbeSink::RecordCanvasToDataUrl() noexcept {
  RecordApiCall(NativeProbeCategory::kCanvas, "canvas.toDataURL");
}

void NativeProbeSink::RecordCanvasToDataUrl(const std::string_view data_url) noexcept {
  constexpr std::string_view kImageDataUrlPrefix = "data:image/";
  if (!IsCanvasImageCaptureEnabled() || !data_url.starts_with(kImageDataUrlPrefix) ||
      data_url.find(";base64,") == std::string_view::npos ||
      data_url.size() > kCanvasDataUrlMaxBytes) {
    RecordCanvasToDataUrl();
    return;
  }
  const std::uint64_t creator_event_id = RecordSurfaceOperation(
      NativeProbeCategory::kCanvas, NativeProbeType::kApiCall, "canvas.toDataURL");
  if (creator_event_id == 0) {
    return;
  }
  CaptureGeneratedArtifact(
      NativeArtifactKind::kCanvasDataUrl, NativeArtifactCaptureOrigin::kCanvasToDataUrl,
      creator_event_id, 0, 0, "canvas://readback",
      // SAFETY: both pointer and byte count come from the same retained view;
      // uint8_t aliases its char storage without changing length or ownership.
      UNSAFE_BUFFERS(
          std::span(reinterpret_cast<const std::uint8_t*>(data_url.data()), data_url.size())));
}

void NativeProbeSink::RecordWebAudioCall(const std::string_view operation) noexcept {
  RecordApiCall(NativeProbeCategory::kWebAudio, operation);
}

void NativeProbeSink::RecordRequestInitiated(const std::int32_t request_id,
                                             const std::string_view method,
                                             const std::string_view url) noexcept {
  if (!emitter_.load(std::memory_order_acquire)) [[likely]] {
    return;
  }
  const std::uint64_t config_generation = config_generation_.load(std::memory_order_acquire);
  if ((config_generation & 1U) != 0) {
    return;
  }
  const std::uint64_t monotonic_time_ns = MonotonicTimeNs();
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at_monotonic_ns =
      expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const NativeRendererProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != config_generation || !emitter ||
      (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns) {
    return;
  }

  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kRequestInitiated;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.request_id = static_cast<std::uint64_t>(static_cast<std::uint32_t>(request_id));
  SetPayload(event, method, " ");
  const std::size_t method_size = event.header.payload_size;
  if ((event.header.flags & static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated)) == 0) {
    const std::size_t available = event.inline_payload.size() - method_size;
    const std::size_t url_size = std::min(url.size(), available);
    std::transform(url.begin(), url.begin() + static_cast<std::ptrdiff_t>(url_size),
                   event.inline_payload.begin() + static_cast<std::ptrdiff_t>(method_size),
                   [](const char character) {
                     return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    event.header.payload_size += static_cast<std::uint32_t>(url_size);
    if (url_size != url.size()) {
      event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
    }
  }
  static_cast<void>(emitter(event, config_generation));
}

void NativeProbeSink::NoteVmDispatchLoss(const std::uint64_t generation,
                                         const std::uint64_t session_id,
                                         const std::uint64_t monotonic_time_ns,
                                         const std::uint64_t frame_id,
                                         const std::uint32_t process_id,
                                         const std::uint32_t thread_id,
                                         const std::uint64_t interpreter_artifact_id) noexcept {
  const std::uint64_t previous_artifact =
      dispatch_loss_artifact_id_.load(std::memory_order_relaxed);
  if (previous_artifact != 0 && previous_artifact != interpreter_artifact_id &&
      dispatch_loss_dropped_.load(std::memory_order_relaxed) >
          dispatch_loss_reported_.load(std::memory_order_relaxed)) {
    PublishVmDispatchBudgetGap();
  }
  dispatch_loss_generation_.store(generation, std::memory_order_relaxed);
  dispatch_loss_session_id_.store(session_id, std::memory_order_relaxed);
  dispatch_loss_time_ns_.store(monotonic_time_ns, std::memory_order_relaxed);
  dispatch_loss_frame_id_.store(frame_id, std::memory_order_relaxed);
  dispatch_loss_process_id_.store(process_id, std::memory_order_relaxed);
  dispatch_loss_thread_id_.store(thread_id, std::memory_order_relaxed);
  dispatch_loss_artifact_id_.store(interpreter_artifact_id, std::memory_order_relaxed);
  std::uint64_t dropped = dispatch_loss_dropped_.load(std::memory_order_relaxed);
  while (dropped != std::numeric_limits<std::uint64_t>::max() &&
         !dispatch_loss_dropped_.compare_exchange_weak(dropped, dropped + 1,
                                                       std::memory_order_relaxed)) {
  }
}

void NativeProbeSink::PublishVmDispatchBudgetGap() noexcept {
  // EmitEvent publishes pending losses before a normal event. The gap emit
  // re-enters EmitEvent, which must not publish again on this thread.
  thread_local bool publishing = false;
  if (publishing) {
    return;
  }
  if (!emitter_.load(std::memory_order_acquire)) {
    return;
  }
  publishing = true;
  struct ClearPublish {
    bool& flag;
    ~ClearPublish() { flag = false; }
  } clear{publishing};

  for (int attempt = 0; attempt < 4; ++attempt) {
    const std::uint64_t generation = dispatch_loss_generation_.load(std::memory_order_relaxed);
    const std::uint64_t dropped = dispatch_loss_dropped_.load(std::memory_order_relaxed);
    std::uint64_t reported = dispatch_loss_reported_.load(std::memory_order_relaxed);
    if (generation == 0 || (generation & 1U) != 0 || dropped <= reported) {
      return;
    }
    if (!dispatch_loss_reported_.compare_exchange_strong(reported, dropped,
                                                         std::memory_order_relaxed)) {
      continue;
    }
    const std::uint64_t weight = dropped - reported;
    NativeProbeEvent reference{};
    reference.header.category = NativeProbeCategory::kVm;
    reference.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
    reference.header.monotonic_time_ns = dispatch_loss_time_ns_.load(std::memory_order_relaxed);
    reference.header.session_id = dispatch_loss_session_id_.load(std::memory_order_relaxed);
    reference.header.process_id = dispatch_loss_process_id_.load(std::memory_order_relaxed);
    reference.header.thread_id = dispatch_loss_thread_id_.load(std::memory_order_relaxed);
    reference.header.frame_id = dispatch_loss_frame_id_.load(std::memory_order_relaxed);
    NativeProbeEvent gap = MakeNativeProbeGapEvent(reference, weight);
    gap.header.frame_id = reference.header.frame_id;
    gap.header.artifact_id = dispatch_loss_artifact_id_.load(std::memory_order_relaxed);
    const NativeProbeEmitStatus status = NativeProbeTransport::EmitStatus(gap, generation);
    if (status == NativeProbeEmitStatus::kAdmitted) {
      continue;
    }
    if (status == NativeProbeEmitStatus::kQueueFull) {
      // TryPush already added this weight to DroppedCount. Keeping the claim
      // avoids a second budget gap for the same observations.
      return;
    }
    std::uint64_t claimed = dropped;
    static_cast<void>(dispatch_loss_reported_.compare_exchange_strong(claimed, reported,
                                                                      std::memory_order_relaxed));
    return;
  }
}

void NativeProbeSink::RecordVmDispatchSample(const NativeVmDispatchSamplePayload& sample) noexcept {
  if (!IsEmittableVmDispatchSample(sample) || !emitter_.load(std::memory_order_acquire)) {
    return;
  }
  const std::uint64_t config_generation = config_generation_.load(std::memory_order_acquire);
  if ((config_generation & 1U) != 0) {
    return;
  }
  const std::uint64_t monotonic_time_ns = MonotonicTimeNs();
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at_monotonic_ns =
      expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const NativeRendererProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != config_generation || !emitter ||
      session_id == 0 || (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kVm)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns) {
    return;
  }

  const NativeProbeFrameIdProvider frame_id_provider =
      frame_id_provider_.load(std::memory_order_relaxed);
  const std::uint64_t frame_id = frame_id_provider ? frame_id_provider() : 0;
  const auto process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  const auto thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  const auto note_loss = [&]() {
    NoteVmDispatchLoss(config_generation, session_id, monotonic_time_ns, frame_id, process_id,
                       thread_id, sample.interpreter_artifact_id);
  };

  const std::uint32_t recorded = dispatch_sample_budget_.TryReserve(config_generation);
  if (recorded >= kNativeVmDispatchSampleBudget) {
    note_loss();
    return;
  }

  NativeProbeEvent event;
  if (PrepareVmDispatchProbeEvent(sample, recorded, 0, monotonic_time_ns, session_id, process_id,
                                  thread_id, frame_id,
                                  event) != NativeVmDispatchPrepareStatus::kReady) {
    dispatch_sample_budget_.Release(recorded, config_generation);
    return;
  }
  // Flush an earlier rejected emit before this sample takes a sequence, so the
  // gap is queued first and its sequence stays below this sample.
  PublishVmDispatchBudgetGap();
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  switch (NativeProbeTransport::EmitStatus(event, config_generation)) {
    case NativeProbeEmitStatus::kAdmitted:
      return;
    case NativeProbeEmitStatus::kQueueFull:
      // The ring counted this sample. Return the budget slot so a later
      // observation can use it after the queue drains.
      dispatch_sample_budget_.Release(recorded, config_generation);
      return;
    case NativeProbeEmitStatus::kRejected:
      dispatch_sample_budget_.Release(recorded, config_generation);
      note_loss();
      return;
  }
}

bool NativeProbeSink::SnapshotVmAdmission(VmAdmission& admission) const noexcept {
  admission = {};
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if (generation == 0 || (generation & 1U) != 0 || !emitter_.load(std::memory_order_acquire)) {
    return false;
  }
  const std::uint64_t monotonic_time_ns = MonotonicTimeNs();
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at_monotonic_ns =
      expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const NativeRendererProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != generation || emitter == nullptr ||
      session_id == 0 || (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kVm)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns) {
    return false;
  }
  const NativeProbeFrameIdProvider frame_id_provider =
      frame_id_provider_.load(std::memory_order_relaxed);
  admission.generation = generation;
  admission.session_id = session_id;
  admission.monotonic_time_ns = monotonic_time_ns;
  admission.frame_id = frame_id_provider ? frame_id_provider() : 0;
  admission.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  admission.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  return true;
}

void NativeProbeSink::DisableOwnedRegisterSampling() noexcept {
  owned_register_sampling_.store(0, std::memory_order_release);
}

bool NativeProbeSink::EnableOwnedRegisterSampling(
    const OwnedRegisterSamplePolicy& policy) noexcept {
  if (policy.finding_id == 0 || policy.investigation_id == 0 ||
      policy.interpreter_artifact_id == 0 || policy.bytecode_artifact_id == 0) {
    return false;
  }
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission)) {
    return false;
  }
  owned_register_finding_id_.store(policy.finding_id, std::memory_order_relaxed);
  owned_register_investigation_id_.store(policy.investigation_id, std::memory_order_relaxed);
  owned_register_interpreter_id_.store(policy.interpreter_artifact_id, std::memory_order_relaxed);
  owned_register_bytecode_id_.store(policy.bytecode_artifact_id, std::memory_order_relaxed);
  owned_register_sampling_.store(1, std::memory_order_release);
  return true;
}

void NativeProbeSink::IngestOwnedRegisterInvocation(const std::uint64_t invocation_id) noexcept {
  if (owned_register_sampling_.load(std::memory_order_acquire) == 0 || invocation_id == 0) {
    return;
  }
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission)) {
    return;
  }
  constexpr char kLabel[] = "owned-register-v1";
  constexpr std::uint16_t kLabelSize = sizeof(kLabel) - 1;
  static_assert(kLabelSize <= kNativeVmFindingLabelCapacity);
  NativeVmFindingPayload payload{};
  payload.kind = NativeVmFindingKind::kInvocation;
  payload.host_runtime = NativeVmHostRuntime::kUnknown;
  payload.confidence = NativeVmFindingConfidence::kObserved;
  payload.flags = static_cast<std::uint8_t>(NativeVmFindingFlag::kDynamic);
  payload.label_size = kLabelSize;
  payload.finding_id = owned_register_finding_id_.load(std::memory_order_relaxed);
  payload.investigation_id = owned_register_investigation_id_.load(std::memory_order_relaxed);
  payload.subject_id = invocation_id;
  payload.related_subject_id = owned_register_bytecode_id_.load(std::memory_order_relaxed);
  for (std::uint16_t index = 0; index < kLabelSize; ++index) {
    payload.label[index] = kLabel[index];
  }
  NativeProbeEvent event{};
  event.header.protocol_version = kNativeProbeProtocolVersion;
  event.header.header_size = sizeof(NativeProbeHeader);
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kVmFinding;
  event.header.payload_size = sizeof(NativeVmFindingPayload);
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.monotonic_time_ns = admission.monotonic_time_ns;
  event.header.session_id = admission.session_id;
  event.header.process_id = admission.process_id;
  event.header.thread_id = admission.thread_id;
  event.header.frame_id = admission.frame_id;
  event.header.artifact_id = owned_register_interpreter_id_.load(std::memory_order_relaxed);
  static_assert(sizeof(payload) <= kNativeProbeInlinePayloadSize);
  const auto payload_bytes = std::bit_cast<std::array<std::byte, sizeof(payload)>>(payload);
  std::ranges::copy(payload_bytes, event.inline_payload.begin());
  static_cast<void>(NativeProbeTransport::EmitStatus(event, admission.generation));
}

void NativeProbeSink::IngestOwnedRegisterStep(const std::uint32_t instruction_pointer,
                                              const std::uint32_t opcode,
                                              const std::uint8_t operand_count,
                                              const std::uint32_t sample_index) noexcept {
  if (owned_register_sampling_.load(std::memory_order_acquire) == 0) {
    return;
  }
  NativeVmDispatchSamplePayload sample{};
  sample.instruction_pointer = instruction_pointer;
  sample.opcode = opcode;
  sample.handler_index = opcode;
  sample.sample_index = sample_index;
  sample.operand_count = operand_count;
  sample.finding_id = owned_register_finding_id_.load(std::memory_order_relaxed);
  sample.investigation_id = owned_register_investigation_id_.load(std::memory_order_relaxed);
  sample.interpreter_artifact_id = owned_register_interpreter_id_.load(std::memory_order_relaxed);
  sample.bytecode_artifact_id = owned_register_bytecode_id_.load(std::memory_order_relaxed);
  RecordVmDispatchSample(sample);
}

void IngestOwnedRegisterInvocationThunk(const std::uint64_t invocation_id,
                                        void* const sink) noexcept {
  if (sink == nullptr) {
    return;
  }
  static_cast<NativeProbeSink*>(sink)->IngestOwnedRegisterInvocation(invocation_id);
}

void IngestOwnedRegisterStepThunk(const std::uint32_t instruction_pointer,
                                  const std::uint32_t opcode,
                                  const std::uint8_t operand_count,
                                  const std::uint32_t sample_index,
                                  void* const sink) noexcept {
  if (sink == nullptr) {
    return;
  }
  static_cast<NativeProbeSink*>(sink)->IngestOwnedRegisterStep(instruction_pointer, opcode,
                                                               operand_count, sample_index);
}

}  // namespace reb
