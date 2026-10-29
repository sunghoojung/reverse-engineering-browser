// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_wire.h"

#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/page_guest_dispatch.h"

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
  bool examined = false;
  bool unavailable = false;
};
struct RuntimeObservationCache final {
  std::uint64_t generation = 0;
  std::array<RuntimeObservation, 64> observations{};
  std::size_t count = 0;
  std::size_t next_negative = 0;
  std::size_t scans = 0;
  bool no_signal_reported = false;
  bool classification_limit_reported = false;
  bool classification_unavailable_reported = false;
  bool snapshot_limit_reported = false;
};
thread_local RuntimeObservationCache runtime_observations;

// Negative results may rotate so ordinary allocations cannot occupy every
// observation slot forever. Pin positive evidence, and bound all conversions
// (including retries after allocation failure) per generation and thread.
constexpr std::size_t kRuntimeScriptScanLimit = 256;

RuntimeObservation* FindRuntimeObservation(const std::uint64_t context,
                                           const std::uint64_t script) noexcept {
  for (std::size_t index = 0; index < runtime_observations.count; ++index) {
    auto& entry = runtime_observations.observations[index];
    if (entry.context == context && entry.script == script) {
      return &entry;
    }
  }
  return nullptr;
}

bool RuntimeObservationHasCapacity() noexcept {
  if (runtime_observations.count < runtime_observations.observations.size()) {
    return true;
  }
  for (const auto& entry : runtime_observations.observations) {
    if (!entry.candidate && !entry.dispatch) {
      return true;
    }
  }
  return false;
}

RuntimeObservation* ClaimRuntimeObservation(const std::uint64_t context,
                                            const std::uint64_t script) noexcept {
  if (auto* entry = FindRuntimeObservation(context, script)) {
    return entry;
  }
  auto* entry = static_cast<RuntimeObservation*>(nullptr);
  if (runtime_observations.count < runtime_observations.observations.size()) {
    entry = &runtime_observations.observations[runtime_observations.count++];
  } else {
    const std::size_t capacity = runtime_observations.observations.size();
    for (std::size_t offset = 0; offset < capacity; ++offset) {
      const std::size_t index = (runtime_observations.next_negative + offset) % capacity;
      auto& candidate = runtime_observations.observations[index];
      if (!candidate.candidate && !candidate.dispatch) {
        entry = &candidate;
        runtime_observations.next_negative = (index + 1U) % capacity;
        break;
      }
    }
  }
  if (entry) {
    *entry = {};
    entry->context = context;
    entry->script = script;
  }
  return entry;
}

constexpr char AsciiLower(unsigned char c) noexcept;

[[nodiscard]] bool StartsWithAscii(const std::string_view text,
                                   const std::string_view prefix) noexcept {
  if (text.size() < prefix.size()) {
    return false;
  }
  for (std::size_t index = 0; index < prefix.size(); ++index) {
    if (AsciiLower(static_cast<unsigned char>(text[index])) != prefix[index]) {
      return false;
    }
  }
  return true;
}

// Bounded, allocation-free metadata sanitization. Ambiguous or control-containing
// URLs are unavailable. data and javascript URLs must never become source metadata.
// allow_blob is false while decoding the inner origin of a blob URL.
std::string_view SanitizeRuntimeSourceUrl(std::string_view input,
                                          std::array<char, kNativeArtifactMaxUrlBytes>& output,
                                          const bool allow_blob) noexcept {
  if (input.empty() || input.size() > output.size()) {
    return {};
  }
  for (const char character : input) {
    const auto ch = static_cast<unsigned char>(character);
    if (ch <= 0x20 || ch == 0x7f || ch == '\\') {
      return {};
    }
  }
  input = input.substr(0, input.find_first_of("?#"));
  if (allow_blob && StartsWithAscii(input, "blob:")) {
    std::array<char, kNativeArtifactMaxUrlBytes> inner_storage{};
    const auto inner = SanitizeRuntimeSourceUrl(input.substr(5), inner_storage, false);
    if (inner.empty() ||
        (!StartsWithAscii(inner, "https://") && !StartsWithAscii(inner, "http://"))) {
      return {};
    }
    constexpr std::string_view kBlob = "blob:";
    if (kBlob.size() + inner.size() > output.size()) {
      return {};
    }
    for (std::size_t index = 0; index < kBlob.size(); ++index) {
      output[index] = kBlob[index];
    }
    for (std::size_t index = 0; index < inner.size(); ++index) {
      output[kBlob.size() + index] = inner[index];
    }
    return {output.data(), kBlob.size() + inner.size()};
  }
  const auto scheme = input.find("://");
  if (scheme == std::string_view::npos || scheme > 7) {
    return {};
  }
  std::array<char, 8> scheme_storage{};
  for (std::size_t index = 0; index < scheme; ++index) {
    const auto ch = input[index];
    scheme_storage[index] = ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + ('a' - 'A')) : ch;
  }
  const std::string_view scheme_name(scheme_storage.data(), scheme);
  const bool script_label = scheme_name == "script";
  if (scheme_name != "http" && scheme_name != "https" && scheme_name != "fixture" &&
      !script_label) {
    return {};
  }
  const std::size_t cut_begin = scheme + 3;
  const auto authority_end = input.find('/', cut_begin);
  const auto authority = input.substr(cut_begin, authority_end - cut_begin);
  std::size_t cut_end = 0;
  const auto at = authority.rfind('@');
  if (at != std::string_view::npos) {
    cut_end = cut_begin + at + 1;
  }
  if (authority.empty() || cut_end == cut_begin + authority.size()) {
    return {};
  }
  if (script_label) {
    if (at != std::string_view::npos || authority_end != std::string_view::npos) {
      return {};
    }
    for (const char character : authority) {
      if (character < '0' || character > '9') {
        return {};
      }
    }
  }
  std::size_t length = 0;
  for (std::size_t index = 0; index < input.size(); ++index) {
    if (cut_end != 0 && index >= cut_begin && index < cut_end) {
      continue;
    }
    output[length++] = input[index];
  }
  return {output.data(), length};
}

std::string_view SanitizeRuntimeSourceUrl(
    const std::string_view input,
    std::array<char, kNativeArtifactMaxUrlBytes>& output) noexcept {
  return SanitizeRuntimeSourceUrl(input, output, true);
}

// A script with no name is still the allocating script. The label is the id
// only, so the page cannot put source text into the URL field.
std::string_view RuntimeScriptIdentityLabel(
    std::uint64_t script_id,
    std::array<char, kNativeArtifactMaxUrlBytes>& output) noexcept {
  constexpr std::string_view kPrefix = "script://";
  std::array<char, 20> digits{};
  std::size_t count = 0;
  do {
    digits[count++] = static_cast<char>('0' + static_cast<int>(script_id % 10U));
    script_id /= 10U;
  } while (script_id != 0 && count < digits.size());
  if (kPrefix.size() + count > output.size()) {
    return {};
  }
  for (std::size_t index = 0; index < kPrefix.size(); ++index) {
    output[index] = kPrefix[index];
  }
  for (std::size_t index = 0; index < count; ++index) {
    output[kPrefix.size() + index] = digits[count - 1U - index];
  }
  return {output.data(), kPrefix.size() + count};
}

// Same structural weights as the offline JavaScript detector. Anti-bot lexical
// rules are relevance only and do not admit a buffer. The scan never executes
// source. One malloc/free pair keeps this path noexcept under -fno-exceptions.
constexpr std::size_t kRuntimeSourceScanBytes = kRuntimeScriptNoteBytes;
constexpr std::size_t kRuntimeSourceMaxFunctions = 256;
constexpr int kRuntimeCandidateScore = 20;
constexpr int kRuntimeLikelyScore = 60;
constexpr int kRuntimeLikelyFamilies = 3;

struct RuntimeSourceTier final {
  bool likely = false;
  bool candidate = false;
  bool dispatch = false;
  // False only when the scan did not run, so the caller can try again.
  bool scanned = false;
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

// The mask is a forward lexer, not a parser. Retain token context separately
// from the bytes being blanked: a string, template or regex is still an operand
// when deciding whether the next slash is division. Reuse the classifier's
// bounded scratch stack for delimiter context instead of rescanning backwards.
enum class ScriptDelimiter : std::size_t {
  kGroup,
  kControl,
  kFunctionExpression,
  kFunctionDeclaration,
  kObject,
  kExpressionBody,
  kStatementBody,
  kBracket,
  kPendingClassExpression,
  kPendingClassDeclaration,
};

void MaskScriptSource(const std::span<char> text,
                      const std::span<std::size_t> delimiters) noexcept {
  std::size_t depth = 0;
  bool operand_expected = true;
  bool statement_start = true;
  bool property_name = false;
  bool control_paren = false;
  bool label_pending = false;
  ScriptDelimiter function_paren = ScriptDelimiter::kGroup;
  ScriptDelimiter function_body = ScriptDelimiter::kGroup;
  for (std::size_t index = 0; index < text.size(); ++index) {
    const char current = text[index];
    const char next = index + 1U < text.size() ? text[index + 1U] : '\0';
    if (IsAsciiSpace(static_cast<unsigned char>(current))) {
      continue;
    }
    if (current == '/' && (next == '/' || next == '*')) {
      const bool line = next == '/';
      text[index++] = ' ';
      text[index] = ' ';
      while (index + 1U < text.size()) {
        ++index;
        const char ch = text[index];
        text[index] = ' ';
        if (line && (ch == '\n' || ch == '\r')) {
          text[index] = ch;
          break;
        }
        if (!line && ch == '*' && index + 1U < text.size() && text[index + 1U] == '/') {
          text[++index] = ' ';
          break;
        }
      }
      continue;
    }
    if (current == '\'' || current == '"' || current == '`' ||
        (current == '/' && operand_expected)) {
      const bool regex = current == '/';
      bool escaped = false;
      bool character_class = false;
      text[index] = ' ';
      while (index + 1U < text.size()) {
        ++index;
        const char ch = text[index];
        text[index] = ' ';
        if (escaped) {
          escaped = false;
        } else if (ch == '\\') {
          escaped = true;
        } else if (regex && ch == '[') {
          character_class = true;
        } else if (regex && ch == ']') {
          character_class = false;
        } else if (ch == current && !character_class) {
          if (regex) {
            while (index + 1U < text.size() &&
                   IsIdentCont(static_cast<unsigned char>(text[index + 1U]))) {
              text[++index] = ' ';
            }
          }
          break;
        }
      }
      operand_expected = false;
      statement_start = false;
      property_name = false;
      control_paren = false;
      function_body = ScriptDelimiter::kGroup;
      continue;
    }
    if (IsIdentStart(static_cast<unsigned char>(current))) {
      const std::size_t start = index;
      while (index + 1U < text.size() &&
             IsIdentCont(static_cast<unsigned char>(text[index + 1U]))) {
        ++index;
      }
      const auto word_bytes = text.subspan(start, index - start + 1U);
      const std::string_view word(word_bytes.data(), word_bytes.size());
      if (!property_name && word == "class") {
        // Pending classes are stack entries too: an extends expression can
        // contain another class or function without losing the outer body.
        delimiters[depth++] =
            static_cast<std::size_t>(statement_start ? ScriptDelimiter::kPendingClassDeclaration
                                                     : ScriptDelimiter::kPendingClassExpression);
      }
      const bool starts_statement = statement_start;
      label_pending = !property_name && starts_statement;
      if (!property_name && word == "function") {
        function_paren = statement_start ? ScriptDelimiter::kFunctionDeclaration
                                         : ScriptDelimiter::kFunctionExpression;
      }
      control_paren = !property_name && (word == "if" || word == "while" || word == "for" ||
                                         word == "with" || word == "switch" || word == "catch");
      operand_expected = !property_name && (control_paren || word == "return" || word == "throw" ||
                                            word == "typeof" || word == "case" || word == "void" ||
                                            word == "delete" || word == "in" || word == "of" ||
                                            word == "yield" || word == "await" || word == "new" ||
                                            word == "instanceof" || word == "else" || word == "do");
      statement_start =
          !property_name && (word == "else" || word == "do" || word == "try" || word == "finally" ||
                             word == "catch" || (word == "async" && starts_statement));
      property_name = false;
      function_body = ScriptDelimiter::kGroup;
      continue;
    }
    if (current >= '0' && current <= '9') {
      while (index + 1U < text.size()) {
        const char ch = text[index + 1U];
        if (!IsIdentCont(static_cast<unsigned char>(ch)) && ch != '.' &&
            !((ch == '+' || ch == '-') && (text[index] == 'e' || text[index] == 'E'))) {
          break;
        }
        ++index;
      }
      operand_expected = false;
      statement_start = false;
    } else if (current == '(') {
      const auto kind = function_paren != ScriptDelimiter::kGroup
                            ? function_paren
                            : (control_paren ? ScriptDelimiter::kControl : ScriptDelimiter::kGroup);
      delimiters[depth++] = static_cast<std::size_t>(kind);
      function_paren = ScriptDelimiter::kGroup;
      operand_expected = true;
      statement_start = false;
    } else if (current == '{' || current == '[') {
      auto class_body = ScriptDelimiter::kGroup;
      if (current == '{' && depth > 0) {
        const auto pending = static_cast<ScriptDelimiter>(delimiters[depth - 1U]);
        if (pending == ScriptDelimiter::kPendingClassExpression ||
            pending == ScriptDelimiter::kPendingClassDeclaration) {
          --depth;
          class_body = pending == ScriptDelimiter::kPendingClassDeclaration
                           ? ScriptDelimiter::kStatementBody
                           : ScriptDelimiter::kExpressionBody;
        }
      }
      const auto kind = current == '['                             ? ScriptDelimiter::kBracket
                        : class_body != ScriptDelimiter::kGroup    ? class_body
                        : function_body != ScriptDelimiter::kGroup ? function_body
                        : statement_start || !operand_expected     ? ScriptDelimiter::kStatementBody
                                                                   : ScriptDelimiter::kObject;
      delimiters[depth++] = static_cast<std::size_t>(kind);
      operand_expected = true;
      statement_start =
          kind == ScriptDelimiter::kStatementBody || kind == ScriptDelimiter::kExpressionBody;
    } else if (current == ')' || current == '}' || current == ']') {
      const auto kind =
          depth == 0 ? ScriptDelimiter::kGroup : static_cast<ScriptDelimiter>(delimiters[--depth]);
      operand_expected =
          kind == ScriptDelimiter::kControl || kind == ScriptDelimiter::kStatementBody;
      statement_start = operand_expected;
      function_body =
          kind == ScriptDelimiter::kFunctionDeclaration  ? ScriptDelimiter::kStatementBody
          : kind == ScriptDelimiter::kFunctionExpression ? ScriptDelimiter::kExpressionBody
                                                         : ScriptDelimiter::kGroup;
      control_paren = false;
      property_name = false;
      continue;
    } else if (current == '=' && next == '>') {
      ++index;
      function_body = ScriptDelimiter::kExpressionBody;
      operand_expected = true;
      statement_start = false;
      continue;
    } else if ((current == '+' || current == '-') && next == current) {
      // Prefix ++/-- still needs an operand; postfix ++/-- has one.
      ++index;
      statement_start = false;
    } else {
      operand_expected = current != '.';
      statement_start = current == ';' || (current == ':' && label_pending);
    }
    label_pending = false;
    property_name = current == '.';
    control_paren = false;
    function_body = ScriptDelimiter::kGroup;
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

[[nodiscard]] RuntimeSourceTier ScannedNone() noexcept {
  RuntimeSourceTier tier;
  tier.scanned = true;
  return tier;
}

[[nodiscard]] RuntimeSourceTier ClassifyRuntimeSource(
    const std::span<const std::uint8_t> source,
    const bool source_truncated = false) noexcept {
  if (source.empty()) {
    return ScannedNone();
  }
  // A caller that already cut the script to the scan window must say so.
  // Otherwise an unclosed brace at the cut erases a complete function inside it.
  // length never exceeds the bytes actually passed in.
  const bool truncated = source_truncated || source.size() > kRuntimeSourceScanBytes;
  const std::size_t length = std::min(source.size(), kRuntimeSourceScanBytes);
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
  MaskScriptSource(text, brace_stack);

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
    return ScannedNone();
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
      return ScannedNone();
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
  best_tier.scanned = true;
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
  DisablePageGuestSampling();
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
  native_guest_adapter_.store(nullptr, std::memory_order_release);
  native_guest_capture_.store(nullptr, std::memory_order_release);
  native_guest_host_.store(nullptr, std::memory_order_release);
  if (const auto reset = native_guest_reset_.load(std::memory_order_acquire))
    reset();
  const bool active = emitter && artifact_emitter;
  session_id_.store(active ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(active ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(active ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  capture_canvas_images_.store(active && capture_canvas_images, std::memory_order_relaxed);
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
  auto* entry = ClaimRuntimeObservation(execution_context_id, script_id);
  if (!entry)
    return false;
  if (observation == NativeRuntimeScriptObservation::kStaticDispatchLoop)
    entry->dispatch = true;
  else
    entry->candidate = true;
  entry->examined = true;
  entry->unavailable = false;
  return true;
}

bool NativeProbeSink::RuntimeScriptSourceNoted(const std::uint64_t generation,
                                               const std::uint64_t execution_context_id,
                                               const std::uint64_t script_id) const noexcept {
  if (generation == 0 || runtime_observations.generation != generation ||
      execution_context_id == 0 || script_id == 0)
    return false;
  const auto* entry = FindRuntimeObservation(execution_context_id, script_id);
  return entry && entry->examined;
}

bool NativeProbeSink::RuntimeScriptNoteAccepts(const std::uint64_t generation,
                                               const std::uint64_t execution_context_id,
                                               const std::uint64_t script_id) const noexcept {
  if (generation == 0 || generation != RuntimeCaptureGeneration() || execution_context_id == 0 ||
      script_id == 0) {
    return false;
  }
  if (runtime_observations.generation != generation) {
    return true;
  }
  const auto* entry = FindRuntimeObservation(execution_context_id, script_id);
  return (!entry || !entry->examined) && runtime_observations.scans < kRuntimeScriptScanLimit &&
         (entry || RuntimeObservationHasCapacity());
}

bool NativeProbeSink::RememberRuntimeScriptMiss(const std::uint64_t generation,
                                                const std::uint64_t execution_context_id,
                                                const std::uint64_t script_id) noexcept {
  if (generation == 0 || generation != RuntimeCaptureGeneration() || execution_context_id == 0 ||
      script_id == 0) {
    return false;
  }
  if (runtime_observations.generation != generation) {
    runtime_observations = {};
    runtime_observations.generation = generation;
  }
  if (!RuntimeScriptNoteAccepts(generation, execution_context_id, script_id)) {
    return false;
  }
  ++runtime_observations.scans;
  auto* entry = ClaimRuntimeObservation(execution_context_id, script_id);
  if (entry) {
    entry->examined = true;
    entry->unavailable = true;
  }
  return false;
}

bool NativeProbeSink::NoteRuntimeScriptSource(const std::uint64_t generation,
                                              const std::uint64_t execution_context_id,
                                              const std::uint64_t script_id,
                                              const std::span<const std::uint8_t> source,
                                              const bool source_truncated) noexcept {
  if (generation == 0 || generation != RuntimeCaptureGeneration() || execution_context_id == 0 ||
      script_id == 0 || source.empty())
    return false;
  if (runtime_observations.generation != generation) {
    runtime_observations = {};
    runtime_observations.generation = generation;
  }
  const auto* existing = FindRuntimeObservation(execution_context_id, script_id);
  if (existing && existing->examined)
    return existing->candidate || existing->dispatch;
  if (!RuntimeScriptNoteAccepts(generation, execution_context_id, script_id)) {
    return false;
  }
  ++runtime_observations.scans;
  const RuntimeSourceTier tier = ClassifyRuntimeSource(source, source_truncated);
  if (!tier.scanned) {
    return false;
  }
  auto* entry = ClaimRuntimeObservation(execution_context_id, script_id);
  if (!entry) {
    return false;
  }
  entry->examined = true;
  if (tier.likely || tier.candidate)
    entry->candidate = true;
  if (tier.dispatch)
    entry->dispatch = true;
  return entry->candidate || entry->dispatch;
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
  if (runtime_observations.generation != generation) {
    runtime_observations = {};
    runtime_observations.generation = generation;
  }
  const auto* observation = FindRuntimeObservation(execution_context_id, script_id);
  const bool candidate = observation && observation->candidate;
  const bool dispatch = observation && observation->dispatch;
  if (!candidate && !is_eval && !(bytes >= 256 && dispatch)) {
    if (!observation || !observation->examined || observation->unavailable) {
      const bool limited = !observation && (runtime_observations.scans >= kRuntimeScriptScanLimit ||
                                            !RuntimeObservationHasCapacity());
      auto& reported = limited ? runtime_observations.classification_limit_reported
                               : runtime_observations.classification_unavailable_reported;
      if (!reported) {
        reported = RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                                            limited ? "runtime_script_classification_limit"
                                                    : "runtime_script_classification_unavailable",
                                            generation) != 0;
      }
      return false;
    }
    if (!runtime_observations.no_signal_reported) {
      runtime_observations.no_signal_reported =
          RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                                   "runtime_buffer_no_vm_signal", generation) != 0;
    }
    return false;
  }
  for (const auto& slot : runtime_snapshot_generations_) {
    if (slot.load(std::memory_order_relaxed) < generation) {
      return true;
    }
  }
  if (!runtime_observations.snapshot_limit_reported) {
    runtime_observations.snapshot_limit_reported =
        RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                                 "runtime_typed_array_session_limit", generation) != 0;
  }
  return false;
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
  ObserveCapturedJavaScriptSwitchProgram(content);
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
  auto sanitized_url = SanitizeRuntimeSourceUrl(source_url, sanitized_storage);
  if (sanitized_url.empty() && source_url.empty()) {
    std::array<char, kNativeArtifactMaxUrlBytes> label_storage{};
    const auto label = RuntimeScriptIdentityLabel(script.script_id, label_storage);
    sanitized_url = SanitizeRuntimeSourceUrl(label, sanitized_storage);
  }
  if (execution_context_id == 0 || sanitized_url.empty()) {
    RecordRuntimeBufferEvent(NativeProbeType::kArtifactCaptureFailed, frame_id,
                             "allocating_script_url_unavailable", generation);
    return;
  }
  // Both the allocation hook and direct captures share the same bounded cache.
  // Repeated sources must not bypass negative caching or the total scan budget.
  if (!script.source.empty()) {
    (void)NoteRuntimeScriptSource(generation, execution_context_id, script.script_id,
                                  script.source);
  }
  if (!RuntimeBufferHasSignal(generation, execution_context_id, frame_id, content.size(),
                              script.script_id, script.is_eval))
    return;
  NativeRuntimeScript scoped_script = script;
  scoped_script.session_id = session_id_.load(std::memory_order_relaxed);
  if (config_generation_.load(std::memory_order_acquire) != generation) {
    return;
  }
  std::atomic<std::uint64_t>* claim = nullptr;
  for (auto& slot : runtime_snapshot_generations_) {
    auto previous = slot.load(std::memory_order_relaxed);
    // One CAS per slot bounds contention. A newer generation can reclaim an
    // old slot, but a delayed old capture can never reclaim a newer slot.
    if (previous < generation &&
        slot.compare_exchange_strong(previous, generation, std::memory_order_relaxed)) {
      claim = &slot;
      break;
    }
  }
  if (!claim) {
    if (RuntimeBufferHasSignal(generation, execution_context_id, frame_id, content.size(),
                               script.script_id, script.is_eval)) {
      RecordRuntimeBufferOmission(generation, frame_id, "runtime_buffer_snapshot_contention");
    }
    return;
  }
  const std::uint64_t creator_event_id =
      RecordRuntimeBufferEvent(NativeProbeType::kApiCall, frame_id,
                               "runtime_typed_array_task_checkpoint_snapshot", generation);
  // Rejected creator metadata cannot produce an artifact. Release only our
  // generation's reservation, never a slot reclaimed by a replacement session.
  if (creator_event_id == 0 || RuntimeCaptureGeneration() != generation) {
    auto expected = generation;
    claim->compare_exchange_strong(expected, generation - 1U, std::memory_order_relaxed);
    return;
  }
  scoped_script.capture_generation = generation;
  artifact_emitter(NativeArtifactKind::kBytecodeBuffer,
                   NativeArtifactCaptureOrigin::kRuntimeTypedArray, creator_event_id,
                   execution_context_id, frame_id, sanitized_url, content, scoped_script);
  if (RuntimeCaptureGeneration() != generation) {
    return;
  }
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
  return EmitStatus(event, generation) == NativeProbeEmitStatus::kAdmitted
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
  if (TryRecordNativeGuestHost(event, config_generation))
    return event.header.sequence_number;
  if (emitter(event, config_generation) != NativeProbeEmitStatus::kAdmitted) {
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

NativeProbeEmitStatus NativeProbeSink::EmitStatus(const NativeProbeEvent& event,
                                                  const std::uint64_t generation) const noexcept {
  const auto emitter = emitter_.load(std::memory_order_acquire);
  return emitter && CanAdmitEvent(event, generation) ? emitter(event, generation)
                                                     : NativeProbeEmitStatus::kRejected;
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
    ~ClearPublish() { publishing = false; }
  } clear;

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
    const NativeProbeEmitStatus status = EmitStatus(gap, generation);
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
  switch (EmitStatus(event, config_generation)) {
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
  constexpr std::string_view kLabel = "owned-register-v1";
  constexpr std::uint16_t kLabelSize = kLabel.size();
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
  static_cast<void>(EmitStatus(event, admission.generation));
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

void NativeProbeSink::DisablePageGuestSampling() noexcept {
  javascript_switch_sampling_.store(0, std::memory_order_release);
  wasm_br_table_sampling_.store(0, std::memory_order_release);
}

bool NativeProbeSink::EnableJavaScriptSwitchSampling(const PageGuestSamplePolicy& policy) noexcept {
  if (policy.finding_id == 0 || policy.investigation_id == 0 ||
      policy.interpreter_artifact_id == 0 || policy.bytecode_artifact_id == 0) {
    return false;
  }
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission)) {
    return false;
  }
  javascript_switch_finding_id_.store(policy.finding_id, std::memory_order_relaxed);
  javascript_switch_investigation_id_.store(policy.investigation_id, std::memory_order_relaxed);
  javascript_switch_interpreter_id_.store(policy.interpreter_artifact_id,
                                          std::memory_order_relaxed);
  javascript_switch_bytecode_id_.store(policy.bytecode_artifact_id, std::memory_order_relaxed);
  javascript_switch_sampling_.store(1, std::memory_order_release);
  return true;
}

bool NativeProbeSink::EnableWasmBrTableSampling(const PageGuestSamplePolicy& policy) noexcept {
  if (policy.finding_id == 0 || policy.investigation_id == 0 ||
      policy.interpreter_artifact_id == 0 || policy.bytecode_artifact_id == 0) {
    return false;
  }
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission)) {
    return false;
  }
  wasm_br_table_finding_id_.store(policy.finding_id, std::memory_order_relaxed);
  wasm_br_table_investigation_id_.store(policy.investigation_id, std::memory_order_relaxed);
  wasm_br_table_interpreter_id_.store(policy.interpreter_artifact_id, std::memory_order_relaxed);
  wasm_br_table_bytecode_id_.store(policy.bytecode_artifact_id, std::memory_order_relaxed);
  wasm_br_table_sampling_.store(1, std::memory_order_release);
  return true;
}

void NativeProbeSink::EmitPageGuestInvocation(const std::string_view label,
                                              const NativeVmHostRuntime host_runtime,
                                              const PageGuestIds ids,
                                              const std::uint64_t invocation_id,
                                              const VmAdmission& admission) noexcept {
  NativeVmFindingPayload payload{};
  payload.kind = NativeVmFindingKind::kInvocation;
  payload.host_runtime = host_runtime;
  payload.confidence = NativeVmFindingConfidence::kObserved;
  payload.flags = static_cast<std::uint8_t>(NativeVmFindingFlag::kDynamic);
  payload.label_size = static_cast<std::uint16_t>(label.size());
  payload.finding_id = ids.finding_id;
  payload.investigation_id = ids.investigation_id;
  payload.subject_id = invocation_id;
  payload.related_subject_id = ids.bytecode_artifact_id;
  for (std::size_t index = 0; index < label.size(); ++index) {
    payload.label[index] = label[index];
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
  event.header.artifact_id = ids.interpreter_artifact_id;
  static_assert(sizeof(payload) <= kNativeProbeInlinePayloadSize);
  const auto payload_bytes = std::bit_cast<std::array<std::byte, sizeof(payload)>>(payload);
  std::ranges::copy(payload_bytes, event.inline_payload.begin());
  static_cast<void>(EmitStatus(event, admission.generation));
}

void NativeProbeSink::EmitPageGuestStep(const PageGuestIds ids,
                                        const std::uint32_t instruction_pointer,
                                        const std::uint32_t opcode,
                                        const std::uint8_t operand_count,
                                        const std::uint32_t sample_index) noexcept {
  NativeVmDispatchSamplePayload sample{};
  sample.instruction_pointer = instruction_pointer;
  sample.opcode = opcode;
  sample.handler_index = opcode;
  sample.sample_index = sample_index;
  sample.operand_count = operand_count;
  sample.finding_id = ids.finding_id;
  sample.investigation_id = ids.investigation_id;
  sample.interpreter_artifact_id = ids.interpreter_artifact_id;
  sample.bytecode_artifact_id = ids.bytecode_artifact_id;
  RecordVmDispatchSample(sample);
}

void NativeProbeSink::ObservePageGuest(const bool javascript,
                                       const std::span<const std::uint8_t> bytes) noexcept {
  const std::uint8_t enabled = (javascript ? javascript_switch_sampling_ : wasm_br_table_sampling_)
                                   .load(std::memory_order_acquire);
  if (enabled == 0) {
    return;
  }
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission)) {
    return;
  }
  const PageGuestWalk walk =
      javascript ? WalkJavaScriptSwitchDispatch(bytes) : WalkWasmBrTableDispatch(bytes);
  if (walk.submitted == 0) {
    return;
  }
  const std::uint64_t invocation_id =
      page_guest_invocation_.fetch_add(1, std::memory_order_relaxed);
  if (invocation_id == 0) {
    return;
  }
  const PageGuestIds ids =
      javascript ? PageGuestIds{javascript_switch_finding_id_.load(std::memory_order_relaxed),
                                javascript_switch_investigation_id_.load(std::memory_order_relaxed),
                                javascript_switch_interpreter_id_.load(std::memory_order_relaxed),
                                javascript_switch_bytecode_id_.load(std::memory_order_relaxed)}
                 : PageGuestIds{wasm_br_table_finding_id_.load(std::memory_order_relaxed),
                                wasm_br_table_investigation_id_.load(std::memory_order_relaxed),
                                wasm_br_table_interpreter_id_.load(std::memory_order_relaxed),
                                wasm_br_table_bytecode_id_.load(std::memory_order_relaxed)};
  constexpr std::string_view kJavaScriptLabel = "javascript-switch-dispatch-v1";
  constexpr std::string_view kWasmLabel = "wasm-br-table-dispatch-v1";
  static_assert(kJavaScriptLabel.size() <= kNativeVmFindingLabelCapacity);
  static_assert(kWasmLabel.size() <= kNativeVmFindingLabelCapacity);
  EmitPageGuestInvocation(
      javascript ? kJavaScriptLabel : kWasmLabel,
      javascript ? NativeVmHostRuntime::kJavaScript : NativeVmHostRuntime::kWebAssembly, ids,
      invocation_id, admission);
  for (std::uint32_t index = 0; index < walk.submitted; ++index) {
    const PageGuestStep& step = walk.steps[index];
    EmitPageGuestStep(ids, step.instruction_pointer, step.opcode, step.operand_count, index);
  }
  if (walk.truncated) {
    NoteVmDispatchLoss(admission.generation, admission.session_id, admission.monotonic_time_ns,
                       admission.frame_id, admission.process_id, admission.thread_id,
                       ids.interpreter_artifact_id);
  }
}

void NativeProbeSink::ObserveCapturedJavaScriptSwitchProgram(
    const std::span<const std::uint8_t> program) noexcept {
  ObservePageGuest(true, program);
}

void NativeProbeSink::ObserveCapturedWasmModule(
    const std::span<const std::uint8_t> module) noexcept {
  ObservePageGuest(false, module);
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

void NativeProbeSink::SetNativeWasmDispatchEmitter(NativeWasmDispatchEmitter emitter) noexcept {
  native_wasm_emitter_.store(emitter, std::memory_order_release);
}
bool NativeProbeSink::IsNativeWasmDispatchEnabled() const noexcept {
  // Called by V8 before handle allocation/frame walking. Do not invoke the
  // frame-id provider here: its Blink implementation re-enters V8.
  const auto generation = config_generation_.load(std::memory_order_acquire);
  if (generation == 0 || (generation & 1U) != 0 ||
      native_wasm_capped_generation_.load(std::memory_order_acquire) >= generation ||
      !native_wasm_emitter_.load(std::memory_order_acquire))
    return false;
  const auto categories = category_mask_.load(std::memory_order_relaxed);
  constexpr auto required = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                            NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const bool active = (categories & required) == required &&
                      session_id_.load(std::memory_order_relaxed) != 0 &&
                      emitter_.load(std::memory_order_relaxed) != nullptr &&
                      MonotonicTimeNs() < expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  return active && config_generation_.load(std::memory_order_acquire) == generation;
}
bool NativeProbeSink::NoteNativeWasmDispatchOmission(const VmAdmission& admission,
                                                     NativeWasmOmission reason) noexcept {
  auto& slot = native_wasm_gap_generations_[static_cast<std::size_t>(reason)];
  auto previous = slot.load(std::memory_order_acquire);
  // Odd generation is an in-flight claim; never overwrite a newer configuration.
  while (previous < admission.generation - 1) {
    if (slot.compare_exchange_weak(previous, admission.generation - 1, std::memory_order_acq_rel)) {
      constexpr std::array<std::string_view, 3> reasons{
          "native_wasm_dispatch_input_unavailable", "native_wasm_dispatch_transport_unavailable",
          "native_wasm_dispatch_budget_incomplete"};
      const bool retained = RecordRuntimeBufferEvent(NativeProbeType::kGap, admission.frame_id,
                                                     reasons[static_cast<std::size_t>(reason)],
                                                     admission.generation) != 0;
      auto claimed = admission.generation - 1;
      slot.compare_exchange_strong(claimed, retained ? admission.generation : previous,
                                   std::memory_order_acq_rel);
      return retained;
    }
  }
  return previous == admission.generation;
}
void NativeProbeSink::RecordNativeWasmDispatch(std::uint64_t execution_context_id,
                                               std::uint64_t frame_id,
                                               std::string_view source_url,
                                               std::span<const std::uint8_t> module_bytes,
                                               std::uint32_t function_index,
                                               std::uint32_t module_byte_offset,
                                               std::uint32_t selector,
                                               std::uint32_t table_count,
                                               std::uint64_t document_token_high,
                                               std::uint64_t document_token_low) noexcept {
  if (!IsNativeWasmDispatchEnabled())
    return;
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission) || !(category_mask_.load(std::memory_order_relaxed) &
                                           NativeProbeCategoryMask(NativeProbeCategory::kArtifact)))
    return;
  admission.frame_id = frame_id;
  NativeWasmDispatchObservation observation;
  observation.header.category = NativeProbeCategory::kVm;
  observation.header.type = NativeProbeType::kWasmDispatchObservation;
  observation.header.payload_size = 128;
  observation.header.session_id = admission.session_id;
  observation.header.monotonic_time_ns = admission.monotonic_time_ns;
  observation.header.process_id = admission.process_id;
  observation.header.thread_id = admission.thread_id;
  observation.header.frame_id = frame_id;
  observation.execution_context_id = execution_context_id;
  observation.document_token_high = document_token_high;
  observation.document_token_low = document_token_low;
  observation.function_index = function_index;
  observation.module_byte_offset = module_byte_offset;
  observation.selector = selector;
  observation.table_count = table_count;
  observation.source_url = source_url;
  observation.module_bytes = module_bytes;
  if (!IsValidNativeWasmDispatchInput(observation)) {
    NoteNativeWasmDispatchOmission(admission, NativeWasmOmission::kInput);
    return;
  }
  for (std::size_t i = 0; i < native_wasm_slots_.size(); ++i) {
    auto& slot = native_wasm_slots_[i];
    auto previous = slot.load(std::memory_order_acquire);
    while (previous < admission.generation) {
      if (slot.compare_exchange_weak(previous, admission.generation, std::memory_order_acq_rel)) {
        observation.sample_index = static_cast<std::uint32_t>(i);
        observation.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
        const auto emitter = native_wasm_emitter_.load(std::memory_order_acquire);
        if (config_generation_.load(std::memory_order_acquire) != admission.generation ||
            !emitter || !emitter(observation, admission.generation)) {
          auto claimed = admission.generation;
          slot.compare_exchange_strong(claimed, previous, std::memory_order_acq_rel);
          NoteNativeWasmDispatchOmission(admission, NativeWasmOmission::kTransport);
        }
        return;
      }
    }
  }
  if (NoteNativeWasmDispatchOmission(admission, NativeWasmOmission::kBudget)) {
    auto previous = native_wasm_capped_generation_.load(std::memory_order_acquire);
    while (previous < admission.generation &&
           !native_wasm_capped_generation_.compare_exchange_weak(previous, admission.generation,
                                                                 std::memory_order_acq_rel)) {
    }
  }
}

void NativeProbeSink::SetNativeWasmIndirectEmitter(NativeWasmIndirectEmitter emitter) noexcept {
  native_wasm_indirect_emitter_.store(emitter, std::memory_order_release);
}
bool NativeProbeSink::IsNativeWasmIndirectEnabled() const noexcept {
  // Called by V8 before handle allocation/frame walking, like the br_table
  // predicate. Do not invoke the frame-id provider here.
  const auto generation = config_generation_.load(std::memory_order_acquire);
  if (generation == 0 || (generation & 1U) != 0 ||
      native_wasm_indirect_capped_generation_.load(std::memory_order_acquire) >= generation ||
      !native_wasm_indirect_emitter_.load(std::memory_order_acquire))
    return false;
  const auto categories = category_mask_.load(std::memory_order_relaxed);
  constexpr auto required = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                            NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const bool active = (categories & required) == required &&
                      session_id_.load(std::memory_order_relaxed) != 0 &&
                      emitter_.load(std::memory_order_relaxed) != nullptr &&
                      MonotonicTimeNs() < expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  return active && config_generation_.load(std::memory_order_acquire) == generation;
}
bool NativeProbeSink::NoteNativeWasmIndirectOmission(const VmAdmission& admission,
                                                     NativeWasmOmission reason) noexcept {
  auto& slot = native_wasm_indirect_gap_generations_[static_cast<std::size_t>(reason)];
  auto previous = slot.load(std::memory_order_acquire);
  // Odd generation is an in-flight claim; never overwrite a newer configuration.
  while (previous < admission.generation - 1) {
    if (slot.compare_exchange_weak(previous, admission.generation - 1, std::memory_order_acq_rel)) {
      constexpr std::array<std::string_view, 3> reasons{
          "native_wasm_indirect_input_unavailable", "native_wasm_indirect_transport_unavailable",
          "native_wasm_indirect_budget_incomplete"};
      const bool retained = RecordRuntimeBufferEvent(NativeProbeType::kGap, admission.frame_id,
                                                     reasons[static_cast<std::size_t>(reason)],
                                                     admission.generation) != 0;
      auto claimed = admission.generation - 1;
      slot.compare_exchange_strong(claimed, retained ? admission.generation : previous,
                                   std::memory_order_acq_rel);
      return retained;
    }
  }
  return previous == admission.generation;
}
void NativeProbeSink::RecordNativeWasmIndirect(NativeWasmIndirectObservation observation) noexcept {
  if (!IsNativeWasmIndirectEnabled())
    return;
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission) || !(category_mask_.load(std::memory_order_relaxed) &
                                           NativeProbeCategoryMask(NativeProbeCategory::kArtifact)))
    return;
  admission.frame_id = observation.header.frame_id;
  const auto frame_id = observation.header.frame_id;
  observation.header = NativeProbeHeader{};
  observation.header.category = NativeProbeCategory::kVm;
  observation.header.type = NativeProbeType::kWasmIndirectObservation;
  observation.header.payload_size = 128;
  observation.header.session_id = admission.session_id;
  observation.header.monotonic_time_ns = admission.monotonic_time_ns;
  observation.header.process_id = admission.process_id;
  observation.header.thread_id = admission.thread_id;
  observation.header.frame_id = frame_id;
  observation.sample_index = 0;
  if (!IsValidNativeWasmIndirectInput(observation)) {
    NoteNativeWasmIndirectOmission(admission, NativeWasmOmission::kInput);
    return;
  }
  for (std::size_t i = 0; i < native_wasm_indirect_slots_.size(); ++i) {
    auto& slot = native_wasm_indirect_slots_[i];
    auto previous = slot.load(std::memory_order_acquire);
    while (previous < admission.generation) {
      if (slot.compare_exchange_weak(previous, admission.generation, std::memory_order_acq_rel)) {
        observation.sample_index = static_cast<std::uint32_t>(i);
        observation.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
        const auto emitter = native_wasm_indirect_emitter_.load(std::memory_order_acquire);
        if (config_generation_.load(std::memory_order_acquire) != admission.generation ||
            !emitter || !emitter(observation, admission.generation)) {
          auto claimed = admission.generation;
          slot.compare_exchange_strong(claimed, previous, std::memory_order_acq_rel);
          NoteNativeWasmIndirectOmission(admission, NativeWasmOmission::kTransport);
        }
        return;
      }
    }
  }
  if (NoteNativeWasmIndirectOmission(admission, NativeWasmOmission::kBudget)) {
    auto previous = native_wasm_indirect_capped_generation_.load(std::memory_order_acquire);
    while (previous < admission.generation &&
           !native_wasm_indirect_capped_generation_.compare_exchange_weak(
               previous, admission.generation, std::memory_order_acq_rel)) {
    }
  }
}

namespace {
struct GuestInvocationState final {
  std::uint64_t instance = 0, invocation = 0, frame = 0, document_high = 0, document_low = 0,
                dispatch_sequence = 0;
  NativeProbeEvent invocation_event{};
};
struct GuestDocumentBinding final {
  std::uint64_t frame = 0, high = 0, low = 0, context = 0;
  // Sequence number of the dispatch that last carried the module bytes; zero
  // means the next sample must carry them. Cleared again on a rejection.
  std::uint64_t module_token = 0;
  std::uint8_t module_attempts = 0;
  bool module_accepted = false;
};
struct GuestThreadState final {
  std::uint64_t generation = 0;
  std::array<GuestInvocationState, 128> invocations{};
  std::array<GuestDocumentBinding, 16> documents{};
};
thread_local GuestThreadState guest_thread;
thread_local NativeGuestSnapshot guest_snapshot;
thread_local bool guest_snapshot_busy = false;
thread_local bool guest_snapshot_cancelled = false;
struct GuestSnapshotGuard final {
  GuestSnapshotGuard() noexcept {
    guest_snapshot_busy = true;
    guest_snapshot_cancelled = false;
  }
  ~GuestSnapshotGuard() { guest_snapshot_busy = false; }
  GuestSnapshotGuard(const GuestSnapshotGuard&) = delete;
  GuestSnapshotGuard& operator=(const GuestSnapshotGuard&) = delete;
};
void ResetGuestThread(std::uint64_t generation) noexcept {
  // Reset one small record at a time, not a 42 KiB aggregate stack temporary.
  for (auto& state : guest_thread.invocations)
    state = {};
  for (auto& document : guest_thread.documents)
    document = {};
  guest_thread.generation = generation;
}

}  // namespace
void NativeProbeSink::NoteNativeGuestOmission(std::uint64_t generation,
                                              std::uint64_t frame,
                                              std::size_t kind,
                                              std::string_view reason) noexcept {
  if (!generation || (generation & 1U) || kind >= native_guest_gap_generations_.size())
    return;
  auto& slot = native_guest_gap_generations_[kind];
  auto previous = slot.load(std::memory_order_acquire);
  while (previous < generation - 1) {
    if (slot.compare_exchange_weak(previous, generation - 1, std::memory_order_acq_rel)) {
      const bool retained =
          RecordRuntimeBufferEvent(NativeProbeType::kGap, frame, reason, generation) != 0;
      auto claimed = generation - 1;
      slot.compare_exchange_strong(claimed, retained ? generation : previous,
                                   std::memory_order_acq_rel);
      return;
    }
  }
}
void NativeProbeSink::InvalidateNativeWasmGuest(const NativeWasmGuestStateView& view) noexcept {
  const auto generation = config_generation_.load(std::memory_order_acquire);
  if (guest_thread.generation != generation) {
    ResetGuestThread(generation);
  }
  const auto* adapter = native_guest_adapter_.load(std::memory_order_acquire);
  if (!adapter || view.function_index != adapter->function_index ||
      view.module_byte_offset != adapter->dispatch_module_offset)
    return;
  if (!view.instance_id || !view.invocation_id) {
    for (auto& state : guest_thread.invocations)
      state.dispatch_sequence = 0;
    NoteNativeGuestOmission(generation, 0, 7, "native_guest_runtime_identity_unavailable");
    return;
  }
  for (auto& state : guest_thread.invocations)
    if (state.instance == view.instance_id && state.invocation == view.invocation_id)
      state.dispatch_sequence = 0;
}
void NativeProbeSink::ConfigureNativeWasmGuest(
    std::shared_ptr<const NativeWasmGuestAdapter> adapter,
    NativeGuestCaptureEmitter capture,
    NativeGuestHostEmitter host) noexcept {
  native_guest_capture_.store(capture, std::memory_order_release);
  native_guest_host_.store(host, std::memory_order_release);
  if (!adapter || !IsValidNativeGuestAdapterShape(*adapter)) {
    native_guest_adapter_.store(nullptr, std::memory_order_release);
    return;
  }
  // One immutable startup recipe intentionally retained for process lifetime:
  // hot callback loads cannot block on an atomic shared_ptr implementation.
  if (!native_guest_retained_adapter_)
    native_guest_retained_adapter_ = new NativeWasmGuestAdapter(*adapter);
  if (native_guest_retained_adapter_->json != adapter->json) {
    native_guest_adapter_.store(nullptr, std::memory_order_release);
    NoteNativeGuestOmission(config_generation_.load(std::memory_order_acquire), 0, 6,
                            "native_guest_adapter_restart_required");
    return;
  }
  native_guest_adapter_.store(native_guest_retained_adapter_, std::memory_order_release);
}
void NativeProbeSink::NoteNativeGuestModuleStatus(std::uint64_t module_token,
                                                  bool accepted) noexcept {
  if (!module_token || module_token > (UINT64_MAX >> 1U))
    return;
  const auto slot = native_guest_module_status_next_.fetch_add(1, std::memory_order_relaxed) %
                    native_guest_module_status_.size();
  native_guest_module_status_[slot].store((module_token << 1U) | (accepted ? 1U : 0U),
                                          std::memory_order_release);
}
NativeProbeSink::GuestModuleVerdict NativeProbeSink::NativeGuestModuleVerdict(
    std::uint64_t token) const noexcept {
  for (const auto& entry : native_guest_module_status_) {
    const auto value = entry.load(std::memory_order_acquire);
    if (value >> 1U == token)
      return value & 1U ? GuestModuleVerdict::kAccepted : GuestModuleVerdict::kRejected;
  }
  return GuestModuleVerdict::kPending;
}
bool NativeProbeSink::ClaimNativeGuestHostRoute(std::uint64_t generation) noexcept {
  if (native_guest_host_capped_generation_.load(std::memory_order_acquire) >= generation)
    return false;
  for (auto& slot : native_guest_host_slots_) {
    auto previous = slot.load(std::memory_order_acquire);
    while (previous < generation) {
      if (slot.compare_exchange_weak(previous, generation, std::memory_order_acq_rel))
        return true;
    }
  }
  auto previous = native_guest_host_capped_generation_.load(std::memory_order_acquire);
  while (previous < generation && !native_guest_host_capped_generation_.compare_exchange_weak(
                                      previous, generation, std::memory_order_acq_rel)) {
  }
  return false;
}
void NativeProbeSink::SetNativeWasmGuestRuntime(NativeWasmGuestContextProvider context,
                                                NativeWasmGuestReset reset) noexcept {
  native_guest_context_.store(context, std::memory_order_release);
  native_guest_reset_.store(reset, std::memory_order_release);
}
bool NativeProbeSink::IsNativeWasmGuestEnabled() const noexcept {
  // Keep invalidating parents at matching dispatches after the sample cap.
  return native_guest_adapter_.load(std::memory_order_acquire) &&
         native_guest_capture_.load(std::memory_order_acquire) && IsVmCaptureEnabled() &&
         IsArtifactCaptureEnabled();
}
bool NativeProbeSink::IsNativeWasmGuestDispatchSite(
    std::uint32_t function_index,
    std::uint32_t module_byte_offset) const noexcept {
  // Engine ancestry markers must survive sample caps and metadata rejection.
  // This predicate describes the immutable recipe, not capture admission.
  const auto* adapter = native_guest_adapter_.load(std::memory_order_acquire);
  return adapter && function_index == adapter->function_index &&
         module_byte_offset == adapter->dispatch_module_offset;
}
NativeWasmGuestModuleDecision NativeProbeSink::AdmitNativeWasmGuestModule(
    std::span<const std::uint8_t> module,
    std::uint32_t function_index) const noexcept {
  const auto* adapter = native_guest_adapter_.load(std::memory_order_acquire);
  // Capture state is transient; the engine resets remembered rejections when
  // the enabled interval or capture epoch changes.
  if (!adapter || function_index != adapter->function_index || !IsNativeWasmGuestEnabled())
    return NativeWasmGuestModuleDecision::kNotDispatcher;
  return !module.empty() && module.size() <= kNativeArtifactMaxContentBytes &&
                 NativeGuestDigest(module) == adapter->module_sha256
             ? NativeWasmGuestModuleDecision::kAdmit
             : NativeWasmGuestModuleDecision::kRejectModule;
}
void NativeProbeSink::RecordNativeWasmGuest(std::uint64_t execution_context_id,
                                            std::uint64_t frame_id,
                                            std::string_view source_url,
                                            std::span<const std::uint8_t> module_bytes,
                                            const NativeWasmGuestStateView& view,
                                            std::uint64_t document_token_high,
                                            std::uint64_t document_token_low) noexcept {
  const auto generation = config_generation_.load(std::memory_order_acquire);
  if (guest_thread.generation != generation) {
    ResetGuestThread(generation);
  }
  const auto* adapter = native_guest_adapter_.load(std::memory_order_acquire);
  // A helper br_table in an opcode handler is not a guest instruction boundary.
  if (!adapter || view.function_index != adapter->function_index ||
      view.module_byte_offset != adapter->dispatch_module_offset)
    return;
  if (!view.instance_id || !view.invocation_id) {
    for (auto& state : guest_thread.invocations)
      state.dispatch_sequence = 0;
    NoteNativeGuestOmission(generation, frame_id, 7, "native_guest_runtime_identity_unavailable");
    return;
  }
  GuestInvocationState* state = nullptr;
  for (auto& slot : guest_thread.invocations)
    if (slot.instance == view.instance_id && slot.invocation == view.invocation_id) {
      state = &slot;
      break;
    }
  if (state)
    state->dispatch_sequence = 0;
  if (!IsNativeWasmGuestEnabled() || module_bytes.empty() ||
      module_bytes.size() > kNativeArtifactMaxContentBytes || source_url.empty() ||
      source_url.size() > kNativeArtifactMaxUrlBytes || !execution_context_id || !frame_id ||
      !(document_token_high || document_token_low))
    return;
  VmAdmission admission;
  if (!SnapshotVmAdmission(admission) || admission.generation != generation)
    return;
  admission.frame_id = frame_id;
  if (native_guest_capped_generation_.load(std::memory_order_acquire) >= generation) {
    NoteNativeGuestOmission(generation, frame_id, 0, "native_guest_sample_limit");
    return;
  }
  GuestDocumentBinding* document = nullptr;
  for (auto& entry : guest_thread.documents)
    if (entry.frame == frame_id && entry.context == execution_context_id &&
        entry.high == document_token_high && entry.low == document_token_low) {
      document = &entry;
      break;
    }
  if (!document) {
    for (auto& entry : guest_thread.documents)
      if (!entry.frame) {
        document = &entry;
        break;
      }
    if (!document) {
      NoteNativeGuestOmission(generation, frame_id, 5, "native_guest_document_limit");
      return;
    }
    document->frame = frame_id;
    document->context = execution_context_id;
    document->high = document_token_high;
    document->low = document_token_low;
  }
  if (!document->module_accepted && document->module_token) {
    switch (NativeGuestModuleVerdict(document->module_token)) {
      case GuestModuleVerdict::kAccepted:
        document->module_accepted = true;
        break;
      case GuestModuleVerdict::kRejected:
        document->module_token = 0;
        break;
      case GuestModuleVerdict::kPending:
        break;
    }
  }
  // While a transfer is pending, later samples bind to the browser's in-flight
  // module; if it is rejected the browser marks those dispatches lost.
  const bool send_module = !document->module_accepted && !document->module_token;
  if (send_module && document->module_attempts >= kNativeGuestModuleAttemptLimit) {
    NoteNativeGuestOmission(generation, frame_id, 8, "native_guest_module_unavailable");
    return;
  }
  if (!state) {
    for (auto& slot : guest_thread.invocations)
      if (!slot.invocation) {
        state = &slot;
        break;
      }
    if (!state) {
      NoteNativeGuestOmission(generation, frame_id, 1, "native_guest_invocation_limit");
      return;
    }
    if (NativeGuestDigest(module_bytes) != adapter->module_sha256)
      return;
    state->instance = view.instance_id;
    state->invocation = view.invocation_id;
    state->frame = frame_id;
    state->document_high = document_token_high;
    state->document_low = document_token_low;
  }
  if (state->frame != frame_id || state->document_high != document_token_high ||
      state->document_low != document_token_low)
    return;
  if (guest_snapshot_busy) {
    guest_snapshot_cancelled = true;
    NoteNativeGuestOmission(generation, frame_id, 2, "native_guest_snapshot_reentry");
    return;
  }
  GuestSnapshotGuard snapshot_guard;
  auto& snapshot = guest_snapshot;
  if (!ResolveNativeGuestSnapshot(*adapter, view, snapshot) || guest_snapshot_cancelled) {
    NoteNativeGuestOmission(generation, frame_id, 2, "native_guest_state_unavailable");
    return;
  }
  // Generation tags prevent stale in-flight work consuming a replacement budget.
  std::uint32_t sample_index = UINT32_MAX;
  for (std::size_t index = 0; index < adapter->sample_limit; ++index) {
    auto& slot = native_guest_slots_[index];
    auto previous = slot.load(std::memory_order_acquire);
    while (previous < generation) {
      if (slot.compare_exchange_weak(previous, generation, std::memory_order_acq_rel)) {
        sample_index = static_cast<std::uint32_t>(index);
        break;
      }
    }
    if (sample_index != UINT32_MAX)
      break;
  }
  if (sample_index == UINT32_MAX) {
    auto previous = native_guest_capped_generation_.load(std::memory_order_acquire);
    while (previous < generation && !native_guest_capped_generation_.compare_exchange_weak(
                                        previous, generation, std::memory_order_acq_rel)) {
    }
    NoteNativeGuestOmission(generation, frame_id, 0, "native_guest_sample_limit");
    return;
  }
  NativeGuestCapture capture;
  auto& event = capture.dispatch;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kWasmGuestDispatch;
  event.header.payload_size = 128;
  event.header.session_id = admission.session_id;
  event.header.process_id = admission.process_id;
  event.header.thread_id = admission.thread_id;
  event.header.frame_id = frame_id;
  event.header.monotonic_time_ns = admission.monotonic_time_ns;
  if (!state->invocation_event.header.sequence_number) {
    auto& invocation = state->invocation_event;
    invocation.header = event.header;
    invocation.header.type = NativeProbeType::kWasmGuestInvocation;
    invocation.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
    NativeWasmGuestInvocationPayload payload;
    payload.function_index = view.function_index;
    payload.instance_id = view.instance_id;
    payload.invocation_id = view.invocation_id;
    for (std::size_t i = 0; i < 32; ++i)
      payload.recipe_sha256[i] = static_cast<std::byte>(adapter->recipe_sha256[i]);
    invocation.inline_payload = EncodeNativeWasmGuestInvocationPayload(payload);
  }
  capture.invocation = state->invocation_event;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.parent_event_id = capture.invocation.header.sequence_number;
  NativeWasmGuestDispatchPayload payload;
  payload.function_index = view.function_index;
  payload.module_byte_offset = view.module_byte_offset;
  payload.selector = view.selector;
  payload.table_count = view.table_count;
  payload.sample_index = sample_index;
  payload.instance_id = view.instance_id;
  payload.invocation_id = view.invocation_id;
  payload.guest_pc = snapshot.pc;
  payload.raw_pc_bits = snapshot.raw_pc;
  payload.memory_base = snapshot.memory_base;
  payload.memory_length = snapshot.memory_length;
  payload.pc_local_index = adapter->pc_local_index;
  payload.pc_adjustment = adapter->pc_adjustment;
  payload.memory_index = adapter->memory_index;
  payload.opcode = snapshot.opcode;
  for (std::size_t i = 0; i < 32; ++i)
    payload.recipe_sha256[i] = static_cast<std::byte>(adapter->recipe_sha256[i]);
  event.inline_payload = EncodeNativeWasmGuestDispatchPayload(payload);
  capture.execution_context_id = execution_context_id;
  capture.document_token_high = document_token_high;
  capture.document_token_low = document_token_low;
  capture.source_url = source_url;
  capture.adapter_json = adapter->json;
  capture.module_bytes = send_module ? module_bytes : std::span<const std::uint8_t>{};
  capture.bytecode_bytes = std::span(snapshot.bytes.data(), snapshot.memory_length);
  const auto emit = native_guest_capture_.load(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != generation || !emit ||
      !emit(capture, generation) || guest_snapshot_cancelled ||
      config_generation_.load(std::memory_order_acquire) != generation) {
    NoteNativeGuestOmission(generation, frame_id, 3, "native_guest_transport_unavailable");
    return;
  }
  if (send_module) {
    document->module_token = event.header.sequence_number;
    ++document->module_attempts;
  }
  state->dispatch_sequence = event.header.sequence_number;
}
bool NativeProbeSink::TryRecordNativeGuestHost(NativeProbeEvent& event,
                                               std::uint64_t generation) noexcept {
  const auto* adapter = native_guest_adapter_.load(std::memory_order_acquire);
  const auto context_provider = native_guest_context_.load(std::memory_order_acquire);
  const auto emit = native_guest_host_.load(std::memory_order_acquire);
  if (!adapter || !context_provider || !emit || guest_thread.generation != generation)
    return false;
  NativeWasmGuestContext context;
  if (!context_provider(adapter->function_index, &context) ||
      context.function_index != adapter->function_index)
    return false;
  const auto end = adapter->import_call_offsets.begin() +
                   static_cast<std::ptrdiff_t>(adapter->import_call_count);
  if (std::find(adapter->import_call_offsets.begin(), end, context.import_module_byte_offset) ==
      end)
    return false;
  for (auto& state : guest_thread.invocations) {
    if (state.instance != context.instance_id || state.invocation != context.invocation_id ||
        state.frame != event.header.frame_id || !state.dispatch_sequence)
      continue;
    // Beyond the routing budget the host stays on the ordinary queue without
    // its parent link; the event itself is still retained.
    if (!ClaimNativeGuestHostRoute(generation)) {
      NoteNativeGuestOmission(generation, event.header.frame_id, 9,
                              "native_guest_host_parent_budget");
      return false;
    }
    event.header.parent_event_id = state.dispatch_sequence;
    if (emit(event, generation))
      return true;
    event.header.parent_event_id = 0;
    state.dispatch_sequence = 0;
    NoteNativeGuestOmission(generation, event.header.frame_id, 4,
                            "native_guest_host_transport_unavailable");
    return false;
  }
  return false;
}
}  // namespace reb
