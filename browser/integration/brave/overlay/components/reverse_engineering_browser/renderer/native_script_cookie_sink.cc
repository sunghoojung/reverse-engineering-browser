// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"

#include <algorithm>
#include <limits>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"
#include "crypto/hash.h"

namespace reb {

namespace {

std::string_view Trim(const std::string_view text) noexcept {
  constexpr std::string_view kWhitespace = " \t";
  const std::size_t first = text.find_first_not_of(kWhitespace);
  if (first == std::string_view::npos) {
    return {};
  }
  return text.substr(first, text.find_last_not_of(kWhitespace) - first + 1);
}

std::uint32_t Clamp32(const std::size_t value) noexcept {
  return static_cast<std::uint32_t>(
      std::min<std::size_t>(value, std::numeric_limits<std::uint32_t>::max()));
}

std::uint32_t SaturatingAdd(const std::uint32_t value, const std::uint32_t add) noexcept {
  return value > std::numeric_limits<std::uint32_t>::max() - add
             ? std::numeric_limits<std::uint32_t>::max()
             : value + add;
}

// FNV-1a, over the fields of a read key.
class KeyHash final {
 public:
  void Add(const std::uint64_t value, const std::size_t width) noexcept {
    for (std::size_t i = 0; i < width; ++i) {
      hash_ = (hash_ ^ ((value >> (8U * i)) & 0xffU)) * 0x100000001b3ULL;
    }
  }
  [[nodiscard]] std::uint64_t value() const noexcept { return hash_; }

 private:
  std::uint64_t hash_ = 0xcbf29ce484222325ULL;
};

// Each cookie name of a document.cookie string, in order. Chromium writes
// `name=value` or, for an empty name, the bare value, joined by "; "
// (CanonicalCookie::BuildCookieLine); neither part can hold ';'. This splits
// as the page would: at ';', then at the first '=', whitespace trimmed.
template <class Visit>
void ForEachCookieName(const std::string_view cookie_string, Visit&& visit) noexcept {
  std::size_t start = 0;
  while (start <= cookie_string.size()) {
    std::size_t end = cookie_string.find(';', start);
    if (end == std::string_view::npos) {
      end = cookie_string.size();
    }
    const std::string_view entry = Trim(cookie_string.substr(start, end - start));
    // A cookie has a name or a value, so an empty entry is no cookie.
    if (!entry.empty()) {
      const std::size_t equals = entry.find('=');
      visit(equals == std::string_view::npos ? std::string_view() : Trim(entry.substr(0, equals)));
    }
    start = end + 1;
  }
}

}  // namespace

NativeScriptCookieSink& NativeScriptCookieSink::Get() {
  static base::NoDestructor<NativeScriptCookieSink> sink;
  return *sink;
}

NativeScriptCookieSink::NativeScriptCookieSink() noexcept = default;

void NativeScriptCookieSink::Configure(const bool capture_content,
                                       const FrameProvider provider) noexcept {
  Flush();
  const NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  const bool active = capture_content && provider && (generation & 1U) == 0 &&
                      sink.emitter_.load(std::memory_order_acquire);
  if (active) {
    // Allocated here, on the transport sequence, so a read never allocates
    // and a session without content capture holds no table.
    auto table = std::make_unique<ReadTable>();
    base::AutoLock lock(reads_lock_);
    reads_ = std::move(table);
  }
  provider_.store(active ? provider : nullptr, std::memory_order_relaxed);
  generation_.store(active ? generation : 0, std::memory_order_release);
}

void NativeScriptCookieSink::Flush() noexcept {
  const std::uint64_t generation = generation_.exchange(0, std::memory_order_acq_rel);
  std::unique_ptr<ReadTable> table;
  {
    // A call that took the lock before this sees the old generation and
    // finishes first; one after it finds no table.
    base::AutoLock lock(reads_lock_);
    table = std::move(reads_);
  }
  if (generation == 0 || !table) {
    return;
  }
  for (std::size_t index = 0; index < table->used; ++index) {
    const ReadEntry& entry = table->entries[index];
    if (entry.unreported == 0) {
      continue;
    }
    NativeScriptCookieSummary summary;
    summary.api = entry.key.api;
    summary.count = entry.unreported;
    summary.name_length = entry.key.name_length;
    summary.name_prefix = entry.key.name_prefix;
    summary.string_length = entry.string_length;
    summary.unrecorded_names = entry.unrecorded_names;
    summary.frame = entry.key.frame;
    summary.thread = entry.key.thread;
    summary.flags = static_cast<std::uint8_t>(
        (entry.key.name_length > kNativeScriptCookieNamePrefixBytes
             ? kNativeScriptCookieNameTruncated
             : 0) |
        (entry.key.frame.kind != 0 ? kNativeScriptCookieFrameRecorded : 0) |
        (entry.key.read_record ? kNativeScriptCookieReadRecord : 0));
    static_cast<void>(Emit(summary, entry.key.frame_id, generation));
  }
}

NativeScriptCookieSummary NativeScriptCookieSink::Summary(
    const NativeScriptCookieApi api,
    const std::string_view name) const noexcept {
  NativeScriptCookieSummary summary;
  summary.api = api;
  summary.name_length = Clamp32(name.size());
  const std::size_t kept = std::min(name.size(), summary.name_prefix.size());
  std::transform(name.begin(), name.begin() + static_cast<std::ptrdiff_t>(kept),
                 summary.name_prefix.begin(),
                 [](const char c) { return static_cast<std::uint8_t>(c); });
  if (name.size() > kept) {
    summary.flags |= kNativeScriptCookieNameTruncated;
  }
  // The isolate the frame's script ID belongs to. A thread never attached
  // (none runs these APIs today) records no frame, since none could resolve.
  summary.thread = NativeRequestStackWalk::CurrentScope().thread;
  NativeScriptFrame frame;
  if (const FrameProvider provider = provider_.load(std::memory_order_relaxed);
      summary.thread != 0 && provider && provider(frame) && (frame.kind == 1 || frame.kind == 2) &&
      frame.script_id != 0) {
    frame.combinator = 0;
    frame.flags &= 0x03U;
    summary.frame = frame;
    summary.flags |= kNativeScriptCookieFrameRecorded;
  }
  return summary;
}

void NativeScriptCookieSink::RecordDocumentCookieSet(const std::string_view cookie_string,
                                                     const std::uint64_t frame_id) noexcept {
  if (!IsEnabled()) [[likely]] {
    return;
  }
  // ParsedCookie's pair: up to the first ';', split at the first '='.
  const std::string_view pair = cookie_string.substr(0, cookie_string.find(';'));
  const std::size_t equals = pair.find('=');
  const std::string_view name =
      equals == std::string_view::npos ? std::string_view() : Trim(pair.substr(0, equals));
  const std::string_view value =
      Trim(equals == std::string_view::npos ? pair : pair.substr(equals + 1));
  NativeScriptCookieSummary summary = Summary(NativeScriptCookieApi::kDocumentCookieSet, name);
  summary.value_length = Clamp32(value.size());
  summary.string_length = Clamp32(cookie_string.size());
  Record(summary, frame_id, value);
}

void NativeScriptCookieSink::RecordDocumentCookieGet(const std::string_view cookie_string,
                                                     const std::uint64_t frame_id) noexcept {
  if (!IsEnabled()) [[likely]] {
    return;
  }
  const std::uint64_t generation = generation_.load(std::memory_order_acquire);
  if (generation == 0) {
    return;
  }
  NativeScriptCookieSummary read = Summary(NativeScriptCookieApi::kDocumentCookieGet, {});
  read.string_length = Clamp32(cookie_string.size());
  const std::uint64_t calling_frame = CallingFrameId(frame_id);
  ReadKey key{calling_frame,
              read.thread,
              NativeScriptCookieApi::kDocumentCookieGet,
              false,
              read.frame,
              0,
              {}};
  base::AutoLock lock(reads_lock_);
  if (generation_.load(std::memory_order_acquire) != generation || !reads_) {
    return;
  }
  const std::uint64_t this_read = ++reads_->reads;
  // Names first, so this read's record carries the names none could count.
  std::size_t names = 0;
  std::uint32_t unrecorded = 0;
  ForEachCookieName(cookie_string, [&](const std::string_view name) {
    if (names++ >= kNativeScriptCookieReadNames) {
      ++unrecorded;
      return;
    }
    key.name_length = Clamp32(name.size());
    key.name_prefix = {};
    std::transform(
        name.begin(),
        name.begin() + static_cast<std::ptrdiff_t>(std::min(name.size(), key.name_prefix.size())),
        key.name_prefix.begin(), [](const char c) { return static_cast<std::uint8_t>(c); });
    ReadEntry* const entry = FindOrInsert(key);
    if (!entry) {
      ++unrecorded;
      return;
    }
    if (entry->last_read == this_read) {
      return;
    }
    entry->last_read = this_read;
    if (!CountRead(*entry, read.string_length)) {
      return;
    }
    NativeScriptCookieSummary named = read;
    named.name_length = key.name_length;
    named.name_prefix = key.name_prefix;
    if (key.name_length > kNativeScriptCookieNamePrefixBytes) {
      named.flags |= kNativeScriptCookieNameTruncated;
    }
    named.count = entry->unreported;
    entry->unreported = 0;
    static_cast<void>(Emit(named, calling_frame, generation));
  });
  // The read itself, with the names no name record counted.
  key.read_record = true;
  key.name_length = 0;
  key.name_prefix = {};
  read.flags |= kNativeScriptCookieReadRecord;
  if (ReadEntry* const entry = FindOrInsert(key)) {
    entry->unrecorded_names = SaturatingAdd(entry->unrecorded_names, unrecorded);
    if (!CountRead(*entry, read.string_length)) {
      return;
    }
    read.count = entry->unreported;
    read.unrecorded_names = entry->unrecorded_names;
    entry->unreported = 0;
    entry->unrecorded_names = 0;
  } else {
    read.flags |= kNativeScriptCookieTableFull;
    read.count = 1;
    read.unrecorded_names = unrecorded;
  }
  static_cast<void>(Emit(read, calling_frame, generation));
}

void NativeScriptCookieSink::RecordCookieStore(const NativeScriptCookieApi api,
                                               const std::string_view name,
                                               const std::string_view value) noexcept {
  if (!IsEnabled()) [[likely]] {
    return;
  }
  NativeScriptCookieSummary summary = Summary(api, name);
  if (api == NativeScriptCookieApi::kCookieStoreSet ||
      api == NativeScriptCookieApi::kCookieStoreDelete) {
    summary.value_length = Clamp32(value.size());
    Record(summary, 0, value);
  } else {
    RecordRead(summary, 0);
  }
}

std::uint64_t NativeScriptCookieSink::CallingFrameId(const std::uint64_t frame_id) noexcept {
  // A service worker's cookieStore call names the worker, as its requests do.
  if (const NativeStackScope scope = NativeRequestStackWalk::CurrentScope();
      scope.thread != 0 &&
      scope.thread != static_cast<std::uint8_t>(NativeStackThread::kDocument)) {
    return scope.isolate_key;
  }
  if (frame_id != 0) {
    return frame_id;
  }
  const NativeProbeFrameIdProvider calling =
      NativeProbeSink::Get().frame_id_provider_.load(std::memory_order_relaxed);
  return calling ? calling() : 0;
}

void NativeScriptCookieSink::Record(NativeScriptCookieSummary summary,
                                    std::uint64_t frame_id,
                                    const std::string_view value) noexcept {
  const std::uint64_t generation = generation_.load(std::memory_order_acquire);
  if (generation == 0) {
    return;
  }
  summary.count = 1;
  summary.value_sha256 = crypto::hash::Sha256(value);
  frame_id = CallingFrameId(frame_id);
  // Reserved first so the walked stack's artifact can name this record.
  const std::uint64_t sequence =
      NativeProbeSink::Get().next_sequence_.fetch_add(1, std::memory_order_relaxed);
  NativeStackFrame innermost;
  if (summary.thread != 0 &&
      NativeRequestStackWalk::RecordCookieStack(sequence, frame_id, summary.stack_digest,
                                                innermost) &&
      (innermost.kind == 1 || innermost.kind == 2)) {
    summary.frame = NativeScriptFrame{innermost.kind,
                                      static_cast<std::uint8_t>(innermost.flags & 0x03U),
                                      0,
                                      innermost.script_id,
                                      innermost.position,
                                      innermost.detail};
    summary.flags |= kNativeScriptCookieFrameRecorded | kNativeScriptCookieStackRecorded;
  } else {
    summary.stack_digest = {};
  }
  static_cast<void>(Emit(summary, frame_id, generation, sequence));
}

void NativeScriptCookieSink::RecordRead(NativeScriptCookieSummary summary,
                                        std::uint64_t frame_id) noexcept {
  const std::uint64_t generation = generation_.load(std::memory_order_acquire);
  if (generation == 0) {
    return;
  }
  frame_id = CallingFrameId(frame_id);
  const ReadKey key{frame_id,      summary.thread,      summary.api,        false,
                    summary.frame, summary.name_length, summary.name_prefix};
  base::AutoLock lock(reads_lock_);
  // A configuration that ended while this call ran no longer owns the table.
  if (generation_.load(std::memory_order_acquire) != generation || !reads_) {
    return;
  }
  if (ReadEntry* const entry = FindOrInsert(key)) {
    if (!CountRead(*entry, summary.string_length)) {
      return;
    }
    summary.count = entry->unreported;
    entry->unreported = 0;
  } else {
    summary.flags |= kNativeScriptCookieTableFull;
    summary.count = 1;
  }
  static_cast<void>(Emit(summary, frame_id, generation));
}

NativeScriptCookieSink::ReadEntry* NativeScriptCookieSink::FindOrInsert(
    const ReadKey& key) noexcept {
  ReadTable& table = *reads_;
  KeyHash hash;
  hash.Add(key.frame_id, 8);
  hash.Add(key.thread, 1);
  hash.Add(static_cast<std::uint8_t>(key.api), 1);
  hash.Add(key.read_record ? 1U : 0U, 1);
  hash.Add(key.frame.kind, 1);
  hash.Add(key.frame.flags, 1);
  hash.Add(key.frame.script_id, 4);
  hash.Add(key.frame.position, 4);
  hash.Add(key.frame.function_start, 4);
  hash.Add(key.name_length, 4);
  for (const std::uint8_t byte : key.name_prefix) {
    hash.Add(byte, 1);
  }
  constexpr std::size_t kMask = kReadSlots - 1;
  static_assert((kReadSlots & kMask) == 0, "slot count must be a power of two");
  // At most half the slots are used, so an empty slot ends every probe.
  for (std::size_t slot = static_cast<std::size_t>(hash.value()) & kMask;;
       slot = (slot + 1) & kMask) {
    const std::uint16_t index = table.slots[slot];
    if (index == 0) {
      if (table.used == table.entries.size()) {
        return nullptr;
      }
      ReadEntry& entry = table.entries[table.used];
      entry = ReadEntry();
      entry.key = key;
      table.slots[slot] = static_cast<std::uint16_t>(++table.used);
      return &entry;
    }
    if (table.entries[index - 1U].key == key) {
      return &table.entries[index - 1U];
    }
  }
}

bool NativeScriptCookieSink::CountRead(ReadEntry& entry,
                                       const std::uint32_t string_length) noexcept {
  entry.string_length = string_length;
  ++entry.unreported;
  if (entry.reads != std::numeric_limits<std::uint32_t>::max()) {
    ++entry.reads;
  }
  // Powers of two bound a hot key to log2(reads) records.
  return std::has_single_bit(entry.reads) ||
         entry.unreported == std::numeric_limits<std::uint32_t>::max();
}

bool NativeScriptCookieSink::Emit(const NativeScriptCookieSummary& summary,
                                  const std::uint64_t frame_id,
                                  const std::uint64_t generation,
                                  const std::uint64_t sequence) noexcept {
  NativeProbeSink& sink = NativeProbeSink::Get();
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kScriptCookie;
  event.header.sequence_number =
      sequence ? sequence : sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.session_id = sink.session_id_.load(std::memory_order_relaxed);
  event.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  event.header.payload_size = kNativeRequestPayloadSize;
  event.inline_payload = EncodeNativeScriptCookiePayload(summary);
  // The sink admits only the unchanged session, category and expiry.
  return sink.EmitStatus(event, generation) == NativeProbeEmitStatus::kAdmitted;
}

}  // namespace reb
