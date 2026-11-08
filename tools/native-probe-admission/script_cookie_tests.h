// "Script cookie access" in protocol/native-network-v3.md through the real
// renderer cookie sink and transport. The V8 frame provider is the fixture
// below; Blink's calls are modeled by the sink entry points they use.
#pragma once

#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"
#include "reb/event.hpp"
#include "reb/network_cookies.hpp"

namespace {
reb::NativeScriptFrame fixture_script_frame{1, 1, 0, 77, 1234, 0};
bool fixture_script_frame_available = true;
}  // namespace

namespace reb {
bool CurrentNativeScriptFrame(NativeScriptFrame& frame) noexcept {
  if (!fixture_script_frame_available) {
    return false;
  }
  frame = fixture_script_frame;
  return true;
}
}  // namespace reb

namespace {
reb::ScriptCookiePayload ScriptCookie(const NativeProbeEvent& event) {
  const auto record = std::bit_cast<reb::EventRecord>(event);
  assert(event.header.type == reb::NativeProbeType::kScriptCookie &&
         reb::IsValidScriptCookieEvent(record));
  reb::ScriptCookiePayload value;
  assert(reb::DecodeScriptCookiePayload(record.inline_payload, value));
  return value;
}
std::string NamePrefix(const reb::ScriptCookiePayload& value) {
  return {value.name_prefix.begin(),
          value.name_prefix.begin() +
              static_cast<std::ptrdiff_t>(std::min<std::size_t>(value.name_length, 24))};
}
void ConfigureCookies(NativeProbeQueue& queue,
                      const bool content,
                      const std::uint64_t mask = reb::kAllNativeProbeCategoryMask) {
  transport.Configure(42, mask, kForever, false, {&queue, sizeof(queue)}, 0, {}, {}, {}, false,
                      content);
}

void ScriptCookieAccess() {
  auto& cookies = reb::NativeScriptCookieSink::Get();
  NativeProbeQueue queue;
  const std::uint64_t document_frame = reb::NativeFrameIdOf(5, 6);

  // Metadata-only: one atomic load, no allocation and no record.
  ConfigureCookies(queue, false);
  assert(!cookies.IsEnabled());
  const auto before = allocations.load();
  cookies.RecordDocumentCookieSet("sid=1", document_frame);
  cookies.RecordDocumentCookieGet(5, document_frame);
  cookies.RecordCookieStore(reb::NativeScriptCookieApi::kCookieStoreSet, "sid", "1");
  assert(allocations.load() == before && Drain(queue) == 0);

  // A document.cookie write: name, value digest and lengths, frame, position.
  ConfigureCookies(queue, true);
  assert(cookies.IsEnabled());
  const std::string written = " token = abc123 ; Path=/; Secure";
  cookies.RecordDocumentCookieSet(written, document_frame);
  auto event = One(queue);
  auto value = ScriptCookie(event);
  assert(event.header.frame_id == document_frame && event.header.request_id == 0 &&
         event.header.category == reb::NativeProbeCategory::kNetwork);
  assert(value.api == 1 && value.count == 1 && value.name_length == 5 &&
         NamePrefix(value) == "token" && value.value_length == 6 &&
         value.string_length == written.size() &&
         value.value_sha256 == crypto::hash::Sha256(std::string_view("abc123")) &&
         value.flags == reb::kScriptCookieFrameRecorded && value.frame.kind == 1 &&
         value.frame.flags == 1 && value.frame.script_id == 77 && value.frame.position == 1234);

  // No '=' is an empty name; a long name keeps 24 bytes; the Cookie Store API
  // records the calling frame.
  cookies.RecordDocumentCookieSet("lonely", document_frame);
  value = ScriptCookie(One(queue));
  assert(value.name_length == 0 && value.value_length == 6 && !(value.flags & 1U));
  blink::test_frame_present = true;
  const std::string long_name(30, 'n');
  cookies.RecordCookieStore(reb::NativeScriptCookieApi::kCookieStoreSet, long_name, "v");
  event = One(queue);
  value = ScriptCookie(event);
  assert(event.header.frame_id == reb::NativeFrameIdOf(1, 2) && value.api == 3 &&
         value.name_length == 30 && (value.flags & reb::kScriptCookieNameTruncated) &&
         NamePrefix(value) == std::string(24, 'n') && value.string_length == 0);
  cookies.RecordCookieStore(reb::NativeScriptCookieApi::kCookieStoreDelete, "sid", "");
  value = ScriptCookie(One(queue));
  assert(value.api == 6 && value.value_length == 0 &&
         value.value_sha256 == crypto::hash::Sha256(std::string_view()));
  blink::test_frame_present = false;

  // Without a script frame the position is an explicit absence.
  fixture_script_frame_available = false;
  cookies.RecordDocumentCookieSet("a=b", document_frame);
  value = ScriptCookie(One(queue));
  assert(!(value.flags & reb::kScriptCookieFrameRecorded) && value.frame.script_id == 0);
  fixture_script_frame_available = true;

  // Nine reads of one key record its 1st, 2nd, 4th and 8th read; the
  // configuration end records the remainder. Another position is another key.
  for (int read = 0; read < 9; ++read) {
    cookies.RecordDocumentCookieGet(17, document_frame);
  }
  std::vector<std::uint32_t> counts;
  while (queue.TryPop(event)) {
    value = ScriptCookie(event);
    assert(value.api == 2 && value.string_length == 17 && value.value_length == 0);
    counts.push_back(value.count);
  }
  assert((counts == std::vector<std::uint32_t>{1, 1, 2, 4}));
  fixture_script_frame.position = 99;
  cookies.RecordCookieStore(reb::NativeScriptCookieApi::kCookieStoreGet, "sid", {});
  value = ScriptCookie(One(queue));
  assert(value.api == 4 && value.count == 1 && value.frame.position == 99 &&
         NamePrefix(value) == "sid");
  fixture_script_frame.position = 1234;
  transport.Disable();
  event = One(queue);
  value = ScriptCookie(event);
  assert(value.api == 2 && value.count == 1 && value.frame.position == 1234 &&
         event.header.frame_id == document_frame);
  assert(!cookies.IsEnabled());

  // 256 keys fill the table; a new key is then recorded alone and marked.
  ConfigureCookies(queue, true);
  for (std::uint32_t key = 0; key < reb::kNativeScriptCookieReadKeys; ++key) {
    cookies.RecordDocumentCookieGet(1, key + 1);
  }
  assert(Drain(queue) == reb::kNativeScriptCookieReadKeys);
  cookies.RecordDocumentCookieGet(1, 9999);
  cookies.RecordDocumentCookieGet(1, 9999);
  value = ScriptCookie(Pop(queue));
  assert((value.flags & reb::kScriptCookieTableFull) && value.count == 1);
  value = ScriptCookie(One(queue));
  assert((value.flags & reb::kScriptCookieTableFull) && value.count == 1);
  // A replacement configuration starts an empty table.
  ConfigureCookies(queue, true);
  cookies.RecordDocumentCookieGet(1, 9999);
  value = ScriptCookie(One(queue));
  assert(!(value.flags & reb::kScriptCookieTableFull));

  // The Network category gates admission too.
  ConfigureCookies(queue, true, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas));
  cookies.RecordDocumentCookieSet("a=b", document_frame);
  assert(Drain(queue) == 0);
  transport.Disable();
  assert(!cookies.IsEnabled());
  std::cout << "PASS native script cookies: metadata-only none and allocation-free, write name, "
               "value digest, lengths, frame and position, empty and 24-byte names, calling "
               "frame, missing position, read aggregation at powers of two with the "
               "configuration-end remainder, full table, category gate\n";
}
}  // namespace
