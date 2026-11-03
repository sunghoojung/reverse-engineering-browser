// Offline contract check for the Console document-start script experiment.
// Compiles and runs the exact production matcher, validators and fixed-record
// codec the browser and renderer use. This is not a Blink, V8 or packaged-app
// gate: it proves what a document-start rule admits and refuses, not that the
// pinned browser compiled or injected anything.

#include "components/reverse_engineering_browser/common/native_console_document_start.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "components/reverse_engineering_browser/common/native_console_protocol.h"

namespace {

using namespace reb;

void Check(bool condition, std::string_view message) {
  if (!condition) {
    std::cerr << "Console document-start failure: " << message << '\n';
    std::exit(1);
  }
}

NativeConsoleDocumentStartRule MakeRule(std::string_view origin,
                                        std::string_view path,
                                        std::uint16_t frames) {
  NativeConsoleDocumentStartRule rule;
  Check(origin.size() <= rule.origin.size() && path.size() <= rule.path.size(), "rule fits");
  rule.origin_bytes = static_cast<std::uint16_t>(origin.size());
  rule.path_bytes = static_cast<std::uint16_t>(path.size());
  rule.frame_flags = frames;
  std::memcpy(rule.origin.data(), origin.data(), origin.size());
  std::memcpy(rule.path.data(), path.data(), path.size());
  return rule;
}

NativeConsoleDocumentStartScript MakeScript(std::uint64_t id,
                                            const NativeConsoleDocumentStartRule& rule,
                                            std::string_view source) {
  NativeConsoleDocumentStartScript script;
  Check(source.size() <= script.source.size(), "source fits");
  script.script_id = id;
  script.rule = rule;
  script.source_bytes = static_cast<std::uint32_t>(source.size());
  std::memcpy(script.source.data(), source.data(), source.size());
  return script;
}

void CheckOrigins() {
  // The backend's Rust validator runs these same lines, so the two accept and
  // refuse exactly the same origins. `make native-tests` runs from the root.
  std::ifstream cases("tools/fixtures/console-document-start/rule-origins.txt");
  Check(cases.good(), "the shared origin cases are readable from the repository root");
  std::size_t accepted = 0;
  std::size_t refused = 0;
  for (std::string line; std::getline(cases, line);) {
    if (line.empty() || line.front() == '#')
      continue;
    const auto space = line.find(' ');
    Check(space != std::string::npos, "a case is a verdict and an origin");
    const std::string_view verdict(line.data(), space);
    const auto origin = line.substr(space + 1);
    if (verdict == "accept") {
      Check(IsValidNativeConsoleDocumentStartOrigin(origin), "accepted: " + origin);
      ++accepted;
    } else {
      Check(verdict == "refuse", "a verdict is accept or refuse");
      Check(!IsValidNativeConsoleDocumentStartOrigin(origin), "refused: " + origin);
      ++refused;
    }
  }
  Check(accepted >= 20 && refused >= 60, "every shared origin case was read");
  Check(!IsValidNativeConsoleDocumentStartOrigin(""), "refused: an empty origin");
  Check(IsValidNativeConsoleDocumentStartPath(""), "absent prefix");
  Check(IsValidNativeConsoleDocumentStartPath("/a/b-c_1.html"), "literal prefix");
  for (const auto* path : {"a", "../a", "/a?b", "/a#b", "/a b", "/a\x7f", "/a\n"}) {
    Check(!IsValidNativeConsoleDocumentStartPath(path), std::string("refused path: ") + path);
  }
  std::string long_path(kNativeConsoleDocumentStartPathLimit, 'a');
  long_path[0] = '/';
  Check(IsValidNativeConsoleDocumentStartPath(long_path), "prefix at the limit");
  Check(!IsValidNativeConsoleDocumentStartPath(long_path + "a"), "prefix over the limit");
}

void CheckMatching() {
  const auto top = MakeRule("https://fixture.test", "/lab/", kNativeConsoleDocumentStartTopFrame);
  Check(IsValidNativeConsoleDocumentStartRule(top), "valid top-frame rule");
  Check(NativeConsoleDocumentStartMatches(top, "https://fixture.test", "/lab/page.html", true),
        "exact origin, prefix and frame kind match");
  Check(NativeConsoleDocumentStartMatches(top, "https://fixture.test", "/lab/", true),
        "prefix equal to the path matches");
  // Every axis must be able to refuse on its own.
  Check(!NativeConsoleDocumentStartMatches(top, "https://fixture.test", "/lab/page.html", false),
        "a child frame never satisfies a top-frame rule");
  Check(!NativeConsoleDocumentStartMatches(top, "http://fixture.test", "/lab/page.html", true),
        "scheme is part of the origin");
  Check(!NativeConsoleDocumentStartMatches(top, "https://fixture.test:443", "/lab/x", true),
        "a respelled port is not the same origin string");
  Check(!NativeConsoleDocumentStartMatches(top, "https://sub.fixture.test", "/lab/x", true),
        "a subdomain is never covered by its parent");
  Check(!NativeConsoleDocumentStartMatches(top, "https://fixture.test.evil.test", "/lab/x", true),
        "a suffix is never covered");
  Check(!NativeConsoleDocumentStartMatches(top, "null", "/lab/x", true), "opaque origin refused");
  Check(!NativeConsoleDocumentStartMatches(top, "https://fixture.test", "/lab", true),
        "a shorter path is not covered by a longer prefix");
  Check(!NativeConsoleDocumentStartMatches(top, "https://fixture.test", "/other", true),
        "a different path is refused");

  const auto child = MakeRule("http://127.0.0.1:8080", "", kNativeConsoleDocumentStartChildFrame);
  Check(NativeConsoleDocumentStartMatches(child, "http://127.0.0.1:8080", "/anything", false),
        "absent prefix matches any path in the declared origin");
  Check(!NativeConsoleDocumentStartMatches(child, "http://127.0.0.1:8080", "/anything", true),
        "a top frame never satisfies a child-frame rule");
  Check(!NativeConsoleDocumentStartMatches(child, "http://127.0.0.1:8081", "/x", false),
        "port is part of the origin");

  // An invalid rule matches nothing, so a corrupted record cannot widen scope.
  auto broken = top;
  broken.frame_flags = kNativeConsoleDocumentStartTopFrame | kNativeConsoleDocumentStartChildFrame;
  Check(!IsValidNativeConsoleDocumentStartRule(broken), "both frame kinds refused");
  Check(!NativeConsoleDocumentStartMatches(broken, "https://fixture.test", "/lab/x", true),
        "an invalid rule never matches");
  broken = top;
  broken.frame_flags = 0;
  Check(!IsValidNativeConsoleDocumentStartRule(broken), "no frame kind refused");
  broken = top;
  broken.reserved = 1;
  Check(!IsValidNativeConsoleDocumentStartRule(broken), "reserved must stay zero");
  broken = top;
  broken.origin[broken.origin_bytes] = 'x';
  Check(!IsValidNativeConsoleDocumentStartRule(broken), "trailing origin bytes must stay zero");
  broken = top;
  broken.origin_bytes = 0;
  Check(!IsValidNativeConsoleDocumentStartRule(broken), "an empty origin is refused");
}

void CheckScriptsAndCodec() {
  const auto rule = MakeRule("https://fixture.test", "/", kNativeConsoleDocumentStartTopFrame);
  const auto first = MakeScript(1, rule, "report('one');");
  const auto second = MakeScript(2, rule, "report('two');");
  Check(IsValidNativeConsoleDocumentStartScript(first), "valid script");
  Check(NativeConsoleDocumentStartSource(first) == "report('one');", "source round-trip");
  Check(NativeConsoleDocumentStartDigest("report('one');") !=
            NativeConsoleDocumentStartDigest("report('two');"),
        "distinct sources have distinct labels");
  Check(NativeConsoleDocumentStartDigest("report('one');") ==
            NativeConsoleDocumentStartDigest(NativeConsoleDocumentStartSource(first)),
        "the label is stable");

  std::array<std::uint8_t, kNativeConsoleDocumentStartSetBytes> buffer{};
  const std::array<NativeConsoleDocumentStartScript, 2> set{first, second};
  const auto written = EncodeNativeConsoleDocumentStartScripts(set, buffer);
  Check(written == 2 * sizeof(NativeConsoleDocumentStartScript), "two fixed records encoded");
  std::array<NativeConsoleDocumentStartScript, kNativeConsoleDocumentStartScriptLimit> decoded{};
  Check(DecodeNativeConsoleDocumentStartScripts(std::span(buffer).first(written), decoded) == 2,
        "two records decoded");
  Check(decoded[0].script_id == 1 && decoded[1].script_id == 2, "identities preserved");
  Check(NativeConsoleDocumentStartSource(decoded[1]) == "report('two');", "sources preserved");

  // A truncated, oversized, duplicated or partially invalid set arms nothing.
  Check(DecodeNativeConsoleDocumentStartScripts(std::span(buffer).first(written - 1), decoded) == 0,
        "a truncated record arms nothing");
  Check(DecodeNativeConsoleDocumentStartScripts({}, decoded) == 0, "an empty set arms nothing");
  const std::array<NativeConsoleDocumentStartScript, 2> duplicate{first, MakeScript(1, rule, "x;")};
  const auto duplicate_bytes = EncodeNativeConsoleDocumentStartScripts(duplicate, buffer);
  Check(duplicate_bytes == 2 * sizeof(NativeConsoleDocumentStartScript), "encoded for the decoder");
  Check(DecodeNativeConsoleDocumentStartScripts(std::span(buffer).first(duplicate_bytes),
                                                decoded) == 0,
        "duplicate script identities arm nothing");

  std::vector<NativeConsoleDocumentStartScript> five;
  for (std::uint64_t id = 1; id <= kNativeConsoleDocumentStartScriptLimit + 1; ++id)
    five.push_back(MakeScript(id, rule, "report('x');"));
  std::array<std::uint8_t,
             kNativeConsoleDocumentStartSetBytes + sizeof(NativeConsoleDocumentStartScript)>
      wide{};
  Check(EncodeNativeConsoleDocumentStartScripts(five, wide) == 0, "more than four scripts refused");

  const std::string oversized(kNativeConsoleDocumentStartSourceLimit, 'a');
  auto overlong = MakeScript(3, rule, oversized);
  Check(IsValidNativeConsoleDocumentStartScript(overlong), "source at the per-script limit");
  overlong.source_bytes = kNativeConsoleDocumentStartSourceLimit + 1;
  Check(!IsValidNativeConsoleDocumentStartScript(overlong), "source over the per-script limit");

  // Four maximum-size scripts exceed the total source budget.
  std::vector<NativeConsoleDocumentStartScript> total;
  for (std::uint64_t id = 1; id <= kNativeConsoleDocumentStartScriptLimit; ++id)
    total.push_back(MakeScript(id, rule, oversized));
  const auto total_bytes = EncodeNativeConsoleDocumentStartScripts(total, buffer);
  Check(total_bytes == kNativeConsoleDocumentStartSetBytes, "encoded for the decoder");
  Check(DecodeNativeConsoleDocumentStartScripts(std::span(buffer).first(total_bytes), decoded) == 0,
        "the total source budget is enforced on decode");

  auto empty_source = MakeScript(4, rule, "");
  Check(!IsValidNativeConsoleDocumentStartScript(empty_source), "an empty snippet is refused");
  auto anonymous = MakeScript(0, rule, "report('x');");
  Check(!IsValidNativeConsoleDocumentStartScript(anonymous), "script 0 is refused");
  auto nul = MakeScript(5, rule, std::string_view("a\0b", 3));
  Check(!IsValidNativeConsoleDocumentStartScript(nul), "a NUL byte is refused");
  auto invalid_utf8 = MakeScript(6, rule, std::string_view("\xc3", 1));
  Check(!IsValidNativeConsoleDocumentStartScript(invalid_utf8), "truncated UTF-8 is refused");
  auto surrogate = MakeScript(7, rule, std::string_view("\xed\xa0\x80", 3));
  Check(!IsValidNativeConsoleDocumentStartScript(surrogate), "a UTF-8 surrogate is refused");
  auto overlong_encoding = MakeScript(8, rule, std::string_view("\xc0\xaf", 2));
  Check(!IsValidNativeConsoleDocumentStartScript(overlong_encoding),
        "an over-long UTF-8 encoding is refused");
  auto astral = MakeScript(9, rule, "report('\xf0\x9f\x9b\xa1');");
  Check(IsValidNativeConsoleDocumentStartScript(astral), "valid four-byte UTF-8 is accepted");
}

void CheckWireAdmission() {
  // Operation 4 is session-scoped and carries no document, so it can never be
  // pinned to, or satisfied by, a stale document generation.
  NativeConsoleRequest request;
  request.request_id = 1;
  request.operation = NativeConsoleOperation::kDocumentStart;
  request.source_bytes = 16;
  Check(IsNativeConsoleRequest(request), "document-start request admitted");
  request.target_id = 5;
  Check(!IsNativeConsoleRequest(request), "a document-start request with a target is refused");
  request.target_id = 0;
  request.source_bytes = 0;
  Check(!IsNativeConsoleRequest(request), "an empty document-start command is refused");
  request.source_bytes = kNativeConsolePayloadLimit + 1;
  Check(!IsNativeConsoleRequest(request), "an oversized document-start command is refused");
  request.source_bytes = 16;

  NativeConsoleResponse response;
  response.request_id = 1;
  response.type = NativeConsoleType::kDocumentStart;
  response.payload_bytes = kNativeConsolePayloadLimit;
  Check(IsNativeConsoleResponseFor(response, request), "a bounded JSON reply is admitted");
  response.payload_bytes = kNativeConsolePayloadLimit + 1;
  Check(!IsNativeConsoleResponseFor(response, request), "an oversized reply is refused");
  response.payload_bytes = 4;
  response.type = NativeConsoleType::kRuntime;
  Check(!IsNativeConsoleResponseFor(response, request),
        "the reply type must match the requested operation");

  // The capability flag is only meaningful on a target listing, so it can never
  // be smuggled onto a command reply to claim support.
  response.type = NativeConsoleType::kDocumentStart;
  response.flags = kNativeConsoleDocumentStartSupported;
  Check(!IsNativeConsoleResponse(response, 1), "the capability bit is listing-only");
  response.flags = kNativeConsoleTruncated;
  Check(IsNativeConsoleResponse(response, 1), "truncation stays available on a command reply");
  response.flags = kNativeConsoleResponseFlags + 1;
  Check(!IsNativeConsoleResponse(response, 1), "unknown response flags are refused");

  NativeConsoleResponse listing;
  listing.request_id = 2;
  listing.status = NativeConsoleStatus::kOk;
  listing.type = NativeConsoleType::kTargets;
  listing.item_count = 1;
  listing.payload_bytes = sizeof(NativeConsoleTarget);
  listing.flags = kNativeConsoleDocumentStartSupported | kNativeConsoleTruncated;
  Check(IsNativeConsoleResponse(listing, 2), "a listing may advertise support and truncation");

  // An older browser leaves the bit clear; the owner must then refuse to send
  // operation 4 rather than retire a working v2 session.
  listing.flags = 0;
  Check(IsNativeConsoleResponse(listing, 2), "a v2 listing without the bit stays valid");
}

}  // namespace

int main() {
  CheckOrigins();
  CheckMatching();
  CheckScriptsAndCodec();
  CheckWireAdmission();
  std::cout << "Console document-start rule, codec and wire admission checks passed "
               "(no Blink, V8 or browser execution)\n";
}
