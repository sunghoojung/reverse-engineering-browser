// Offline contract check for the Console document-start script experiment.
// Compiles and runs the exact production matcher, validators and set codec the
// browser and renderer use. This is not a Blink, V8 or packaged-app
// gate: it proves what a document-start rule admits and refuses, not that the
// pinned browser compiled or injected anything.

#include "components/reverse_engineering_browser/common/native_console_document_start.h"

#include <array>
#include <cstddef>
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
  return {.origin = origin, .path = path, .frame_flags = frames};
}

NativeConsoleDocumentStartScript MakeScript(std::uint64_t id,
                                            const NativeConsoleDocumentStartRule& rule,
                                            std::string_view source) {
  return {.script_id = id, .rule = rule, .source = source};
}

std::vector<std::uint8_t> Encode(std::span<const NativeConsoleDocumentStartScript> scripts) {
  std::vector<std::uint8_t> bytes(NativeConsoleDocumentStartEncodedBytes(scripts));
  if (!bytes.empty())
    Check(EncodeNativeConsoleDocumentStartScripts(scripts, bytes), "a sized set encodes");
  return bytes;
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
  // A prefix has no length bound: any literal path a document can commit.
  std::string long_path(1024 * 1024, 'a');
  long_path[0] = '/';
  Check(IsValidNativeConsoleDocumentStartPath(long_path), "a 1 MiB literal prefix");
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
  broken.origin = {};
  Check(!IsValidNativeConsoleDocumentStartRule(broken), "an empty origin is refused");
  // An origin has no length bound either: a long host is still one exact
  // origin, and it matches only itself.
  const std::string long_origin = "https://" + std::string(4096, 'a') + ".test";
  const std::string long_prefix = "/" + std::string(4095, 'p');
  auto long_rule = MakeRule(long_origin, long_prefix, kNativeConsoleDocumentStartTopFrame);
  Check(IsValidNativeConsoleDocumentStartRule(long_rule), "a 4 KiB origin and path prefix");
  Check(NativeConsoleDocumentStartMatches(long_rule, long_origin, long_rule.path, true),
        "a long origin matches itself");
  Check(!NativeConsoleDocumentStartMatches(long_rule, long_origin + "a", long_rule.path, true),
        "a long origin matches nothing longer");
}

void CheckScriptsAndCodec() {
  const auto rule = MakeRule("https://fixture.test", "/", kNativeConsoleDocumentStartTopFrame);
  const auto first = MakeScript(1, rule, "report('one');");
  const auto second = MakeScript(2, rule, "report('two');");
  Check(IsValidNativeConsoleDocumentStartScript(first), "valid script");
  Check(first.source == "report('one');", "source round-trip");
  Check(NativeConsoleDocumentStartDigest("report('one');") !=
            NativeConsoleDocumentStartDigest("report('two');"),
        "distinct sources have distinct labels");
  Check(NativeConsoleDocumentStartDigest("report('one');") ==
            NativeConsoleDocumentStartDigest(first.source),
        "the label is stable");

  const std::array<NativeConsoleDocumentStartScript, 2> set{first, second};
  const auto encoded = Encode(set);
  Check(encoded.size() == sizeof(NativeConsoleDocumentStartSetHeader) +
                              2 * sizeof(NativeConsoleDocumentStartRecordHeader) +
                              2 * (std::string_view("https://fixture.test/").size() + 14),
        "two records take their headers and their bytes, with no padding");
  std::vector<NativeConsoleDocumentStartScript> decoded;
  Check(DecodeNativeConsoleDocumentStartScripts(encoded, decoded) && decoded.size() == 2,
        "two records decoded");
  Check(decoded[0].script_id == 1 && decoded[1].script_id == 2, "identities preserved");
  Check(decoded[1].source == "report('two');", "sources preserved");
  Check(decoded[0].rule.origin == "https://fixture.test" && decoded[0].rule.path == "/" &&
            decoded[0].rule.frame_flags == kNativeConsoleDocumentStartTopFrame,
        "rules preserved");
  Check(
      decoded[0].source.data() >= reinterpret_cast<const char*>(encoded.data()) &&
          decoded[0].source.data() < reinterpret_cast<const char*>(encoded.data()) + encoded.size(),
      "decoded sources are views into the shared bytes, not copies");

  // A truncated, padded, corrupted, duplicated or partially invalid set arms
  // nothing, and leaves nothing decoded.
  const auto refused = [&decoded](std::vector<std::uint8_t> bytes, std::string_view why) {
    Check(!DecodeNativeConsoleDocumentStartScripts(bytes, decoded) && decoded.empty(), why);
  };
  refused({encoded.begin(), encoded.end() - 1}, "a truncated record arms nothing");
  refused({}, "an empty region arms nothing");
  auto padded = encoded;
  padded.push_back(0);
  refused(padded, "trailing bytes the header does not cover arm nothing");
  auto magic = encoded;
  magic[0] ^= 1;
  refused(magic, "a wrong magic arms nothing");
  auto count = encoded;
  count[4] = 0xff;
  count[5] = 0xff;
  count[6] = 0xff;
  count[7] = 0x7f;
  refused(count, "a count the bytes cannot hold arms nothing");
  static_assert(offsetof(NativeConsoleDocumentStartRecordHeader, reserved) == 22);
  auto reserved = encoded;
  reserved[sizeof(NativeConsoleDocumentStartSetHeader) + 22] = 1;
  refused(reserved, "a nonzero reserved field arms nothing");
  auto origin_past = encoded;
  origin_past[sizeof(NativeConsoleDocumentStartSetHeader) + 15] = 0x7f;
  refused(origin_past, "an origin length past the region arms nothing");
  auto overlong = encoded;
  overlong[sizeof(NativeConsoleDocumentStartSetHeader) + 8] = 0xff;
  refused(overlong, "a source length past the region arms nothing");
  const std::array<NativeConsoleDocumentStartScript, 2> duplicate{first, MakeScript(1, rule, "x;")};
  Check(NativeConsoleDocumentStartEncodedBytes(duplicate) == 0,
        "the encoder refuses duplicate script identities");
  auto reordered = encoded;
  reordered[sizeof(NativeConsoleDocumentStartSetHeader)] = 3;
  refused(reordered, "identities that do not increase arm nothing");
  auto invalid = encoded;
  invalid.back() = 0xff;
  refused(invalid, "one invalid snippet arms none of the set");

  // No count or size budget: many scripts and a large snippet round-trip.
  std::vector<NativeConsoleDocumentStartScript> many;
  for (std::uint64_t id = 1; id <= 10000; ++id)
    many.push_back(MakeScript(id, rule, "report('x');"));
  Check(DecodeNativeConsoleDocumentStartScripts(Encode(many), decoded) && decoded.size() == 10000,
        "ten thousand scripts arm");
  const std::string large(80 * 1024 * 1024, 'a');
  const std::array<NativeConsoleDocumentStartScript, 1> one{MakeScript(1, rule, large)};
  const auto large_set = Encode(one);
  Check(DecodeNativeConsoleDocumentStartScripts(large_set, decoded) &&
            decoded[0].source.size() == large.size(),
        "an 80 MiB snippet arms");

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
  // Only the record format's own 32-bit length bounds a command or a reply.
  request.source_bytes = 0xffffffffu;
  Check(IsNativeConsoleRequest(request), "a command of any length a record can name");
  request.source_bytes = 16;

  NativeConsoleResponse response;
  response.request_id = 1;
  response.type = NativeConsoleType::kDocumentStart;
  response.payload_bytes = 0xffffffffu;
  Check(IsNativeConsoleResponseFor(response, request), "a reply of any length is admitted");
  response.payload_bytes = 4;
  response.type = NativeConsoleType::kRuntime;
  Check(!IsNativeConsoleResponseFor(response, request),
        "the reply type must match the requested operation");

  // The capability flag is only meaningful on a target listing, so it can never
  // be smuggled onto a command reply to claim support.
  response.type = NativeConsoleType::kDocumentStart;
  response.flags = kNativeConsoleDocumentStartSupported;
  Check(!IsNativeConsoleResponse(response, 1), "the capability bit is listing-only");
  // Nothing is cut to fit a record, so only a partial listing says so.
  response.flags = kNativeConsoleTruncated;
  Check(!IsNativeConsoleResponse(response, 1), "a command reply is never truncated");
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
  listing.item_count = 2;
  Check(!IsNativeConsoleResponse(listing, 2), "a count the payload cannot hold is refused");
  listing.item_count = 0;
  listing.payload_bytes = 0;
  Check(IsNativeConsoleResponse(listing, 2), "an empty listing is valid");
}

void CheckTargets() {
  // Variable-length targets carry their whole metadata, however long.
  const std::string origin = "https://fixture.test";
  const std::string label = "top #7 · " + std::string(100000, 't');
  const std::string url = origin + "/" + std::string(2 * 1024 * 1024, 'u');
  std::string payload;
  for (std::uint64_t id = 1; id <= 100; ++id) {
    NativeConsoleTarget target;
    target.id = id;
    target.origin_bytes = static_cast<std::uint32_t>(origin.size());
    target.label_bytes = static_cast<std::uint32_t>(label.size());
    target.url_bytes = static_cast<std::uint32_t>(url.size());
    target.flags = kNativeConsoleTargetTopFrame;
    payload.append(reinterpret_cast<const char*>(&target), sizeof(target));
    payload += origin + label + url;
  }
  const auto bytes = std::as_bytes(std::span(payload));
  std::size_t offset = 0;
  for (std::uint64_t id = 1; id <= 100; ++id) {
    NativeConsoleTarget target;
    std::string_view read_origin, read_label, read_url;
    Check(ReadNativeConsoleTarget(bytes, offset, target, read_origin, read_label, read_url) &&
              target.id == id && read_origin == origin && read_label == label && read_url == url,
          "a hundred targets with 2 MiB URLs read back whole");
  }
  Check(offset == bytes.size(), "the listing ends after its last target");
  NativeConsoleTarget target;
  std::string_view a, b, c;
  offset = 0;
  Check(!ReadNativeConsoleTarget(bytes.first(sizeof(target) + 3), offset, target, a, b, c),
        "a target whose strings run past the payload is refused");
}

void CheckStops() {
  // A command Stop names its request; an injection Stop names its script, or
  // every script below an id, never a command or a later script.
  constexpr auto kStop = kNativeConsoleDocumentStartStopBit;
  constexpr auto kBelow = kStop | kNativeConsoleDocumentStartStopBelowBit;
  static_assert(NativeConsoleStopNames(7, 7) && !NativeConsoleStopNames(7, 8));
  static_assert(NativeConsoleStopNames(kStop | 3, kStop | 3));
  static_assert(!NativeConsoleStopNames(kStop | 3, kStop | 4));
  static_assert(!NativeConsoleStopNames(kStop | 3, 3), "an injection Stop never ends a command");
  static_assert(NativeConsoleStopNames(kBelow | 5, kStop | 4));
  static_assert(!NativeConsoleStopNames(kBelow | 5, kStop | 5), "a later script keeps running");
  static_assert(!NativeConsoleStopNames(kBelow | 5, 4), "a set Stop never ends a command");
  static_assert(!NativeConsoleStopNames(0, 0));
}

}  // namespace

int main() {
  CheckOrigins();
  CheckMatching();
  CheckScriptsAndCodec();
  CheckWireAdmission();
  CheckTargets();
  CheckStops();
  std::cout << "Console document-start rule, codec and wire admission checks passed "
               "(no Blink, V8 or browser execution)\n";
}
