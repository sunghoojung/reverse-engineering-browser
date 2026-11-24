// Direct API checks that the decoder library holds whatever its input needs:
// nesting, token, field, frame, digit, token-size and secret-size cases that
// fixed caps once refused, and Magic/SHA output on empty and binary input.
#include "reb/decoder.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void Check(bool condition, std::string_view operation, std::string_view message) {
  if (!condition) {
    std::cerr << "Decoder scale failure (" << operation << "): " << message << '\n';
    std::exit(1);
  }
}

std::vector<std::uint8_t> Bytes(const std::string_view text) {
  return {text.begin(), text.end()};
}

std::string Text(const std::vector<std::uint8_t>& bytes) {
  return {bytes.begin(), bytes.end()};
}

reb::DecoderResult Run(const std::string_view name, const std::span<const std::uint8_t> input) {
  const auto operation = reb::DecoderOperationFromName(name);
  Check(operation.has_value(), name, "operation name was not recognized");
  return reb::TransformBytes(*operation, input);
}

std::string Expect(const std::string_view name, const std::span<const std::uint8_t> input) {
  const auto result = Run(name, input);
  Check(result.status == reb::DecoderStatus::kOk && result.error.empty(), name, result.error);
  return Text(result.output);
}

// The digit-at-a-time conversion the limb conversion replaced, as a reference.
std::string ReferenceBase36(std::string decimal) {
  constexpr char kDigits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  std::string reversed;
  while (!(decimal.size() == 1 && decimal[0] == '0')) {
    unsigned remainder = 0;
    std::string quotient;
    for (const char digit : decimal) {
      const unsigned value = remainder * 10U + static_cast<unsigned>(digit - '0');
      if (!quotient.empty() || value / 36U != 0) {
        quotient.push_back(static_cast<char>('0' + value / 36U));
      }
      remainder = value % 36U;
    }
    reversed.push_back(kDigits[remainder]);
    decimal = quotient.empty() ? "0" : quotient;
  }
  return reversed.empty() ? "0" : std::string(reversed.rbegin(), reversed.rend());
}

void CheckMagicAndDigests() {
  const std::array<std::pair<std::string_view, std::size_t>, 4> operations = {{
      {"sha256", 64},
      {"sha384", 96},
      {"sha512", 128},
      {"magic-inspect", 0},
  }};
  const std::array<std::vector<std::uint8_t>, 3> fixtures = {{
      {},
      {0, 255, 128, 1},
      {'d', 'e', 'a', 'd', 'b', 'e', 'e', 'f'},
  }};
  for (const auto& [name, digest_size] : operations) {
    const auto operation = reb::DecoderOperationFromName(name);
    Check(operation.has_value(), name, "operation name was not recognized");
    Check(reb::DecoderOperationName(*operation) == name, name, "name did not round-trip");
    for (const auto& fixture : fixtures) {
      const auto original = fixture;
      const auto output = Expect(name, fixture);
      Check(!output.empty(), name, "successful output unexpectedly empty");
      if (digest_size != 0) {
        Check(output.size() == digest_size, name, "digest hexadecimal size mismatch");
      }
      Check(fixture == original, name, "input bytes changed");
    }
  }
}

void CheckJson() {
  constexpr std::size_t kDepth = 1'000'000;
  const std::string arrays = std::string(kDepth, '[') + std::string(kDepth, ']');
  Check(Expect("json-minify", Bytes(arrays)) == arrays, "json-minify",
        "a million nested arrays did not round-trip");
  std::string objects;
  for (std::size_t index = 0; index < 200'000; ++index) {
    objects += "{ \"a\" : ";
  }
  objects += "1";
  objects += std::string(200'000, '}');
  std::string compact;
  for (std::size_t index = 0; index < 200'000; ++index) {
    compact += "{\"a\":";
  }
  compact += "1" + std::string(200'000, '}');
  Check(Expect("json-minify", Bytes(objects)) == compact, "json-minify",
        "200,000 nested objects did not minify exactly");
  const std::string pretty = Expect("json-pretty", Bytes("[[1,{\"k\":[]}],{}]"));
  Check(pretty == "[\n  [\n    1,\n    {\n      \"k\": []\n    }\n  ],\n  {}\n]", "json-pretty",
        "pretty layout changed");
  constexpr std::size_t kPrettyDepth = 4'000;
  const std::string deep = std::string(kPrettyDepth, '[') + std::string(kPrettyDepth, ']');
  // Each enclosing level adds its brackets, two newlines and both indents.
  Check(Expect("json-pretty", Bytes(deep)).size() ==
            2 + 6 * (kPrettyDepth - 1) + 2 * (kPrettyDepth - 1) * (kPrettyDepth - 2),
        "json-pretty", "4,000 nested arrays did not indent every level");
  std::string tokens = "[";
  for (std::size_t index = 0; index < 300'000; ++index) {
    tokens += index == 0 ? "1" : ",1";
  }
  tokens += "]";
  Check(Expect("json-minify", Bytes(tokens)) == tokens, "json-minify",
        "300,000 tokens did not round-trip");
  for (const std::string_view malformed :
       {"[", "[1,", "{\"a\":", "{\"a\" 1}", "[1 2]", "{1:2}", "[]]", "{\"a\":1"}) {
    const auto result = Run("json-minify", Bytes(malformed));
    Check(result.status == reb::DecoderStatus::kInvalidInput && result.output.empty() &&
              !result.error.empty(),
          "json-minify", "malformed JSON was accepted");
  }
}

void CheckWire() {
  std::vector<std::uint8_t> fields;
  for (std::size_t index = 0; index < 20'000; ++index) {
    fields.insert(fields.end(), {8, 1});
  }
  const std::string report = Expect("protobuf-inspect", fields);
  std::size_t count = 0;
  for (std::size_t at = report.find("\"field_number\""); at != std::string::npos;
       at = report.find("\"field_number\"", at + 1)) {
    ++count;
  }
  Check(count == 20'000, "protobuf-inspect", "20,000 fields were not all reported");
  std::vector<std::uint8_t> frames;
  for (std::size_t index = 0; index < 5'000; ++index) {
    frames.insert(frames.end(), {0, 0, 0, 0, 2, 8, 1});
  }
  Check(Expect("grpc-web-inspect", frames).find("\"end\":35000,") != std::string::npos,
        "grpc-web-inspect", "5,000 frames were not all reported");
}

void CheckBase36() {
  std::uint32_t seed = 0x9e3779b9U;
  for (std::size_t length = 1; length <= 400; length += 7) {
    std::string decimal;
    for (std::size_t index = 0; index < length; ++index) {
      seed ^= seed << 13U;
      seed ^= seed >> 17U;
      seed ^= seed << 5U;
      decimal.push_back(static_cast<char>('0' + (index == 0 ? 1 + seed % 9U : seed % 10U)));
    }
    const std::string encoded = Expect("base36-encode", Bytes(decimal));
    Check(encoded == ReferenceBase36(decimal), "base36-encode", "limb result differs");
    Check(Expect("base36-decode", Bytes(encoded)) == decimal, "base36-decode",
          "limb result did not round-trip");
    Check(Expect("base36-encode", Bytes("-" + decimal)) == "-" + encoded, "base36-encode",
          "sign was not kept");
  }
  for (const auto& [decimal, base36] : std::array<std::pair<std::string_view, std::string_view>, 6>{
           {{"0", "0"},
            {"-000", "0"},
            {"35", "z"},
            {"2176782336", "1000000"},
            {"1000000000", "gjdgxs"},
            {"18446744073709551616", "3w5e11264sgsg"}}}) {
    Check(Expect("base36-encode", Bytes(decimal)) == base36, "base36-encode", decimal);
  }
  Check(Expect("base36-decode", Bytes("ZZ")) == "1295", "base36-decode", "upper case differs");
  const std::string digits(200'000, '7');
  const std::string encoded = Expect("base36-encode", Bytes(digits));
  Check(Expect("base36-decode", Bytes(encoded)) == digits, "base36",
        "200,000 digits did not round-trip");
}

void CheckLargeBytes() {
  const std::vector<std::uint8_t> zeros(64U << 20U, 0);
  const auto compressed = Run("gzip-compress", zeros);
  Check(compressed.status == reb::DecoderStatus::kOk, "gzip-compress", compressed.error);
  const auto inflated = Run("gzip-decompress", compressed.output);
  Check(inflated.status == reb::DecoderStatus::kOk && inflated.output == zeros, "gzip-decompress",
        "64 MiB did not inflate whole");
  const std::vector<std::uint8_t> text(9U << 20U, 'a');
  const auto encoded = Run("base64-encode", text);
  Check(encoded.status == reb::DecoderStatus::kOk && encoded.output.size() == 12U << 20U,
        "base64-encode", "9 MiB did not encode whole");
  const auto decoded = Run("base64-decode", encoded.output);
  Check(decoded.status == reb::DecoderStatus::kOk && decoded.output == text, "base64-decode",
        "12 MiB did not decode whole");
}

void CheckJwt() {
  const std::string claim(200'000, 'c');
  const std::string payload = "{\"sub\":\"" + claim + "\"}";
  const std::vector<std::uint8_t> secret(10'000, 's');
  const auto created = reb::CreateJwt(payload, reb::JwtAlgorithm::kHs512, secret, std::nullopt);
  Check(created.status == reb::DecoderStatus::kOk && created.token.size() > 64U << 10U,
        "jwt-create", created.error);
  const auto verified = reb::VerifyJwt(created.token, secret);
  Check(verified.status == reb::DecoderStatus::kOk &&
            verified.signature_status == reb::JwtSignatureStatus::kVerified &&
            verified.payload_json.find(claim) != std::string::npos,
        "jwt-verify", "a 270 KB token with a 10 KB secret did not verify");
  // An RS512 signature from a 4096-bit key is 512 bytes.
  const auto header = Run("base64url-encode", Bytes("{\"alg\":\"RS512\",\"typ\":\"JWT\"}"));
  const auto body = Run("base64url-encode", Bytes("{\"sub\":\"x\"}"));
  const auto signature = Run("base64url-encode", std::vector<std::uint8_t>(512, 7));
  const auto inspected =
      reb::InspectJwt(Text(header.output) + "." + Text(body.output) + "." + Text(signature.output));
  Check(inspected.status == reb::DecoderStatus::kOk && inspected.signature_bytes == 512 &&
            inspected.signature_status == reb::JwtSignatureStatus::kUnsupported,
        "jwt-inspect", "a 512-byte signature was refused");
}

}  // namespace

int main() {
  CheckMagicAndDigests();
  CheckJson();
  CheckWire();
  CheckBase36();
  CheckLargeBytes();
  CheckJwt();
  std::cout << "PASS direct decoder API at scale: a million nested arrays, 200,000 nested "
               "objects, 300,000 tokens, 20,000 protobuf fields, 5,000 gRPC-web frames, "
               "200,000-digit Base36 against a reference, 64 MiB inflation, 12 MiB Base64, a "
               "270 KB JWT with a 10 KB secret, a 512-byte signature, and Magic/SHA on empty and "
               "binary input\n";
}
