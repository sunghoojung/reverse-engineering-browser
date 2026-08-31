#include "reb/decoder.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

namespace {

std::vector<std::uint8_t> Bytes(const std::string_view value) {
  return {reinterpret_cast<const std::uint8_t*>(value.data()),
          reinterpret_cast<const std::uint8_t*>(value.data()) + value.size()};
}

std::string Text(const reb::DecoderResult& result) {
  return {reinterpret_cast<const char*>(result.output.data()), result.output.size()};
}

reb::DecoderResult Transform(const reb::DecoderOperation operation,
                             const std::string_view input,
                             const std::size_t output_limit = reb::kDecoderMaxOutputBytes) {
  const std::vector<std::uint8_t> bytes = Bytes(input);
  return reb::TransformBytes(operation, bytes, output_limit);
}

}  // namespace

int main() {
  CHECK(reb::DecoderOperationFromName("base64-decode") == reb::DecoderOperation::kBase64Decode);
  CHECK(!reb::DecoderOperationFromName("unknown").has_value());
  CHECK(reb::DecoderOperationName(reb::DecoderOperation::kGzipDecompress) == "gzip-decompress");

  const reb::DecoderResult base64 = Transform(reb::DecoderOperation::kBase64Encode, "Origin Trace");
  CHECK(base64.status == reb::DecoderStatus::kOk);
  CHECK(Text(base64) == "T3JpZ2luIFRyYWNl");
  CHECK(Text(Transform(reb::DecoderOperation::kBase64Decode, Text(base64))) == "Origin Trace");
  CHECK(Transform(reb::DecoderOperation::kBase64Decode, "YQ=").status ==
        reb::DecoderStatus::kInvalidInput);
  CHECK(Transform(reb::DecoderOperation::kBase64Decode, "YR==").status ==
        reb::DecoderStatus::kInvalidInput);

  const reb::DecoderResult base64_url =
      Transform(reb::DecoderOperation::kBase64UrlEncode, "\xfb\xff");
  CHECK(Text(base64_url) == "-_8");
  CHECK(Text(Transform(reb::DecoderOperation::kBase64UrlDecode, "-_8")) == "\xfb\xff");

  const std::string bytes_with_null("A\0Z", 3);
  CHECK(Text(Transform(reb::DecoderOperation::kHexEncode, bytes_with_null)) == "41005a");
  CHECK(Text(Transform(reb::DecoderOperation::kHexDecode, "0x41:00-5A")) == bytes_with_null);
  CHECK(Transform(reb::DecoderOperation::kHexDecode, "abc").status ==
        reb::DecoderStatus::kInvalidInput);

  const std::string unicode = "value / \xe2\x9c\x93";
  const reb::DecoderResult url = Transform(reb::DecoderOperation::kUrlEncode, unicode);
  CHECK(Text(url) == "value%20%2F%20%E2%9C%93");
  CHECK(Text(Transform(reb::DecoderOperation::kUrlDecode, Text(url))) == unicode);
  CHECK(Transform(reb::DecoderOperation::kUrlDecode, "%GG").status ==
        reb::DecoderStatus::kInvalidInput);

  CHECK(Text(Transform(reb::DecoderOperation::kBase36Encode, "123456789012345678901234567890")) ==
        "byw97um9s91dlz68tsi");
  CHECK(Text(Transform(reb::DecoderOperation::kBase36Decode, "byw97um9s91dlz68tsi")) ==
        "123456789012345678901234567890");
  CHECK(Text(Transform(reb::DecoderOperation::kBase36Encode, "-36")) == "-10");

  const std::string repeated(32U << 10U, 'A');
  for (const auto pair : {
           std::pair(reb::DecoderOperation::kGzipCompress, reb::DecoderOperation::kGzipDecompress),
           std::pair(reb::DecoderOperation::kZlibCompress, reb::DecoderOperation::kZlibDecompress),
           std::pair(reb::DecoderOperation::kDeflateCompress,
                     reb::DecoderOperation::kDeflateDecompress),
       }) {
    const reb::DecoderResult compressed = Transform(pair.first, repeated);
    CHECK(compressed.status == reb::DecoderStatus::kOk);
    CHECK(compressed.output.size() < repeated.size());
    const reb::DecoderResult decompressed =
        reb::TransformBytes(pair.second, compressed.output, repeated.size());
    CHECK(decompressed.status == reb::DecoderStatus::kOk);
    CHECK(Text(decompressed) == repeated);
    CHECK(reb::TransformBytes(pair.second, compressed.output, 1'024).status ==
          reb::DecoderStatus::kOutputLimit);
  }
  CHECK(Transform(reb::DecoderOperation::kGzipDecompress, "not gzip").status ==
        reb::DecoderStatus::kInvalidInput);

  const std::vector<std::uint8_t> oversized_input(reb::kDecoderMaxInputBytes + 1, 0);
  CHECK(reb::TransformBytes(reb::DecoderOperation::kHexEncode, oversized_input).status ==
        reb::DecoderStatus::kInvalidInput);

  const std::string json = R"({ "alpha" : [1, true, null], "nested": {"text":"safe"} })";
  const reb::DecoderResult minified = Transform(reb::DecoderOperation::kJsonMinify, json);
  CHECK(Text(minified) == R"({"alpha":[1,true,null],"nested":{"text":"safe"}})");
  const reb::DecoderResult pretty =
      reb::TransformBytes(reb::DecoderOperation::kJsonPretty, minified.output);
  CHECK(Text(pretty).find("\n  \"alpha\": [") != std::string::npos);
  CHECK(Transform(reb::DecoderOperation::kJsonMinify, "{\"bad\":01}").status ==
        reb::DecoderStatus::kInvalidInput);
  CHECK(Transform(reb::DecoderOperation::kJsonPretty, json, 8).status ==
        reb::DecoderStatus::kOutputLimit);
  const std::string invalid_utf8("{\"value\":\"\xff\"}", 13);
  CHECK(Transform(reb::DecoderOperation::kJsonMinify, invalid_utf8).status ==
        reb::DecoderStatus::kInvalidInput);
  const std::string too_deep = std::string(66, '[') + "0" + std::string(66, ']');
  CHECK(Transform(reb::DecoderOperation::kJsonMinify, too_deep).status ==
        reb::DecoderStatus::kInvalidInput);

  constexpr std::string_view kPayload = R"({"sub":"123","admin":true})";
  constexpr std::string_view kSecret = "secret";
  const std::vector<std::uint8_t> secret = Bytes(kSecret);
  const std::array<std::pair<std::string_view, reb::JwtAlgorithm>, 3> signed_tokens = {{
      {"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0."
       "4EgcHtcYc2TlAm54RQRAMM4--ALPIGwXRwjRBu6AMoQ",
       reb::JwtAlgorithm::kHs256},
      {"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0."
       "7OlZxlZD02RqEPu6EneodidxvSl1fIO9ZwnX3eBpOeCkdbw-bLxLpr8A6w-ARLuz",
       reb::JwtAlgorithm::kHs384},
      {"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0."
       "VmQMUFKrsHUaxCG7X4DQRX7ynKbDENVHmitDhA_OPiNiqK8smb18YA5TbT3AGkBbcpyOI8vA04ElAKiQJe5cXA",
       reb::JwtAlgorithm::kHs512},
  }};
  for (const auto& [token, algorithm] : signed_tokens) {
    const reb::JwtInspection inspection = reb::InspectJwt(token);
    CHECK(inspection.status == reb::DecoderStatus::kOk);
    CHECK(inspection.algorithm_kind == algorithm);
    CHECK(inspection.signature_status == reb::JwtSignatureStatus::kNotChecked);
    CHECK(inspection.payload_json.find("\"admin\": true") != std::string::npos);
    const reb::JwtInspection verified = reb::VerifyJwt(token, secret);
    CHECK(verified.signature_status == reb::JwtSignatureStatus::kVerified);
    const std::vector<std::uint8_t> wrong_secret = Bytes("wrong");
    CHECK(reb::VerifyJwt(token, wrong_secret).signature_status ==
          reb::JwtSignatureStatus::kInvalid);
    const reb::JwtCreation created = reb::CreateJwt(kPayload, algorithm, secret, std::nullopt);
    CHECK(created.status == reb::DecoderStatus::kOk);
    CHECK(created.token == token);
  }

  const std::string long_payload = "{\"data\":\"" + std::string(200, 'A') + "\"}";
  const std::vector<std::uint8_t> long_secret(200, 'B');
  const std::array<std::pair<reb::JwtAlgorithm, std::string_view>, 3> long_signatures = {{
      {reb::JwtAlgorithm::kHs256, "dNCSUyVUmvlnERJAxe-LQZbKavK5XZJMOHv6CTmyxuY"},
      {reb::JwtAlgorithm::kHs384,
       "tpwrhbWQ1rpEXIh0BMOKZntHyQVZHHmeAz99U1h6WVUEzXOOxkfu-GHW3XrloyrN"},
      {reb::JwtAlgorithm::kHs512,
       "Zj9Bd_I6EaYc961yWdlgS3XQGx5N0ux3WC8irNEN8b1k9K85vJpx8GEDYyNmOoNuVQIhCfQyIaIj_"
       "DnRdlJbtg"},
  }};
  for (const auto& [algorithm, signature] : long_signatures) {
    const reb::JwtCreation created =
        reb::CreateJwt(long_payload, algorithm, long_secret, std::nullopt);
    CHECK(created.status == reb::DecoderStatus::kOk);
    CHECK(created.token.ends_with(signature));
    CHECK(reb::VerifyJwt(created.token, long_secret).signature_status ==
          reb::JwtSignatureStatus::kVerified);
  }

  const reb::JwtCreation expiring =
      reb::CreateJwt("{}", reb::JwtAlgorithm::kHs256, secret, 2'000'000'000ULL);
  CHECK(expiring.status == reb::DecoderStatus::kOk);
  const reb::JwtInspection expiring_inspection = reb::VerifyJwt(expiring.token, secret);
  CHECK(expiring_inspection.signature_status == reb::JwtSignatureStatus::kVerified);
  CHECK(expiring_inspection.payload_json.find("2000000000") != std::string::npos);

  const reb::JwtCreation unsigned_token =
      reb::CreateJwt(kPayload, reb::JwtAlgorithm::kNone, {}, std::nullopt);
  CHECK(unsigned_token.status == reb::DecoderStatus::kOk);
  CHECK(unsigned_token.token.ends_with('.'));
  CHECK(reb::InspectJwt(unsigned_token.token).signature_status ==
        reb::JwtSignatureStatus::kUnsigned);
  CHECK(reb::InspectJwt("eyJhbGciOiJub25lIn0.e30.c2ln").signature_status ==
        reb::JwtSignatureStatus::kInvalid);
  const reb::JwtInspection unsupported = reb::InspectJwt("eyJhbGciOiJSUzI1NiJ9.e30.");
  CHECK(unsupported.status == reb::DecoderStatus::kOk);
  CHECK(unsupported.signature_status == reb::JwtSignatureStatus::kUnsupported);
  CHECK(reb::InspectJwt("not-a-token").status == reb::DecoderStatus::kInvalidInput);
  CHECK(reb::InspectJwt("eyJhbGciOiJIUzI1NiIsImFsZyI6IkhTNTEyIn0.e30.").status ==
        reb::DecoderStatus::kInvalidInput);
  CHECK(reb::InspectJwt("eyJhbGciOjF9.e30.").status == reb::DecoderStatus::kInvalidInput);
  CHECK(reb::CreateJwt(kPayload, reb::JwtAlgorithm::kNone, secret, std::nullopt).status ==
        reb::DecoderStatus::kInvalidInput);
  CHECK(reb::CreateJwt("{\"exp\":1}", reb::JwtAlgorithm::kHs256, secret, 2).status ==
        reb::DecoderStatus::kInvalidInput);

  const std::string inspection_json =
      reb::JwtInspectionToJson(reb::VerifyJwt(signed_tokens.front().first, secret));
  CHECK(inspection_json.find("\"signature_status\":\"verified\"") != std::string::npos);
  CHECK(inspection_json.find("\"protocol_version\":1") != std::string::npos);

  std::cout << "decoder_test passed\n";
  return 0;
}
