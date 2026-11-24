#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace reb {

// Inputs, outputs, tokens, secrets and JSON nesting have no fixed size: a
// transform holds what its input needs, and JSON is parsed with an explicit
// stack, so depth costs heap rather than the call stack. A caller that must
// stop long work runs these in a process it can terminate.

enum class DecoderOperation : std::uint8_t {
  kBase64Encode,
  kBase64Decode,
  kBase64UrlEncode,
  kBase64UrlDecode,
  kHexEncode,
  kHexDecode,
  kUrlEncode,
  kUrlDecode,
  kBase36Encode,
  kBase36Decode,
  kGzipCompress,
  kGzipDecompress,
  kZlibCompress,
  kZlibDecompress,
  kDeflateCompress,
  kDeflateDecompress,
  kJsonPretty,
  kJsonMinify,
  kProtobufInspect,
  kGrpcWebInspect,
  kGrpcWebTextInspect,
  kMagicInspect,
  kSha256,
  kSha384,
  kSha512,
};

enum class DecoderStatus : std::uint8_t {
  kOk,
  kInvalidInput,
  kUnsupported,
  kInternalError,
};

struct DecoderResult final {
  DecoderStatus status = DecoderStatus::kInternalError;
  std::vector<std::uint8_t> output;
  std::string error;
};

[[nodiscard]] std::optional<DecoderOperation> DecoderOperationFromName(
    std::string_view name) noexcept;
[[nodiscard]] std::string_view DecoderOperationName(DecoderOperation operation) noexcept;
[[nodiscard]] DecoderResult TransformBytes(DecoderOperation operation,
                                           std::span<const std::uint8_t> input);

enum class JwtAlgorithm : std::uint8_t {
  kNone,
  kHs256,
  kHs384,
  kHs512,
  kUnsupported,
};

enum class JwtSignatureStatus : std::uint8_t {
  kNotChecked,
  kVerified,
  kInvalid,
  kUnsigned,
  kUnsupported,
};

struct JwtInspection final {
  DecoderStatus status = DecoderStatus::kInvalidInput;
  std::string error;
  std::string algorithm;
  JwtAlgorithm algorithm_kind = JwtAlgorithm::kUnsupported;
  JwtSignatureStatus signature_status = JwtSignatureStatus::kNotChecked;
  std::string header_json;
  std::string payload_json;
  std::size_t token_bytes = 0;
  std::size_t signature_bytes = 0;
};

struct JwtCreation final {
  DecoderStatus status = DecoderStatus::kInvalidInput;
  std::string error;
  std::string token;
};

[[nodiscard]] JwtInspection InspectJwt(std::string_view token);
[[nodiscard]] JwtInspection VerifyJwt(std::string_view token, std::span<const std::uint8_t> secret);
[[nodiscard]] JwtCreation CreateJwt(std::string_view payload_json,
                                    JwtAlgorithm algorithm,
                                    std::span<const std::uint8_t> secret,
                                    std::optional<std::uint64_t> expires_at);
[[nodiscard]] std::string JwtInspectionToJson(const JwtInspection& inspection);
[[nodiscard]] std::string JwtCreationToJson(const JwtCreation& creation);

}  // namespace reb
