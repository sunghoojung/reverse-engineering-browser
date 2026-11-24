#include "reb/decoder.hpp"

#include <sys/resource.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

bool SetProcessLimit(const int resource, const rlimit& limit, const std::string_view label) {
  if (setrlimit(resource, &limit) == 0) {
    return true;
  }
  std::cerr << "Decoder " << label << " limit failed: " << std::strerror(errno) << '\n';
  return false;
}

// No CPU-time, memory or output-size limit: a decode runs as long as its
// input needs, and the caller stops it by terminating the process when its
// request goes away. Captured bytes never reach a core file, and the decoder
// needs no descriptors beyond its standard streams.
bool ApplyProcessLimits() {
  const rlimit no_core{.rlim_cur = 0, .rlim_max = 0};
  const rlimit open_files{.rlim_cur = 32, .rlim_max = 32};
  return SetProcessLimit(RLIMIT_CORE, no_core, "core") &&
         SetProcessLimit(RLIMIT_NOFILE, open_files, "open-file");
}

std::vector<std::uint8_t> ReadStandardInput() {
  std::vector<std::uint8_t> input;
  std::array<char, 64U << 10U> chunk{};
  while (std::cin.good()) {
    std::cin.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const std::streamsize count = std::cin.gcount();
    if (count <= 0) {
      break;
    }
    input.insert(input.end(), reinterpret_cast<const std::uint8_t*>(chunk.data()),
                 reinterpret_cast<const std::uint8_t*>(chunk.data()) + count);
  }
  return input;
}

bool WriteStandardOutput(const std::span<const std::uint8_t> output) {
  if (!output.empty()) {
    std::cout.write(reinterpret_cast<const char*>(output.data()),
                    static_cast<std::streamsize>(output.size()));
  }
  return std::cout.good();
}

// A frame is an 8-byte big-endian length and that many bytes.
std::optional<std::uint64_t> ReadFrameSize(const std::span<const std::uint8_t> input,
                                           std::size_t& position) {
  if (input.size() - position < 8) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (std::size_t offset = 0; offset < 8; ++offset) {
    value = (value << 8U) | input[position + offset];
  }
  position += 8;
  return value;
}

bool ReadFrame(const std::span<const std::uint8_t> input,
               std::size_t& position,
               std::span<const std::uint8_t>& frame) {
  const std::optional<std::uint64_t> size = ReadFrameSize(input, position);
  if (!size.has_value() || *size > input.size() - position) {
    return false;
  }
  frame = input.subspan(position, static_cast<std::size_t>(*size));
  position += static_cast<std::size_t>(*size);
  return true;
}

std::optional<reb::JwtAlgorithm> ParseJwtAlgorithm(const std::string_view value) {
  if (value == "none") {
    return reb::JwtAlgorithm::kNone;
  }
  if (value == "HS256") {
    return reb::JwtAlgorithm::kHs256;
  }
  if (value == "HS384") {
    return reb::JwtAlgorithm::kHs384;
  }
  if (value == "HS512") {
    return reb::JwtAlgorithm::kHs512;
  }
  return std::nullopt;
}

std::optional<std::uint64_t> ParseExpiration(const std::string_view value, bool& valid) {
  valid = false;
  if (value == "none") {
    valid = true;
    return std::nullopt;
  }
  std::uint64_t expiration = 0;
  const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), expiration);
  if (error != std::errc() || end != value.data() + value.size()) {
    return std::nullopt;
  }
  valid = true;
  return expiration;
}

reb::JwtInspection JwtInspectionError(const std::string_view message) {
  reb::JwtInspection inspection;
  inspection.status = reb::DecoderStatus::kInvalidInput;
  inspection.error = message;
  return inspection;
}

reb::JwtCreation JwtCreationError(const std::string_view message) {
  reb::JwtCreation creation;
  creation.status = reb::DecoderStatus::kInvalidInput;
  creation.error = message;
  return creation;
}

int Transform(const std::string_view operation_name) {
  const std::optional<reb::DecoderOperation> operation =
      reb::DecoderOperationFromName(operation_name);
  if (!operation.has_value()) {
    std::cerr << "Unknown decoder operation\n";
    return 2;
  }
  const auto input = ReadStandardInput();
  reb::DecoderResult result = reb::TransformBytes(*operation, input);
  if (result.status != reb::DecoderStatus::kOk) {
    std::cerr << result.error << '\n';
    return 2;
  }
  if (!WriteStandardOutput(result.output)) {
    std::cerr << "Decoder output could not be written\n";
    return 4;
  }
  return 0;
}

int InspectJwt() {
  const auto input = ReadStandardInput();
  const std::string_view token(reinterpret_cast<const char*>(input.data()), input.size());
  std::cout << reb::JwtInspectionToJson(reb::InspectJwt(token));
  return std::cout.good() ? 0 : 4;
}

int VerifyJwt() {
  const auto input = ReadStandardInput();
  std::size_t position = 0;
  std::span<const std::uint8_t> token;
  std::span<const std::uint8_t> secret;
  if (!ReadFrame(input, position, token) || !ReadFrame(input, position, secret) ||
      position != input.size()) {
    std::cout << reb::JwtInspectionToJson(
        JwtInspectionError("JWT verification frame is malformed"));
    return 0;
  }
  const std::string_view token_text(reinterpret_cast<const char*>(token.data()), token.size());
  std::cout << reb::JwtInspectionToJson(reb::VerifyJwt(token_text, secret));
  return std::cout.good() ? 0 : 4;
}

int CreateJwt(const std::string_view algorithm_name, const std::string_view expiration_text) {
  const std::optional<reb::JwtAlgorithm> algorithm = ParseJwtAlgorithm(algorithm_name);
  bool expiration_valid = false;
  const std::optional<std::uint64_t> expiration =
      ParseExpiration(expiration_text, expiration_valid);
  if (!algorithm.has_value() || !expiration_valid) {
    std::cout << reb::JwtCreationToJson(JwtCreationError("JWT creation arguments are invalid"));
    return 0;
  }
  const auto input = ReadStandardInput();
  std::size_t position = 0;
  std::span<const std::uint8_t> payload;
  std::span<const std::uint8_t> secret;
  if (!ReadFrame(input, position, payload) || !ReadFrame(input, position, secret) ||
      position != input.size()) {
    std::cout << reb::JwtCreationToJson(JwtCreationError("JWT creation frame is malformed"));
    return 0;
  }
  const std::string_view payload_text(reinterpret_cast<const char*>(payload.data()),
                                      payload.size());
  std::cout << reb::JwtCreationToJson(reb::CreateJwt(payload_text, *algorithm, secret, expiration));
  return std::cout.good() ? 0 : 4;
}

void PrintUsage() {
  std::cerr << "Usage: reb-decoder transform OPERATION\n"
               "       reb-decoder jwt-inspect\n"
               "       reb-decoder jwt-verify\n"
               "       reb-decoder jwt-create ALGORITHM EXPIRATION_EPOCH|none\n";
}

}  // namespace

int main(const int argc, const char* const argv[]) {
  if (!ApplyProcessLimits()) {
    std::cerr << "Decoder process limits could not be applied\n";
    return 5;
  }
  if (argc == 3 && std::string_view(argv[1]) == "transform") {
    return Transform(argv[2]);
  }
  if (argc == 2 && std::string_view(argv[1]) == "jwt-inspect") {
    return InspectJwt();
  }
  if (argc == 2 && std::string_view(argv[1]) == "jwt-verify") {
    return VerifyJwt();
  }
  if (argc == 4 && std::string_view(argv[1]) == "jwt-create") {
    return CreateJwt(argv[2], argv[3]);
  }
  PrintUsage();
  return 1;
}
