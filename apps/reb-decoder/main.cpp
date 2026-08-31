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

constexpr std::size_t kMaximumFramedInput =
    reb::kDecoderMaxJwtBytes + reb::kDecoderMaxSecretBytes + 8;

bool SetProcessLimit(const int resource, const rlimit& limit, const std::string_view label) {
  if (setrlimit(resource, &limit) == 0) {
    return true;
  }
  std::cerr << "Decoder " << label << " limit failed: " << std::strerror(errno) << '\n';
  return false;
}

bool ApplyProcessLimits() {
  const rlimit no_core{.rlim_cur = 0, .rlim_max = 0};
#if !defined(__APPLE__)
  const rlimit address_space{.rlim_cur = 128U << 20U, .rlim_max = 128U << 20U};
#endif
  const rlimit cpu_time{.rlim_cur = 2, .rlim_max = 2};
  const rlimit file_size{.rlim_cur = 2U << 20U, .rlim_max = 2U << 20U};
  const rlimit open_files{.rlim_cur = 32, .rlim_max = 32};
  const bool memory_limited =
#if defined(__APPLE__)
      true;
#else
      SetProcessLimit(RLIMIT_AS, address_space, "address-space");
#endif
  return memory_limited && SetProcessLimit(RLIMIT_CORE, no_core, "core") &&
         SetProcessLimit(RLIMIT_CPU, cpu_time, "CPU") &&
         SetProcessLimit(RLIMIT_FSIZE, file_size, "output-file") &&
         SetProcessLimit(RLIMIT_NOFILE, open_files, "open-file");
}

std::optional<std::vector<std::uint8_t>> ReadStandardInput(const std::size_t maximum_bytes) {
  std::vector<std::uint8_t> input;
  input.reserve(std::min(maximum_bytes, static_cast<std::size_t>(64U << 10U)));
  std::array<char, 32U << 10U> chunk{};
  while (std::cin.good()) {
    std::cin.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const std::streamsize count = std::cin.gcount();
    if (count <= 0) {
      break;
    }
    const std::size_t added = static_cast<std::size_t>(count);
    if (added > maximum_bytes - std::min(input.size(), maximum_bytes)) {
      return std::nullopt;
    }
    input.insert(input.end(), reinterpret_cast<const std::uint8_t*>(chunk.data()),
                 reinterpret_cast<const std::uint8_t*>(chunk.data()) + added);
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

std::optional<std::uint32_t> ReadFrameSize(const std::span<const std::uint8_t> input,
                                           std::size_t& position) {
  if (position + 4 > input.size()) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (std::size_t offset = 0; offset < 4; ++offset) {
    value = (value << 8U) | input[position + offset];
  }
  position += 4;
  return value;
}

bool ReadFrame(const std::span<const std::uint8_t> input,
               std::size_t& position,
               const std::size_t maximum_bytes,
               std::span<const std::uint8_t>& frame) {
  const std::optional<std::uint32_t> size = ReadFrameSize(input, position);
  if (!size.has_value() || *size > maximum_bytes || *size > input.size() - position) {
    return false;
  }
  frame = input.subspan(position, *size);
  position += *size;
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

int Transform(const std::string_view operation_name) {
  const std::optional<reb::DecoderOperation> operation =
      reb::DecoderOperationFromName(operation_name);
  if (!operation.has_value()) {
    std::cerr << "Unknown decoder operation\n";
    return 2;
  }
  const auto input = ReadStandardInput(reb::kDecoderMaxInputBytes);
  if (!input.has_value()) {
    std::cerr << "Decoder input exceeds 1 MiB\n";
    return 2;
  }
  reb::DecoderResult result = reb::TransformBytes(*operation, *input);
  if (result.status != reb::DecoderStatus::kOk) {
    std::cerr << result.error << '\n';
    return result.status == reb::DecoderStatus::kOutputLimit ? 3 : 2;
  }
  if (!WriteStandardOutput(result.output)) {
    std::cerr << "Decoder output could not be written\n";
    return 4;
  }
  return 0;
}

int InspectJwt() {
  const auto input = ReadStandardInput(reb::kDecoderMaxJwtBytes);
  if (!input.has_value()) {
    std::cout << reb::JwtInspectionToJson(
        {.status = reb::DecoderStatus::kInvalidInput, .error = "JWT exceeds 64 KiB"});
    return 0;
  }
  const std::string_view token(reinterpret_cast<const char*>(input->data()), input->size());
  std::cout << reb::JwtInspectionToJson(reb::InspectJwt(token));
  return std::cout.good() ? 0 : 4;
}

int VerifyJwt() {
  const auto input = ReadStandardInput(kMaximumFramedInput);
  if (!input.has_value()) {
    std::cout << reb::JwtInspectionToJson({.status = reb::DecoderStatus::kInvalidInput,
                                           .error = "JWT verification input is oversized"});
    return 0;
  }
  std::size_t position = 0;
  std::span<const std::uint8_t> token;
  std::span<const std::uint8_t> secret;
  if (!ReadFrame(*input, position, reb::kDecoderMaxJwtBytes, token) ||
      !ReadFrame(*input, position, reb::kDecoderMaxSecretBytes, secret) ||
      position != input->size()) {
    std::cout << reb::JwtInspectionToJson({.status = reb::DecoderStatus::kInvalidInput,
                                           .error = "JWT verification frame is malformed"});
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
    std::cout << reb::JwtCreationToJson({.status = reb::DecoderStatus::kInvalidInput,
                                         .error = "JWT creation arguments are invalid"});
    return 0;
  }
  const auto input = ReadStandardInput(kMaximumFramedInput);
  std::size_t position = 0;
  std::span<const std::uint8_t> payload;
  std::span<const std::uint8_t> secret;
  if (!input.has_value() || !ReadFrame(*input, position, 56U << 10U, payload) ||
      !ReadFrame(*input, position, reb::kDecoderMaxSecretBytes, secret) ||
      position != input->size()) {
    std::cout << reb::JwtCreationToJson(
        {.status = reb::DecoderStatus::kInvalidInput, .error = "JWT creation frame is malformed"});
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
