// Test-only parser driver. Production CLI resource limits remain unchanged.
// ASan needs a large virtual shadow map, incompatible with the CLI's RLIMIT_AS.
#include "reb/decoder.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
  if (argc != 3 || std::string_view(argv[1]) != "transform") {
    return 2;
  }
  const auto operation = reb::DecoderOperationFromName(argv[2]);
  if (!operation.has_value()) {
    return 2;
  }
  std::vector<std::uint8_t> input;
  std::array<char, 4096> chunk{};
  while (std::cin.good()) {
    std::cin.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const auto count = std::cin.gcount();
    if (count <= 0) {
      break;
    }
    const auto size = static_cast<std::size_t>(count);
    if (size > reb::kDecoderMaxInputBytes - input.size()) {
      return 2;
    }
    input.insert(input.end(), chunk.begin(), chunk.begin() + count);
  }
  if (!std::cin.eof()) {
    return 2;
  }
  const auto result = reb::TransformBytes(*operation, input);
  if (result.status != reb::DecoderStatus::kOk) {
    return result.status == reb::DecoderStatus::kOutputLimit ? 3 : 2;
  }
  std::cout.write(reinterpret_cast<const char*>(result.output.data()),
                  static_cast<std::streamsize>(result.output.size()));
  return std::cout.good() ? 0 : 2;
}
