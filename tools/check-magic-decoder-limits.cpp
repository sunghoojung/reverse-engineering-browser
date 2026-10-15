// Direct API checks cover output budgets that the production CLI does not expose.
#include "reb/decoder.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void Check(bool condition, std::string_view operation, std::string_view message) {
  if (!condition) {
    std::cerr << "Magic/SHA boundary failure (" << operation << "): " << message << '\n';
    std::exit(1);
  }
}

void CheckFailure(const reb::DecoderResult& result,
                  reb::DecoderStatus expected,
                  std::string_view operation,
                  std::string_view message) {
  Check(result.status == expected, operation, message);
  Check(result.output.empty(), operation, "rejected operation emitted partial bytes");
  Check(!result.error.empty(), operation, "rejected operation omitted its error");
}

}  // namespace

int main() {
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
  const std::vector<std::uint8_t> oversized(reb::kDecoderMaxInputBytes + 1);
  for (const auto& [name, digest_size] : operations) {
    const auto operation = reb::DecoderOperationFromName(name);
    Check(operation.has_value(), name, "operation name was not recognized");
    Check(reb::DecoderOperationName(*operation) == name, name, "name did not round-trip");
    for (const auto& fixture : fixtures) {
      const auto original = fixture;
      const auto full = reb::TransformBytes(*operation, fixture);
      Check(full.status == reb::DecoderStatus::kOk && full.error.empty(), name,
            "default output budget failed");
      Check(!full.output.empty(), name, "successful output unexpectedly empty");
      if (digest_size != 0) {
        Check(full.output.size() == digest_size, name, "digest hexadecimal size mismatch");
      }
      const auto exact = reb::TransformBytes(*operation, fixture, full.output.size());
      Check(exact.status == reb::DecoderStatus::kOk && exact.output == full.output &&
                exact.error.empty(),
            name, "exact output budget failed or changed bytes");
      CheckFailure(reb::TransformBytes(*operation, fixture, full.output.size() - 1),
                   reb::DecoderStatus::kOutputLimit, name, "one-byte-short budget was accepted");
      CheckFailure(reb::TransformBytes(*operation, fixture, 1), reb::DecoderStatus::kOutputLimit,
                   name, "one-byte budget was accepted");
      CheckFailure(reb::TransformBytes(*operation, fixture, 0), reb::DecoderStatus::kInvalidInput,
                   name, "zero budget was accepted");
      CheckFailure(reb::TransformBytes(*operation, fixture, reb::kDecoderMaxOutputBytes + 1),
                   reb::DecoderStatus::kInvalidInput, name, "oversized budget was accepted");
      Check(fixture == original, name, "input bytes changed");
    }
    CheckFailure(reb::TransformBytes(*operation, oversized), reb::DecoderStatus::kInvalidInput,
                 name, "oversized input was accepted");
  }
  std::cout << "PASS direct Magic/SHA API: exact and short output budgets, invalid caps, "
               "oversized input, name round trips and unchanged empty/binary/ambiguous input\n";
}
