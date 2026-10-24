#include "components/reverse_engineering_browser/common/page_guest_dispatch.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

bool Fail(const char* message) {
  std::fprintf(stderr, "FAIL %s\n", message);
  return false;
}

std::vector<std::uint8_t> LinearBrTableModule() {
  std::vector<std::uint8_t> body{0x00};
  body.insert(body.end(), 16, 0x01);
  body.insert(body.end(), {0x41, 0x00, 0x0E, 0x00, 0x00, 0x0B});
  std::vector<std::uint8_t> module{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04,
                                   0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x0A};
  module.push_back(static_cast<std::uint8_t>(body.size() + 2));
  module.push_back(0x01);
  module.push_back(static_cast<std::uint8_t>(body.size()));
  module.insert(module.end(), body.begin(), body.end());
  return module;
}

}  // namespace

int main() {
  const auto empty = reb::WalkJavaScriptSwitchDispatch({});
  if (empty.submitted != 0 || empty.truncated) {
    return Fail("empty javascript program");
  }
  const std::array<std::uint8_t, 1> unsupported{0x01};
  if (reb::WalkJavaScriptSwitchDispatch(unsupported).submitted != 0) {
    return Fail("unsupported javascript opcode");
  }

  std::vector<std::uint8_t> program;
  for (int step = 0; step < 17; ++step) {
    program.insert(program.end(), {16, 0, static_cast<std::uint8_t>(step)});
  }
  program.push_back(19);
  const auto javascript = reb::WalkJavaScriptSwitchDispatch(program);
  if (!javascript.halted || javascript.truncated || javascript.submitted != 18) {
    return Fail("javascript step count");
  }
  for (std::uint32_t index = 0; index < 17; ++index) {
    const auto& step = javascript.steps[index];
    if (step.instruction_pointer != index * 3 || step.opcode != 16 || step.operand_count != 2) {
      return Fail("javascript store step");
    }
  }
  if (javascript.steps[17].instruction_pointer != 51 || javascript.steps[17].opcode != 19 ||
      javascript.steps[17].operand_count != 0) {
    return Fail("javascript halt");
  }

  const std::array<std::uint8_t, 2> loop{18, 0};
  const auto spinning = reb::WalkJavaScriptSwitchDispatch(loop);
  if (spinning.submitted != reb::kPageGuestStepCap || !spinning.truncated || spinning.halted) {
    return Fail("javascript step cap");
  }
  if (spinning.steps[0].instruction_pointer != 0 || spinning.steps[0].opcode != 18) {
    return Fail("javascript jump pc");
  }

  const std::array<std::uint8_t, 8> module_header{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
  if (reb::WalkWasmBrTableDispatch(module_header).submitted != 0) {
    return Fail("wasm without code");
  }
  std::vector<std::uint8_t> no_branch{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
                                      0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
                                      0x01, 0x00, 0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B};
  if (reb::WalkWasmBrTableDispatch(no_branch).submitted != 0) {
    return Fail("wasm without br_table");
  }

  const auto module = LinearBrTableModule();
  const auto wasm = reb::WalkWasmBrTableDispatch(module);
  if (!wasm.halted || wasm.truncated || wasm.submitted != 18) {
    return Fail("wasm step count");
  }
  for (std::uint32_t index = 0; index < 16; ++index) {
    if (wasm.steps[index].opcode != 0x01 || wasm.steps[index].operand_count != 0) {
      return Fail("wasm nop");
    }
    if (index > 0 &&
        wasm.steps[index].instruction_pointer != wasm.steps[index - 1].instruction_pointer + 1) {
      return Fail("wasm nop pc");
    }
  }
  if (wasm.steps[16].opcode != 0x41 || wasm.steps[16].operand_count != 1 ||
      wasm.steps[17].opcode != 0x0E || wasm.steps[17].operand_count != 1) {
    return Fail("wasm br_table tail");
  }

  const std::array<std::uint8_t, 54> fixture = {
      0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
      0x03, 0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x0A, 0x1D, 0x01, 0x1B, 0x01,
      0x01, 0x7F, 0x03, 0x40, 0x20, 0x00, 0x41, 0x01, 0x6A, 0x21, 0x00, 0x41, 0x00, 0x2D,
      0x00, 0x00, 0x1A, 0x41, 0x00, 0x0E, 0x02, 0x00, 0x00, 0x00, 0x0B, 0x0B};
  const auto looped = reb::WalkWasmBrTableDispatch(fixture);
  if (looped.submitted != reb::kPageGuestStepCap || !looped.truncated) {
    return Fail("wasm fixture cap");
  }
  bool saw_branch = false;
  for (std::uint32_t index = 0; index < looped.submitted; ++index) {
    if (looped.steps[index].opcode == 0x0E && looped.steps[index].operand_count == 3) {
      saw_branch = true;
    }
  }
  if (!saw_branch || looped.steps[0].opcode != 0x03) {
    return Fail("wasm fixture opcodes");
  }

  std::puts("PASS page guest walks observe javascript and wasm program counters");
  return 0;
}
