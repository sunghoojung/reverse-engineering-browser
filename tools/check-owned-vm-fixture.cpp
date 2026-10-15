#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

#include "../apps/reb-native-vm-fixture/owned_vm_helper_protocol.hpp"
#include "reb/owned_vm_fixture.hpp"

namespace reb {
// Test-only access exercises corruption/budget rejection without a production
// setter, arbitrary program input, or a command that can alter the fixture.
struct OwnedVmFixtureTestAccess final {
  static VmSnapshot& State(OwnedVmFixture& fixture) { return fixture.state_; }
  static void Count(OwnedVmFixture& fixture, std::uint64_t count) {
    fixture.executed_count_ = count;
  }
};
}  // namespace reb
namespace {
using namespace reb;
namespace helper = reb::owned_vm_helper;
void Require(bool condition, const char* name) {
  if (!condition) {
    std::cerr << "FAIL: " << name << '\n';
    std::exit(1);
  }
}
void Interpreter() {
  constexpr VmScope scope{1, 2, 3, 100};
  for (const auto architecture : {OwnedVmArchitecture::kRegister, OwnedVmArchitecture::kStack}) {
    for (const auto capacity : std::array<std::size_t, 3>{0, 2, 64}) {
      OwnedVmFixture untraced(architecture);
      OwnedVmFixture traced(architecture);
      NativeVmRecorder recorder(capacity);
      Require(recorder.Enable(scope, 0), "enable paired recorder");
      const auto initial = OwnedVmFixture::InitialState(architecture);
      Require(traced.snapshot() == initial && traced.executed_count() == 0 &&
                  recorder.records().empty(),
              "initial paused snapshot executes nothing");
      for (std::uint64_t i = 0; i < 9; ++i) {
        const auto before = traced.snapshot();
        for (int inspect = 0; inspect < 5; ++inspect)
          Require(traced.snapshot() == before && traced.executed_count() == i,
                  "repeated snapshots inert");
        const auto plain = untraced.ExecuteOne();
        const auto observed = traced.ExecuteOne(&recorder, 2, recorder.generation(), i + 1);
        Require(plain.status == OwnedVmExecuteStatus::kCommitted &&
                    observed.status == OwnedVmExecuteStatus::kCommitted &&
                    untraced.snapshot() == traced.snapshot() && traced.executed_count() == i + 1 &&
                    observed.transition.before == before &&
                    observed.transition.after == traced.snapshot(),
                "one atomic complete transition with paired entire state");
        Require(observed.recorder_result ==
                    (i < capacity ? VmRecordResult::kRecorded : VmRecordResult::kFull),
                "capacity loss does not change execution");
      }
      const auto final = traced.snapshot();
      Require(final.halted && final.pc == 10 && recorder.stats().attempted == 9,
              "real ninth halt instruction");
      Require(traced.ExecuteOne(&recorder, 2, recorder.generation(), 10).status ==
                      OwnedVmExecuteStatus::kHalted &&
                  traced.snapshot() == final && traced.executed_count() == 9 &&
                  recorder.stats().attempted == 9,
              "halt rejects without mutation or recorder attempt");
    }
    for (int corruption = 0; corruption < 4; ++corruption) {
      OwnedVmFixture fixture(architecture);
      auto& state = OwnedVmFixtureTestAccess::State(fixture);
      if (corruption == 0)
        state.pc = 7;
      else if (corruption == 1)
        state.stack[7] = {1, VmEvidence::kUnknown};
      else if (corruption == 2)
        state.register_count = 255;
      else
        state.memory[0] = {16, {99, VmEvidence::kObserved}};
      const auto before = state;
      NativeVmRecorder recorder;
      Require(recorder.Enable(scope, 0), "enable malformed fixture recorder");
      Require(fixture.ExecuteOne(&recorder, 2, recorder.generation(), 1).status ==
                      OwnedVmExecuteStatus::kInvalidState &&
                  fixture.snapshot() == before && fixture.executed_count() == 0 &&
                  recorder.stats().attempted == 0,
              "invalid PC/operand/storage fails before atomic commit");
    }
    for (const auto count : {kOwnedVmDispatchBudget, std::numeric_limits<std::uint64_t>::max()}) {
      OwnedVmFixture fixture(architecture);
      OwnedVmFixtureTestAccess::Count(fixture, count);
      const auto before = fixture.snapshot();
      Require(fixture.ExecuteOne().status == OwnedVmExecuteStatus::kBudget &&
                  fixture.snapshot() == before && fixture.executed_count() == count,
              "dispatch hard budget never wraps");
    }
  }
  OwnedVmFixture invalid(static_cast<OwnedVmArchitecture>(255));
  Require(invalid.ExecuteOne().status == OwnedVmExecuteStatus::kInvalidState,
          "invalid internal architecture does not dispatch");
}
void Codec() {
  constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t parsed = 0;
  Require(helper::CanonicalU64("18446744073709551615", parsed) && parsed == maximum,
          "lossless maximum decimal uint64");
  Require(helper::CanonicalU64("0", parsed) && parsed == 0, "canonical zero");
  for (const auto text : {"", "00", "01", "+1", "-1", "1.0", "1e3", " 1", "1 ", "0x1",
                          "18446744073709551616", "999999999999999999999"})
    Require(!helper::CanonicalU64(text, parsed), "noncanonical or overflowing uint64 rejected");
  std::array<std::uint8_t, helper::kRequestBytes> bytes{};
  helper::WriteLe(bytes, 0, 4, helper::kMagic);
  helper::WriteLe(bytes, 4, 2, helper::kVersion);
  helper::WriteLe(bytes, 6, 2, 2);
  for (const auto offset : std::array<std::size_t, 3>{8, 16, 24})
    helper::WriteLe(bytes, offset, 8, maximum);
  helper::Request request;
  Require(helper::DecodeRequest(bytes, request) && request.request_id == maximum &&
              request.generation == maximum && request.executed_count == maximum &&
              request.operation == helper::Operation::kExecuteOne,
          "explicit little endian lossless uint64 request");
  bytes[39] = 1;
  Require(!helper::DecodeRequest(bytes, request), "reserved request bytes rejected");
  const auto header = helper::ResponseHeader(helper::Status::kCountMismatch, maximum, 32768);
  Require(helper::ReadLe(header, 0, 4) == helper::kMagic && helper::ReadLe(header, 4, 2) == 1 &&
              helper::ReadLe(header, 6, 2) == 3 && helper::ReadLe(header, 8, 8) == maximum &&
              helper::ReadLe(header, 16, 4) == 32768 && helper::ReadLe(header, 20, 4) == 0,
          "explicit response header offsets");
  Require(!helper::Expired(99, 98, 100) && helper::Expired(100, 99, 100) &&
              helper::Expired(101, 99, 100) && helper::Expired(98, 99, 100) &&
              helper::Expired(0, 0, 100),
          "deadline equality, rollback, and invalid monotonic clock fail closed");
  helper::PayloadBuffer buffer;
  std::ostream out(&buffer);
  const std::string limit(helper::kMaxPayloadBytes, 'x');
  out << limit;
  Require(out.good() && buffer.view() == limit, "exactly 32 KiB payload fits");
  out << 'x';
  Require(!out.good() && buffer.view().size() == helper::kMaxPayloadBytes,
          "limit plus one fails without growing or silently succeeding");
}
}  // namespace
int main() {
  Interpreter();
  Codec();
  std::cout << "Owned VM core and private codec checks passed\n";
}
