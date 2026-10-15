#ifndef REB_OWNED_VM_FIXTURE_HPP_
#define REB_OWNED_VM_FIXTURE_HPP_

#include <cstdint>

#include "reb/native_vm_recorder.hpp"

namespace reb {

enum class OwnedVmArchitecture : std::uint8_t { kRegister, kStack };
enum class OwnedVmExecuteStatus : std::uint8_t { kCommitted, kHalted, kBudget, kInvalidState };
inline constexpr std::uint64_t kOwnedVmDispatchBudget = 16;

struct OwnedVmExecuteResult final {
  OwnedVmExecuteStatus status = OwnedVmExecuteStatus::kInvalidState;
  VmStep transition{};
  VmRecordResult recorder_result = VmRecordResult::kDisabled;
};

// One owner only. The two compiled programs have no external inputs. Snapshot
// reads are inert; only ExecuteOne can change state. No callbacks, I/O, locks,
// allocation, or exceptions occur in the instruction/recorder path.
class OwnedVmFixture final {
 public:
  explicit OwnedVmFixture(OwnedVmArchitecture architecture) noexcept;
  [[nodiscard]] static VmSnapshot InitialState(OwnedVmArchitecture architecture) noexcept;
  [[nodiscard]] const VmSnapshot& snapshot() const noexcept;
  [[nodiscard]] std::uint64_t executed_count() const noexcept;
  // Admission (scope, monotonic deadline, count/request guards) belongs to the
  // private control owner. Recording happens only after one atomic commit and
  // cannot undo an instruction, even when capacity is exhausted.
  [[nodiscard]] OwnedVmExecuteResult ExecuteOne(NativeVmRecorder* recorder = nullptr,
                                                std::uint64_t document_id = 0,
                                                std::uint64_t generation = 0,
                                                std::uint64_t now = 0) noexcept;

 private:
  friend struct OwnedVmFixtureTestAccess;
  [[nodiscard]] bool ValidState() const noexcept;
  OwnedVmArchitecture architecture_;
  VmSnapshot state_{};
  std::uint64_t executed_count_ = 0;
};

}  // namespace reb
#endif  // REB_OWNED_VM_FIXTURE_HPP_
