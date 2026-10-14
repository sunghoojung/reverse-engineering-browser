#ifndef REB_NATIVE_VM_RECORDER_HPP_
#define REB_NATIVE_VM_RECORDER_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace reb {

// Local cooperative-fixture API, not a serialized ABI or browser wire format.
// IDs and memory addresses are guest integers, never host pointers.
enum class VmEvidence : std::uint8_t { kUnknown, kObserved, kInferred };
enum class VmLocation : std::uint8_t { kImmediate, kRegister, kStack, kMemory };
enum class VmAccess : std::uint8_t { kRead, kWrite };
enum class VmRecordResult : std::uint8_t {
  kRecorded,
  kStaleGeneration,
  kExhausted,
  kDisabled,
  kExpired,
  kWrongDocument,
  kMalformed,
  kFull
};
inline constexpr std::size_t kNativeVmSlots = 8;
inline constexpr std::size_t kNativeVmEffects = 8;
inline constexpr std::size_t kNativeVmRecords = 64;

struct VmValue final {
  std::uint64_t bits = 0;
  VmEvidence evidence = VmEvidence::kUnknown;
  bool operator==(const VmValue&) const = default;
};
struct VmMemoryCell final {
  std::uint64_t guest_address = 0;
  VmValue value{};
  bool operator==(const VmMemoryCell&) const = default;
};
struct VmSnapshot final {
  std::uint64_t pc = 0;
  VmEvidence pc_evidence = VmEvidence::kUnknown;
  std::uint8_t register_count = 0;
  std::uint8_t stack_count = 0;
  std::uint8_t memory_count = 0;
  // True means the producer knows the state view omits additional locations.
  bool partial = false;
  bool halted = false;
  std::array<VmValue, kNativeVmSlots> registers{};
  std::array<VmValue, kNativeVmSlots> stack{};
  std::array<VmMemoryCell, kNativeVmSlots> memory{};
  bool operator==(const VmSnapshot&) const = default;
};
struct VmOperand final {
  VmLocation location = VmLocation::kImmediate;
  std::uint64_t index = 0;
  VmValue value{};
};
struct VmEffect final {
  VmAccess access = VmAccess::kRead;
  VmLocation location = VmLocation::kRegister;
  std::uint64_t index = 0;
  VmValue value{};
};
struct VmStep final {
  std::uint32_t opcode = 0;
  VmEvidence opcode_evidence = VmEvidence::kUnknown;
  std::uint8_t operand_count = 0;
  std::uint8_t effect_count = 0;
  bool partial = false;
  std::array<VmOperand, 4> operands{};
  std::array<VmEffect, kNativeVmEffects> effects{};
  VmSnapshot before{};
  VmSnapshot after{};
};
struct VmScope final {
  std::uint64_t session_id = 0;
  std::uint64_t document_id = 0;
  std::uint64_t invocation_id = 0;
  std::uint64_t expires_at = 0;
};
struct VmRecordedStep final {
  std::uint64_t sequence = 0;
  std::uint64_t tick = 0;
  VmStep step{};
};
struct VmRecorderStats final {
  std::uint64_t attempted = 0;
  std::uint64_t recorded = 0;
  std::uint64_t full = 0;
  std::uint64_t malformed = 0;
  std::uint64_t wrong_document = 0;
  std::uint64_t stale_generation = 0;
  std::uint64_t exhausted = 0;
  std::uint64_t expired = 0;
  std::uint64_t partial = 0;
};
static_assert(std::is_trivially_copyable_v<VmStep>);
static_assert(std::is_standard_layout_v<VmStep>);

// Single owner/thread only. No I/O, locks, allocation, exceptions, or callbacks
// in recording. Caller supplies trusted monotonically increasing clock ticks
// and a document generation token. This is not an authorization verifier.
class NativeVmRecorder final {
 public:
  explicit NativeVmRecorder(std::size_t capacity = kNativeVmRecords) noexcept;
  // Every enable attempt clears retained data and counters, including failures.
  [[nodiscard]] bool Enable(VmScope scope, std::uint64_t now) noexcept;
  void Disable() noexcept;
  // Navigation/detachment must call this before another document can execute.
  void InvalidateDocument() noexcept;
  // Capture generation() once when starting the invocation; never refresh it
  // on an old producer after re-enable. Stale identity is rejected before time.
  [[nodiscard]] VmRecordResult Record(std::uint64_t document_id,
                                      std::uint64_t generation,
                                      std::uint64_t now,
                                      const VmStep& step) noexcept;
  [[nodiscard]] std::span<const VmRecordedStep> records() const noexcept;
  [[nodiscard]] const VmRecorderStats& stats() const noexcept;
  [[nodiscard]] const VmScope& scope() const noexcept;
  [[nodiscard]] std::uint64_t generation() const noexcept;

 private:
  std::array<VmRecordedStep, kNativeVmRecords> records_{};
  VmRecorderStats stats_{};
  VmScope scope_{};
  std::size_t capacity_ = 0;
  std::size_t size_ = 0;
  std::uint64_t last_tick_ = 0;
  std::uint64_t generation_ = 0;
  bool enabled_ = false;
};

}  // namespace reb
#endif  // REB_NATIVE_VM_RECORDER_HPP_
