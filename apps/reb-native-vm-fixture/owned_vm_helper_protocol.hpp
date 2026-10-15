#ifndef REB_APPS_OWNED_VM_HELPER_PROTOCOL_HPP_
#define REB_APPS_OWNED_VM_HELPER_PROTOCOL_HPP_

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <span>
#include <streambuf>
#include <string_view>
#include <system_error>

// Private process pipe protocol. These host value types are never dumped to
// the wire; every integer is explicitly encoded little endian below.
namespace reb::owned_vm_helper {
inline constexpr std::uint32_t kMagic = 0x314d5652;  // RVM1 bytes
inline constexpr std::uint16_t kVersion = 1;
inline constexpr std::size_t kRequestBytes = 40;
inline constexpr std::size_t kResponseHeaderBytes = 24;
inline constexpr std::size_t kMaxPayloadBytes = 32 * 1024;
inline constexpr std::uint64_t kMaxLifetimeMs = 60000;
inline constexpr std::size_t kMaxStderrBytes = 8 * 1024;
enum class Operation : std::uint16_t { kInspect = 1, kExecuteOne = 2, kClose = 3 };
enum class Status : std::uint16_t {
  kOk = 0,
  kMalformed = 1,
  kStaleGeneration = 2,
  kCountMismatch = 3,
  kRequestId = 4,
  kExpired = 5,
  kHalted = 6,
  kResourceLimit = 7,
  kFixtureError = 8,
  kClosed = 9,
};
struct Request final {
  Operation operation = Operation::kInspect;
  std::uint64_t request_id = 0;
  std::uint64_t generation = 0;
  std::uint64_t executed_count = 0;
};
inline std::uint64_t ReadLe(std::span<const std::uint8_t> bytes,
                            std::size_t offset,
                            std::size_t width) noexcept {
  std::uint64_t result = 0;
  for (std::size_t i = 0; i < width; ++i)
    result |= std::uint64_t{bytes[offset + i]} << (8 * i);
  return result;
}
inline void WriteLe(std::span<std::uint8_t> bytes,
                    std::size_t offset,
                    std::size_t width,
                    std::uint64_t value) noexcept {
  for (std::size_t i = 0; i < width; ++i)
    bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
}
inline bool DecodeRequest(const std::array<std::uint8_t, kRequestBytes>& bytes,
                          Request& request) noexcept {
  request.request_id = ReadLe(bytes, 8, 8);
  request.generation = ReadLe(bytes, 16, 8);
  request.executed_count = ReadLe(bytes, 24, 8);
  const auto operation = ReadLe(bytes, 6, 2);
  if (ReadLe(bytes, 0, 4) != kMagic || ReadLe(bytes, 4, 2) != kVersion ||
      ReadLe(bytes, 32, 8) != 0 || operation < 1 || operation > 3)
    return false;
  request.operation = static_cast<Operation>(operation);
  return true;
}
inline std::array<std::uint8_t, kResponseHeaderBytes> ResponseHeader(Status status,
                                                                     std::uint64_t request_id,
                                                                     std::uint32_t payload_bytes) {
  std::array<std::uint8_t, kResponseHeaderBytes> bytes{};
  WriteLe(bytes, 0, 4, kMagic);
  WriteLe(bytes, 4, 2, kVersion);
  WriteLe(bytes, 6, 2, static_cast<std::uint16_t>(status));
  WriteLe(bytes, 8, 8, request_id);
  WriteLe(bytes, 16, 4, payload_bytes);
  return bytes;
}
inline bool CanonicalU64(std::string_view text, std::uint64_t& result) noexcept {
  if (text.empty() || text.size() > 20 || (text.size() > 1 && text.front() == '0'))
    return false;
  for (const char digit : text) {
    if (digit < '0' || digit > '9')
      return false;
  }
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
inline bool Expired(std::uint64_t now, std::uint64_t previous, std::uint64_t deadline) noexcept {
  return now == 0 || now < previous || now >= deadline;
}
// Stream overflow fails instead of allocating or silently truncating. The
// caller checks ostream state before sending any response header or payload.
class PayloadBuffer final : public std::streambuf {
 public:
  PayloadBuffer() { setp(bytes_.data(), bytes_.data() + bytes_.size()); }
  [[nodiscard]] std::string_view view() const noexcept {
    return {pbase(), static_cast<std::size_t>(pptr() - pbase())};
  }

 private:
  std::array<char, kMaxPayloadBytes> bytes_{};
};
}  // namespace reb::owned_vm_helper
#endif  // REB_APPS_OWNED_VM_HELPER_PROTOCOL_HPP_
