#ifndef REB_LOCAL_IPC_HPP_
#define REB_LOCAL_IPC_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace reb {

inline constexpr std::uint32_t kLocalIpcMagic = 0x52454249;
inline constexpr std::uint16_t kLocalIpcVersion = 1;
inline constexpr std::size_t kLocalIpcTokenSize = 32;

using LocalIpcToken = std::array<std::byte, kLocalIpcTokenSize>;

struct LocalIpcHello final {
  std::uint32_t magic = kLocalIpcMagic;
  std::uint16_t version = kLocalIpcVersion;
  std::uint16_t size = static_cast<std::uint16_t>(sizeof(LocalIpcHello));
  std::uint64_t session_id = 0;
  LocalIpcToken token{};
  std::array<std::byte, 16> reserved{};
};

static_assert(sizeof(LocalIpcHello) == 64);
static_assert(alignof(LocalIpcHello) == 8);

[[nodiscard]] bool DecodeLocalIpcToken(std::string_view encoded,
                                       LocalIpcToken& token) noexcept;
[[nodiscard]] std::string EncodeLocalIpcToken(const LocalIpcToken& token);

[[nodiscard]] bool LoadLocalIpcToken(const std::string& path,
                                     LocalIpcToken& token,
                                     std::string& error);
[[nodiscard]] bool LoadOrCreateLocalIpcToken(const std::string& path,
                                             LocalIpcToken& token,
                                             std::string& error);

[[nodiscard]] bool ConstantTimeTokenEquals(const LocalIpcToken& left,
                                           const LocalIpcToken& right) noexcept;
[[nodiscard]] int ConnectAuthenticatedLocalIpc(const std::string& socket_path,
                                               const std::string& token_path,
                                               std::uint64_t session_id,
                                               std::string& error);
[[nodiscard]] bool ReadExact(int descriptor, std::span<std::byte> output,
                             std::string& error);
[[nodiscard]] bool WriteExact(int descriptor,
                              std::span<const std::byte> input,
                              std::string& error);

}  // namespace reb

#endif  // REB_LOCAL_IPC_HPP_
