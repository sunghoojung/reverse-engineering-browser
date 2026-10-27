// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-in for Chromium's crypto/hash.h, used only by the native
// overlay harnesses under tools/. Never part of a browser build.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_CRYPTO_HASH_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_CRYPTO_HASH_H_

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace crypto::hash {
inline constexpr std::size_t kSha256Size = 32;
}  // namespace crypto::hash

namespace crypto::hash {
namespace detail {
constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
};

class GuestSha256 final {
 public:
  void Update(const std::uint8_t* data, std::size_t size) noexcept {
    total_size_ += size;
    while (size > 0) {
      const std::size_t copied = std::min(size, block_.size() - block_size_);
      std::copy_n(data, copied, block_.begin() + static_cast<std::ptrdiff_t>(block_size_));
      block_size_ += copied;
      data += copied;
      size -= copied;
      if (block_size_ == block_.size()) {
        Transform();
        block_size_ = 0;
      }
    }
  }

  [[nodiscard]] std::array<std::uint8_t, 32> Final() noexcept {
    const std::uint64_t bit_size = static_cast<std::uint64_t>(total_size_) * 8U;
    block_[block_size_++] = 0x80U;
    if (block_size_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0U);
      Transform();
      block_size_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.begin() + 56, 0U);
    for (std::size_t index = 0; index < 8; ++index) {
      block_[63 - index] = static_cast<std::uint8_t>(bit_size >> (index * 8U));
    }
    Transform();

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t index = 0; index < state_.size(); ++index) {
      digest[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24U);
      digest[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16U);
      digest[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8U);
      digest[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
    }
    return digest;
  }

 private:
  void Transform() noexcept {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 4;
      schedule[index] = (static_cast<std::uint32_t>(block_[offset]) << 24U) |
                        (static_cast<std::uint32_t>(block_[offset + 1]) << 16U) |
                        (static_cast<std::uint32_t>(block_[offset + 2]) << 8U) |
                        static_cast<std::uint32_t>(block_[offset + 3]);
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
      const std::uint32_t s0 = std::rotr(schedule[index - 15], 7) ^
                               std::rotr(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3U);
      const std::uint32_t s1 = std::rotr(schedule[index - 2], 17) ^
                               std::rotr(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10U);
      schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (std::size_t index = 0; index < schedule.size(); ++index) {
      const std::uint32_t sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const std::uint32_t choice = (e & f) ^ (~e & g);
      const std::uint32_t temporary1 =
          h + sum1 + choice + kSha256RoundConstants[index] + schedule[index];
      const std::uint32_t sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temporary2 = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temporary1;
      d = c;
      c = b;
      b = a;
      a = temporary1 + temporary2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  std::array<std::uint8_t, 64> block_{};
  std::size_t block_size_ = 0;
  std::size_t total_size_ = 0;
};

}  // namespace detail

// Test-only FIPS 180-4 reference with the same contract as Chromium's
// crypto::hash::Sha256. Production builds link //crypto instead.
inline std::array<std::uint8_t, kSha256Size> Sha256(std::span<const std::uint8_t> bytes) {
  detail::GuestSha256 hash;
  hash.Update(bytes.data(), bytes.size());
  return hash.Final();
}
inline std::array<std::uint8_t, kSha256Size> Sha256(std::string_view text) {
  return Sha256(std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}
}  // namespace crypto::hash

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_CRYPTO_HASH_H_
