// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-ins for the pinned Chromium types the native header capture
// reads (protocol/native-network-v3.md): base::Lock, COMPONENT_EXPORT,
// net::ReferrerPolicy, net::IPEndPoint and network::mojom::HttpRawHeaderPair.
// Used only by the overlay harnesses under tools/.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_HEADERS_STUB_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_HEADERS_STUB_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#define COMPONENT_EXPORT(component)

namespace base {
// The harnesses are single-threaded; the sink's lock discipline is unchanged.
class Lock {
 public:
  void Acquire() {}
  void Release() {}
};
class AutoLock {
 public:
  explicit AutoLock(Lock& lock) : lock_(lock) { lock_.Acquire(); }
  ~AutoLock() { lock_.Release(); }

 private:
  Lock& lock_;
};
}  // namespace base

namespace net {
enum class ReferrerPolicy {
  CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE = 0,
  NEVER_CLEAR = 3,
  NO_REFERRER = 7,
};
struct IPAddressBytes {
  std::array<std::uint8_t, 16> value{};
  std::size_t length = 0;
  const std::uint8_t* data() const { return value.data(); }
  std::size_t size() const { return length; }
};
struct IPAddress {
  IPAddressBytes value;
  bool IsIPv4() const { return value.length == 4; }
  bool IsIPv6() const { return value.length == 16; }
  const IPAddressBytes& bytes() const { return value; }
};
struct IPEndPoint {
  IPAddress ip;
  std::uint16_t port_number = 0;
  const IPAddress& address() const { return ip; }
  std::uint16_t port() const { return port_number; }
};
}  // namespace net

namespace network::mojom {
struct HttpRawHeaderPair {
  std::string key;
  std::string value;
};
using HttpRawHeaderPairPtr = std::unique_ptr<HttpRawHeaderPair>;
}  // namespace network::mojom

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_HEADERS_STUB_H_
