// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-ins for the pinned Chromium types the native header and
// cookie capture reads (protocol/native-network-v3.md): base::Lock,
// COMPONENT_EXPORT, net::ReferrerPolicy, net::IPEndPoint, the net cookie list
// types and network::mojom::HttpRawHeaderPair. Used only by the overlay
// harnesses under tools/.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_HEADERS_STUB_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_HEADERS_STUB_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
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
struct Time {
  std::int64_t ms = 0;
  bool is_null() const { return ms == 0; }
  std::int64_t InMillisecondsSinceUnixEpoch() const { return ms; }
};
}  // namespace base

namespace net {
// net/cookies at the pin: the fields VisitCookie reads.
enum class CookieSameSite { UNSPECIFIED = -1, NO_RESTRICTION = 0, LAX_MODE = 1, STRICT_MODE = 2 };
enum CookiePriority {
  COOKIE_PRIORITY_LOW = 0,
  COOKIE_PRIORITY_MEDIUM = 1,
  COOKIE_PRIORITY_HIGH = 2
};
enum class CookieEffectiveSameSite {
  NO_RESTRICTION = 0,
  LAX_MODE = 1,
  STRICT_MODE = 2,
  LAX_MODE_ALLOW_UNSAFE = 3,
  UNDEFINED = 4,
};
enum class CookieSourceScheme { kUnset = 0, kNonSecure = 1, kSecure = 2 };
struct CookieReasonSet {
  std::uint64_t bits = 0;
  std::uint64_t ToEnumBitmask() const { return bits; }
};
struct CookieInclusionStatus {
  std::uint64_t exclusions = 0;
  std::uint64_t warnings = 0;
  CookieReasonSet exclusion_reasons() const { return {exclusions}; }
  CookieReasonSet warning_reasons() const { return {warnings}; }
};
struct CookieAccessResult {
  CookieInclusionStatus status;
  CookieEffectiveSameSite effective_same_site = CookieEffectiveSameSite::UNDEFINED;
};
struct SchemefulSite {
  std::string text;
  std::string Serialize() const { return text; }
};
struct CookiePartitionKey {
  SchemefulSite top_level;
  bool third_party = false;
  const SchemefulSite& site() const { return top_level; }
  bool IsThirdParty() const { return third_party; }
};
struct CanonicalCookie {
  std::string name, value, domain, path;
  base::Time expiry;
  bool secure = false;
  bool http_only = false;
  CookieSameSite same_site = CookieSameSite::UNSPECIFIED;
  CookiePriority priority = COOKIE_PRIORITY_MEDIUM;
  std::optional<CookiePartitionKey> partition_key;
  CookieSourceScheme source_scheme = CookieSourceScheme::kUnset;
  int source_port = -1;
  const std::string& Name() const { return name; }
  std::string Value() const { return value; }
  const std::string& Domain() const { return domain; }
  const std::string& Path() const { return path; }
  base::Time ExpiryDate() const { return expiry; }
  bool SecureAttribute() const { return secure; }
  bool IsHttpOnly() const { return http_only; }
  CookieSameSite SameSite() const { return same_site; }
  CookiePriority Priority() const { return priority; }
  const std::optional<CookiePartitionKey>& PartitionKey() const { return partition_key; }
  CookieSourceScheme SourceScheme() const { return source_scheme; }
  int SourcePort() const { return source_port; }
  bool IsDomainCookie() const { return !domain.empty() && domain[0] == '.'; }
};
struct CookieWithAccessResult {
  CanonicalCookie cookie;
  CookieAccessResult access_result;
};
struct CookieAndLineWithAccessResult {
  std::optional<CanonicalCookie> cookie;
  std::string cookie_string;
  CookieAccessResult access_result;
};
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
