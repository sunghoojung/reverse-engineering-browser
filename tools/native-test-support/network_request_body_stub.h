// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-ins for the pinned Chromium request-header and upload-body
// types the native network sink reads (net::HttpRequestHeaders::GetHeaderView
// and GetHeaderVector, network::DataElement::TryAs/As,
// ResourceRequestBody::elements and contains_sensitive_info). Used only by the
// overlay harnesses under tools/.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_REQUEST_BODY_STUB_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_REQUEST_BODY_STUB_H_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace net {
class HttpRequestHeaders {
 public:
  struct HeaderKeyValuePair {
    std::string key;
    std::string value;
  };
  using HeaderVector = std::vector<HeaderKeyValuePair>;
  static constexpr char kContentType[] = "Content-Type";
  void SetHeader(std::string name, std::string value) {
    headers_.push_back({std::move(name), std::move(value)});
  }
  std::optional<std::string_view> GetHeaderView(std::string_view key) const {
    for (const auto& [name, value] : headers_) {
      if (name.size() == key.size() &&
          std::equal(name.begin(), name.end(), key.begin(),
                     [](char a, char b) { return (a | 0x20) == (b | 0x20); })) {
        return std::string_view(value);
      }
    }
    return std::nullopt;
  }
  const HeaderVector& GetHeaderVector() const { return headers_; }

 private:
  HeaderVector headers_;
};
}  // namespace net

namespace network {
class DataElementBytes {
 public:
  explicit DataElementBytes(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {}
  const std::vector<std::uint8_t>& bytes() const { return bytes_; }

 private:
  std::vector<std::uint8_t> bytes_;
};
struct DataElementFile {};
struct DataElementDataPipe {};
struct DataElementChunkedDataPipe {};
// The pinned DataElement is a variant whose default state is std::monostate.
class DataElement {
 public:
  DataElement() = default;
  template <class T>
  explicit DataElement(T value) : variant_(std::move(value)) {}
  template <class T>
  const T* TryAs() const {
    return std::get_if<T>(&variant_);
  }
  template <class T>
  const T& As() const {
    return std::get<T>(variant_);
  }

 private:
  std::variant<std::monostate,
               DataElementBytes,
               DataElementDataPipe,
               DataElementChunkedDataPipe,
               DataElementFile>
      variant_;
};
class ResourceRequestBody {
 public:
  const std::vector<DataElement>* elements() const { return &elements_; }
  std::vector<DataElement>* elements_mutable() { return &elements_; }
  bool contains_sensitive_info() const { return contains_sensitive_info_; }
  void set_contains_sensitive_info(bool value) { contains_sensitive_info_ = value; }

 private:
  std::vector<DataElement> elements_;
  bool contains_sensitive_info_ = false;
};
}  // namespace network

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_NETWORK_REQUEST_BODY_STUB_H_
