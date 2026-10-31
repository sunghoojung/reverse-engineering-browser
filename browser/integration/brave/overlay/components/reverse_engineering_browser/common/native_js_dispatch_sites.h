// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_DISPATCH_SITES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_DISPATCH_SITES_H_
#include <charconv>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "native_js_dispatch.h"
namespace reb {
namespace native_js_dispatch_sites_detail {
inline bool Keys(const base::DictValue& dict, std::initializer_list<std::string_view> keys) {
  if (dict.size() != keys.size())
    return false;
  for (auto key : keys)
    if (!dict.contains(key))
      return false;
  return true;
}
// JSON integers are bounded by the JSON reader's int range; offsets and
// lengths are below the 16 MiB artifact limit, far inside it.
inline bool U32(const base::DictValue& dict, std::string_view key, std::uint32_t& out) {
  const auto value = dict.FindInt(key);
  if (!value || *value < 0)
    return false;
  out = static_cast<std::uint32_t>(*value);
  return true;
}
inline bool Sha256(const std::string* text, std::array<std::uint8_t, 32>* out) {
  if (!text || text->size() != 64)
    return false;
  const auto nibble = [](char c) -> int {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
  };
  for (std::size_t i = 0; i < 32; ++i) {
    const int high = nibble((*text)[i * 2]), low = nibble((*text)[i * 2 + 1]);
    if (high < 0 || low < 0)
      return false;
    if (out)
      (*out)[i] = static_cast<std::uint8_t>(high * 16 + low);
  }
  return true;
}
// Canonical unsigned decimal artifact identity: no sign, no leading zero.
inline bool Decimal(const std::string* text) {
  if (!text || text->empty() || text->size() > 20 || ((*text)[0] == '0' && text->size() > 1))
    return false;
  std::uint64_t value = 0;
  const char* const end = std::to_address(text->cend());
  const auto result = std::from_chars(text->data(), end, value);
  return result.ec == std::errc{} && result.ptr == end;
}
}  // namespace native_js_dispatch_sites_detail

// Parses native-js-dispatch-sites-v1 (protocol/native-js-dispatch-v1.md):
// exact compact canonical JSON, 1 to 8 unique sites. Returns the fixed
// 44-byte renderer records, or an empty vector for any refusal. Provenance
// fields are validated for format and not used for matching.
inline std::vector<std::uint8_t> ParseNativeJsDispatchSites(std::string_view json) {
  using namespace native_js_dispatch_sites_detail;
  if (json.empty() || json.size() > kNativeJsDispatchSitesFileLimit)
    return {};
  const auto parsed = base::JSONReader::Read(json, base::JSON_PARSE_RFC);
  if (!parsed || !parsed->is_dict())
    return {};
  std::string canonical;
  if (!base::JSONWriter::Write(*parsed, &canonical) || canonical != json)
    return {};
  const auto& dict = parsed->GetDict();
  if (!Keys(dict, {"sites", "version"}) || dict.FindInt("version") != 1)
    return {};
  const auto* list = dict.FindList("sites");
  if (!list || list->empty() || list->size() > kNativeJsDispatchSiteLimit)
    return {};
  std::vector<NativeJsDispatchSite> sites;
  for (const auto& entry : *list) {
    const auto* site_dict = entry.GetIfDict();
    if (!site_dict || !Keys(*site_dict, {"anchor_offset", "artifact_id", "artifact_sha256",
                                         "byte_offset", "shape", "source_length", "source_sha256"}))
      return {};
    NativeJsDispatchSite site;
    std::uint32_t byte_offset = 0;
    const auto* shape = site_dict->FindString("shape");
    if (!shape || (*shape != "switch" && *shape != "indexed-call") ||
        !U32(*site_dict, "anchor_offset", site.anchor_offset) ||
        !U32(*site_dict, "source_length", site.source_length) ||
        !U32(*site_dict, "byte_offset", byte_offset) ||
        !Decimal(site_dict->FindString("artifact_id")) ||
        !Sha256(site_dict->FindString("artifact_sha256"), nullptr) ||
        !Sha256(site_dict->FindString("source_sha256"), &site.source_sha256))
      return {};
    site.shape =
        *shape == "switch" ? NativeJsDispatchShape::kSwitch : NativeJsDispatchShape::kIndexedCall;
    if (!IsValidNativeJsDispatchSite(site))
      return {};
    for (const auto& previous : sites)
      if (previous.source_sha256 == site.source_sha256 &&
          previous.anchor_offset == site.anchor_offset)
        return {};
    sites.push_back(site);
  }
  std::vector<std::uint8_t> records;
  records.reserve(sites.size() * kNativeJsDispatchSiteRecordSize);
  for (const auto& site : sites) {
    const auto record = EncodeNativeJsDispatchSite(site);
    records.insert(records.end(), record.begin(), record.end());
  }
  return records;
}
}  // namespace reb
#endif
