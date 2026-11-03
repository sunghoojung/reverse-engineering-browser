// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_INVOCATION_SITES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_INVOCATION_SITES_H_
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "native_js_dispatch_sites.h"
#include "native_js_invocation.h"
namespace reb {
// Parses native-js-invocation-sites-v1 (protocol/native-js-invocation-v1.md):
// the native-js-dispatch-sites-v1 form with every shape "function-entry",
// exact compact canonical JSON, 1 to 8 unique sites. Returns the fixed 44-byte
// renderer records, or an empty vector for any refusal. Provenance fields are
// validated for format and not used for matching.
inline std::vector<std::uint8_t> ParseNativeJsInvocationSites(std::string_view json) {
  using namespace native_js_dispatch_sites_detail;
  if (json.empty() || json.size() > kNativeJsInvocationSitesFileLimit)
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
  if (!list || list->empty() || list->size() > kNativeJsInvocationSiteLimit)
    return {};
  std::vector<NativeJsInvocationSite> sites;
  for (const auto& entry : *list) {
    const auto* site_dict = entry.GetIfDict();
    if (!site_dict || !Keys(*site_dict, {"anchor_offset", "artifact_id", "artifact_sha256",
                                         "byte_offset", "shape", "source_length", "source_sha256"}))
      return {};
    NativeJsInvocationSite site;
    std::uint32_t byte_offset = 0;
    const auto* shape = site_dict->FindString("shape");
    if (!shape || *shape != "function-entry" ||
        !U32(*site_dict, "anchor_offset", site.anchor_offset) ||
        !U32(*site_dict, "source_length", site.source_length) ||
        !U32(*site_dict, "byte_offset", byte_offset) ||
        !Decimal(site_dict->FindString("artifact_id")) ||
        !Sha256(site_dict->FindString("artifact_sha256"), nullptr) ||
        !Sha256(site_dict->FindString("source_sha256"), &site.source_sha256) ||
        !IsValidNativeJsInvocationSite(site))
      return {};
    for (const auto& previous : sites)
      if (previous.source_sha256 == site.source_sha256 &&
          previous.anchor_offset == site.anchor_offset)
        return {};
    sites.push_back(site);
  }
  std::vector<std::uint8_t> records;
  records.reserve(sites.size() * kNativeJsInvocationSiteRecordSize);
  for (const auto& site : sites) {
    const auto record = EncodeNativeJsInvocationSite(site);
    records.insert(records.end(), record.begin(), record.end());
  }
  return records;
}
}  // namespace reb
#endif
