// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_INVOCATION_SITES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_INVOCATION_SITES_H_
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "native_js_dispatch_sites.h"
#include "native_js_invocation.h"
namespace reb {
// Parses a native JavaScript invocation site file
// (protocol/native-js-invocation-v1.md#site-file): exact compact canonical
// JSON in one of two versions, each site's shape "function-entry" and each
// (source_sha256, anchor_offset) unique. Version 1 is native-js-dispatch-sites-v1
// with at least one site, all armed. Version 2 is a slot table that may be
// empty, each site with an `armed` boolean, so a revision can disarm a slot
// without renumbering the others. Either holds up to
// kNativeJsInvocationSiteListLimit sites. Returns the sites by slot, or
// nullopt for any refusal. Provenance fields are validated for format and not
// used for matching.
inline std::optional<std::vector<NativeJsInvocationSite>> ParseNativeJsInvocationSiteList(
    std::string_view json) {
  using namespace native_js_dispatch_sites_detail;
  if (json.empty())
    return std::nullopt;
  const auto parsed = base::JSONReader::Read(json, base::JSON_PARSE_RFC);
  if (!parsed || !parsed->is_dict())
    return std::nullopt;
  std::string canonical;
  if (!base::JSONWriter::Write(*parsed, &canonical) || canonical != json)
    return std::nullopt;
  const auto& dict = parsed->GetDict();
  const auto version = dict.FindInt("version");
  if (!Keys(dict, {"sites", "version"}) || (version != 1 && version != 2))
    return std::nullopt;
  const bool slot_table = version == 2;
  const auto* list = dict.FindList("sites");
  if (!list || (!slot_table && list->empty()) || list->size() > kNativeJsInvocationSiteListLimit)
    return std::nullopt;
  std::vector<NativeJsInvocationSite> sites;
  sites.reserve(list->size());
  for (const auto& entry : *list) {
    const auto* site_dict = entry.GetIfDict();
    if (!site_dict ||
        !(slot_table
              ? Keys(*site_dict, {"anchor_offset", "armed", "artifact_id", "artifact_sha256",
                                  "byte_offset", "shape", "source_length", "source_sha256"})
              : Keys(*site_dict, {"anchor_offset", "artifact_id", "artifact_sha256", "byte_offset",
                                  "shape", "source_length", "source_sha256"})))
      return std::nullopt;
    NativeJsInvocationSite site;
    std::uint32_t byte_offset = 0;
    const auto* shape = site_dict->FindString("shape");
    const auto armed = slot_table ? site_dict->FindBool("armed") : std::optional<bool>(true);
    if (!shape || *shape != "function-entry" || !armed ||
        !U32(*site_dict, "anchor_offset", site.anchor_offset) ||
        !U32(*site_dict, "source_length", site.source_length) ||
        !U32(*site_dict, "byte_offset", byte_offset) ||
        !Decimal(site_dict->FindString("artifact_id")) ||
        !Sha256(site_dict->FindString("artifact_sha256"), nullptr) ||
        !Sha256(site_dict->FindString("source_sha256"), &site.source_sha256) ||
        !IsValidNativeJsInvocationSite(site))
      return std::nullopt;
    site.armed = *armed;
    sites.push_back(site);
  }
  if (HasRepeatedNativeJsInvocationSite(sites))
    return std::nullopt;
  return sites;
}

// The fixed 44-byte renderer records of sites, one per slot.
inline std::vector<std::uint8_t> EncodeNativeJsInvocationSites(
    const std::vector<NativeJsInvocationSite>& sites) {
  std::vector<std::uint8_t> records;
  records.reserve(sites.size() * kNativeJsInvocationSiteRecordSize);
  for (const auto& site : sites) {
    const auto record = EncodeNativeJsInvocationSite(site);
    records.insert(records.end(), record.begin(), record.end());
  }
  return records;
}

// The renderer records of a site file, or nullopt for any refusal.
inline std::optional<std::vector<std::uint8_t>> ParseNativeJsInvocationSites(
    std::string_view json) {
  const auto sites = ParseNativeJsInvocationSiteList(json);
  if (!sites)
    return std::nullopt;
  return EncodeNativeJsInvocationSites(*sites);
}
}  // namespace reb
#endif
