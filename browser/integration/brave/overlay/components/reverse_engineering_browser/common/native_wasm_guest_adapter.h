// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_GUEST_ADAPTER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_GUEST_ADAPTER_H_
#include <charconv>
#include <memory>
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "native_wasm_guest.h"
namespace reb {
namespace native_guest_adapter_detail {
inline bool Keys(const base::DictValue& dict, std::initializer_list<std::string_view> keys) {
  if (dict.size() != keys.size())
    return false;
  for (auto key : keys)
    if (!dict.contains(key))
      return false;
  return true;
}
inline bool U32(const base::DictValue& dict, std::string_view key, std::uint32_t& out) {
  const auto value = dict.FindInt(key);
  if (!value || *value < 0)
    return false;
  out = static_cast<std::uint32_t>(*value);
  return true;
}
template <class T>
bool Decimal(const std::string* text, T& out) {
  if (!text || text->empty() || (text->size() > 1 && (*text)[0] == '0') || *text == "-0" ||
      (text->size() > 2 && (*text)[0] == '-' && (*text)[1] == '0') || (*text)[0] == '+')
    return false;
  const auto result = std::from_chars(text->data(), text->data() + text->size(), out);
  return result.ec == std::errc{} && result.ptr == text->data() + text->size();
}
inline bool Type(const std::string* text, std::uint8_t& out) {
  if (!text || (*text != "i32" && *text != "i64"))
    return false;
  out = *text == "i32" ? 32 : 64;
  return true;
}
inline bool Source(const base::DictValue* dict, NativeGuestValueSource& out) {
  if (!dict)
    return false;
  const auto* kind = dict->FindString("kind");
  if (!kind)
    return false;
  if (*kind == "constant")
    return Keys(*dict, {"kind", "value"}) && Decimal(dict->FindString("value"), out.constant);
  if (*kind != "local" && *kind != "memory-chain")
    return false;
  out.is_local = true;
  if (!U32(*dict, "local_index", out.local_index) ||
      !Type(dict->FindString("value_type"), out.value_type))
    return false;
  if (*kind == "local")
    return Keys(*dict, {"kind", "local_index", "value_type"});
  if (!Keys(*dict, {"kind", "local_index", "value_type", "memory_index", "offsets"}) ||
      out.value_type != 32 || !U32(*dict, "memory_index", out.memory_index))
    return false;
  const auto* offsets = dict->FindList("offsets");
  if (!offsets || offsets->empty() || offsets->size() > out.offsets.size())
    return false;
  for (std::size_t i = 0; i < offsets->size(); ++i) {
    const auto value = (*offsets)[i].GetIfInt();
    if (!value || *value < 0)
      return false;
    out.offsets[i] = static_cast<std::uint32_t>(*value);
  }
  out.chain_count = static_cast<std::uint8_t>(offsets->size());
  return true;
}
// One site's local, memory and opcode interpretation. A version 1 recipe
// carries these keys at its top level; version 2 carries them per site.
inline bool Site(const base::DictValue& dict, NativeWasmGuestSite& out) {
  if (!U32(dict, "function_index", out.function_index) ||
      !U32(dict, "dispatch_module_offset", out.dispatch_module_offset) ||
      out.dispatch_module_offset < 8)
    return false;
  const auto* pc = dict.FindDict("pc");
  const auto* memory = dict.FindDict("bytecode");
  const auto* opcode = dict.FindDict("opcode");
  if (!pc || !Keys(*pc, {"local_index", "value_type", "adjustment", "subtract_memory_base"}) ||
      !U32(*pc, "local_index", out.pc_local_index) ||
      !Type(pc->FindString("value_type"), out.pc_value_type) ||
      !Decimal(pc->FindString("adjustment"), out.pc_adjustment) ||
      !pc->FindBool("subtract_memory_base"))
    return false;
  out.subtract_memory_base = *pc->FindBool("subtract_memory_base");
  if (!memory || !Keys(*memory, {"memory_index", "base", "length"}) ||
      !U32(*memory, "memory_index", out.memory_index) ||
      !Source(memory->FindDict("base"), out.memory_base) ||
      !Source(memory->FindDict("length"), out.memory_length))
    return false;
  std::uint32_t width = 0;
  if (!opcode || !Keys(*opcode, {"width", "endian"}) || !U32(*opcode, "width", width) ||
      (width != 1 && width != 2 && width != 4))
    return false;
  const auto* endian = opcode->FindString("endian");
  if (!endian || (*endian != "little" && *endian != "big"))
    return false;
  out.opcode_width = static_cast<std::uint8_t>(width);
  out.opcode_big_endian = *endian == "big";
  const auto* imports = dict.FindList("import_call_offsets");
  if (!imports || imports->size() > out.import_call_offsets.size())
    return false;
  for (std::size_t i = 0; i < imports->size(); ++i) {
    const auto value = (*imports)[i].GetIfInt();
    if (!value || *value < 8)
      return false;
    out.import_call_offsets[i] = static_cast<std::uint32_t>(*value);
    if (i && out.import_call_offsets[i] <= out.import_call_offsets[i - 1])
      return false;
  }
  out.import_call_count = imports->size();
  return true;
}
}  // namespace native_guest_adapter_detail
// Exact compact canonical JSON rejects duplicates and ambiguous spellings.
// Version 1 is one site. Version 2 lists 1 to 8 sites of the same module in
// strictly increasing function index order, which rejects duplicate sites and
// keeps one canonical spelling; all of them share one sample limit.
inline std::shared_ptr<const NativeWasmGuestAdapter> ParseNativeWasmGuestAdapter(
    std::string_view json) {
  using namespace native_guest_adapter_detail;
  if (json.empty() || json.size() > kNativeGuestAdapterLimit)
    return {};
  const auto parsed = base::JSONReader::Read(json, base::JSON_PARSE_RFC);
  if (!parsed || !parsed->is_dict())
    return {};
  std::string canonical;
  if (!base::JSONWriter::Write(*parsed, &canonical) || canonical != json)
    return {};
  const auto& dict = parsed->GetDict();
  const auto version = dict.FindInt("version");
  auto result = std::make_shared<NativeWasmGuestAdapter>();
  if (version == 1) {
    if (!Keys(dict, {"version", "module_sha256", "function_index", "dispatch_module_offset", "pc",
                     "bytecode", "opcode", "import_call_offsets", "sample_limit"}) ||
        !Site(dict, result->sites[0]))
      return {};
    result->site_count = 1;
  } else if (version == 2) {
    const auto* sites = dict.FindList("sites");
    if (!Keys(dict, {"version", "module_sha256", "sample_limit", "sites"}) || !sites ||
        sites->empty() || sites->size() > result->sites.size())
      return {};
    for (std::size_t i = 0; i < sites->size(); ++i) {
      const auto* site = (*sites)[i].GetIfDict();
      if (!site ||
          !Keys(*site, {"function_index", "dispatch_module_offset", "pc", "bytecode", "opcode",
                        "import_call_offsets"}) ||
          !Site(*site, result->sites[i]) ||
          (i && result->sites[i].function_index <= result->sites[i - 1].function_index))
        return {};
    }
    result->site_count = sites->size();
  } else {
    return {};
  }
  if (!U32(dict, "sample_limit", result->sample_limit) || !result->sample_limit ||
      result->sample_limit > kNativeGuestSampleLimit)
    return {};
  const auto* digest = dict.FindString("module_sha256");
  if (!digest || digest->size() != 64)
    return {};
  for (std::size_t i = 0; i < 32; ++i) {
    const auto nibble = [](char c) -> int {
      return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
    };
    const int high = nibble((*digest)[i * 2]), low = nibble((*digest)[i * 2 + 1]);
    if (high < 0 || low < 0)
      return {};
    result->module_sha256[i] = static_cast<std::uint8_t>(high * 16 + low);
  }
  result->json = std::move(canonical);
  result->recipe_sha256 = NativeGuestDigest(
      std::span(reinterpret_cast<const std::uint8_t*>(result->json.data()), result->json.size()));
  return result;
}
}  // namespace reb
#endif
