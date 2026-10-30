// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h"
#include <string>
#include <vector>
#include "testing/gtest/include/gtest/gtest.h"
namespace reb {
namespace {
// Authored adjustment variant; not the verified public QuickJS adapter.
constexpr std::string_view kRecipe =
    R"({"bytecode":{"base":{"kind":"memory-chain","local_index":10,"memory_index":0,"offsets":[1708,20],"value_type":"i32"},"length":{"kind":"memory-chain","local_index":10,"memory_index":0,"offsets":[1708,24],"value_type":"i32"},"memory_index":0},"dispatch_module_offset":132727,"function_index":414,"import_call_offsets":[150000],"module_sha256":"0000000000000000000000000000000000000000000000000000000000000000","opcode":{"endian":"little","width":1},"pc":{"adjustment":"-1","local_index":320,"subtract_memory_base":true,"value_type":"i32"},"sample_limit":256,"version":1})";
TEST(NativeWasmGuestAdapter, ExactTypedRecipe) {
  const auto recipe = ParseNativeWasmGuestAdapter(kRecipe);
  ASSERT_TRUE(recipe);
  ASSERT_EQ(recipe->site_count, 1U);  // Version 1 is a one-site adapter.
  const auto& site = recipe->sites[0];
  EXPECT_EQ(site.function_index, 414U);
  EXPECT_EQ(site.pc_local_index, 320U);
  EXPECT_EQ(recipe->sample_limit, 256U);
  EXPECT_EQ(site.memory_base.chain_count, 2);
  EXPECT_EQ(site.pc_adjustment, -1);
  EXPECT_EQ(site.memory_length.offsets[1], 24U);
  EXPECT_EQ(FindNativeGuestSite(*recipe, 414, 132727), &site);
  EXPECT_FALSE(FindNativeGuestSite(*recipe, 414, 132728));
}
TEST(NativeWasmGuestAdapter, RejectsAmbiguityAndUnsupportedInputs) {
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(std::string(kRecipe) + "\n"));
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(
      "{" + std::string(kRecipe).substr(1, kRecipe.size() - 2) + ",\"version\":1}"));
  for (const auto replacement : {"0", "257", "-1", "1.0", "\"16\""}) {
    std::string text(kRecipe);
    const auto at = text.find("\"sample_limit\":256");
    text.replace(at + 15, 3, replacement);
    EXPECT_FALSE(ParseNativeWasmGuestAdapter(text));
  }
  for (const auto replacement : {"i16", "f32", "ref"}) {
    std::string text(kRecipe);
    const auto at = text.rfind("i32");
    text.replace(at, 3, replacement);
    EXPECT_FALSE(ParseNativeWasmGuestAdapter(text));
  }
  std::string text(kRecipe);
  text.replace(text.find("\"-1\""), 4, "\"-01\"");
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(text));
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(std::string(8193, ' ')));
}
// Owned synthetic sites; canonical key order is the JSON writer's sorted order.
std::string Site(int function, int offset, std::string_view imports = "") {
  return R"({"bytecode":{"base":{"kind":"constant","value":"0"},"length":{"kind":"constant","value":"16"},"memory_index":0},"dispatch_module_offset":)" +
         std::to_string(offset) + R"(,"function_index":)" + std::to_string(function) +
         R"(,"import_call_offsets":[)" + std::string(imports) +
         R"(],"opcode":{"endian":"little","width":1},"pc":{"adjustment":"0","local_index":2,"subtract_memory_base":false,"value_type":"i32"}})";
}
std::string Recipe(const std::vector<std::string>& sites, std::string_view limit = "256") {
  std::string list;
  for (const auto& site : sites)
    list += (list.empty() ? "" : ",") + site;
  return R"({"module_sha256":"0000000000000000000000000000000000000000000000000000000000000000","sample_limit":)" +
         std::string(limit) + R"(,"sites":[)" + list + R"(],"version":2})";
}
TEST(NativeWasmGuestAdapter, VersionTwoSitesShareOneBudget) {
  const auto recipe = ParseNativeWasmGuestAdapter(Recipe({Site(20, 40, "64"), Site(30, 90)}, "3"));
  ASSERT_TRUE(recipe);
  ASSERT_EQ(recipe->site_count, 2U);
  EXPECT_EQ(recipe->sample_limit, 3U);
  EXPECT_EQ(recipe->sites[0].import_call_count, 1U);
  std::uint32_t index = 9;
  EXPECT_EQ(FindNativeGuestSite(*recipe, 30, 90, &index), &recipe->sites[1]);
  EXPECT_EQ(index, 1U);
  EXPECT_EQ(FindNativeGuestDispatcher(*recipe, 20), &recipe->sites[0]);
  EXPECT_FALSE(FindNativeGuestSite(*recipe, 30, 40));  // Another site's br_table.
  EXPECT_FALSE(FindNativeGuestDispatcher(*recipe, 25));
  std::vector<std::string> eight;
  for (int n = 0; n < 8; ++n)
    eight.push_back(Site(n, 8 + n));
  EXPECT_TRUE(ParseNativeWasmGuestAdapter(Recipe(eight)));
}
TEST(NativeWasmGuestAdapter, RejectsMalformedVersionTwo) {
  std::vector<std::string> nine;
  for (int n = 0; n < 9; ++n)
    nine.push_back(Site(n, 8 + n));
  for (const auto& text : {
           Recipe({}),                                          // No site.
           Recipe(nine),                                        // More than eight sites.
           Recipe({Site(20, 40), Site(20, 40)}),                // Duplicate site.
           Recipe({Site(20, 40), Site(20, 90)}),                // Two sites of one dispatcher.
           Recipe({Site(30, 90), Site(20, 40)}),                // Not in canonical order.
           Recipe({Site(20, 40)}, "257"),                       // Budget over the limit.
           Recipe({Site(20, 40)}, "0"), Recipe({Site(20, 4)}),  // Not a module code offset.
       })
    EXPECT_FALSE(ParseNativeWasmGuestAdapter(text)) << text;
  // A per-site budget would multiply the shared one.
  auto per_site = Recipe({Site(20, 40)});
  const std::string_view pc_end = R"("value_type":"i32"})";
  per_site.insert(per_site.find(pc_end) + pc_end.size(), R"(,"sample_limit":16)");
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(per_site));
  // Version 1 keys at the top of a version 2 recipe, or an unknown version.
  auto mixed = Recipe({Site(20, 40)});
  mixed.insert(1, R"("function_index":20,)");
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(mixed));
  auto future = Recipe({Site(20, 40)});
  future.replace(future.find(R"("version":2)"), 11, R"("version":3)");
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(future));
  // Too large: one byte over the bound is refused before parsing.
  auto large = Recipe({Site(20, 40)});
  large.resize(kNativeGuestAdapterLimit + 1, ' ');
  EXPECT_FALSE(ParseNativeWasmGuestAdapter(large));
}
}  // namespace
}  // namespace reb
