// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h"
#include "testing/gtest/include/gtest/gtest.h"
namespace reb {
namespace {
// Authored adjustment variant; not the verified public QuickJS adapter.
constexpr std::string_view kRecipe =
    R"({"bytecode":{"base":{"kind":"memory-chain","local_index":10,"memory_index":0,"offsets":[1708,20],"value_type":"i32"},"length":{"kind":"memory-chain","local_index":10,"memory_index":0,"offsets":[1708,24],"value_type":"i32"},"memory_index":0},"dispatch_module_offset":132727,"function_index":414,"import_call_offsets":[150000],"module_sha256":"0000000000000000000000000000000000000000000000000000000000000000","opcode":{"endian":"little","width":1},"pc":{"adjustment":"-1","local_index":320,"subtract_memory_base":true,"value_type":"i32"},"sample_limit":256,"version":1})";
TEST(NativeWasmGuestAdapter, ExactTypedRecipe) {
  const auto recipe = ParseNativeWasmGuestAdapter(kRecipe);
  ASSERT_TRUE(recipe);
  EXPECT_EQ(recipe->pc_local_index, 320U);
  EXPECT_EQ(recipe->sample_limit, 256U);
  EXPECT_EQ(recipe->memory_base.chain_count, 2);
  EXPECT_EQ(recipe->pc_adjustment, -1);
  EXPECT_EQ(recipe->memory_length.offsets[1], 24U);
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
}  // namespace
}  // namespace reb
