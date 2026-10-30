// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#include "brave/components/reverse_engineering_browser/common/native_js_dispatch_sites.h"

#include <string>

#include "testing/gtest/include/gtest/gtest.h"
namespace reb {
namespace {
// Authored keys; not derived from a captured artifact.
constexpr std::string_view kSites =
    R"({"sites":[{"anchor_offset":120,"artifact_id":"12","artifact_sha256":"00000000000000000000000000000000000000000000000000000000000000ab","byte_offset":118,"shape":"switch","source_length":456,"source_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"},{"anchor_offset":300,"artifact_id":"12","artifact_sha256":"00000000000000000000000000000000000000000000000000000000000000ab","byte_offset":310,"shape":"indexed-call","source_length":456,"source_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}],"version":1})";
std::string Replace(std::string_view text, std::string_view from, std::string_view to) {
  std::string result(text);
  const auto at = result.find(from);
  EXPECT_NE(at, std::string::npos);
  result.replace(at, from.size(), to);
  return result;
}
TEST(NativeJsDispatchSites, ExactRecords) {
  const auto records = ParseNativeJsDispatchSites(kSites);
  ASSERT_EQ(records.size(), 2U * kNativeJsDispatchSiteRecordSize);
  std::array<NativeJsDispatchSite, kNativeJsDispatchSiteLimit> sites{};
  ASSERT_EQ(DecodeNativeJsDispatchSites(records, sites), 2U);
  EXPECT_EQ(sites[0].shape, NativeJsDispatchShape::kSwitch);
  EXPECT_EQ(sites[0].anchor_offset, 120U);
  EXPECT_EQ(sites[0].source_length, 456U);
  EXPECT_EQ(sites[0].source_sha256[0], 1);
  EXPECT_EQ(sites[0].source_sha256[31], 0x20);
  EXPECT_EQ(sites[1].shape, NativeJsDispatchShape::kIndexedCall);
  EXPECT_EQ(sites[1].anchor_offset, 300U);
}
TEST(NativeJsDispatchSites, RejectsAmbiguityAndUnsupportedInputs) {
  EXPECT_TRUE(ParseNativeJsDispatchSites(std::string(kSites) + "\n").empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(Replace(kSites, "\"sites\":", "\"sites\" :")).empty());
  EXPECT_TRUE(
      ParseNativeJsDispatchSites(Replace(kSites, "\"version\":1", "\"version\":2")).empty());
  EXPECT_TRUE(
      ParseNativeJsDispatchSites(Replace(kSites, "\"shape\":\"switch\"", "\"shape\":\"if-ladder\""))
          .empty());
  EXPECT_TRUE(
      ParseNativeJsDispatchSites(Replace(kSites, "\"anchor_offset\":120", "\"anchor_offset\":456"))
          .empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(Replace(kSites, "\"anchor_offset\":300",
                                                 "\"anchor_offset\":120"))
                  .empty());  // duplicate (source_sha256, anchor_offset)
  EXPECT_TRUE(ParseNativeJsDispatchSites(
                  Replace(kSites, "\"artifact_id\":\"12\"", "\"artifact_id\":\"012\""))
                  .empty());
  EXPECT_TRUE(
      ParseNativeJsDispatchSites(Replace(kSites, "\"artifact_id\":\"12\"", "\"artifact_id\":12"))
          .empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(Replace(kSites, "0102030405", "0102030X05")).empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(Replace(kSites, "0102030405", "0102030A05")).empty());
  EXPECT_TRUE(
      ParseNativeJsDispatchSites(Replace(kSites, "\"byte_offset\":118", "\"byte_offset\":-1"))
          .empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(R"({"sites":[],"version":1})").empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(std::string(4097, ' ')).empty());
  std::string nine = R"({"sites":[)";
  for (int n = 0; n < 9; ++n) {
    const std::string anchor = std::to_string(10 + n);
    nine +=
        std::string(n ? "," : "") + R"({"anchor_offset":)" + anchor +
        R"(,"artifact_id":"1","artifact_sha256":"00000000000000000000000000000000000000000000000000000000000000ab","byte_offset":0,"shape":"switch","source_length":456,"source_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"})";
  }
  nine += R"(],"version":1})";
  EXPECT_TRUE(ParseNativeJsDispatchSites(nine).empty());
}
}  // namespace
}  // namespace reb
