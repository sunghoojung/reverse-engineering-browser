// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#include "brave/components/reverse_engineering_browser/common/native_js_invocation_sites.h"

#include <string>

#include "testing/gtest/include/gtest/gtest.h"
namespace reb {
namespace {
// Authored keys; not derived from a captured artifact.
constexpr std::string_view kSites =
    R"({"sites":[{"anchor_offset":120,"artifact_id":"12","artifact_sha256":"00000000000000000000000000000000000000000000000000000000000000ab","byte_offset":118,"shape":"function-entry","source_length":456,"source_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}],"version":1})";
std::string Replace(std::string_view text, std::string_view from, std::string_view to) {
  std::string result(text);
  const auto at = result.find(from);
  EXPECT_NE(at, std::string::npos);
  result.replace(at, from.size(), to);
  return result;
}
TEST(NativeJsInvocationSites, ExactRecords) {
  const auto records = ParseNativeJsInvocationSites(kSites);
  ASSERT_EQ(records.size(), kNativeJsInvocationSiteRecordSize);
  EXPECT_EQ(records[40], kNativeJsInvocationFunctionEntryShape);
  std::array<NativeJsInvocationSite, kNativeJsInvocationSiteLimit> sites{};
  ASSERT_EQ(DecodeNativeJsInvocationSites(records, sites), 1U);
  EXPECT_EQ(sites[0].anchor_offset, 120U);
  EXPECT_EQ(sites[0].source_length, 456U);
  EXPECT_EQ(sites[0].source_sha256[0], 1);
  EXPECT_EQ(sites[0].source_sha256[31], 0x20);
}
TEST(NativeJsInvocationSites, RejectsOtherShapesAndMalformedInputs) {
  // A dispatch site file never arms a function entry, and the reverse.
  EXPECT_TRUE(ParseNativeJsInvocationSites(
                  Replace(kSites, "\"shape\":\"function-entry\"", "\"shape\":\"switch\""))
                  .empty());
  EXPECT_TRUE(ParseNativeJsDispatchSites(kSites).empty());
  EXPECT_TRUE(ParseNativeJsInvocationSites(std::string(kSites) + "\n").empty());
  EXPECT_TRUE(
      ParseNativeJsInvocationSites(Replace(kSites, "\"version\":1", "\"version\":2")).empty());
  EXPECT_TRUE(ParseNativeJsInvocationSites(
                  Replace(kSites, "\"anchor_offset\":120", "\"anchor_offset\":456"))
                  .empty());
  EXPECT_TRUE(ParseNativeJsInvocationSites(R"({"sites":[],"version":1})").empty());
  std::array<NativeJsInvocationSite, kNativeJsInvocationSiteLimit> sites{};
  auto records = ParseNativeJsInvocationSites(kSites);
  records[40] = 1;  // a switch record is not a function-entry record
  EXPECT_EQ(DecodeNativeJsInvocationSites(records, sites), 0U);
  EXPECT_TRUE(ParseNativeJsInvocationSites(std::string(kNativeJsInvocationSitesFileLimit + 1, ' '))
                  .empty());
}
// Every one-byte slot is armable, and a full list of the longest canonical
// sites fits the file limit.
std::string ManySites(std::size_t count) {
  std::string json = R"({"sites":[)";
  for (std::size_t n = 0; n < count; ++n) {
    json +=
        std::string(n ? "," : "") + R"({"anchor_offset":)" + std::to_string(10 + n) +
        R"(,"artifact_id":"18446744073709551615","artifact_sha256":"00000000000000000000000000000000000000000000000000000000000000ab","byte_offset":2147483647,"shape":"function-entry","source_length":2147483647,"source_sha256":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"})";
  }
  return json + R"(],"version":1})";
}
TEST(NativeJsInvocationSites, EverySlotUpToTheLimit) {
  const auto full = ManySites(kNativeJsInvocationSiteLimit);
  ASSERT_LE(full.size(), kNativeJsInvocationSitesFileLimit);
  const auto records = ParseNativeJsInvocationSites(full);
  ASSERT_EQ(records.size(), kNativeJsInvocationSiteLimit * kNativeJsInvocationSiteRecordSize);
  std::array<NativeJsInvocationSite, kNativeJsInvocationSiteLimit> sites{};
  ASSERT_EQ(DecodeNativeJsInvocationSites(records, sites), kNativeJsInvocationSiteLimit);
  EXPECT_EQ(sites.back().anchor_offset, 10U + kNativeJsInvocationSiteLimit - 1);
  EXPECT_TRUE(ParseNativeJsInvocationSites(ManySites(kNativeJsInvocationSiteLimit + 1)).empty());
}
}  // namespace
}  // namespace reb
