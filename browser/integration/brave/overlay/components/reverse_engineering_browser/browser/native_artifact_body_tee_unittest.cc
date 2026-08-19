// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/test/task_environment.h"
#include "base/test/test_timeouts.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace reb {
namespace {

struct CompletionResult {
  bool called = false;
  bool complete = false;
  std::vector<std::uint8_t> content;
};

void RecordCompletion(CompletionResult* result,
                      const bool complete,
                      std::vector<std::uint8_t> content) {
  result->called = true;
  result->complete = complete;
  result->content = std::move(content);
}

TEST(NativeArtifactBodyTeeTest, ForwardsAndCapturesCompleteBody) {
  base::test::TaskEnvironment task_environment;
  mojo::ScopedDataPipeProducerHandle source_producer;
  mojo::ScopedDataPipeConsumerHandle source_consumer;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, source_producer, source_consumer), MOJO_RESULT_OK);

  CompletionResult result;
  bool started = false;
  mojo::ScopedDataPipeConsumerHandle forwarded = NativeArtifactBodyTee::Create(
      std::move(source_consumer), 1024, 32, base::BindOnce(&RecordCompletion, &result), started);
  ASSERT_TRUE(started);

  const std::string body = "export const captured = true;\n";
  ASSERT_TRUE(mojo::BlockingCopyFromString(body, source_producer));
  source_producer.reset();
  task_environment.RunUntilIdle();

  std::string forwarded_body;
  ASSERT_TRUE(mojo::BlockingCopyToString(std::move(forwarded), &forwarded_body));
  EXPECT_EQ(forwarded_body, body);
  ASSERT_TRUE(result.called);
  EXPECT_TRUE(result.complete);
  EXPECT_EQ(std::string(result.content.begin(), result.content.end()), body);
}

TEST(NativeArtifactBodyTeeTest, ForwardsBodyButRejectsCaptureOverLimit) {
  base::test::TaskEnvironment task_environment;
  mojo::ScopedDataPipeProducerHandle source_producer;
  mojo::ScopedDataPipeConsumerHandle source_consumer;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, source_producer, source_consumer), MOJO_RESULT_OK);

  CompletionResult result;
  bool started = false;
  mojo::ScopedDataPipeConsumerHandle forwarded = NativeArtifactBodyTee::Create(
      std::move(source_consumer), 8, 8, base::BindOnce(&RecordCompletion, &result), started);
  ASSERT_TRUE(started);

  const std::string body = "0123456789abcdef";
  ASSERT_TRUE(mojo::BlockingCopyFromString(body, source_producer));
  source_producer.reset();
  task_environment.RunUntilIdle();

  std::string forwarded_body;
  ASSERT_TRUE(mojo::BlockingCopyToString(std::move(forwarded), &forwarded_body));
  EXPECT_EQ(forwarded_body, body);
  ASSERT_TRUE(result.called);
  EXPECT_FALSE(result.complete);
  EXPECT_TRUE(result.content.empty());
}

}  // namespace
}  // namespace reb

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  mojo::core::Init();
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
