// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_BODY_TEE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_BODY_TEE_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/data_pipe_producer.h"
#include "mojo/public/cpp/system/simple_watcher.h"

namespace reb {

class NativeArtifactBodyTee final : public base::RefCounted<NativeArtifactBodyTee> {
 public:
  using Completion = base::OnceCallback<void(bool complete, std::vector<std::uint8_t> content)>;

  // Returns the original source unchanged when a forwarding pipe cannot be
  // created. Otherwise, the returned consumer receives exactly the original
  // body while a bounded immutable copy is delivered through `completion`.
  [[nodiscard]] static mojo::ScopedDataPipeConsumerHandle Create(
      mojo::ScopedDataPipeConsumerHandle source,
      std::size_t capture_limit,
      std::size_t reserve_size,
      Completion completion,
      bool& started);

  NativeArtifactBodyTee(const NativeArtifactBodyTee&) = delete;
  NativeArtifactBodyTee& operator=(const NativeArtifactBodyTee&) = delete;

 private:
  friend class base::RefCounted<NativeArtifactBodyTee>;

  NativeArtifactBodyTee(mojo::ScopedDataPipeConsumerHandle source,
                        mojo::ScopedDataPipeProducerHandle target,
                        std::size_t capture_limit,
                        std::size_t reserve_size,
                        Completion completion);
  ~NativeArtifactBodyTee();

  void Start();
  void OnReadable(MojoResult result, const mojo::HandleSignalsState& state);
  void OnDataWritten(MojoResult result);
  void Finish(bool complete);

  mojo::ScopedDataPipeConsumerHandle source_;
  mojo::SimpleWatcher source_watcher_;
  std::unique_ptr<mojo::DataPipeProducer> target_;
  std::string write_buffer_;
  std::vector<std::uint8_t> captured_;
  const std::size_t capture_limit_;
  bool exceeded_limit_ = false;
  bool write_pending_ = false;
  Completion completion_;
  scoped_refptr<NativeArtifactBodyTee> keep_alive_;
  base::WeakPtrFactory<NativeArtifactBodyTee> weak_factory_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_BODY_TEE_H_
