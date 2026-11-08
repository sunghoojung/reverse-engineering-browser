// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_BODY_TEE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_BODY_TEE_H_

#include <memory>
#include <string>

#include "base/functional/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_capture_buffer.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/data_pipe_producer.h"
#include "mojo/public/cpp/system/simple_watcher.h"

namespace reb {

class NativeArtifactBodyTee final : public base::RefCounted<NativeArtifactBodyTee> {
 public:
  // complete is false when the source failed; the buffer's status names its own refusal.
  using Completion = base::OnceCallback<void(bool complete, NativeArtifactCaptureBuffer captured)>;

  // Returns the original source unchanged when a forwarding pipe cannot be
  // created. Otherwise, the returned consumer receives exactly the original
  // body while `captured` grows within its pool.
  [[nodiscard]] static mojo::ScopedDataPipeConsumerHandle Create(
      mojo::ScopedDataPipeConsumerHandle source,
      NativeArtifactCaptureBuffer captured,
      Completion completion,
      bool& started);

  NativeArtifactBodyTee(const NativeArtifactBodyTee&) = delete;
  NativeArtifactBodyTee& operator=(const NativeArtifactBodyTee&) = delete;

 private:
  friend class base::RefCounted<NativeArtifactBodyTee>;

  NativeArtifactBodyTee(mojo::ScopedDataPipeConsumerHandle source,
                        mojo::ScopedDataPipeProducerHandle target,
                        NativeArtifactCaptureBuffer captured,
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
  NativeArtifactCaptureBuffer captured_;
  bool write_pending_ = false;
  Completion completion_;
  scoped_refptr<NativeArtifactBodyTee> keep_alive_;
  base::WeakPtrFactory<NativeArtifactBodyTee> weak_factory_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_BODY_TEE_H_
