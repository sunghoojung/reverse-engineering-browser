// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_AGENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_AGENT_H_

#include <cstdint>
#include <string>

#include "brave/components/reverse_engineering_browser/common/native_console.mojom.h"
#include "content/public/renderer/render_frame_observer.h"
#include "mojo/public/cpp/bindings/associated_receiver.h"

namespace reb {

class NativeConsoleAgent final : public content::RenderFrameObserver,
                                 public mojom::NativeConsoleAgent {
 public:
  static void CreateIfEnabled(content::RenderFrame* frame);
  NativeConsoleAgent(const NativeConsoleAgent&) = delete;
  NativeConsoleAgent& operator=(const NativeConsoleAgent&) = delete;
  ~NativeConsoleAgent() override;

 private:
  explicit NativeConsoleAgent(content::RenderFrame* frame);
  void OnDestruct() override;
  void Bind(mojo::PendingAssociatedReceiver<mojom::NativeConsoleAgent> receiver);
  void Describe(DescribeCallback callback) override;
  void Evaluate(const base::UnguessableToken& document,
                std::uint64_t expires_at_monotonic_us,
                const std::string& source,
                EvaluateCallback callback) override;
  mojo::AssociatedReceiver<mojom::NativeConsoleAgent> receiver_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_AGENT_H_
