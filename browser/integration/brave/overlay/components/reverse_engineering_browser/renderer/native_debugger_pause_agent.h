// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_PAUSE_AGENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_PAUSE_AGENT_H_

#include <cstdint>
#include <string>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/unguessable_token.h"
#include "brave/components/reverse_engineering_browser/common/native_debugger_pause.mojom.h"
#include "brave/components/reverse_engineering_browser/renderer/native_debugger_pause_session.h"
#include "content/public/renderer/render_frame_observer.h"
#include "mojo/public/cpp/bindings/associated_receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/web/web_local_frame_client.h"

namespace reb {

// The pausing debugger of one frame, protocol/native-debugger-pause-v1.md.
// Created only with --reb-native-debugger; without it this observer does not
// exist, nothing is allocated and no hot path gains a check: V8's own
// breakpoint machinery does the pausing, so this experiment adds no probe.
//
// Threads: this object lives on the renderer main thread. Its IoAgent lives
// on the renderer IO thread, where it is bound while the page is running,
// and hands each command to the frame's InspectorTaskRunner, whose task type
// is unpausable. That is the whole reason a paused main thread can still be
// told to resume.
class NativeDebuggerPauseAgent final : public content::RenderFrameObserver,
                                       public mojom::NativeDebuggerPauseBroker {
 public:
  static void CreateIfEnabled(content::RenderFrame* frame);
  NativeDebuggerPauseAgent(const NativeDebuggerPauseAgent&) = delete;
  NativeDebuggerPauseAgent& operator=(const NativeDebuggerPauseAgent&) = delete;
  ~NativeDebuggerPauseAgent() override;

 private:
  class IoAgent;

  explicit NativeDebuggerPauseAgent(content::RenderFrame* frame);

  // content::RenderFrameObserver:
  void OnDestruct() override;
  void DidCommitProvisionalLoad(ui::PageTransition transition) override;
  void DidSetPageLifecycleState(blink::BFCacheStateChange change) override;

  void Bind(mojo::PendingAssociatedReceiver<mojom::NativeDebuggerPauseBroker> receiver);

  // mojom::NativeDebuggerPauseBroker:
  void Attach(mojo::PendingReceiver<mojom::NativeDebuggerPauseAgent> agent,
              mojo::PendingRemote<mojom::NativeDebuggerPauseObserver> observer,
              std::uint64_t target_id) override;

  // Runs on the main thread, including inside the nested pause loop.
  void RunCommand(const base::UnguessableToken& document,
                  std::uint16_t operation,
                  std::uint64_t lease_id,
                  std::uint64_t expires_at_monotonic_us,
                  const std::string& command,
                  mojom::NativeDebuggerPauseAgent::CommandCallback callback);
  // The browser side went away mid-pause: resume and disarm rather than
  // leaving a page stopped with nothing able to reach it. `generation` is the
  // attachment it belongs to, so a loss reported by a replaced IO agent
  // cannot tear down the one that replaced it.
  void OnIoAgentLost(std::uint64_t generation);
  void DiscardSession(std::uint8_t reason);
  // What the session tells the browser, through this agent's own weak
  // pointer: a report that arrives after this agent is gone does nothing
  // instead of reaching a destroyed remote.
  void ReportPaused(std::uint64_t lease,
                    std::uint8_t reason,
                    std::uint64_t breakpoint,
                    std::uint32_t frames,
                    std::uint32_t async_frames,
                    bool truncated);
  void ReportResumed(std::uint64_t lease, std::uint8_t end, std::uint32_t paused_ms);
  void ReportCleared(std::uint8_t reason, std::uint32_t dropped);
  // Posts a task to this frame's main thread that runs while it is paused.
  void PostToPausedThread(base::OnceClosure task);

  // Reference counted, because the page can destroy this frame from inside
  // script the session is evaluating: the object then outlives this agent
  // until that command has returned.
  scoped_refptr<NativeDebuggerPauseSession> session_;
  // Counts attachments, so a lost IO agent only disarms its own.
  std::uint64_t generation_ = 0;
  mojo::Remote<mojom::NativeDebuggerPauseObserver> observer_;
  // Owned by the IO thread; deleted there when this observer goes away or a
  // second Attach replaces it.
  base::raw_ptr<IoAgent> io_agent_ = nullptr;
  mojo::AssociatedReceiver<mojom::NativeDebuggerPauseBroker> receiver_{this};
  base::WeakPtrFactory<NativeDebuggerPauseAgent> weak_factory_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_PAUSE_AGENT_H_
