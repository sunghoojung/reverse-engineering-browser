// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_OF_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_OF_H_

#include <cstdint>

#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"

namespace reb {

// The tab id of protocol/native-network-v3.md: the primary main frame's
// FrameTreeNodeId of the frame's outermost WebContents, or 0.
[[nodiscard]] inline std::uint32_t NativeTabOf(content::RenderFrameHost* frame) {
  content::WebContents* contents =
      frame ? content::WebContents::FromRenderFrameHost(frame) : nullptr;
  contents = contents ? contents->GetOutermostWebContents() : nullptr;
  content::RenderFrameHost* const main_frame = contents ? contents->GetPrimaryMainFrame() : nullptr;
  const content::FrameTreeNodeId tab_id =
      main_frame ? main_frame->GetFrameTreeNodeId() : content::FrameTreeNodeId();
  return tab_id ? static_cast<std::uint32_t>(tab_id.value()) : 0;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_OF_H_
