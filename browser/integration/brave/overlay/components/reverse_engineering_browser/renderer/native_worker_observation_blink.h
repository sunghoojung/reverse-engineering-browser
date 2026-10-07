// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_OBSERVATION_BLINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_OBSERVATION_BLINK_H_

#include <array>

#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/renderer/native_worker_observation_sink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"

namespace reb {
namespace worker_observation {
template <typename Token>
NativeWorkerToken TokenValue(const Token& token) {
  return {token.value().GetHighForSerialization(), token.value().GetLowForSerialization()};
}
inline NativeWorkerToken ContextToken(const blink::ExecutionContextToken& token) {
  return token.Visit([](const auto& value) { return TokenValue(value); });
}
inline std::uint64_t Now() {
  return static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
}
inline void ObserveCreator(blink::ExecutionContext* creator,
                           const blink::DedicatedWorkerToken& worker,
                           const NativeWorkerObservationInput& input,
                           std::array<std::uint64_t, 3>* outgoing = nullptr) {
  if (!IsNativeWorkerObservationEnabled() || !creator ||
      (!creator->IsWindow() && !creator->IsDedicatedWorkerGlobalScope())) {
    return;
  }
  const auto creator_token = creator->GetExecutionContextToken();
  if (!creator_token.Is<blink::LocalFrameToken>() &&
      !creator_token.Is<blink::DedicatedWorkerToken>()) {
    return;
  }
  const auto kind = creator_token.Is<blink::LocalFrameToken>()
                        ? NativeWorkerCreatorKind::kDocument
                        : NativeWorkerCreatorKind::kDedicatedWorker;
  NativeWorkerMessageTag accepted;
  static_cast<void>(ObserveNativeWorker(TokenValue(worker), ContextToken(creator_token), kind,
                                        input, Now(), &accepted));
  if (outgoing) {
    *outgoing = {accepted.session_id, accepted.generation, accepted.send_sequence};
  }
}
inline void ObserveScope(blink::ExecutionContext* scope,
                         const NativeWorkerObservationInput& input,
                         std::array<std::uint64_t, 3>* outgoing = nullptr) {
  if (!IsNativeWorkerObservationEnabled() || !scope || !scope->IsDedicatedWorkerGlobalScope()) {
    return;
  }
  const auto creator = scope->GetParentExecutionContextToken();
  if (!creator ||
      (!creator->Is<blink::LocalFrameToken>() && !creator->Is<blink::DedicatedWorkerToken>())) {
    return;
  }
  const auto kind = creator->Is<blink::LocalFrameToken>()
                        ? NativeWorkerCreatorKind::kDocument
                        : NativeWorkerCreatorKind::kDedicatedWorker;
  NativeWorkerMessageTag accepted;
  static_cast<void>(ObserveNativeWorker(ContextToken(scope->GetExecutionContextToken()),
                                        ContextToken(*creator), kind, input, Now(), &accepted));
  if (outgoing) {
    *outgoing = {accepted.session_id, accepted.generation, accepted.send_sequence};
  }
}
inline NativeWorkerMessageTag ReceivedTag(const std::array<std::uint64_t, 3>& tag) {
  return {tag[0], tag[1], tag[2]};
}
}  // namespace worker_observation
}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_OBSERVATION_BLINK_H_
