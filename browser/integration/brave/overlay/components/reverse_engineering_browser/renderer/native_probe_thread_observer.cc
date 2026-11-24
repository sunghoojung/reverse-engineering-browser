// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_thread_observer.h"

#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"
#include "content/public/renderer/render_thread.h"
#include "content/public/renderer/render_thread_observer.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"

namespace reb {

namespace {

class NativeProbeThreadObserver final : public content::RenderThreadObserver {
 public:
  void RegisterMojoInterfaces(blink::AssociatedInterfaceRegistry* associated_interfaces) override {
    associated_interfaces->AddInterface<mojom::NativeProbeClient>(base::BindRepeating(
        &NativeProbeTransport::BindClient, base::Unretained(&NativeProbeTransport::Get())));
  }

  void UnregisterMojoInterfaces(
      blink::AssociatedInterfaceRegistry* associated_interfaces) override {
    associated_interfaces->RemoveInterface(mojom::NativeProbeClient::Name_);
  }
};

}  // namespace

void RegisterNativeProbeClient(content::RenderThread& thread) {
  // The transport it binds lives for the process, and so does this.
  static base::NoDestructor<NativeProbeThreadObserver> observer;
  thread.AddObserver(observer.get());
}

}  // namespace reb
