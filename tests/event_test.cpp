#include <cstdint>
#include <iostream>

#include "reb/event.hpp"

int main() {
  const reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kVm, reb::EventType::kVmDispatchSample, 1, 2, 3);
  if (!reb::IsValidEvent(event) ||
      reb::EventTypeName(reb::EventType::kVmDispatchSample) != "vm_dispatch_sample") {
    std::cerr << "VM dispatch event type contract failed\n";
    return 1;
  }
  return 0;
}
