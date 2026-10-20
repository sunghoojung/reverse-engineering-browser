#ifndef REB_OWNED_VM_DISPATCH_EVENTS_HPP_
#define REB_OWNED_VM_DISPATCH_EVENTS_HPP_

// Explicit synthetic native-event export. Does not attach to a browser.
int EmitOwnedVmDispatchEvents(int argc, char** argv, bool observe_owned_clock = false);

#endif  // REB_OWNED_VM_DISPATCH_EVENTS_HPP_
