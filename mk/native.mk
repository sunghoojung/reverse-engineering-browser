# Explicit link dependencies keep each application independent.
# Header dependencies are emitted by the compiler for every translation unit.

DEMO_BINARY := $(BUILD_DIR)/reb-event-demo
PRODUCER_BINARY := $(BUILD_DIR)/reb-event-producer
BROKER_BINARY := $(BUILD_DIR)/reb-event-broker
ARTIFACT_PRODUCER_BINARY := $(BUILD_DIR)/reb-artifact-producer
ARTIFACT_RECEIVER_BINARY := $(BUILD_DIR)/reb-artifact-receiver
HEAP_SNAPSHOT_BINARY := $(BUILD_DIR)/reb-heap-snapshot
DECODER_BINARY := $(BUILD_DIR)/reb-decoder
DEBUGGER_TRANSPORT_BINARY := $(BUILD_DIR)/reb-debugger-transport
NATIVE_CONSOLE_BINARY := $(BUILD_DIR)/reb-console
NATIVE_CONSOLE_MESSAGES_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_console_messages.o
NATIVE_CONSOLE_IO_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_console_io.o
NATIVE_PROBE_QUEUE_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_queue.o
NATIVE_WORKER_SOURCE_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_worker_source.o
NATIVE_WORKER_OBSERVATION_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_worker_observation.o
NATIVE_WORKER_TRANSFER_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_worker_transfer.o
NATIVE_WORKER_AUTHORITY_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_worker_authority.o
NATIVE_WORKER_TRANSFER_GATE_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_worker_transfer_gate.o
NATIVE_PROXY_POLICY_OBJECT := $(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_proxy_policy.o
NATIVE_PROXY_POLICY_TEST := $(BUILD_DIR)/check-native-proxy-policy
ORIGIN_TRACE_BACKEND := apps/origin-trace-backend/target/debug/origin-trace-backend
VM_ANALYZER := apps/origin-trace-backend/target/debug/origin-trace-vm

APP_BINARIES := \
	$(DEMO_BINARY) \
	$(PRODUCER_BINARY) \
	$(BROKER_BINARY) \
	$(ARTIFACT_PRODUCER_BINARY) \
	$(ARTIFACT_RECEIVER_BINARY) \
	$(HEAP_SNAPSHOT_BINARY) \
	$(DECODER_BINARY) \
	$(DEBUGGER_TRANSPORT_BINARY) \
	$(NATIVE_CONSOLE_BINARY)
$(DEMO_BINARY): $(BUILD_DIR)/apps/reb-event-demo/main.o \
	$(BUILD_DIR)/src/capture/event.o $(NATIVE_CONSOLE_MESSAGES_OBJECT) $(NATIVE_PROBE_QUEUE_OBJECT) $(NATIVE_WORKER_SOURCE_OBJECT) $(NATIVE_WORKER_OBSERVATION_OBJECT) $(NATIVE_WORKER_TRANSFER_OBJECT) $(NATIVE_WORKER_AUTHORITY_OBJECT) $(NATIVE_WORKER_TRANSFER_GATE_OBJECT)
$(BUILD_DIR)/apps/reb-event-demo/main.o: CPPFLAGS += -Ibrowser/integration/brave/overlay
$(PRODUCER_BINARY): $(BUILD_DIR)/apps/reb-event-producer/main.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/transport/local_ipc.o \
	$(BUILD_DIR)/src/capture/vm_finding.o
$(BROKER_BINARY): $(BUILD_DIR)/services/event-broker/main.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/evidence/event_broker.o \
	$(BUILD_DIR)/src/transport/local_ipc.o \
	$(BUILD_DIR)/src/evidence/origin_trace.o \
	$(BUILD_DIR)/src/evidence/request_signal_profile.o
$(ARTIFACT_PRODUCER_BINARY): $(BUILD_DIR)/apps/reb-artifact-producer/main.o \
	$(BUILD_DIR)/src/evidence/artifact.o \
	$(BUILD_DIR)/src/transport/local_ipc.o
$(ARTIFACT_RECEIVER_BINARY): $(BUILD_DIR)/services/artifact-receiver/main.o \
	$(BUILD_DIR)/src/evidence/artifact.o \
	$(BUILD_DIR)/src/transport/local_ipc.o
$(HEAP_SNAPSHOT_BINARY): $(BUILD_DIR)/apps/reb-heap-snapshot/main.o \
	$(BUILD_DIR)/src/analysis/heap_snapshot.o
$(DECODER_BINARY): $(BUILD_DIR)/apps/reb-decoder/main.o \
	$(BUILD_DIR)/src/analysis/decoder.o
$(DEBUGGER_TRANSPORT_BINARY): $(BUILD_DIR)/apps/reb-debugger-transport/main.o \
	$(BUILD_DIR)/src/transport/debugger_transport.o
$(NATIVE_CONSOLE_BINARY): $(BUILD_DIR)/apps/native-console/main.o $(NATIVE_CONSOLE_IO_OBJECT)
$(BUILD_DIR)/apps/native-console/main.o: CPPFLAGS += -Ibrowser/integration/brave/overlay
$(DECODER_BINARY): LDLIBS += $(ZLIB_LIBS)

$(NATIVE_PROXY_POLICY_TEST): $(BUILD_DIR)/tools/check-native-proxy-policy.o $(NATIVE_PROXY_POLICY_OBJECT)

$(BUILD_DIR)/tools/check-native-proxy-policy.o: CPPFLAGS += -Ibrowser/integration/brave/overlay

$(APP_BINARIES) $(NATIVE_PROXY_POLICY_TEST):
	@mkdir -p $(@D)
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@
	SCCACHE_DISABLE=1 $(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -MM -MP -MT $@ -MF $(@:.o=.d) $<

$(BUILD_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@
	SCCACHE_DISABLE=1 $(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -MM -MP -MT $@ -MF $(@:.o=.d) $<

# sccache replays cached dependency files with the original output path. Generate
# these separately, without cache, so each build directory has correct targets.
# Discover dependency files without adding sources to any link target implicitly.
NATIVE_CPP_SOURCES := $(wildcard src/*/*.cpp apps/*/main.cpp services/*/main.cpp)
NATIVE_OBJECTS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(NATIVE_CPP_SOURCES)) \
	$(NATIVE_CONSOLE_MESSAGES_OBJECT) $(NATIVE_PROBE_QUEUE_OBJECT) $(NATIVE_CONSOLE_IO_OBJECT) $(NATIVE_WORKER_SOURCE_OBJECT) $(NATIVE_WORKER_OBSERVATION_OBJECT) $(NATIVE_WORKER_TRANSFER_OBJECT) $(NATIVE_WORKER_AUTHORITY_OBJECT) $(NATIVE_WORKER_TRANSFER_GATE_OBJECT) \
	$(NATIVE_PROXY_POLICY_OBJECT) $(BUILD_DIR)/tools/check-native-proxy-policy.o

$(NATIVE_OBJECTS): mk/config.mk mk/native.mk
$(APP_BINARIES) $(NATIVE_PROXY_POLICY_TEST): mk/native.mk

-include $(NATIVE_OBJECTS:.o=.d)
