# Explicit link dependencies keep component tests independent.
# Header dependencies are emitted by the compiler for every translation unit.

DEMO_BINARY := $(BUILD_DIR)/reb-event-demo
PRODUCER_BINARY := $(BUILD_DIR)/reb-event-producer
BROKER_BINARY := $(BUILD_DIR)/reb-event-broker
ARTIFACT_PRODUCER_BINARY := $(BUILD_DIR)/reb-artifact-producer
ARTIFACT_RECEIVER_BINARY := $(BUILD_DIR)/reb-artifact-receiver
HEAP_SNAPSHOT_BINARY := $(BUILD_DIR)/reb-heap-snapshot
DECODER_BINARY := $(BUILD_DIR)/reb-decoder
DEBUGGER_TRANSPORT_BINARY := $(BUILD_DIR)/reb-debugger-transport
VM_ANALYZER := apps/research-ui/vm_analyzer.py

APP_BINARIES := \
	$(DEMO_BINARY) \
	$(PRODUCER_BINARY) \
	$(BROKER_BINARY) \
	$(ARTIFACT_PRODUCER_BINARY) \
	$(ARTIFACT_RECEIVER_BINARY) \
	$(HEAP_SNAPSHOT_BINARY) \
	$(DECODER_BINARY) \
	$(DEBUGGER_TRANSPORT_BINARY)
TEST_BINARIES := \
	$(BUILD_DIR)/tests/artifact_test \
	$(BUILD_DIR)/tests/decoder_test \
	$(BUILD_DIR)/tests/debugger_transport_test \
	$(BUILD_DIR)/tests/event_test \
	$(BUILD_DIR)/tests/event_broker_test \
	$(BUILD_DIR)/tests/heap_snapshot_test \
	$(BUILD_DIR)/tests/local_ipc_test \
	$(BUILD_DIR)/tests/native_probe_queue_test \
	$(BUILD_DIR)/tests/origin_trace_test \
	$(BUILD_DIR)/tests/request_signal_profile_test \
	$(BUILD_DIR)/tests/spsc_ring_test \
	$(BUILD_DIR)/tests/vm_finding_test

$(DEMO_BINARY): $(BUILD_DIR)/apps/reb-event-demo/main.o \
	$(BUILD_DIR)/src/capture/event.o
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
$(BUILD_DIR)/tests/artifact_test: $(BUILD_DIR)/tests/artifact_test.o \
	$(BUILD_DIR)/src/evidence/artifact.o
$(BUILD_DIR)/tests/decoder_test: $(BUILD_DIR)/tests/decoder_test.o \
	$(BUILD_DIR)/src/analysis/decoder.o
$(BUILD_DIR)/tests/debugger_transport_test: $(BUILD_DIR)/tests/debugger_transport_test.o \
	$(BUILD_DIR)/src/transport/debugger_transport.o
$(BUILD_DIR)/tests/event_test: $(BUILD_DIR)/tests/event_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/transport/local_ipc.o
$(BUILD_DIR)/tests/event_broker_test: $(BUILD_DIR)/tests/event_broker_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/evidence/event_broker.o
$(BUILD_DIR)/tests/heap_snapshot_test: $(BUILD_DIR)/tests/heap_snapshot_test.o \
	$(BUILD_DIR)/src/analysis/heap_snapshot.o
$(BUILD_DIR)/tests/local_ipc_test: $(BUILD_DIR)/tests/local_ipc_test.o \
	$(BUILD_DIR)/src/transport/local_ipc.o
$(BUILD_DIR)/tests/native_probe_queue_test: $(BUILD_DIR)/tests/native_probe_queue_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/evidence/event_broker.o \
	$(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_queue.o
$(BUILD_DIR)/tests/origin_trace_test: $(BUILD_DIR)/tests/origin_trace_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/evidence/origin_trace.o
$(BUILD_DIR)/tests/request_signal_profile_test: $(BUILD_DIR)/tests/request_signal_profile_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/evidence/request_signal_profile.o
$(BUILD_DIR)/tests/spsc_ring_test: $(BUILD_DIR)/tests/spsc_ring_test.o
$(BUILD_DIR)/tests/vm_finding_test: $(BUILD_DIR)/tests/vm_finding_test.o \
	$(BUILD_DIR)/src/capture/event.o \
	$(BUILD_DIR)/src/capture/vm_finding.o

$(DECODER_BINARY) $(BUILD_DIR)/tests/decoder_test: LDLIBS += $(ZLIB_LIBS)

$(APP_BINARIES) $(TEST_BINARIES):
	@mkdir -p $(@D)
	$(CXX) $(filter %.o,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -MMD -MP -c $< -o $@

# Discover dependency files without adding sources to any link target implicitly.
NATIVE_CPP_SOURCES := $(wildcard src/*/*.cpp apps/*/main.cpp services/*/main.cpp tests/*.cpp)
NATIVE_OBJECTS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(NATIVE_CPP_SOURCES)) \
	$(BUILD_DIR)/browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_queue.o

$(NATIVE_OBJECTS): mk/config.mk mk/native.mk
$(APP_BINARIES) $(TEST_BINARIES): mk/native.mk

-include $(NATIVE_OBJECTS:.o=.d)
