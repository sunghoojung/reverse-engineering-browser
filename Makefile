CXX ?= c++
OPT_CXXFLAGS ?= -O2 -g

BUILD_DIR := build
SANITIZE_BUILD_DIR := $(BUILD_DIR)/sanitize
INCLUDE_DIR := include
NATIVE_HEADERS := $(shell find $(INCLUDE_DIR) -type f -name '*.hpp')
TRACKED_BROWSER_PROTOCOL_HEADERS := $(shell find \
	browser/integration/brave/overlay/components/reverse_engineering_browser/common \
	-type f -name '*.h')
DEMO_NETWORK_PAYLOAD_HEX := 504f535420636f6c6c6563746f722e6578616d706c652e74657374

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
DEFAULT_SANITIZERS := undefined
else
DEFAULT_SANITIZERS := address,undefined
endif
SANITIZERS ?= $(DEFAULT_SANITIZERS)

COMMON_CXXFLAGS := \
	-std=c++20 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Wconversion \
	-Wsign-conversion \
	-Wshadow \
	-Werror \
	-pthread \
	$(EXTRA_CXXFLAGS)

CPPFLAGS := -I$(INCLUDE_DIR)
LDFLAGS := -pthread $(EXTRA_LDFLAGS)

LIB_OBJECTS := \
	$(BUILD_DIR)/src/artifact.o \
	$(BUILD_DIR)/src/event.o \
	$(BUILD_DIR)/src/event_broker.o
DEMO_BINARY := $(BUILD_DIR)/reb-event-demo
PRODUCER_BINARY := $(BUILD_DIR)/reb-event-producer
BROKER_BINARY := $(BUILD_DIR)/reb-event-broker
ARTIFACT_PRODUCER_BINARY := $(BUILD_DIR)/reb-artifact-producer
ARTIFACT_RECEIVER_BINARY := $(BUILD_DIR)/reb-artifact-receiver
TEST_BINARIES := \
	$(BUILD_DIR)/tests/artifact_test \
	$(BUILD_DIR)/tests/event_test \
	$(BUILD_DIR)/tests/event_broker_test \
	$(BUILD_DIR)/tests/spsc_ring_test

.PHONY: all app app-build artifact-producer artifact-receiver bootstrap-brave bootstrap-test brave-doctor brave-probe-check browser-sync browser-sync-test broker check clean demo e2e format producer sanitize test ui ui-test workspace-check

all: demo producer broker artifact-producer artifact-receiver

check: workspace-check bootstrap-test browser-sync-test test ui-test

bootstrap-brave:
	./scripts/bootstrap-brave.sh

bootstrap-test:
	./tests/bootstrap_brave_test.sh

brave-doctor:
	./scripts/brave-toolchain.sh doctor

brave-probe-check:
	./scripts/brave-toolchain.sh probe-check

browser-sync:
	./scripts/sync-browser-integration.sh

browser-sync-test:
	./tests/sync_browser_integration_test.sh

workspace-check:
	./scripts/check-workspace.sh

demo: $(DEMO_BINARY)

producer: $(PRODUCER_BINARY)

broker: $(BROKER_BINARY)

artifact-producer: $(ARTIFACT_PRODUCER_BINARY)

artifact-receiver: $(ARTIFACT_RECEIVER_BINARY)

e2e: producer broker artifact-producer artifact-receiver
	@mkdir -p $(BUILD_DIR)/sessions
	$(PRODUCER_BINARY) | $(BROKER_BINARY) --store $(BUILD_DIR)/sessions/demo.jsonl
	$(RM) -r "$(BUILD_DIR)/sessions/artifacts"
	$(ARTIFACT_PRODUCER_BINARY) | $(ARTIFACT_RECEIVER_BINARY) --store $(BUILD_DIR)/sessions/artifacts
	test "$$(wc -l < $(BUILD_DIR)/sessions/demo.jsonl | tr -d ' ')" = "7"
	test "$$(grep -c '\"payload\":\"$(DEMO_NETWORK_PAYLOAD_HEX)\"' $(BUILD_DIR)/sessions/demo.jsonl)" = "2"
	test "$$(wc -l < $(BUILD_DIR)/sessions/artifacts/manifest.jsonl | tr -d ' ')" = "2"

ui: e2e
	python3 apps/research-ui/server.py --store $(BUILD_DIR)/sessions/demo.jsonl

app-build: e2e
	./scripts/build-research-app.sh

app: app-build
	open "$(CURDIR)/$(BUILD_DIR)/Origin Trace.app" --args \
		--store "$(CURDIR)/$(BUILD_DIR)/sessions/demo.jsonl" \
		--artifacts "$(CURDIR)/$(BUILD_DIR)/sessions/artifacts"

$(BUILD_DIR)/src/%.o: src/%.cpp $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@

$(DEMO_BINARY): apps/reb-event-demo/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

$(PRODUCER_BINARY): apps/reb-event-producer/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

$(ARTIFACT_PRODUCER_BINARY): apps/reb-artifact-producer/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

$(ARTIFACT_RECEIVER_BINARY): services/artifact-receiver/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

$(BROKER_BINARY): services/event-broker/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

$(BUILD_DIR)/tests/%: tests/%.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS) $(TRACKED_BROWSER_PROTOCOL_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

test: $(TEST_BINARIES)
	@set -e; for test_binary in $(TEST_BINARIES); do \
		echo "Running $$test_binary"; \
		$$test_binary; \
	done

ui-test:
	python3 -m unittest discover -s apps/research-ui -p 'test_*.py'

sanitize:
	$(MAKE) BUILD_DIR=$(SANITIZE_BUILD_DIR) clean
	$(MAKE) \
		BUILD_DIR=$(SANITIZE_BUILD_DIR) \
		OPT_CXXFLAGS="-O1 -g" \
		EXTRA_CXXFLAGS="-fsanitize=$(SANITIZERS) -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=$(SANITIZERS)" \
		test

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $$(find include src apps tests -type f \( -name '*.cpp' -o -name '*.hpp' \)); \
	else \
		echo "clang-format is not installed"; \
		exit 1; \
	fi

clean:
	rm -rf $(BUILD_DIR)
