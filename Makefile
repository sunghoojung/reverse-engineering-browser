CXX ?= c++
CLANG_FORMAT ?= clang-format
OPT_CXXFLAGS ?= -O2 -g

BUILD_DIR := build
SANITIZE_BUILD_DIR := $(BUILD_DIR)/sanitize
INCLUDE_DIR := include
NATIVE_HEADERS := $(shell find $(INCLUDE_DIR) -type f -name '*.hpp')
TRACKED_BROWSER_PROTOCOL_HEADERS := $(shell find \
	browser/integration/brave/overlay/components/reverse_engineering_browser/common \
	-type f -name '*.h')
FORMATTED_SOURCES := $(shell git ls-files '*.cc' '*.cpp' '*.h' '*.hpp')
SHELL_SOURCES := $(shell git ls-files '*.sh')
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
	$(BUILD_DIR)/src/event.o \
	$(BUILD_DIR)/src/event_broker.o \
	$(BUILD_DIR)/src/local_ipc.o
DEMO_BINARY := $(BUILD_DIR)/reb-event-demo
PRODUCER_BINARY := $(BUILD_DIR)/reb-event-producer
BROKER_BINARY := $(BUILD_DIR)/reb-event-broker
TEST_BINARIES := \
	$(BUILD_DIR)/tests/event_test \
	$(BUILD_DIR)/tests/event_broker_test \
	$(BUILD_DIR)/tests/local_ipc_test \
	$(BUILD_DIR)/tests/native_probe_queue_test \
	$(BUILD_DIR)/tests/spsc_ring_test

.PHONY: all app app-build bootstrap-brave bootstrap-test brave-doctor brave-probe-check browser-sync browser-sync-test broker check clean demo e2e format format-check lint live producer python-check repository-check sanitize shellcheck socket-e2e test ui ui-test workflow-check workspace-check

all: demo producer broker

check: workspace-check bootstrap-test browser-sync-test test ui-test

lint: format-check shellcheck python-check repository-check workflow-check

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

e2e: producer broker
	@mkdir -p $(BUILD_DIR)/sessions
	$(PRODUCER_BINARY) | $(BROKER_BINARY) --store $(BUILD_DIR)/sessions/demo.jsonl
	test "$$(wc -l < $(BUILD_DIR)/sessions/demo.jsonl | tr -d ' ')" = "7"
	test "$$(grep -c '\"payload\":\"$(DEMO_NETWORK_PAYLOAD_HEX)\"' $(BUILD_DIR)/sessions/demo.jsonl)" = "2"
	python3 tools/validate-evidence-store.py $(BUILD_DIR)/sessions/demo.jsonl
	./tests/event_broker_socket_test.sh $(BROKER_BINARY) $(PRODUCER_BINARY) $(DEMO_NETWORK_PAYLOAD_HEX)

socket-e2e: producer broker
	./tests/event_broker_socket_test.sh $(BROKER_BINARY) $(PRODUCER_BINARY) $(DEMO_NETWORK_PAYLOAD_HEX)

ui: e2e
	python3 apps/research-ui/server.py --store $(BUILD_DIR)/sessions/demo.jsonl

app-build: e2e
	./scripts/build-research-app.sh

app: app-build
	open "$(CURDIR)/$(BUILD_DIR)/Origin Trace.app" --args --store "$(CURDIR)/$(BUILD_DIR)/sessions/demo.jsonl"

live: app-build broker
	./scripts/run-live-session.sh

$(BUILD_DIR)/src/%.o: src/%.cpp $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@

$(DEMO_BINARY): apps/reb-event-demo/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $(filter %.cpp %.o,$^) $(LDFLAGS) -o $@

$(PRODUCER_BINARY): apps/reb-event-producer/main.cpp $(LIB_OBJECTS) $(NATIVE_HEADERS)
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
	@if command -v $(CLANG_FORMAT) >/dev/null 2>&1; then \
		$(CLANG_FORMAT) -i $(FORMATTED_SOURCES); \
	else \
		echo "$(CLANG_FORMAT) is not installed"; \
		exit 1; \
	fi

format-check:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || { \
		echo "$(CLANG_FORMAT) is not installed" >&2; exit 1; \
	}
	$(CLANG_FORMAT) --dry-run --Werror $(FORMATTED_SOURCES)

shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { \
		echo "shellcheck is not installed" >&2; exit 1; \
	}
	shellcheck $(SHELL_SOURCES)

python-check:
	python3 -m compileall -q apps/research-ui tools
	python3 -m ruff check apps/research-ui tools

repository-check:
	./scripts/check-repository-hygiene.sh

workflow-check:
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "actionlint is not installed" >&2; exit 1; \
	}
	actionlint

clean:
	rm -rf $(BUILD_DIR)
