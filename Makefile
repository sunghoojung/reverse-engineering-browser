CXX ?= c++
OPT_CXXFLAGS ?= -O2 -g

BUILD_DIR := build
SANITIZE_BUILD_DIR := $(BUILD_DIR)/sanitize
INCLUDE_DIR := include

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
	$(BUILD_DIR)/src/event_broker.o
DEMO_BINARY := $(BUILD_DIR)/reb-event-demo
PRODUCER_BINARY := $(BUILD_DIR)/reb-event-producer
BROKER_BINARY := $(BUILD_DIR)/reb-event-broker
TEST_BINARIES := \
	$(BUILD_DIR)/tests/event_test \
	$(BUILD_DIR)/tests/event_broker_test \
	$(BUILD_DIR)/tests/spsc_ring_test

.PHONY: all bootstrap-brave brave-doctor brave-probe-check browser-sync broker check clean demo e2e format producer sanitize test ui workspace-check

all: demo producer broker

check: workspace-check test

bootstrap-brave:
	./scripts/bootstrap-brave.sh

brave-doctor:
	./scripts/brave-toolchain.sh doctor

brave-probe-check:
	./scripts/brave-toolchain.sh probe-check

browser-sync:
	./scripts/sync-browser-integration.sh

workspace-check:
	./scripts/check-workspace.sh

demo: $(DEMO_BINARY)

producer: $(PRODUCER_BINARY)

broker: $(BROKER_BINARY)

e2e: producer broker
	@mkdir -p $(BUILD_DIR)/sessions
	$(PRODUCER_BINARY) | $(BROKER_BINARY) --store $(BUILD_DIR)/sessions/demo.jsonl
	test "$$(wc -l < $(BUILD_DIR)/sessions/demo.jsonl | tr -d ' ')" = "4"

ui: e2e
	python3 apps/research-ui/server.py --store $(BUILD_DIR)/sessions/demo.jsonl

$(BUILD_DIR)/src/%.o: src/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) -c $< -o $@

$(DEMO_BINARY): apps/reb-event-demo/main.cpp $(LIB_OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $^ $(LDFLAGS) -o $@

$(PRODUCER_BINARY): apps/reb-event-producer/main.cpp $(LIB_OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $^ $(LDFLAGS) -o $@

$(BROKER_BINARY): services/event-broker/main.cpp $(LIB_OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $^ $(LDFLAGS) -o $@

$(BUILD_DIR)/tests/%: tests/%.cpp $(LIB_OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(COMMON_CXXFLAGS) $(OPT_CXXFLAGS) $^ $(LDFLAGS) -o $@

test: $(TEST_BINARIES)
	@set -e; for test_binary in $(TEST_BINARIES); do \
		echo "Running $$test_binary"; \
		$$test_binary; \
	done

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
