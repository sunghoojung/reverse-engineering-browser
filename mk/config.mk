CXX ?= c++
REB_DEV_TOOLS_DIR ?= $(HOME)/.local/share/reb-tools
CLANG_FORMAT ?= $(if $(wildcard $(REB_DEV_TOOLS_DIR)/bin/clang-format),$(REB_DEV_TOOLS_DIR)/bin/clang-format,clang-format)
RUFF ?= $(if $(wildcard $(REB_DEV_TOOLS_DIR)/bin/ruff),$(REB_DEV_TOOLS_DIR)/bin/ruff,python3 -m ruff)
OPT_CXXFLAGS ?= -O2 -g

BUILD_DIR := build
SANITIZE_BUILD_DIR := $(BUILD_DIR)/sanitize
INCLUDE_DIR := include
# Include new files and omit removed paths before changes are staged.
# Vendored third-party sources stay byte-identical to upstream; see
# apps/origin-trace-backend/vendor/README.md.
VENDORED_SOURCES := apps/origin-trace-backend/vendor/%
FORMATTED_SOURCES := $(filter-out $(VENDORED_SOURCES),$(wildcard $(shell git ls-files --cached --others --exclude-standard '*.cc' '*.cpp' '*.h' '*.hpp')))
SHELL_SOURCES := $(wildcard $(shell git ls-files --cached --others --exclude-standard '*.sh'))
DEMO_NETWORK_PAYLOAD_HEX := 504f535420636f6c6c6563746f722e6578616d706c652e74657374
DEMO_WEB_AUDIO_PAYLOAD_HEX := 4f66666c696e65417564696f436f6e746578742e737461727452656e646572696e67

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
DEFAULT_SANITIZERS := undefined
# Origin Trace.app ships these executables, so they target the oldest macOS
# its Info.plist admits instead of the build host's release. Native objects
# depend on that file, and the app build refuses a bundled Mach-O that
# records a newer minimum.
MACOS_INFO_PLIST := apps/research-ui/macos/Info.plist
MACOS_DEPLOYMENT_TARGET := $(shell plutil -extract LSMinimumSystemVersion raw -o - $(MACOS_INFO_PLIST) 2>/dev/null)
ifeq ($(MACOS_DEPLOYMENT_TARGET),)
$(error Cannot read LSMinimumSystemVersion from $(MACOS_INFO_PLIST))
endif
PLATFORM_FLAGS := -mmacosx-version-min=$(MACOS_DEPLOYMENT_TARGET)
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
	$(PLATFORM_FLAGS) \
	$(EXTRA_CXXFLAGS)

CPPFLAGS := -I$(INCLUDE_DIR)
LDFLAGS := -pthread $(PLATFORM_FLAGS) $(EXTRA_LDFLAGS)
ZLIB_LIBS ?= -lz
