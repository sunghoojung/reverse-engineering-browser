CXX ?= c++
CLANG_FORMAT ?= clang-format
OPT_CXXFLAGS ?= -O2 -g

BUILD_DIR := build
SANITIZE_BUILD_DIR := $(BUILD_DIR)/sanitize
INCLUDE_DIR := include
# Include new files and omit removed paths before changes are staged.
FORMATTED_SOURCES := $(wildcard $(shell git ls-files --cached --others --exclude-standard '*.cc' '*.cpp' '*.h' '*.hpp'))
SHELL_SOURCES := $(wildcard $(shell git ls-files --cached --others --exclude-standard '*.sh'))
DEMO_NETWORK_PAYLOAD_HEX := 504f535420636f6c6c6563746f722e6578616d706c652e74657374
DEMO_WEB_AUDIO_PAYLOAD_HEX := 4f66666c696e65417564696f436f6e746578742e737461727452656e646572696e67

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
ZLIB_LIBS ?= -lz
