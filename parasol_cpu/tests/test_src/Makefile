# Makefile for compiling Parasol test programs
#
# Usage:
#   make        - Build all test binaries
#   make clean  - Remove all test binaries
#
# Requires LLVM_DIR environment variable pointing to Parasol LLVM build directory

ifndef LLVM_DIR
$(error LLVM_DIR environment variable is not set. Set it to your Parasol LLVM build directory, e.g., ~/code/sunscreen-llvm/build)
endif

SOURCES := $(wildcard *.c)
TARGETS := $(patsubst %.c,../test_data/%,$(SOURCES))

all: $(TARGETS)

clean:
	$(RM) $(TARGETS)

../test_data/%: %.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o $@ $<
	# Strip only .comment section to reduce binary size while preserving symbols
	$(LLVM_DIR)/bin/llvm-strip --no-strip-all --remove-section .comment $@

.PHONY: all clean
