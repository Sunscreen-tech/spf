SOURCES := $(wildcard *.c)
TARGETS := $(patsubst %.c,../test_data/%,$(SOURCES))

all: $(TARGETS)

clean:
	$(RM) $(TARGETS)

../test_data/%: %.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o $@ $<
	$(LLVM_DIR)/bin/llvm-strip --no-strip-all --remove-section .comment $@

.PHONY: all clean
