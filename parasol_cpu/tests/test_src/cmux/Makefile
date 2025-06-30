all: ../../test_data/cmux

clean:
	$(RM) ../../test_data/cmux

../../test_data/cmux: cmux.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/cmux cmux.c
