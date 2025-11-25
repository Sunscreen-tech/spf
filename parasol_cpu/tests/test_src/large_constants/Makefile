all: ../../test_data/large_constants

clean:
	$(RM) ../../test_data/large_constants

../../test_data/large_constants: large_constants.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/large_constants large_constants.c
