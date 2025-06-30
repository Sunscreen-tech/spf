all: ../../test_data/prng

clean:
	$(RM) ../../test_data/prng

../../test_data/prng: prng.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/prng prng.c
