all: ../../test_data/prng

clean:
	$(RM) ../../test_data/prng.o ../../test_data/prng

../../test_data/prng.o: prng.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/prng.o prng.c

../../test_data/prng: ../../test_data/prng.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/prng.o -o ../../test_data/prng
