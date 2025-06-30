all: ../../test_data/hamming_distance

clean:
	$(RM) ../../test_data/hamming_distance

../../test_data/hamming_distance: hamming_distance.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/hamming_distance hamming_distance.c
