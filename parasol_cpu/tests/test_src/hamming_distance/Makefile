all: ../../test_data/hamming_distance

clean:
	rm ../../test_data/hamming_distance.o ../../test_data/hamming_distance

../../test_data/hamming_distance.o: hamming_distance.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/hamming_distance.o hamming_distance.c

../../test_data/hamming_distance: ../../test_data/hamming_distance.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/hamming_distance.o -o ../../test_data/hamming_distance
