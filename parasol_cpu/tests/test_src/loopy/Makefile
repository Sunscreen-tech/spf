all: ../../test_data/loopy

clean:
	rm ../../test_data/loopy.o ../../test_data/loopy

../../test_data/loopy.o: loopy.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/loopy.o loopy.c

../../test_data/loopy: ../../test_data/loopy.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/loopy.o -o ../../test_data/loopy
