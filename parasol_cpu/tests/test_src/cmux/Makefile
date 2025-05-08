all: ../../test_data/cmux

clean:
	rm ../../test_data/cmux.o ../../test_data/cmux

../../test_data/cmux.o: cmux.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/cmux.o cmux.c

../../test_data/cmux: ../../test_data/cmux.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/cmux.o -o ../../test_data/cmux
