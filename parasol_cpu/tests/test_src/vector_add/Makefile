all: ../../test_data/vector_add

clean:
	rm ../../test_data/vector_add.o ../../test_data/vector_add

../../test_data/vector_add.o: vector_add.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/vector_add.o vector_add.c

../../test_data/vector_add: ../../test_data/vector_add.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/vector_add.o -o ../../test_data/vector_add
