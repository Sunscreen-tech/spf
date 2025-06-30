all: ../../test_data/vector_add

clean:
	$(RM) ../../test_data/vector_add

../../test_data/vector_add: vector_add.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/vector_add vector_add.c
