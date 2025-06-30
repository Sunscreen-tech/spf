all: ../../test_data/add

clean:
	$(RM) ../../test_data/add

../../test_data/add: add.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/add add.c
