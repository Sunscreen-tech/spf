all: ../../test_data/add

clean:
	$(RM) ../../test_data/add.o ../../test_data/add

../../test_data/add.o: add.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/add.o add.c

../../test_data/add: ../../test_data/add.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/add.o -o ../../test_data/add
