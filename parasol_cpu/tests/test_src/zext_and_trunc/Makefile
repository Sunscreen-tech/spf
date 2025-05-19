all: ../../test_data/zext_and_trunc

clean:
	$(RM) ../../test_data/zext_and_trunc.o ../../test_data/zext_and_trunc

../../test_data/zext_and_trunc.o: zext_and_trunc.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/zext_and_trunc.o zext_and_trunc.c

../../test_data/zext_and_trunc: ../../test_data/zext_and_trunc.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/zext_and_trunc.o -o ../../test_data/zext_and_trunc
