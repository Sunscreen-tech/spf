all: ../../test_data/zext_and_trunc

clean:
	$(RM) ../../test_data/zext_and_trunc

../../test_data/zext_and_trunc: zext_and_trunc.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/zext_and_trunc zext_and_trunc.c
