all: ../../test_data/transfer

clean:
	$(RM) ../../test_data/transfer

../../test_data/transfer: transfer.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/transfer transfer.c
