all: ../../test_data/transfer

clean:
	$(RM) ../../test_data/transfer.o ../../test_data/transfer

../../test_data/transfer.o: transfer.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/transfer.o transfer.c

../../test_data/transfer: ../../test_data/transfer.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/transfer.o -o ../../test_data/transfer
