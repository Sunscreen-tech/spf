all: ../../test_data/auction

clean:
	$(RM) ../../test_data/auction.o ../../test_data/auction

../../test_data/auction.o: auction.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/auction.o auction.c

../../test_data/auction: ../../test_data/auction.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/auction.o -o ../../test_data/auction
