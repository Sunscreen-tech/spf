all: ../../test_data/auction

clean:
	$(RM) ../../test_data/auction

../../test_data/auction: auction.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/auction auction.c
