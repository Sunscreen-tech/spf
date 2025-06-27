all: ../../test_data/args

clean:
	$(RM) ../../test_data/args.o ../../test_data/args

../../test_data/args.o: args.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/args.o args.c

../../test_data/args: ../../test_data/args.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/args.o -o ../../test_data/args
