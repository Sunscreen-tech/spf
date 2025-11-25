all: ../../test_data/args

clean:
	$(RM) ../../test_data/args

../../test_data/args: args.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/args args.c
	$(LLVM_DIR)/bin/llvm-strip --no-strip-all --remove-section .comment ../../test_data/args
