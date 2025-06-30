all: ../../test_data/for_loop

clean:
	$(RM) ../../test_data/for_loop

../../test_data/for_loop: for_loop.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/for_loop for_loop.c
