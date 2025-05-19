all: ../../test_data/for_loop

clean:
	rm ../../test_data/for_loop.o ../../test_data/for_loop

../../test_data/for_loop.o: for_loop.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/for_loop.o for_loop.c

../../test_data/for_loop: ../../test_data/for_loop.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/for_loop.o -o ../../test_data/for_loop
