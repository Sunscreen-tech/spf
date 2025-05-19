all: ../../test_data/cardio

clean:
	$(RM) ../../test_data/cardio.o ../../test_data/cardio

../../test_data/cardio.o: cardio.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/cardio.o cardio.c

../../test_data/cardio: ../../test_data/cardio.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/cardio.o -o ../../test_data/cardio
