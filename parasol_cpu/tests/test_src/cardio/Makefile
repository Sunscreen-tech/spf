all: ../../test_data/cardio

clean:
	$(RM) ../../test_data/cardio

../../test_data/cardio: cardio.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/cardio cardio.c
