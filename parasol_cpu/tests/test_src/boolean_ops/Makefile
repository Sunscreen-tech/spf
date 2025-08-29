all: ../../test_data/boolean_ops

clean:
	$(RM) ../../test_data/boolean_ops

../../test_data/boolean_ops: boolean_ops.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/boolean_ops boolean_ops.c