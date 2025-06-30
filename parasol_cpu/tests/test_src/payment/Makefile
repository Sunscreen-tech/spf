all: ../../test_data/payment

clean:
	$(RM) ../../test_data/payment

../../test_data/payment: payment.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/payment payment.c
