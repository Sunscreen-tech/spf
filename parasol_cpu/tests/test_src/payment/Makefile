all: ../../test_data/payment

clean:
	$(RM) ../../test_data/payment.o ../../test_data/payment

../../test_data/payment.o: payment.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/payment.o payment.c

../../test_data/payment: ../../test_data/payment.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/payment.o -o ../../test_data/payment
