all: ../../test_data/chi_sq

clean:
	rm ../../test_data/chi_sq.o ../../test_data/chi_sq

../../test_data/chi_sq.o: chi_sq.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -c -o ../../test_data/chi_sq.o chi_sq.c

../../test_data/chi_sq: ../../test_data/chi_sq.o
	$(LLVM_DIR)/bin/ld.lld ../../test_data/chi_sq.o -o ../../test_data/chi_sq
