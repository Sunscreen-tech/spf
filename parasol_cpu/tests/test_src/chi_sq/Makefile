all: ../../test_data/chi_sq

clean:
	$(RM) ../../test_data/chi_sq

../../test_data/chi_sq: chi_sq.c
	$(LLVM_DIR)/bin/clang -O2 -target parasol -o ../../test_data/chi_sq chi_sq.c
