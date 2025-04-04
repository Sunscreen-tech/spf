typedef unsigned char uint8_t;

[[clang::fhe_circuit]] void add(
    [[clang::encrypted]] uint8_t *a,
    [[clang::encrypted]] uint8_t *b,
    [[clang::encrypted]] uint8_t *output
) {
    *output = *a + *b;
}