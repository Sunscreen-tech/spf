typedef unsigned char uint8_t;

[[clang::fhe_circuit]] uint8_t add(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b
) {
    return a + b;
}
