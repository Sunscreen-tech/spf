typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

[[clang::fhe_program]] void vector_add(
    [[clang::encrypted]] uint8_t* a,
    [[clang::encrypted]] uint8_t* b,
    [[clang::encrypted]] uint8_t* c
) {
    for (uint32_t i = 0; i < 8; i++) {
        c[i] = a[i] + b[i];
    }
}
