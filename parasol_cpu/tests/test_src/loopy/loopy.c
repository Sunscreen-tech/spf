typedef unsigned int uint32_t;

[[clang::fhe_program]] uint32_t loopy(
    uint32_t* a,
    uint32_t len
) {
    uint32_t x = 0;

    for (uint32_t i = 0; i < len; i++) {
        x += a[i];
    }

    return x;
}
