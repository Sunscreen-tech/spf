#include<stdint.h>
#include<stdbool.h>

[[clang::fhe_circuit]] uint8_t cmux(
    [[clang::encrypted]] uint8_t bound,
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b
) {
    return bound > 10 ? a : b;
}
