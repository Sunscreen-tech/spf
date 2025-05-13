#include <stdint.h>
#include <stdbool.h>

[[clang::fhe_circuit]] void zext_and_trunc(
    [[clang::encrypted]] uint8_t u8_a,
    [[clang::encrypted]] uint32_t u32_b,
    [[clang::encrypted]] uint32_t *u32_output_ptr,
    [[clang::encrypted]] uint8_t *u8_output_ptr,
    [[clang::encrypted]] bool *bool_output_ptr,
    [[clang::encrypted]] uint32_t *comparison_output_ptr
    // [[clang::encrypted]] bool *bool_output_ptr
) {
    // Extend
    uint32_t u32_a = u8_a;
    *u32_output_ptr = u32_a + u32_b;

    // Truncate
    char u8_b = u32_b;
    *u8_output_ptr = u8_a + u8_b;

    // // To bool!
    bool bool_a = u8_a > 0;
    bool bool_b = u8_b > 0;

    *bool_output_ptr = bool_a && bool_b;

    // Comparison to check boolean truncation
    uint32_t c = u8_a > u8_b ? 14 : 9;
    *comparison_output_ptr = c;
}
