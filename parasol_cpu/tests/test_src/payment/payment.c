#include <stdint.h>

[[clang::fhe_program]] void payment(
    [[clang::encrypted]] uint32_t amount,
    [[clang::encrypted]] uint32_t *balance_pointer
) {
    uint32_t balance = *balance_pointer;

    uint32_t transfer_amount = amount < balance ? amount : 0;
    *balance_pointer = balance - transfer_amount;
}

