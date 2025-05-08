typedef unsigned short uint16_t;

typedef struct Result {
    uint16_t alpha;
    uint16_t b_1;
    uint16_t b_2;
    uint16_t b_3;
} Result;

[[clang::fhe_circuit]] void chi_sq(
    [[clang::encrypted]] uint16_t n_0,
    [[clang::encrypted]] uint16_t n_1,
    [[clang::encrypted]] uint16_t n_2,
    [[clang::encrypted]] Result* res
) {
    uint16_t value_n_0 = n_0;
    uint16_t value_n_1 = n_1;
    uint16_t value_n_2 = n_2;

    uint16_t a = 4 * value_n_0 * value_n_2 - value_n_1 * value_n_1;
    uint16_t x = 2 * value_n_0 + value_n_1;
    uint16_t y = 2 * value_n_2 + value_n_1;

    res->alpha = a * a;
    res->b_1 = 2 * x * x;
    res->b_2 = x * y;
    res->b_3 = 2 * y * y;
}