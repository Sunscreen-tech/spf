typedef unsigned short uint16_t;

typedef struct Result {
    uint16_t alpha;
    uint16_t b_1;
    uint16_t b_2;
    uint16_t b_3;
} Result;

[[clang::fhe_program]] Result chi_sq(
    [[clang::encrypted]] uint16_t n_0,
    [[clang::encrypted]] uint16_t n_1,
    [[clang::encrypted]] uint16_t n_2
) {
    uint16_t a = 4 * n_0 * n_2 - n_1 * n_1;
    uint16_t x = 2 * n_0 + n_1;
    uint16_t y = 2 * n_2 + n_1;

    Result res = {
        a * a,
        2 * x * x,
        x * y,
        2 * y * y
    };

    return res;
}