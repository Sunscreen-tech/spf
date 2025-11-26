#include <stdbool.h>

[[clang::fhe_program]] bool boolean_and(
    bool a,
    bool b
) {
    return a && b;
}

[[clang::fhe_program]] bool boolean_or(
    bool a,
    bool b
) {
    return a || b;
}

[[clang::fhe_program]] bool boolean_xor(
    bool a,
    bool b
) {
    return a != b;
}