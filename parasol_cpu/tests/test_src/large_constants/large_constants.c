// Test 64-bit constant addition (encrypted)
long long add_const_64_enc([[clang::encrypted]] long long a) {
    return a + 0x123456789ABCDEF0LL;
}

// Test 64-bit constant addition (plaintext)
long long add_const_64_plain(long long a) {
    return a + 0x123456789ABCDEF0LL;
}

// Test with a different 64-bit constant (all high bits set)
long long add_high_bits_64(long long a) {
    return a + 0xFF00000000000000LL;
}

// Sum array using zero as initial accumulator - tests that zero constant
// is properly loaded (not optimized away like a + 0 would be)
long long sum_array_64(long long *arr, int n) {
    long long acc = 0LL;
    for (int i = 0; i < n; i++) {
        acc = acc + arr[i];
    }
    return acc;
}

// Test with two different constants in the same function (encrypted)
long long add_two_consts_64([[clang::encrypted]] long long a) {
    return (a + 0xAAAABBBBCCCCDDDDLL) + 0x1111222233334444LL;
}
