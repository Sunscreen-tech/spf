typedef unsigned short uint16_t;

[[clang::fhe_circuit]]
void xor_shift([[clang::encrypted]] uint16_t *rn)
{
    *rn ^= *rn << 7;
    *rn ^= *rn >> 9;
    *rn ^= *rn << 8;
}
