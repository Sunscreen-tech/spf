#pragma once
#include <cstdint>

class LweDef {
public:
    uint32_t size;
};

class GlweDef {
public:
    uint32_t polynomial_degree;
    uint32_t size;
};

class RadixDecomposition {
    uint32_t count;
    uint32_t log;
};