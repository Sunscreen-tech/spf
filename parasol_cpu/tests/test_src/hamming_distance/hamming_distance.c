#include <stdbool.h>
#include <stdint.h>

#define SIZE 64

inline bool get_bit(uint64_t flags, unsigned int n) {
  return ((flags >> n) & 0x1);
}

[[clang::fhe_circuit]] uint8_t
hamming_distance([[clang::encrypted]] uint64_t a,
                 [[clang::encrypted]] uint64_t b
) {
  uint8_t distance = 0;

#pragma clang loop unroll(full)
  for (int i = 0; i < SIZE; i++) {
    if (get_bit(a, i) != get_bit(b, i)) {
      distance++;
    }
  }
  return distance;
}
