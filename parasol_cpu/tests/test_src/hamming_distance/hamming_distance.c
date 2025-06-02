#include <stdbool.h>
#include <stdint.h>

inline bool get_bit(uint64_t flags, unsigned int n) {
  return ((flags >> n) & 0x1);
}

[[clang::fhe_program]] uint8_t
hamming_distance([[clang::encrypted]] uint8_t* a,
                 [[clang::encrypted]] uint8_t* b,
                 uint8_t len
) {
  uint8_t distance = 0;

  for (int i = 0; i < len; i++) {
    for (int j = 0; j < 8; j++) {
      if (get_bit(a[i], j) != get_bit(b[i], j)) {
          distance++;
      }
    }
    
  }
  return distance;
}
