#include <stdbool.h>

typedef unsigned char uint8_t;

inline bool get_bit(uint8_t flags, unsigned int n) {
  return ((flags >> n) & 0x1);
}

[[clang::fhe_program]] uint8_t
cardio([[clang::encrypted]] uint8_t flags,
       [[clang::encrypted]] uint8_t age,
       [[clang::encrypted]] uint8_t hdl,
       [[clang::encrypted]] uint8_t weight,
       [[clang::encrypted]] uint8_t height,
       [[clang::encrypted]] uint8_t physical_activity,
       [[clang::encrypted]] uint8_t glasses_alcohol
) {
  bool man = get_bit(flags, 0);
  bool smoking = get_bit(flags, 1);
  bool diabetic = get_bit(flags, 2);
  bool high_bp = get_bit(flags, 3);

  uint8_t cond1 = man && (age > 50);
  uint8_t cond2 = !man && (age > 60);
  uint8_t cond3 = smoking;
  uint8_t cond4 = diabetic;
  uint8_t cond5 = high_bp;
  uint8_t cond6 = hdl < 40;
  uint8_t cond7 = weight > ((uint8_t)(height - 90));
  uint8_t cond8 = physical_activity < 30;
  uint8_t cond9 = man && (glasses_alcohol > 3);
  uint8_t cond10 = !man && (glasses_alcohol > 2);

  return cond1 + cond2 + cond3 + cond4 + cond5 + cond6 + cond7 + cond8 +
                cond9 + cond10;
}
