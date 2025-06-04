#include <stdbool.h>

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

typedef struct Winner {
  uint16_t bid;
  uint16_t idx;
} Winner;

[[clang::fhe_program]] void auction([[clang::encrypted]] uint16_t *bids,
                                    uint16_t len,
                                    [[clang::encrypted]] Winner *winningBid) {
  winningBid->bid = bids[0];
  winningBid->idx = 0;

  for (uint16_t i = 1; i < len; i++) {
    bool isWinner = bids[i] >= winningBid->bid;

    winningBid->bid = isWinner ? bids[i] : winningBid->bid;
    winningBid->idx = isWinner ? i : winningBid->idx;
  }
}

[[clang::fhe_program]] void
auction_optimized([[clang::encrypted]] uint16_t *bids,
                  [[clang::encrypted]] uint16_t *scratch, uint16_t len,
                  [[clang::encrypted]] Winner *winningBid) {
  winningBid->bid = bids[0];
  winningBid->idx = 0;

  for (uint16_t i = 0; i < len; i++) {
    scratch[2 * i] = bids[i];
    scratch[2 * i + 1] = i;
  }

  len /= 2;

  while (len > 0) {
    for (uint16_t i = 0; i < len; i++) {
      bool gt = scratch[4 * i] > scratch[4 * i + 2];

      scratch[2 * i] = gt ? scratch[4 * i] : scratch[4 * i + 2];
      scratch[2 * i + 1] = gt ? scratch[4 * i + 1] : scratch[4 * i + 3];
    }

    len /= 2;
  }

  winningBid->bid = scratch[0];
  winningBid->idx = scratch[1];
}
