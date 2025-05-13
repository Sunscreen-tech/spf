#include <stdbool.h>
#include <stdint.h>

[[clang::fhe_circuit]]
void transfer([[clang::encrypted]] uint32_t *sender_balance_pointer,
              [[clang::encrypted]] uint32_t *recipient_balance_pointer,
              [[clang::encrypted]] uint32_t transfer_amount) {

  uint32_t sender_balance = *sender_balance_pointer;
  uint32_t recipient_balance = *recipient_balance_pointer;

  bool sender_can_transfer = sender_balance >= transfer_amount;
  bool recipient_can_receive =
      recipient_balance + transfer_amount >= recipient_balance;

  // Determine the fundable transfer amount
  uint32_t fundable_transfer_amount =
      (sender_can_transfer && recipient_can_receive) ? transfer_amount : 0;

  // Update the balances
  *sender_balance_pointer = sender_balance - fundable_transfer_amount;
  *recipient_balance_pointer = recipient_balance + fundable_transfer_amount;
}
