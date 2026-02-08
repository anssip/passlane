## 1. Entity: Add `last4()` method

- [x] 1.1 Add `pub fn last4(&self) -> String` method to `PaymentCard` in `src/vault/entities.rs` that returns the card number formatted as `•••• XXXX` (last 4 digits). If the number has fewer than 4 characters, return `•••• ` followed by the full number.
- [x] 1.2 Add a unit test for `last4()` covering: normal 16-digit number, short number (< 4 chars), exactly 4-digit number.

## 2. UI: Add "Last 4" column to non-verbose payment cards table

- [x] 2.1 In `show_payment_cards_table` in `src/ui/output.rs`, add `"Last 4"` to the non-verbose headers list after `"Name"`, resulting in `["", "Name", "Last 4", "Color", "Expiry", "Modified"]`.
- [x] 2.2 In the non-verbose row construction in the same function, add `Cell::new(card.last4())` after the Name cell.

## 3. Verification

- [x] 3.1 Run `cargo build` and confirm no compilation errors.
- [x] 3.2 Run `cargo test` and confirm all tests pass including the new `last4()` test.
