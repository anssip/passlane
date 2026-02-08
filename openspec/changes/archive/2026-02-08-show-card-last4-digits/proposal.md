## Why

When listing payment cards with `show -p`, the non-verbose table only displays Name, Color, Expiry, and Modified — but no part of the card number. If a user has multiple cards with similar names (e.g., two Visa cards), there's no way to distinguish them without entering verbose mode or drilling into each card's details. Showing the last 4 digits provides a safe, universally-recognized identifier without exposing the full card number.

## What Changes

- The non-verbose payment cards table (displayed by `show -p` and `show -p <REGEXP>`) will include a new "Last 4" column showing the last 4 digits of each card's number (e.g., `•••• 1234`).
- The `list -p` plain text (non-verbose) output will also include the last 4 digits for consistency.
- No changes to verbose mode (which already shows the full card number), JSON output, or card detail views.

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `list-command`: The plain text non-verbose output for payment cards will include a "Last 4" column showing the masked card number.

## Impact

- `src/ui/output.rs`: `show_payment_cards_table` — add "Last 4" column to the non-verbose branch.
- `src/vault/entities.rs`: Optionally add a `last4()` helper method on `PaymentCard` to extract the last 4 digits of the number.
- `src/actions/list.rs`: No code changes needed — it already calls `show_payment_cards_table`.
- `src/actions/show.rs`: No code changes needed — it already calls `show_payment_cards_table`.
