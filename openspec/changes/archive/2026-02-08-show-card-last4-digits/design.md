## Context

The `show_payment_cards_table` function in `src/ui/output.rs` renders payment cards in two modes controlled by a `show_cleartext` boolean:

- **Non-verbose** (`show_cleartext: false`): Columns are `[index, Name, Color, Expiry, Modified]`. No card number info at all.
- **Verbose** (`show_cleartext: true`): Columns are `[index, Name, Color, Number, Expiry, CVV, Name on card, Modified]`. Full card number shown.

Both `show -p` and `list -p` call this same function, so the change applies to both commands automatically.

The `PaymentCard` entity stores the full card number as a `String` field accessed via `card.number()`.

## Goals / Non-Goals

**Goals:**
- Add a masked card number column (last 4 digits) to the non-verbose payment cards table
- Provide a reusable `last4()` method on `PaymentCard` for consistent formatting

**Non-Goals:**
- Changing verbose mode output (already shows full number)
- Changing JSON output format for `list -p --json`
- Changing the card detail view (`show_card`)
- Handling card numbers shorter than 4 digits (real card numbers are 13-19 digits)

## Decisions

### 1. Add a `last4()` method to `PaymentCard`

Add a method `pub fn last4(&self) -> String` on `PaymentCard` in `entities.rs` that returns the last 4 digits formatted as `•••• XXXX`.

**Rationale:** Centralizing the masking logic in the entity keeps it reusable and testable, rather than embedding string slicing in the UI layer.

**Edge case handling:** If the card number has fewer than 4 characters, return the full number prefixed with `•••• ` — this is a defensive fallback but shouldn't occur with real card data.

### 2. Insert the column after Name in the non-verbose table

The non-verbose column order will be: `[index, Name, Last 4, Color, Expiry, Modified]`.

**Rationale:** Placing "Last 4" right after "Name" groups the card-identifying information together. Color and Expiry are secondary attributes.

### 3. Use `••••` (bullet) as the masking character

Format: `•••• 1234`

**Rationale:** This matches the convention used by banks, payment apps, and most UIs that display masked card numbers. It's universally recognized.

## Risks / Trade-offs

- **[Minimal risk] Terminal encoding**: The `•` (bullet, U+2022) character requires UTF-8 support. All modern terminals support this. If a terminal doesn't render it, the output degrades gracefully to replacement characters — not a blocking issue.
