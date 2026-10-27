# ADR 0008: Typed message replies

- Status: accepted; automated gates and direct, phone-courier, and ESP-courier physical proofs passed
- Date: 2026-08-12

## Context

The presentation layer exposed WhatsApp-style Reply, but the first implementation represented a
reply by prefixing ordinary text with a quoted Markdown-like block. That looked correct on two
phones but gave the protocol, stores, and recipients no durable reply relationship. It also made
ordinary user text ambiguous and could not reliably survive future rendering changes.

## Decision

Keep the existing `RMSG` version-1 record unchanged for ordinary messages. A real reply uses
strict `RMSG` version 2 with:

- the reply message's own random 128-bit ID;
- the existing non-empty UTF-8 body, bounded to 2,048 bytes;
- a different 128-bit ID identifying the referenced message; and
- a non-empty authenticated fallback preview, bounded to 256 UTF-8 bytes.

The shared Rust encoder/parser owns these bounds and rejects unknown flags, invalid UTF-8,
trailing data, empty previews, oversized fields, and self-replies. The body is never rewritten
into quoted text. New readers accept both versions; non-reply sends continue to emit version 1.

Direct BLE and direct Wi-Fi carry the canonical record inside their authenticated link channel.
Mesh encrypts and signs the same canonical record end to end. Phone and ESP couriers carry only
the outer opaque `RLY1` envelope and therefore cannot see the reply ID, preview, or body. The
recipient commits the typed message before emitting a receipt. That receipt binds the reply's own
message ID, exactly like every other message.

Android message stores migrate additively. Existing encrypted rows remain local content version
1. New rows encrypt the complete canonical `RMSG` record as local content version 2 and bind that
version into AES-GCM associated data. Reply metadata therefore survives process death, retries,
pagination, direct delivery, phone couriers, and fixed-node couriers without plaintext database
columns.

The largest legal reply produces a 4,196-byte courier envelope. The ESP32 prototype record limit
is consequently 4,352 bytes. Its 192-record quota and 24 control slots remain unchanged.

## Missing referenced messages

The referenced message may be outside the loaded page, deleted locally in a future product, or
absent after history loss. The fallback preview remains displayable, so rendering never depends on
loading the original. A future jump-to-original interaction may use the ID when available; failure
to find it must remain a harmless UI condition.

## Compatibility

This is a pre-release protocol addition. Current builds read old version-1 history, and ordinary
messages remain version 1. A version-2 reply requires both endpoints to run a build containing this
ADR. An older endpoint rejects it and cannot produce a receipt, so it remains Waiting rather than
being falsely marked Delivered. Before a public mixed-version release, reply capability must be
authenticated and negotiated or the minimum supported version must be enforced.

## Verification

Automated coverage includes strict version-2 round trips and malformed/boundary rejection,
maximum-size recipient encryption/decryption with the exact fixed-node envelope bound, JNI packed
result parsing, additive Android database migrations, encrypted reply persistence, Flutter
platform propagation, and a UI test proving the transmitted body no longer contains the old quote
prefix.

The physical reply gate passed on 2026-08-12 through each relevant route: direct BLE between the
phones, one phone courier, and one ESP courier. In every route the recipient rendered the typed
reply relationship and bounded preview, while the sender reached Delivered only after the
recipient-authenticated receipt returned. Courier custody alone did not create Delivered.
