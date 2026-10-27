# ADR 0003: Durable verified direct text

- Status: accepted and physically validated
- Date: 2026-08-03

## Decision

Relay direct text uses a small versioned application record parsed by the shared Rust core only after Noise authentication. Each message has a cryptographically random 128-bit ID and at most 2,048 bytes of non-empty UTF-8 text. Version 1 remains the ordinary-text format. ADR 0008 adds a strictly bounded version 2 for typed replies while keeping version-1 records readable. Receipts contain the exact accepted message ID and are themselves carried inside the Noise transport.

User content requires the persistent remote identity key to be locally marked verified on both endpoints. The sender writes a local pending record before sending. The receiver performs its encrypted-at-rest database commit and duplicate check before generating a receipt. Only an authenticated matching receipt moves the sender record to delivered.

Android stores the canonical message content with AES-256-GCM under a non-exportable Android Keystore key. The message ID, peer safety fingerprint, direction, and new local content version are authenticated as associated data. SQLite holds ordering and delivery metadata plus nonce and ciphertext, never plaintext message text or reply preview. Existing version-1 rows retain their original associated-data layout and migrate additively.

## Why

BLE write success proves only that a fragment reached an operating-system stack. It does not prove decryption, parsing, durable storage, correct recipient identity, or end-to-end delivery. The selected ordering gives a precise crash rule: uncertainty may leave a visible pending item or cause a safe duplicate receipt, but it cannot create a false delivered state or duplicate presentation.

## Consequences

- Direct verified messaging works over the universal BLE fallback without Internet or Wi-Fi.
- A receiver may safely acknowledge an exact retransmission after suppressing duplicate presentation.
- Clearing application data destroys local message history, the storage key, device identity, and trust decisions.
- This ADR does not define multi-hop recipient encryption, prekeys, conversation ratchets, reconciliation, or the Wi-Fi bulk transport. Those require separate decisions and tests.
