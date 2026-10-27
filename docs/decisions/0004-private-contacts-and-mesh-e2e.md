# ADR 0004: Private contacts and recipient-only mesh envelopes

- Status: accepted for the Phase 1 implementation and three-device validation
- Date: 2026-08-03

## Decision

Relay separates a human contact, a radio encounter, a hop-encrypted link, and an end-to-end conversation. They are not interchangeable identifiers or security claims.

A person chooses a display name. Display names are intentionally not globally unique because a fully offline system has no global naming authority. A contact is selected by a locally saved cryptographic identity, shown with the person's chosen name and a short Relay ID. Contacts are initially exchanged face-to-face over a QR code or an already authenticated nearby link. The user confirms the safety code before the contact becomes verified. No display name, stable identity key, contact ID, or stable routing value appears in BLE or Wi-Fi discovery.

Each contact exchange binds:

- the existing persistent platform identity used by Relay's verified Noise link;
- a vodozemac Ed25519 signing identity and Curve25519 Olm identity;
- one recipient prekey for asynchronous session creation; and
- a random, per-contact, per-direction route secret.

The platform identity signs the complete end-to-end bundle during phone integration. The Rust end-to-end bundle is also self-signed so malformed or substituted internal keys fail before use. A route secret is unique to one contact direction; it is never broadcast. Its HMAC output lets the recipient recognize a message while looking random to couriers. The same secret, with a different domain label, seals the Olm frame so a courier cannot inspect or correlate exposed ratchet headers.

Recipient encryption uses `vodozemac` 0.10.0 with its version-2 full-length MAC configuration, pinned at the reviewed version. Vodozemac supplies asynchronous 3DH session setup, an Olm double ratchet, skipped-message handling, strict Ed25519 verification, encrypted state pickles, and contributory X25519 checks. Relay additionally signs the bounded inner application record, binds both endpoint signing identities and the immutable message ID inside ciphertext, and pads the sealed Olm frame into coarse size classes.

The outer courier envelope contains only a random message ID, a per-message destination authenticator, bounded routing policy, mutable hop/age/copy state, and opaque ciphertext. Couriers may store, copy, reorder, delay, or drop it, but cannot decrypt or forge accepted content. Link encryption such as Noise protects one physical hop; it does not replace this recipient-only layer.

Normal text sending is limited to at most 32 emitted but not end-to-end-acknowledged messages per conversation. Additional text remains durably queued at the sender. This stays below the ratchet implementation's skipped-key retention bound under mesh reordering. Reconciliation prioritizes lower conversation sequence numbers.

## Persistence order

Sending must atomically persist the advanced ratchet state, encrypted envelope, and local queued message before the envelope is eligible for radio transfer. Receiving must atomically persist the advanced ratchet state, plaintext-at-rest record, and duplicate marker before emitting an end-to-end receipt. A hop acknowledgement means only that another courier accepted custody. Only a recipient-authenticated receipt means delivered.

## Library decision

The official Signal `libsignal` implementation remains a strong future option, especially for PQXDH, but it is AGPL-3.0 and adopting it would impose a project-wide licensing decision. Relay is currently MIT OR Apache-2.0, so that dependency is not introduced silently.

Vodozemac 0.10.0 is Apache-2.0, Rust-native, independently audited, and maintained as Matrix's reference Olm implementation. Release 0.10.0 changed Diffie-Hellman operations and session creation to reject non-contributory all-zero results. Its audit predates some current code and Relay's metadata wrapper is a new composition, so this decision is not a production security claim. Dependency review, protocol review, fuzzing, and an independent audit remain release gates.

Primary references:

- https://github.com/matrix-org/vodozemac
- https://github.com/matrix-org/vodozemac/blob/main/CHANGELOG.md
- https://matrix.org/blog/2022/05/16/independent-public-audit-of-vodozemac-a-native-rust-reference-implementation-of-matrix-end-to-end-encryption/
- https://signal.org/docs/specifications/doubleratchet/
- https://signal.org/docs/specifications/pqxdh/
- https://github.com/signalapp/libsignal

## First physical acceptance gate

With phones A, B, and C:

1. A and C are verified contacts; B is only a courier.
2. A creates a text while C is out of range.
3. B meets A and accepts only the opaque envelope.
4. A leaves; B later meets C and forwards it.
5. C decrypts and presents the text exactly once.
6. The end-to-end receipt returns toward A, possibly through B.
7. B's database and diagnostics contain no plaintext, stable A/C identity, conversation ID, or contact name.

## Deferred decisions

- post-quantum asynchronous setup and migration from classical 3DH;
- encrypted ratchet headers without Relay's per-contact sealed wrapper;
- human root identities with separately revocable multi-device keys;
- group membership and group ratchets;
- public stranger routing, Sybil admission, and cover traffic.
