# PDR-0001: Direct-link secure-session handshake

Status: accepted for Phase 0 engineering; not a release security claim.

Date: 2026-08-03

## Decision

Use `Noise_XX_25519_ChaChaPoly_SHA256` for a first encounter between two Relay phones:

- Noise XX for a three-message mutual static-key proof with identity hiding after the first ephemeral message;
- X25519 for Diffie-Hellman;
- ChaCha20-Poly1305 for authenticated encryption;
- SHA-256 for hashing and HKDF;
- `snow` 0.10.0 as the Phase 0 Rust implementation;
- a maximum 512-byte Relay handshake frame, far below Noise's general 65,535-byte limit;
- a maximum 32 KiB plaintext per direct-link transport message;
- fail-closed session state after malformed input or authentication failure.

The prologue binds the Relay protocol family, major version, secure-link framing version, transport type, and both rotating encounter tokens in initiator/responder order. A handshake from one encounter therefore cannot be transplanted silently into another encounter or protocol context.

## Trust meaning

Noise XX proves that the same peers possessing the exchanged static Noise keys completed this session. It does **not** prove a human identity until the remote key is verified or pinned through the later QR/NFC contact flow. The UI and logs must call this an encrypted unknown-peer session, not a verified contact.

Discovery advertisements continue to contain no static or identity key.

Later known-contact sessions may use an IK-style authenticated resumption only after the stored key binding and downgrade behavior are specified and tested.

## Why this suite

The Noise specification defines the XX pattern and the selected primitives. The active libp2p Noise specification independently selects the same suite and explains its use for initially unknown peers. Using one fixed suite prevents opportunistic cipher negotiation and downgrade complexity in the first protocol version.

## Implementation boundary

The complete handshake and transport cipher state live in the shared Rust core. Kotlin transports only bounded opaque handshake/ciphertext frames. Flutter never receives private key material or plaintext from an unverified native parser.

## Known limitation

The `snow` project states that it has not received a formal audit. We will use it for tests and prototypes, retain interoperability vectors, review dependency changes, and require an external audit or audited replacement before claiming production-grade security.

## Primary references

- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [libp2p Noise secure-channel specification](https://github.com/libp2p/specs/blob/master/noise/README.md)
- [`snow` 0.10.0 documentation](https://docs.rs/crate/snow/0.10.0)
