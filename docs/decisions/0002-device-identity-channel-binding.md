# ADR 0002: hardware-protected signing identity bound to each Noise channel

- Status: accepted for Phase 0 implementation
- Date: 2026-08-03

## Context

Noise XX gives Relay an encrypted channel and reveals each session's Noise static public key, but the current Phase 0 key is regenerated when discovery restarts. That proves an authenticated exchange with an unknown nearby peer; it does not prove continuity with a device a person previously trusted.

Relay must support Android API 31 and current Android, later interoperate with iOS, keep stable identity material out of BLE advertisements, and avoid exporting identity private keys from platform secure storage.

The Noise framework explicitly supports application-layer authentication by signing the completed handshake hash. Such a signature is channel-bound and cannot be moved to another Noise session. Android Keystore supports non-exportable P-256 ECDSA keys and can use TEE or StrongBox hardware when available. P-256 also maps cleanly to Apple Secure Enclave for the later iOS implementation.

## Decision

1. Each installation owns a persistent P-256 ECDSA signing key under a versioned platform-keystore alias.
2. StrongBox is preferred when available, with a TEE/software Keystore fallback; availability is recorded, never assumed.
3. The private signing key never leaves Android Keystore. Relay stores and exchanges only the X.509-encoded public key and DER-encoded signatures.
4. After Noise XX completes, both peers sign a domain-separated value containing the Noise handshake hash and their protocol role.
5. Signed identity proofs travel only inside the established Noise transport channel.
6. The initiator proof is verified before the responder returns its proof. Both proofs must verify before engineering data or user content is accepted.
7. The public-key fingerprint becomes the stable device identifier used for trust-on-first-use, safety-number comparison, and QR verification. It is never placed in discovery advertisements.
8. “Authenticated device key” and “human verified” are separate states. Relay must not label a key as person-verified until the user scans/compares it through a trusted interaction.
9. A previously trusted peer presenting a different identity key is a blocking security event. Queued messages are not silently delivered across the change.

## Safety fingerprint

The canonical pair fingerprint is derived from the protocol version and the two identity public keys in deterministic bytewise order. Both peers therefore display the same value regardless of who initiated the BLE connection. The first UI representation will be grouped decimal/hex text; QR encoding will carry the exact versioned binary payload plus a checksum.

## Consequences

- A stolen Relay database is insufficient to impersonate the installation without use of its Keystore key.
- Noise session keys retain forward secrecy independently of the long-lived signing identity.
- Reinstall/key loss intentionally causes a visible identity change.
- Hardware-backed protection differs by device and must be surfaced as a capability, not treated as a correctness dependency.
- This does not prove a real-world name. It proves continuity of a cryptographic installation identity that a person may verify.

## Rejected alternatives

- **Stable identity in BLE advertisements:** leaks a trackable identifier.
- **Treat the transient Noise static key as a durable identity:** it is currently regenerated and is not protected by the platform keystore.
- **Require StrongBox:** excludes valid phones and is unnecessary for protocol correctness.
- **Phone-number identity or server key transparency:** conflicts with Relay's offline-first, accountless baseline. A transparency layer may be optional later.
- **Accept key changes silently:** defeats the safety-number threat model.

## Primary references

- Noise Protocol Framework, channel binding: https://noiseprotocol.org/noise.pdf
- Android Keystore system: https://developer.android.com/privacy-and-security/keystore
- Android `KeyGenParameterSpec` P-256 ECDSA example: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec
- Signal X3DH authentication considerations: https://signal.org/docs/specifications/x3dh/
- Signal Sesame identity-key change handling: https://signal.org/docs/specifications/sesame/sesame.pdf
