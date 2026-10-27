# ADR 0006: Experimental ESP32 fixed courier

Date: 2026-08-10
Updated: 2026-08-11
Status: Experimental single-node text/receipt courier physically proven; extended by ADR 0007

## Context

Hypha's long-range roadmap includes optional fixed relays. At the time this experiment
started, Milestone 0 and the one-courier file gate were the immediate product priority.
The August 10 roadmap update kept HAR1 closure first, then promoted production hardening
of the **text/receipt-only** fixed courier into the supervised Venue Pilot track. Focused
HAR1 return/application/cleanup is now treated as complete. An
ESP32-WROOM board with 4 MB flash and no PSRAM is available for the first experiment.

The experiment must not redesign or weaken the physically proven phone mesh. A fixed
node is a blind store-and-forward courier: it must not learn message plaintext,
contacts, conversations, filenames, attachment keys, or stable endpoint identities.

## Decision

### Compatibility and discovery

- Keep all existing phone-to-phone BLE UUIDs, RMS2/RLY1 formats, discovery, Noise
  sessions, background behavior, and direct Wi-Fi behavior unchanged.
- Use an additive fixed-node BLE service
  `7e57d014-2b97-4d12-9f65-53a4c7a36c81` and transfer characteristic
  `7e57d015-2b97-4d12-9f65-53a4c7a36c81`.
- The experimental advertisement uses the development manufacturer ID `0xFFFF`, an
  `HN` version marker, and an eight-byte random boot encounter token. It contains no
  stable node or endpoint identity.
- Phone encounters remain anonymous to the node. The phone sends only an encounter
  token, ephemeral session material, and opaque courier records.

### Session security

- The node owns a persistent P-256 identity in NVS and signs the encounter-bound
  handshake transcript with ECDSA-SHA256.
- Every session uses ephemeral P-256 ECDH, HKDF-SHA256, and directional AES-256-GCM
  records with strict sequence numbers.
- Authentication or sequence failure closes the session and produces no accepted ID.
- The current Android client treats a newly seen node key as trust on first use. This
  proves possession of the same key on later encounters; it is not human/admin
  verification and must not be labelled verified.
- This additive node protocol does not replace the pinned phone-to-phone Noise suite.

### Courier data and durability

- Carry the existing deterministic RMS2 exchange containing canonical RLY1 opaque
  envelopes. Do not create a second message format for the node.
- The node may inspect only the bounded courier-visible routing fields already present
  in RLY1. Recipient ciphertext remains opaque.
- Store at most 192 records and at most 4,352 bytes per record in the current prototype, with
  24 slots reserved for receipt/control traffic. ADR 0008 proves the largest typed-reply RLY1
  envelope is 4,196 bytes; the small remainder is fixed framing headroom.
- Return an accepted object ID only after the validated record is durably committed to
  LittleFS. Exact duplicates are idempotent; same-ID/different-payload conflicts fail.
- Conserve the RLY1 copy budget exactly during multi-copy forwarding. Update the
  retained copy only after the phone acknowledges what it accepted.
- Private last-copy route probes are not implemented for the node. Last-copy records
  remain on the phone and fail closed instead of being sprayed.
- An accepted ID is hop custody only. It is never recipient delivery and cannot create
  a delivery receipt. Only recipient E2E processing can create the receipt that marks
  the sender Delivered.
- Phone encounters and existing text/receipt mesh work preempt node synchronization.

### Scope boundary

The first experiment carries multi-copy text and recipient receipts only. It does not
carry file bytes or attachment chunks and does not implement Wi-Fi, ESP-NOW, LoRa, or
last-copy private routing. ADR 0007 separately extends the same additive BLE service with
experimental mutually authenticated fixed-node relaying. That extension does not expand
this ADR's file/media scope or production claims.

## Consequences

The design reuses the proven opaque mesh objects and gives the small board a bounded,
crash-recoverable role. A seized or malicious node can still drop, replay, delay, and
correlate encounters, but recipient authentication prevents it from reading or forging
messages and receipts.

The prototype is not production-secure fixed-relay hardware. Promotion requires at
least secure boot, signed firmware, flash encryption or a secure element, authenticated
provisioning/revocation, a recovery/update policy, resource-abuse testing, and a sound
offline lifetime-aging design. This ESP32 has no trusted clock, so expiry while powered
off is not yet enforceable honestly.

## Verification state

Source checks completed through 2026-08-11:

- ESP32 firmware compiled with warnings enabled using Arduino ESP32 core 3.3.11;
- latest image size with ADR 0007's node-relay extension is 1,237,499 bytes (about 94%
  of the default app partition), with 41,980 bytes of static RAM (about 12%);
- Android debug Kotlin compilation passed;
- the complete Android unit suite passed with 100 tests in 21 suites, including focused
  node handshake/session, bounded response-fragment assembly, scheduling, and RMS2 tests;
- firmware was flashed to the ESP32 on COM10;
- serial reported storage, identity, and BLE ready before and after reboot.

The isolated A001 -> ESP32 -> Samsung short-text path and the Samsung -> ESP32 -> A001
recipient-authenticated receipt return both physically passed. Samsung received the
newest relayed message exactly once and A001 later changed from Waiting to Delivered
only after receiving Samsung's E2E receipt. ESP32 custody alone did not change status.

Two integration defects were found and fixed during the proof: ordinary phone
advertisements could cancel an already admitted fixed-node sync, and Android reset its
multi-fragment HNR1 response accumulator before each continuation read. Scheduling now
lets an admitted bounded node exchange finish, and a strict bounded assembler preserves
and validates all fragments. The proof is functionally correct but conservatively timed:
the recipient normally needs a later sync to upload the newly generated receipt, followed
by another sender sync. Latency optimization remains follow-up work.

The firmware also exposes a local serial `CLEAR_RECORDS` maintenance command. Its first
physical use removed seven courier records and `STATUS` then reported `records=0` while
the persistent node identity remained unchanged.

This makes the board a physically proven experimental Hypha text/receipt courier. It is
still not a production node or a file/media mesh. ADR 0007 records the later, separately
gated two-node BLE text/receipt relay proof.

## Physical acceptance gate

1. Keep the recipient out of direct BLE range and queue one short mesh text on the sender.
2. Let only the sender encounter the ESP32 and observe successful node synchronization.
3. Isolate the sender, let only the recipient encounter the ESP32, and receive exactly once.
4. Keep the recipient near long enough for a second synchronization to upload its receipt.
5. Isolate the recipient and let the sender encounter the node again.
6. Confirm Delivered appears only after the sender authenticates that recipient receipt.
7. Confirm the node exposes no plaintext, contact, conversation, or stable endpoint data.

This gate passed on 2026-08-10. Repeat it after latency/scheduling changes and for release
regressions; do not reinterpret this single-node gate as proof of files. Node-to-node
claims must use ADR 0007's separate acceptance evidence and limits.
