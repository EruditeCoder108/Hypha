# Relay protocol invariants



Status: Updated through ADR 0010. Any change to these rules requires a protocol decision record and tests.



## Discovery



1. A BLE advertisement contains no stable identity, device name, public key, room identifier, neighbor list, or exact timestamp.

2. Discovery tokens rotate and cannot be used as message-routing identifiers.

3. Correctness cannot depend on extended advertisements, a particular PHY, ranging, or direct Wi-Fi.



## Envelope



1. Every accepted envelope has exactly one immutable 128-bit message ID.

2. The outer format is versioned, deterministic, strictly bounded, and rejects trailing or ambiguous data.

3. Identity, conversation, content type, exact timestamp, and attachment metadata remain inside authenticated ciphertext.

4. An envelope expires from accumulated monotonic age, not from an untrusted wall clock.

5. A node may shorten its local retention under pressure but cannot rewrite the sender's asserted lifetime.



## Routing



1. A node never increases an envelope's copy budget.

2. A binary spray operation conserves budget exactly: `kept + transferred = previous`.

3. Hop count never decreases and cannot exceed hop limit.

4. Duplicate receipt never causes duplicate presentation.

5. A link acknowledgement is not an end-to-end delivery receipt.

6. `Sent via mesh` may be shown only after an authenticated relay durably accepts custody. It is

   not recipient delivery and cannot produce `Delivered`.

7. Relay-to-relay forwarding must not delete the only useful copy. Multi-copy handoff conserves

   the bounded copy budget, and retained-budget changes commit only for records actually accepted.

8. A recognized final Android recipient may release an Android courier copy after durable final

   acceptance. The original sender retains its record until it authenticates the recipient receipt.



## Resources



1. All lengths, nesting, queues, fragments, handshakes, and reconciliation work are bounded before allocation.

2. Untrusted traffic cannot evict higher-priority trusted control data without an explicit congestion policy.

3. Parsing malformed data produces an error, never a crash or partial accepted state.



## BLE fallback transport



1. A GATT frame is bounded by both the negotiated `ATT_MTU - 3` and the 512-byte maximum attribute value.

2. An OEM Bluetooth-stack argument rejection becomes a link failure and never terminates the app process.

3. Transfer metadata is validated before allocation; fragments are accepted only in the declared transfer and exact sequence.

4. A completed engineering transfer is acknowledged only after its declared length and integrity value verify.

5. GATT read responses use bounded, sequenced application fragments so the control path still works at the mandatory 23-byte ATT MTU.



## Security



1. No custom cryptographic primitive is permitted.

2. Ciphertext is authenticated before application parsing or presentation.

3. Relays do not receive stable sender or recipient identities.

4. Protocol/version/capability negotiation is bound into the authenticated handshake.

5. Security-sensitive state changes are crash-consistent before success is reported.

6. Direct BLE sessions use the pinned `Noise_XX_25519_ChaChaPoly_SHA256` suite and bind protocol, transport, and ordered encounter tokens into the prologue.

7. Raw static private keys remain inside the Rust core; platform code receives opaque handles only.

8. An unknown-peer Noise session is encrypted but is never presented as identity-verified.

9. Transfer success requires an authenticated encrypted receipt from the peer, not merely a local GATT write acknowledgement.

10. Any ciphertext authentication failure permanently closes that secure session, produces no success receipt, and never reaches application parsing.

11. Persistent identity proofs sign the completed Noise handshake hash with a role-separated platform-keystore key and travel only inside Noise transport encryption.

12. Stable identity public keys never appear in discovery advertisements.

13. A matching signature proves control of a device key; only an explicit fingerprint/QR comparison may elevate that key to human-verified.



## Direct text and storage



1. User-authored content is sent or accepted only when the authenticated persistent peer key is locally verified; an encrypted unknown-peer session is insufficient.

2. Direct text is valid only after the bounded shared Rust parser accepts its version, type, flags/reserved bits, 128-bit message ID, exact UTF-8 lengths, and 2,048-byte body limit. Version 1 carries ordinary text. Version 2 additionally binds a different 128-bit replied-to message ID and a non-empty fallback preview of at most 256 UTF-8 bytes.

3. The sender durably records `pending` before network delivery and may record `delivered` only after authenticating a receipt bound to the same message ID.

4. The receiver durably stores and duplicate-checks a message before creating its delivery receipt.

5. An exact duplicate message ID may be acknowledged again but is never presented or stored twice; a same-ID content or identity mismatch fails closed.

6. Local message content, including typed reply metadata, is authenticated encryption at rest under a non-exportable platform-keystore key; message ID, peer fingerprint, direction, and local content version are authenticated as associated data. Version-1 database rows remain readable after the additive migration.

7. A reply receipt acknowledges the reply message's own ID, never the referenced message ID. A missing referenced message may affect navigation only; the authenticated fallback preview keeps the reply understandable and cannot be interpreted as delivery of the referenced message.



## Experimental fixed couriers



These rules apply to the experimental ESP32 fixed-courier lane in ADRs 0006 and 0007. Its current

UUIDs and resource limits are engineering values, not a frozen production-hardware profile.



1. Fixed-courier support is additive and cannot change the existing phone BLE UUIDs, phone-to-phone Noise suite, RMS2/RLY1 encoding, discovery, or direct Wi-Fi behavior.

2. A fixed-node advertisement contains only a version marker and rotating encounter material; it never contains a stable node identity, endpoint identity, contact, conversation, or route.

3. The phone remains anonymous to the fixed node. Node identity proof is bound to the encounter transcript. Lab-mode authentication must never be presented as human/admin verification; only an active identity in a verified Managed Venue inventory may be described as operator-approved.

4. Fixed-node records are directionally authenticated and strictly sequenced; an authentication, replay, or sequence failure closes the session without accepting courier data.

5. A fixed courier accepts only canonical bounded RLY1 opaque envelopes through RMS2. It receives no plaintext, content key, filename, preview, MIME type, contact key, conversation, or stable endpoint identity.

6. An accepted object ID may be returned only after the exact validated envelope is durably committed. Exact duplicates are idempotent and same-ID/different-payload conflicts fail closed.

7. Multi-copy forwarding conserves the copy budget exactly. The retained copy changes only after the receiving authenticated peer acknowledges its accepted object ID.

8. Until authenticated private route probes are implemented, last-copy records remain on the phone and the fixed-node path fails closed.

9. Fixed-node custody is never recipient delivery, cannot create HAR1, and cannot mark a sender Delivered. Only a recipient-authenticated E2E receipt can do that.

10. The current ESP32 prototype is bounded to 192 records of at most 4,352 bytes each, with 24 slots reserved for control/receipt traffic, and carries only multi-copy text/receipt envelopes. The largest currently valid typed-reply envelope is 4,196 bytes; the remaining bytes are framing headroom, not permission for unbounded payloads.

11. Local maintenance may explicitly purge the fixed courier's durable record store, but it must not disclose record contents, silently claim delivery, or change the persistent node identity. Purged custody copies are unrecoverable and must be reported honestly.

12. Fixed nodes mutually authenticate persistent node identities inside the encrypted BLE encounter before node inventory or record exchange. A failed identity proof accepts nothing.

13. Node exchange is bounded and inventory-first. Exact duplicate inventory cannot consume another copy budget, and no record accepted during an exchange may be echoed back in that exchange.

14. Fixed-node phone service and receipt/control traffic retain scheduling priority, with a bounded fairness opportunity for ordinary text so neither class can starve indefinitely.

15. A fixed node cannot infer that an anonymous phone is the final recipient. Phone custody alone therefore cannot delete the node's copy or create global cleanup. Such copies remain bounded by budget, hop/lifetime limits, quotas, eviction policy, and maintenance until a separately authenticated cleanup design exists.

16. BLE fixed-node-to-fixed-node text/receipt relay is experimental and governed by ADR 0007. Files, media, Wi-Fi, ESP-NOW, LoRa, and last-copy private routing remain outside the implemented ESP scope.

17. A fixed-node server connection is locally bounded even before envelope admission exists. Encrypted session confirmation, authenticated idle time, absolute connection life, transfer starts, declared bytes, reads, and writes have hard monotonic limits. Malformed framing, CRC, sequence, authentication, or protocol order is terminal and forces disconnect outside the BLE callback.

18. Repeated connection-guard failures may cause only a short bounded advertising backoff with aggregate diagnostics. A bounded per-radio connection window may keep an address only in volatile RAM for short-lived availability isolation; the guard must never persist, log, export, or treat that address, a discovery token, stable endpoint identity, or inferred user identity as trust or user identity. An already-isolated radio must not poison the aggregate allowance for other peers.

19. A valid node possession proof is not venue approval. ADR 0010 Managed Venue mode admits only an active courier key in the operator-signed HVI1 inventory after identity proof and before inventory, offers, custody, or copy-budget change. Unknown, revoked, replaced, unavailable-policy, invalid-policy, and rollback cases fail closed. TOFU remains clearly labelled Lab mode.

20. Entering Managed Venue mode requires explicit local authority bootstrap. Later HVI1 objects must keep the venue and authority anchors and advance the monotonic version fence; a corrupt policy or reboot failure must not silently downgrade to Lab mode. Returning to Lab mode is a separately confirmed local reset that preserves courier records and node identity.

21. A structurally valid RLY1 envelope and an encrypted hop do not prove admission. Production opaque-envelope admission, priority authority, quotas, and congestion behavior require ADR 0009 Gate C and privacy/cryptographic review before public deposits.

22. Parsed `age <= lifetime` is not expiry enforcement. A production fixed node must accumulate monotonic residence age, advance offered age, durably remove expiry, prevent delayed resurrection, and state its powered-off-time policy as required by ADR 0009 Gate D.

23. The raw P-256 key in ordinary Preferences/NVS is prototype-only. Production identity/update claims require the shipping-hardware secure boot, protected key storage, signed anti-rollback update, gated maintenance, and recovery evidence in ADR 0009 Gate E.

24. The selected Gate C public authorization is the fixed 422-byte HAT1 RFC 9578 profile in ADR 0011. It binds one venue/epoch/class/priority and one immutable RLY1 envelope while permitting only monotonic age/hop/copy forwarding. It grants no public security-control authority and is not live admission until signed HAP1 policy, supervised blind issuance, compound-record storage, durable replay/accounting state, and custody integration pass their gates.

