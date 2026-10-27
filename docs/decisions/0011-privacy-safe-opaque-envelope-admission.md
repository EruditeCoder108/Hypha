# ADR 0011: Privacy-safe opaque-envelope admission contract



- Status: HAT1 cryptographic profile selected after desktop/Android interoperability and

  ESP32 compile feasibility; signed policy, issuance, persistence, and live relay integration

  remain pending

- Date: 2026-08-15



## Context



An encrypted fixed-node session and a structurally valid `RLY1` envelope prove neither that the

envelope is authorized Hypha traffic nor that its claimed priority is honest. A malicious nearby

client can otherwise create valid-looking opaque bytes, label them control traffic, rotate radio

identifiers, repeat duplicates, or create same-ID conflicts until storage, airtime, or CPU is

consumed.



ADR 0010 answers which fixed-node keys a venue approves. It does not authorize phone deposits or

node offers. Gate C needs a separate admission decision without revealing a stable sender,

recipient, contact, conversation, route, or human identity to a courier.



This ADR first established a semantic contract and deterministic policy model. The 2026-08-15

feasibility slice now selects a narrow RFC 9578 Blind RSA application profile called `HAT1` and

fixes its bytes and failure semantics. It still does not change `RLY1`/`RMS2`, custody, priority,

storage, routing, or live phone/ESP admission. Production integration remains gated on the signed

policy/issuer lifecycle and an external cryptographic review of the complete issuance flow.



## Threat and privacy boundary



The admission design must handle:



- structurally valid random ciphertext and repeated failed proofs;

- a client claiming control/receipt priority with an ordinary-message authorization;

- exact duplicate floods and same-ID/different-payload conflicts;

- reconnects with rotating BLE addresses or encounter tokens;

- a valid but over-quota participant;

- a revoked, rolled-back, wrong-venue, or wrong-policy authorization;

- store pressure where legitimate security control, receipts, and text must still progress.



It does not defeat radio jamming, a physically absent route, a compromised endpoint using its

legitimate allowance, or a malicious approved courier that accepts and later discards custody.



The minimum privacy properties are:



1. No proof field is a human identity, device identity, contact, conversation, destination, or

   route identifier.

2. The selected pilot profile does not create an origin-equivalent node tag. Participant limits

   are enforced while an operator-supervised issuer approves a bounded number of blinded requests.

   A node sees a random token nonce bound to one envelope, not a stable origin identifier.

3. The random token nonce and token key id form a local spend key bound to one immutable envelope.

   Exact replay is detectable without turning that key into a cross-message identity.

4. Managed nodes re-run the reviewed proof verifier locally. They do not trust a previous courier's

   unsigned statement that an envelope was admitted.

5. Radio address, rotating discovery token, node fingerprint, destination hint, message ID, and

   ciphertext digest are not used as an origin identity.

6. Aggregate counters may record coarse outcomes and object classes only. They must not log quota

   tags, spend identifiers, proof bytes, envelope IDs, destination hints, or ciphertext digests.



Separate class keys reveal the requested coarse class to the issuer and partition anonymity sets.

Timing and radio observation can also correlate issuance and later deposit. HAT1 prevents the

issuer from seeing the blinded envelope commitment; it is not anonymity against a global observer.



## Research review of candidate constructions



This review checked standards and maintained source before selecting new cryptography. It does not

make any candidate part of Hypha's production protocol.



### RFC 9578 publicly verifiable one-use tokens



Privacy Pass provides a standardized authorization architecture and an IETF Standards Track Blind

RSA issuance protocol. Its public token can be checked offline with the issuer public key. The

issuer does not learn the blinded token input, and issuing a bounded batch can move the

per-participant rate limit away from a stable tag at each node.



For the RFC 9578 2048-bit token, the exact token size is 354 bytes: 2-byte type, 32-byte nonce,

32-byte challenge digest, 32-byte key id, and 256-byte authenticator. The challenge digest could

commit to a canonical Hypha venue/policy/class/envelope authorization, but that would be a new

application profile requiring its own vectors and review. A token only proves issuer authorization;

it does not prove that opaque ciphertext really contains a receipt or security command.



This candidate has important costs:



- cached tokens are bearer capabilities, so theft, sharing/hoarding, replay state, and issuance

  abuse need explicit handling;

- class-specific keys or challenges can bound the authority granted, but can partition anonymity

  sets and still allow a holder to spend a scarce receipt token on junk;

- the current 4,196-byte maximum typed-reply RLY1 record has only 156 bytes below the ESP's

  4,352-byte record ceiling. An inline 354-byte token would exceed that ceiling by 198 bytes;

- ESP-IDF exposes RSA and SHA-384 support. Hypha's current application partition is already at 95%,

  so public-key verification must be measured in an isolated compile/timing/RAM spike. A reviewed

  larger partition or higher-capacity shipping board is an available option, not an automatic

  rejection, but it must preserve update/recovery space and Gate E protections; and

- issuer key rotation, operator policy epochs, offline refill, revocation, and cached-token

  invalidation must not silently rely on wall-clock time before Gate D.



Primary references:



- RFC 9576 Privacy Pass architecture: https://www.rfc-editor.org/rfc/rfc9576.html

- RFC 9578 issuance protocols and vectors: https://www.rfc-editor.org/rfc/rfc9578.html

- RFC 9474 RSA blind signatures: https://www.rfc-editor.org/rfc/rfc9474.html

- Cloudflare CIRCL RFC 9474 implementation: https://github.com/cloudflare/circl/tree/main/blindsign/blindrsa

- ESP-IDF Mbed TLS configuration: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/protocols/mbedtls.html



### Anonymous Rate-Limited Credentials



The IETF ARC draft targets the harder problem directly: one credential can create a fixed number

of unlinkable presentations. It uses P-256 commitments, a keyed verifier, client-side mutable

nonce state, and an integrated zero-knowledge range proof. Reusing presentation state can break

unlinkability. The current presentation is also large: with compressed P-256 elements and a limit

of eight uses, the draft formula yields 744 bytes before any Hypha framing.



ARC is valuable research, but it is not suitable for the Venue Pilot now. As of this review it is

an Internet-Draft with open design questions, its repository provides a proof-of-concept area

rather than a mature ESP32 library, verification needs secret key material on every accepting

node, and its code/CPU/storage cost has not been measured on Hypha hardware.



Primary references:



- ARC cryptography draft: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/

- ARC protocol draft: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-protocol/

- ARC working repository: https://github.com/ietf-wg-privacypass/draft-arc



### Node-local origin-equivalent tags



The existing semantic model keeps this as a conservative fallback because it can enforce a quota

across rotating radio sessions with small bookkeeping. It remains unselected: no reviewed

construction currently derives a tag that is simultaneously node/venue/epoch scoped, resistant

to forgery and reset, unavailable for cross-node correlation, and practical for offline issuance.

It therefore must not be mistaken for implemented anonymity.



### Research decision



Select RFC 9578 publicly verifiable Blind RSA with SHA-384 and RSA-PSS salt length 48 for the

supervised Venue Pilot, profiled below as `HAT1`. Use maintained reviewed-source implementations

for blind issuance/client work and a small fixed verifier on ESP32. Do not select ARC or invent a

node-local anonymous credential for this pilot.



Cloudflare's `privacypass-ts` 0.9.0 (Apache-2.0, Node 20+) generated the checked-in blind-issuance

interoperability vector. Its locked production dependency audit reported zero known production

vulnerabilities on 2026-08-15; development-tool findings are not shipped. The Rust `privacypass`

crate is MIT and supports the same public token flow, but its own README says it has not been

independently audited. Neither library is silently vendored or treated as a substitute for review.

The existing Android JNI boundary makes Rust a possible future phone-client integration, while the

offline Node operator tooling makes the TypeScript implementation a possible issuer. That final

dependency/integration choice remains a separately reviewed implementation step.



### First feasibility result: official public-token verification



The standalone Node feasibility verifier now parses the exact 354-byte token, recomputes the

SHA-256 challenge digest and SPKI key identifier, and verifies the RFC-required RSA-PSS/SHA-384

signature with a 48-byte salt. RFC 9578 Appendix A.2 test vector 1 passes. Deterministic rejection

cases cover wrong length/type, changed challenge, changed key identifier, changed authenticator,

and invalid input types; the focused suite passes 6/6.



This proves that Hypha's ordinary desktop tooling can consume the standard public token without a

new verifier dependency. The fixture carries the RFC test-vector attribution and Revised BSD

license text. No production admission or wire path calls this verifier.



## Selected HAT1 binary profile



`HAT1` is a fixed 422-byte sidecar. All integers are unsigned big-endian. Parsers reject unknown

versions, classes, flags, reserved bits, lengths, or trailing bytes before public-key work.



| Offset | Bytes | Field |

| ---: | ---: | --- |

| 0 | 4 | ASCII `HAT1` |

| 4 | 1 | version `1` |

| 5 | 1 | authorized object class |

| 6 | 1 | exact existing `RLY1` priority |

| 7 | 1 | flags, exactly zero |

| 8 | 16 | random venue id |

| 24 | 8 | monotonic operator admission-policy epoch |

| 32 | 2 | initial copy-budget ceiling |

| 34 | 2 | reserved, exactly zero |

| 36 | 32 | immutable envelope commitment |

| 68 | 354 | exact RFC 9578 type `0x0002` token |



The envelope commitment is:



```text

SHA-256(

  "Hypha/RLY1-admission-binding/v1\0" ||

  RLY1[0..48] ||                 # magic, version, exact priority, reserved,

                                  # message id, destination hint, lifetime

  RLY1[56] ||                    # immutable hop limit

  HAT1.initial_copy_budget_u16 ||

  RLY1[60..64] ||                # ciphertext length

  SHA-256(RLY1.ciphertext)

)

```



Portable `age_ms`, `hops_taken`, and current `copy_budget` are deliberately omitted. Every node

still requires `age <= lifetime`, `hops_taken <= hop_limit`, and

`0 < current_copy_budget <= HAT1.initial_copy_budget`. A new phone deposit additionally requires

age and hops to be zero and current copies to equal the authenticated initial ceiling. Therefore a

forwarder can only move mutable fields in their safe direction and cannot reset a depleted copy

budget with the same ticket.



The RFC token challenge uses the canonical RFC 9577 `TokenChallenge` encoding:



```text

token_type         = 0x0002

issuer_name        = ASCII "admission.hypha.invalid"

redemption_context = SHA-256(HAT1[0..68])

origin_info        = empty

```



The constant `.invalid` name prevents an accidental DNS/Internet trust claim. Venue and epoch are

inside the hashed header; the RFC token key id is SHA-256 over the exact issuer RSA-PSS SPKI.



### Public classes and honest priority limits



| HAT1 class | Meaning | Required RLY1 priority | Pilot issuance |

| ---: | --- | ---: | --- |

| 1 | recipient receipt | `Control (0)` | small bounded allowance |

| 2 | text | `DirectText (2)` | enabled |

| 3 | manifest | `Manifest (4)` | disabled until attachment relay is reviewed |

| 4 | bulk | `Bulk (5)` | disabled until attachment relay is reviewed |



There is no public class 0. Security/control administration requires a separate operator-only

capability and cannot be minted with a public blind ticket. `Safety (1)` and `RoomHistory (3)` are

not part of HAT1 version 1.



A blind courier cannot prove that opaque ciphertext really decrypts to a receipt. The pilot accepts

that a malicious holder may spend its own scarce class-1 ticket on junk. This misuse is bounded by

the much smaller receipt issuance allowance, local duplicate/failure limits, class storage limits,

and total capacity. It does not grant security-control authority. Claiming anything stronger would

require a new reviewed proof.



### Signed admission policy and key lifecycle



Before live integration, the HVI1 venue authority must sign a separate versioned admission policy

object (working name `HAP1`). HAP1 must contain the HVI1 venue id, a strictly increasing admission

epoch and rollback fence, supported HAT versions, the exact RSA-PSS SPKI and key id for each class,

active/revoked/replaced state, enabled classes, per-class envelope ceilings, issuance allowances,

node accounting limits, and total/class reserves. It must use two durable slots and fail closed on

corruption or rollback in Managed Venue mode. Lab mode remains explicitly separate.



Each class uses a different issuer key. The operator-supervised local issuer may approve only a

bounded number of blinded requests for the selected class; it records coarse counts, not blinded

requests, token nonces, challenges, envelope ids, destination hints, or ciphertext digests. The

issuer learns the class key requested and request timing, but not the blinded HAT1 header. Issuance

and redemption diagnostics must not create a joinable identifier.



An issued ticket is a bearer capability tied to one immutable envelope. Theft or sharing can replay

that exact opaque object but cannot authorize different bytes. A node stores a bounded tombstone for

the token key id plus nonce and binding. The same ticket may legitimately accompany the same object

across multiple nodes; each node admits it at most once and treats exact local repeats as idempotent.

This is not global copy-budget enforcement against a malicious endpoint. Issuance bounds distinct

authorized objects, while existing copy semantics remain cooperation rules between authenticated

participants.



A higher signed HAP1 epoch can revoke or replace a class issuer immediately for new admission.

Older custody is neither deleted nor re-labelled Delivered. No admission validity depends on wall

clock time before Gate D; cached authority ends through explicit epoch/key rotation. Lost issuer

keys are replaced by a higher policy epoch, never by accepting an older rollback.



### Sidecar and record ceiling



HAT1 travels beside RLY1, not inside recipient ciphertext and not inside the existing 64-byte RLY1

header. A maximum current typed-reply RLY1 is 4,196 bytes, so RLY1 plus HAT1 is 4,618 bytes. Live

integration therefore needs a versioned compound record and a reviewed record ceiling above the

current 4,352 bytes; it must not silently append bytes to an existing RLY1 parser. The 16 KiB

transfer ceiling is large enough, so this does not by itself require fragmentation. Storage byte

quotas, hashes, custody ACKs, and RMS2 framing must cover the complete compound record before the

sender changes copy state.



## Feasibility evidence (2026-08-15)



- A blind-issued HAT1 golden vector generated by `privacypass-ts` verifies byte-for-byte in the

  dependency-free Node verifier and Android/JVM `RSASSA-PSS` verifier.

- Focused HAT1/RFC tests pass 13/13 in Node and 5/5 on Android. They reject immutable mutations,

  copy rollback, non-initial deposits, wrong venue/epoch/class key, forged priority/reserved bits,

  key-id changes, and signature changes.

- The normal warning-clean ESP32 build remains 1,245,559 bytes flash and 42,212 bytes static RAM.

  Enabling the isolated RSA-PSS/SHA-384 verification probe compiles at 1,265,931 bytes and 42,268

  bytes: a 20,372-byte flash and 56-byte static-RAM delta. It still fits the current partition at

  96%, with 44,789 bytes of program space remaining.

- The compile-only probe is disabled in normal builds. It has not been flashed, so on-board parse/

  verification success, elapsed time, stack peak, watchdog behavior, and adversarial timing remain

  physical evidence, not claims.



## Selected verifier-to-policy contract



A HAT1 verifier hands the local policy engine an authenticated result containing:



- venue id and operator policy epoch;

- supported proof version;

- token key id plus random nonce as the local portable-ticket/spend key;

- the class-specific issuer key selected by signed HAP1 policy;

- authorized coarse object class;

- maximum encoded bytes, lifetime, hop limit, and initial copy budget;

- exact allowed `RLY1` priority;

- a binding to the immutable envelope fields and ciphertext digest; and

- a non-revoked result under the locally installed operator policy.



The binding covers `message_id`, destination hint, asserted lifetime, hop limit, initial copy-budget

ceiling, priority, ciphertext length, and ciphertext digest. Portable age, hops taken, and current

copy budget may only move in their already-safe direction and may never exceed the authorization.



The original policy model treats proof verification as an input fact. HAT1 now supplies the exact

candidate construction and golden vectors, but no production caller may create that fact until

signed HAP1 installation, blind issuance, durable replay state, and specialist review are wired and

accepted together.



### Object class and priority authority



The raw `RLY1.priority` byte is never authority by itself. Version 1 of the selected policy requires

an exact match between the verifier-authorized class and priority:



| Authority | Allowed existing priority | HAT1 public class |

| --- | ---: | ---: |

| separate operator security control | `Control (0)` | none |

| recipient receipt | `Control (0)` | 1 |

| text | `DirectText (2)` | 2 |

| manifest | `Manifest (4)` | 3, disabled in pilot |

| bulk | `Bulk (5)` | 4, disabled in pilot |



`Safety (1)` and `RoomHistory (3)` are not admitted by the Venue Pilot profile. Security control

is reserved for a separately authorized protocol/administrative capability. An ordinary message

grant cannot become control or receipt traffic by changing one byte. A recipient requests a small

bounded class-1 blind ticket allowance; because ciphertext stays opaque, spending that allowance on

junk is possible but explicitly bounded and does not become a security-control grant.



## Deterministic admission order



For every offered envelope, the policy performs this order before storage or custody:



1. Apply the existing structural `RLY1` bounds and the per-session attempt ceiling.

2. Verify HAT1 and its venue, epoch, version, class-key status, and immutable

   envelope binding.

3. Require exact class/priority agreement and authorized lifetime/hop/copy/byte ceilings.

4. Check local ticket replay/tombstone state.

5. If the message ID already exists, return idempotent duplicate custody only when the canonical

   digest matches. A different digest is a conflict and never replaces the durable record.

6. Check per-session, per-ticket, and object-class object/byte quotas. Issuance-side participant

   allowance is checked before the issuer performs blind signing.

7. Check class reserves and total store limits without evicting an existing higher-priority record.

8. Commit the exact envelope and accounting crash-consistently, then and only then acknowledge

   custody or permit a sender copy-budget change.



Any failure returns no custody, changes no copy budget, stores no envelope, and consumes no normal

object/byte quota. Failed-proof, duplicate-attempt, and conflict counters have their own small

ceilings so those paths are not free work.



## Replay, conflict, and revocation semantics



- An exact duplicate with a valid current proof is idempotent: it may repeat the already-durable

  accepted ID but does not consume object/byte quota or create another record.

- Duplicate attempts remain bounded per session and ticket key. Crossing that bound causes

  local backoff without changing the durable record.

- Reusing a token key id plus nonce for a different immutable binding is a replay violation.

- A same-ID/different-digest offer is a conflict even when both proofs otherwise verify. The first

  durable record wins; the conflicting ticket is tombstoned, and repeated conflicts may back off

  only the current encrypted session. A node does not invent a stable origin tag.

- A higher operator policy epoch can revoke an issuer, grant family, or proof version. Revocation

  blocks new admission and duplicate custody acknowledgement. It does not delete existing custody,

  restore a sender copy, or invent recipient delivery.

- Epochs are explicit monotonic operator versions, not wall-clock expiry. Gate D separately governs

  envelope residence age and powered-off time.



## Quotas, congestion, and progress



The production numeric profile remains a live-integration decision. The policy must nevertheless

have explicit, independently bounded counters for:



- attempts, proof failures, duplicates, conflicts, new objects, and bytes per encrypted session;

- one immutable object and a byte ceiling per ticket;

- approved blind-signing requests per supervised issuer session/class/epoch, held only by the

  issuer and not transmitted to relay nodes;

- objects and bytes per coarse class; and

- total stored objects and bytes.



The active-session table, ticket/tombstone table, issuer allowance table, and every counter window

are themselves bounded. Reaching an accounting-table limit fails new admission closed; it does not

fall back to unmetered storage.



Store admission preserves declared reserves in this order:



```text

security control -> recipient receipts -> text -> manifest -> bulk

```



Lower classes cannot consume the unused reserve of a higher class. Gate C admission does not add

automatic eviction or cleanup. When no eligible capacity remains, it rejects the new offer. A

later eviction design must be separately crash-safe and cannot delete the last useful copy.



The BLE guard in Gate A continues to bound anonymous connection work. Gate C adds session/proof

accounting after the encrypted session. A radio address is never a quota key. Round-robin encounter

scheduling plus class reserves must give a valid receipt or text attempt a bounded opportunity

after finite invalid or bulk work; no claim is made against continuous RF jamming.



## Failure and recovery semantics



- Parser, proof, policy, quota, reserve, and storage failures are distinct coarse diagnostics.

- A failed durable write acknowledges nothing and advances no quota/copy state.

- Restart restores records, ticket tombstones, quota windows, and the active operator epoch

  consistently or fails admission closed. It never falls back to ungoverned public deposits.

- Counter corruption blocks new public admission but must not erase existing custody.

- Policy update or revocation during a session is checked again immediately before commit.

- Admission is not delivery. Only the recipient-authenticated E2E receipt can produce Delivered.



## Deterministic acceptance model



The standalone model and tests must prove at least:



1. valid admission and exact duplicate idempotence;

2. valid-looking junk and failed proof floods never consume store or normal quota;

3. forged control priority is rejected;

4. duplicate floods are bounded and charged only to duplicate/attempt accounting;

5. same-ID conflicts preserve the first durable bytes and tombstone the conflicting ticket;

6. rotating radio sessions cannot turn invalid proofs or one ticket into admission for different

   envelopes; supervised issuer allowance is a separate bounded service gate;

7. bulk pressure cannot consume receipt/text reserves;

8. wrong venue/epoch, revoked grants, and ticket replay fail closed;

9. every rejection leaves custody and copy-budget state unchanged; and

10. legitimate receipt and text work progresses after adversarial junk/bulk attempts.



The model uses small test-only limits so boundary behavior is visible. It is not production relay

code and its `verified` fixture flag is not a proof implementation.



## Consequences and next decision



This ADR makes the selected admission proof and its privacy limits reviewable before wire or

custody changes. It removes the proposed node-local origin tag from the selected pilot profile and

moves participant allowance to supervised blind issuance.



Gate C remains unimplemented in the live phone and ESP admission paths. The next substantial Gate C

implementation slice is signed HAP1 policy plus operator issuance and phone blinding, followed by a

versioned compound RLY1+HAT1 record, crash-safe ticket tombstones/accounting, and only then live

custody integration. Gate D monotonic expiry remains the next independent slice after Gate C.

