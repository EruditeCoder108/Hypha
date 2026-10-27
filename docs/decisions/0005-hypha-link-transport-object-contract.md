# ADR 0005: Minimal Hypha Link transport and object contract

- Status: accepted for additive Milestone 0 implementation
- Date: 2026-08-09

## Context

Hypha already has two physically proven paths:

- BLE discovery, verified Noise sessions, text, recipient receipts, mesh inventory, and
  opaque text couriering; and
- BLE-authorized Wi-Fi Direct sessions for encrypted, resumable direct attachments.

This decision adds the smallest common boundary needed for attachment couriering. It
does not replace either path, change compatibility identifiers, or move normal text to
Wi-Fi. The existing `RLY1` envelope, `RMS2` mesh exchange, BLE frame values, Wi-Fi
Direct protocol version, UUIDs, database names, package name, and 30-second warm-group
behavior remain unchanged.

## Decision

Hypha Link separates four things:

1. an encounter-scoped transport session;
2. an immutable encrypted object;
3. mutable courier custody and routing state; and
4. a recipient-authenticated outcome.

Transports move bounded opaque control records and chunks. They do not decide whether
an object is delivered, expose endpoint identity to a courier, or own product state.

## Minimal typed transport contract

The contract below is descriptive Kotlin-shaped pseudocode. Milestone 0 may introduce
these types around the existing classes without changing their current wire behavior.

```kotlin
interface HyphaTransport {
    val adapter: AdapterId
    fun availability(): TransportAvailability
    fun capabilities(): TransportCapabilities
    suspend fun open(encounter: EncounterHandle, request: SessionRequest): SessionHandle
    suspend fun sendControl(session: SessionHandle, frame: ControlFrame): SendResult
    suspend fun sendChunks(session: SessionHandle, request: ChunkSendRequest): ChunkSendResult
    suspend fun cancel(session: SessionHandle, transfer: TransferHandle)
    suspend fun disconnect(session: SessionHandle)
    val events: Flow<TransportEvent>
}
```

`EncounterHandle`, `SessionHandle`, and `TransferHandle` are random, process-local,
generation-scoped handles. They are not contact IDs, fingerprints, discovery tokens,
or wire routing values. A stale generation cannot emit success into a replacement
session.

The required typed values are:

- `TransportAvailability`: `unsupported`, `permissionMissing`, `radioOff`, `ready`,
  `busy(retryAfter)`, or `recovering`;
- `TransportCapabilities`: bounded control size, bounded chunk size, resumable support,
  setup-cost class, observed throughput range, metered/battery cost, and whether a
  verified hop session is required;
- `TransportEvent`: availability/capability change, session opened/closed, bounded
  control received, chunk progress, chunk durably committed, cancellation, and failure;
- `SendResult`: remote transport acceptance only;
- `ChunkSendResult`: the exact durably accepted chunk bitmap, never delivery.

Capability negotiation occurs inside an authenticated Noise or fast session and is
bound to that session. An unrecognized capability is ignored. An old peer continues
using the proven direct text, text mesh, and direct attachment paths.

### Existing adapter mapping

- `RelayGattLink` is the BLE control adapter. Its current authenticated text, contact,
  Wi-Fi-upgrade, and `RMS2` mesh transfers map to bounded control frames. Existing GATT
  fragmentation, 23-byte ATT MTU support, priorities, and receipts are unchanged.
- `RelayWifiDirect` is the fast chunk adapter. Its existing BLE-issued, single-use
  `RelayWifiUpgradeAuthorization`, PSK-bound fast session, recovery generation, resume,
  progress, cancellation, and 30-second warm reuse remain the implementation.
- `RelayBleDiscovery`, background service ownership, reboot recovery, and the current
  encounter scheduler remain lifecycle owners. The new contract does not start Wi-Fi
  speculatively.
- Flutter receives object/product state. It does not receive sockets, P2P groups,
  characteristics, content keys, or transport-specific delivery claims.

Scheduler order is fixed:

```text
security control + recipient receipts + text + text mesh
    -> attachment manifest/control
    -> attachment chunks
```

## Object model

Endpoint code uses typed object classes: text, recipient receipt, attachment manifest,
attachment chunk, audio manifest, audio chunk, contact update, and future group control.
The exact application type remains inside recipient-authenticated ciphertext. Couriers
see only the coarse scheduling/storage class needed to apply consent and quota:
`control`, `message`, `manifest`, or `bulk`.

Every object has one random immutable 128-bit `object_id`. An attachment and all its
chunks use the same attachment `object_id`; a chunk is addressed by
`(object_id, chunk_index)`. IDs are never derived from a filename, content hash,
contact, conversation, key, timestamp, or endpoint identity.

The existing `RLY1` `Envelope` carries the recipient-encrypted private attachment
manifest with `Priority::Manifest`. It retains the existing opaque destination hint,
monotonic age, lifetime, hop limit, copy budget, and recipient-only ciphertext. Mutable
age/hop/copy state is not part of attachment content identity.

### Recipient-private attachment manifest

Only sender and recipient parse this signed, ratcheted content:

```text
version + attachment_kind + zero reserved bits
object_id[16]
courier_plan_sha256[32]
content_key[32]
plaintext_bytes:u64
plaintext_sha256[32]
mime_type: bounded ASCII
file_name: bounded safe UTF-8
```

The content key, filename, MIME type, kind, plaintext size, plaintext digest, sender,
recipient, conversation, and previews never appear in courier records. The signed
recipient payload binds both endpoint signing identities, the object ID, sequence, and
the SHA-256 digest of the canonical courier plan. The recipient rejects a mismatch
before accepting any file as complete.

Chunk nonces are public cryptographic parameters, not keys. They travel only in the
opaque chunk record. Chunk ciphertext remains AES-256-GCM from the proven attachment
store. The existing direct manifest remains supported for direct peers; it is not sent
to couriers because it contains private metadata and the content key.

### Courier attachment plan

The canonical courier-readable plan contains only:

```text
magic + version + zero reserved bits
chunk_count:u16
object_id[16]
cancellation_commitment[32]
total_ciphertext_bytes:u64
for each sequential chunk: ciphertext_bytes:u32 + ciphertext_sha256[32]
```

The plan contains no stable endpoint identity or human metadata. The recipient-private
manifest authenticates its canonical digest, so a courier cannot substitute the plan.

For the BLE custody control slice, the RLY1 manifest and HAP1 plan travel together in a
bounded canonical `HAO1` offer. Its capability bytes advertise object-plan version 1 and
custody-bitmap version 1 only after Noise encryption; chunk-transport capability remains
zero until a real fast opaque-chunk adapter is integrated. It has exact manifest/plan
lengths, zero reserved bits, a 32,768-byte plaintext ceiling, and contains no file bytes.

### Opaque courier chunk record

```text
magic + version + zero reserved bits
chunk_index:u16
object_id[16]
nonce[12]
ciphertext_bytes:u32
ciphertext_sha256[32]
ciphertext[ciphertext_bytes]
```

A receiving hop validates version, exact length, index, descriptor, SHA-256, quota,
and cancellation/expiry state before a durable commit. It acknowledges the bit only
after the chunk file and database state are crash-consistent.

## Routing, custody, and delivery

Attachment defaults for the first courier proof are a seven-day lifetime, hop limit 16,
and copy budget 2. The existing protocol maxima remain 30 days, 64 copies, and the
bounded hop field. A node never increases a budget; binary spray conserves it exactly.
Direct-recipient transfer may use the final copy.

A chunk bitmap has exactly `ceil(chunk_count / 8)` bytes. Bit `i` is
`1 << (i % 8)` in byte `i / 8`; unused high bits in the final byte must be zero.

A custody acknowledgement contains the object ID, canonical plan digest, a durable-plan
flag, and the exact durable chunk bitmap. It is authenticated by the current hop session.
It permits resumption and copy-budget accounting. It must never update the sender UI to
Delivered.

A recipient receipt contains the object ID and canonical plan digest. It is signed and
ratcheted by the verified recipient, carried as an opaque `Priority::Control` envelope,
and may return through the existing BLE text mesh. The recipient creates it only after
all chunks authenticate, the plaintext digest verifies, and the incoming attachment and
duplicate marker are durable. Only this receipt means Delivered.

## State transitions

```text
queued -> offered -> partially custodied -> fully custodied -> recipient received
   |          |               |
   +----------+---------------+-> cancelled
   +----------+---------------+-> expired
```

Custody and recipient receipt are independent monotonic facts. Retry never clears a
durable chunk bit. Duplicate chunks do not increase stored bytes. A same
`(object_id, index)` with different descriptor or bytes fails closed.

User cancellation is terminal on the sender: no new offers or retries may start, and
the sender keeps a bounded tombstone. The plan carries `SHA-256(cancel_secret)`; an
exact 32-byte preimage can authorize deletion of that object at couriers without
revealing an endpoint. A cancellation is not a delivery receipt and cannot be undone.
Until cancellation propagation is implemented, remote copies expire or are removed by
an authenticated recipient receipt; the UI must not promise remote deletion.

Pause and transport failure are retryable states, not cancellation.

## Strict version-1 limits

| Item | Limit |
|---|---:|
| Plaintext file | 96 MiB |
| Plaintext image | 25 MiB |
| Plaintext chunk | 192 KiB |
| GCM tag | 16 bytes per chunk |
| Chunks per attachment | 512 |
| Courier plan | 18,496 bytes |
| One chunk ciphertext | 196,624 bytes |
| Filename | 128 UTF-8 bytes |
| MIME type | 96 lowercase ASCII bytes |
| Chunk bitmap | 64 bytes |
| Active courier attachment plans | 64 |
| Inventory IDs per exchange | 512 |
| Engineering courier attachment quota | 128 MiB total |
| Attachment lifetime | 7 days default, 30 days maximum |
| Initial file copy budget | 2 default, 64 protocol maximum |

All counts and lengths are checked before allocation. Integers are unsigned big-endian.
Formats have distinct four-byte magic values, version 1, zero reserved fields, one
canonical encoding, and exact-length decoding. Unknown versions, set reserved bits,
integer overflow, trailing bytes, duplicate indices, non-canonical bitmaps, and hashes
or sizes that disagree with the plan are rejected.

The 128 MiB quota is a first-proof engineering default, not permission to consume free
space. A courier may configure less. Admission checks configured quota and platform
low-storage state before reserving the exact requested chunk bytes. At least 32 MiB of
device free space remains outside Hypha's reservation during the engineering proof.

## Persistence, quotas, and cleanup

- Sender: persist recipient-encrypted manifest, plan, chunk files, ratchet advance, and
  queued timeline state before making the object offerable.
- Courier: persist plan/chunk and custody state in one crash-consistent commit before
  setting a custody bit.
- Recipient: persist ratchet advance, verified incoming attachment, duplicate marker,
  and timeline state before creating the recipient receipt.
- On startup: remove unreferenced temporary files, verify stored lengths/digests lazily
  before offering, restore bitmaps, and expire by accumulated monotonic residence time.
- On recipient receipt: sender releases outgoing payload chunks after timeline state is
  Delivered; couriers remove matching plan/chunks when the authenticated receipt is
  learned or according to bounded gradual cleanup.
- On cancellation: sender removes eligible payload chunks after the tombstone is durable;
  couriers remove only after a valid cancellation preimage, recipient receipt, expiry,
  or local quota eviction.
- On pressure: expired/cancelled/receipt-confirmed bulk data first, then lowest-value
  partial untrusted bulk. Control, receipts, and text are never evicted for attachment
  chunks.

## Compatibility and rollout

The new formats are additive. No existing on-wire value is reinterpreted. Support is
advertised only inside an authenticated session as separate object-plan, custody-bitmap,
and courier-chunk capability versions. If either peer lacks them, Hypha continues with
the proven text mesh and direct attachment behavior and does not attempt file couriering.

The initial GATT mapping adds attachment-plan start value `0x1A` and attachment-custody
response value `0x09` on the existing characteristic. Existing frame and response values,
UUIDs, fragmentation, RMS2, and direct Wi-Fi authorization remain unchanged. HAO1 is
Noise-encrypted; HCU1 is returned Noise-encrypted only after durable courier admission.

The sender-to-courier chunk slice is additive: authenticated GATT start value `0x1B`
carries canonical `HWF1`, which binds the object ID and plan digest to the existing RWUO
Wi-Fi capability. Fast-session payload kind 3 carries only HCU1 resume state and canonical
HAC1 records framed by bounded `HXS1`/`HXD1`. Wi-Fi begins only for real HCU1 missing bits,
and final HCU1 is emitted only after durable chunk commits. None of these values can create
HAR1 or recipient delivery.

The courier-to-recipient slice adds authenticated GATT start value `0x1C` and fast-session
payload kind 4 without changing existing values. The responder authorizes only a complete
durable HAP1/HAC1 set matching the recipient-private plan digest. `HXP1` requests one random
object, `HRD1` carries canonical HAP1 plus public GCM nonces, and `HRQ1` carries only the
recipient's durable chunk bitmap for exact resume. HAM1 plaintext, content keys, names,
MIME types, digests of plaintext, contacts, and conversations never travel to the courier.
Fast-hop completion remains distinct from HAR1.

HAR1 return/application remains additive. After the recipient attachment database has
durably reached `READY`, the endpoint ratchets and stores HAR1 as an ordinary
control-priority RLY1 envelope for RMS2 return. The sender first commits the authenticated
HAR1 ratchet state and exact object/plan/recipient binding, then its attachment database may
record `Delivered` and release outgoing payload chunks. A crash between those databases
leaves a durable pending application fact and retries without creating delivery early.

Opaque HAR1 cannot itself tell a blind courier which attachment to erase. After the sender
authenticates HAR1 and records `Delivered`, additive GATT start value `0x1D` carries canonical
HCL1 inside the existing Noise/device-proof session. HCL1 contains only object ID, plan
digest, and the 32-byte preimage of HAP1's existing cancellation commitment. The courier
deletes only after the object/plan and preimage match, then returns exact encrypted HCA1 as
response `0x0A`. This cleanup control runs after text/receipts/RMS2, is restart-safe at the
sender, and cannot create HAR1 or Delivered by itself.

The RLY1 carried inside HAO1 is admitted to the ordinary RMS2 store after durable courier
plan commit and before HCU1 is returned. Active courier plans also restore their opaque RLY1
to RMS2 on startup. Thus reboot or an update between custody and recipient encounter cannot
strand HAP1/HAC1 without its recipient-private routing envelope.

Recipient E2E integration reuses the signed, ratcheted `RSP1` version-1 container with
previously unused payload types 3 (HAM1 manifest) and 4 (HAR1 receipt). Existing text and
text-receipt types 1 and 2 are unchanged. The Android JNI/Kotlin bridge is additive and
accepts a typed attachment manifest as either the first or a later ratcheted payload.
Radio integration follows only after golden vectors and strict rejection tests pass.

## Required tests

- deterministic golden bytes and exact round trips for private manifest, courier plan,
  courier chunk, custody bitmap, and recipient receipt;
- unknown version, reserved bits, truncation, trailing data, overflow, zero/oversized
  fields, unsafe name/MIME, and maximum-size boundaries;
- plan digest and chunk digest mismatch rejection;
- duplicate chunk idempotence and same-ID mismatch rejection;
- canonical bitmap and missing-chunk ordering;
- custody never produces recipient delivery;
- recipient receipt must match both object ID and plan digest;
- HAR1 creation must require an exact durable recipient `READY` object and commit the
  ratchet, RMS2 envelope, generated marker, and pending-manifest removal atomically;
- sender HAR1 application must bind recipient, object, and plan before `Delivered`, survive
  a cross-database crash, and keep cleanup pending until exact HCA1;
- HCL1/HCA1 canonical decoding, wrong-preimage rejection, duplicate cleanup idempotence,
  and text/receipt/RMS2 scheduling priority;
- quota admission, low-storage refusal, expiry, cancellation, and cleanup ordering;
- existing `relay-wire`, `relay-message`, `relay-core`, E2E, BLE, and direct Wi-Fi tests
  remain unchanged and pass before integration.

## Consequences

This decision gives the proven transports one small common vocabulary and fixes the
privacy boundary for multi-hop files. It does not yet make files multi-hop. Deterministic
records, durable courier storage, recipient E2E state, and the BLE plan/custody source path
now exist. Durable sender HAM1/HAP1 preparation and protected HCU1 resume knowledge are
also wired through the normal attachment action without changing direct Wi-Fi behavior.
The physical control-only and sender-to-courier missing-HAC1 Wi-Fi proofs now pass.
Courier-to-recipient missing-chunk transfer, recipient materialization, complete verification,
and opening the exact file now physically pass for the preserved 11-chunk object. The first
Wi-Fi Direct connect failed and the bounded retry recovered without a resend. The proof also
found and fixed a scheduler starvation: a mesh hint that has already produced an authenticated
unchanged empty exchange may yield to attachment control, while eligible text/receipt/mesh,
in-flight exchanges, and failed-link backoff remain ahead of it. HAR1 return through the
existing mesh and sender delivery/cleanup follow this gate.
