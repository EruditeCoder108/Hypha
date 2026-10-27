# Hypha deep audit — 25 October 2026

This document preserves the **pre-repair** audit. The subsequent implementation and
current results are recorded in [the custody repair checkpoint](CUSTODY_REPAIR_2026-10-25.md).
D01's replacement recovery, D03, D04, and D05 now have passing software regressions;
the remaining findings and physical gates stay open. Original outputs below retain
their historical values.

## Result and next build decision

Preserve the working BLE prototype. Before adding LoRa, close three demonstrated reliability defects: **ESP store recovery, custody acknowledgement reconciliation, and Android age preservation during forwarding commits**. They affect the existing network and would also affect a LoRa adapter.

This review went beyond document inspection. An audit harness compiled the actual ESP storage, codec, offer, and acknowledgement functions into a Windows executable and injected an interrupted handoff and a power cut at a filesystem operation. Six additional Android tests executed the real `RelayMeshStore` under Robolectric. The new invariant tests exposed defects despite the existing regression suite passing.

No production application/firmware code or installed device data was changed. Audit code is opt-in under `tools/audit/`. The custom PCB was kept outside the detailed audit, as requested. The selected ESP32-plus-LoRa development module remains the hardware direction.

Checkout reviewed: `30ef099`, branch `codex/horizontal-usb-pcb`. Existing untracked website, hardware references, images, and routing work were preserved.

## Evidence labels

- **Host reproduced:** actual firmware functions executed with an in-memory filesystem following the installed ESP32 core's API behavior. This does not test physical flash, BLE, NVS, watchdogs, or RF.
- **Android reproduced:** an invariant failed against the actual Kotlin SQLite store in a disposable Robolectric environment. This is not phone instrumentation.
- **Source verified:** established by tracing the implementation and, where necessary, primary platform documentation; the corresponding device scenario remains untested.
- **Historical:** a previous dated physical or automated result, not rerun in this audit.

The ESP harness extracts source verbatim and records hashes. Filesystem assumptions were checked against installed Arduino ESP32 core **3.3.11**: `File::name()` delegates to a basename, and filesystem operations require absolute paths beginning with `/`. SHA-256 uses Windows BCrypt. The filesystem double does not model torn flash sectors or wear.

## Priority findings

### D01 — P1: a power cut during ESP record replacement can strand custody

**Evidence: host reproduced; installed filesystem API verified.**

`replaceEnvelope()` writes a temporary record, renames the existing `.obj` to `.bak`, then publishes the new `.obj`. If power stops after the first rename, recovery should restore the old durable record or validate and complete the replacement.

`recoverStoreFiles()` instead collects `entry.name()` and passes those basenames directly to `LittleFS.remove()`, `exists()`, and `rename()`. The installed filesystem rejects those relative paths. The backup remains stranded and the record disappears from normal inventory.

```text
readableAfterRecovery=false
recordsInventoried=0
strandedBackupAndTempFiles=2
relativePathsRejected=3
```

Source: `hardware/esp32/hypha_fixed_node/hypha_fixed_node.ino:676–735`; installed core `libraries/FS/src/vfs_api.cpp:32–34,145–147,445–446`.

**Repair gate:** normalize every maintenance/recovery path into `/mesh/...`; validate candidate records before discarding the backup; test interruption points in store, replace, eviction, and recovery. Preserve an existing valid committed record when a replacement is incomplete or corrupt. Then repeat on hardware without clearing identity or unrelated records.

### D02 — P1: lost custody acknowledgements inflate forwarding allowances

**Evidence: host reproduced on ESP functions and Android reproduced.**

The receiver persists the transferred object before sending its accepted ID. The sender reduces its retained copy budget only after receiving that ID. If custody succeeds but the acknowledgement disappears, the receiver keeps its copies while the sender keeps its original allowance. A later inventory containing the same ID suppresses re-offering but does not reconcile that allowance.

```text
initialBudget=8
senderBudget=8
receiverBudget=4
combinedBudget=12
nextEncounterOffers=0
```

The acknowledged control case retained four plus four, as intended. The Android invariant failed with `expected:<8> but was:<12>`.

Source: `hypha_fixed_node.ino:1445–1531,1537–1597`; `hypha_node_peer.h:384–446`; Android `RelayMeshStore.kt:1307–1342,1460–1515`.

**Repair gate:** define a durable, idempotent handoff/reservation contract, including offer exposure, receiver commit, ACK loss, sender/receiver crash, retry, and cleanup. Do not simply decrement on any later advertised ID: an inventory claim is not custody proof. Account for anonymous phone encounters as well as authenticated node peers. Version any new wire contract explicitly and preserve legacy behavior through a deliberate compatibility path.

### D03 — P1: a late Android forwarding commit can reset age and revive an expired envelope

**Evidence: two Android invariant failures.**

`planForPeer()` snapshots a retained envelope. `commitForwarded()` later writes that old snapshot, resets stored residence age to zero, and installs the current elapsed-time anchor. It does not preserve time spent waiting for the acknowledgement or recheck effective expiry before that write.

Observed cases:

- After 60 seconds between offer and acknowledgement, the next offer had **age 0**, rather than at least 60,000 ms.
- An envelope with a 1,000 ms lifetime became offerable again after an acknowledgement arrived 2,000 ms later.

Source: `RelayMeshStore.kt:1324–1338,1473–1490,3645–3658`.

**Repair gate:** commit against current effective age and immutable payload, never a stale age snapshot; expired local custody must remain expired; preserve copy-budget and peer accounting atomically. Add delayed ACK, elapsed-clock reset, expiry-during-flight, duplicate-commit, and process-restart regressions.

### D04 — P2: corrupt ESP record lengths allocate before being bounded

**Evidence: host reproduced.**

`readRecord()` reads a two-byte stored length and constructs the payload vector before checking the 4,352-byte limit or exact file length. A corrupted header declared 65,535 bytes; the function eventually rejected it, but first made a **65,535-byte allocation**.

Source: `hypha_fixed_node.ino:476–487`.

This is a corruption/recovery and memory-pressure defect. No remote arbitrary-file modification or physical crash was demonstrated.

**Repair gate:** validate magic, length bounds, and exact file size before allocating; cover truncated headers, maximum lengths, corruption, and repeated invalid files.

### D05 — P2: ESP and Android disagree on immutable hop-limit conflicts

**Evidence: ESP host reproduction; Android rejection control passed.**

The ESP duplicate comparator skips the byte range containing age, **hop limit**, hops taken, and copy budget. Hop limit is immutable. Offering the same ID/ciphertext with hop limit changed from eight to nine is classified as an exact duplicate. Android explicitly compares hop limit and rejects that conflict.

Source: `hypha_fixed_node.ino:434–440`; `RelayMeshStore.kt:3168–3179`.

The stored ESP record was not overwritten. The defect is incorrect conflict classification and cross-implementation drift, not proof of plaintext forgery.

**Repair gate:** specify exactly which bytes may change during forwarding and run the same immutable-field mutation vectors against Rust, Android, and ESP parsers/stores.

### D06 — P2: fixed-node expiry and pressure policy remain incomplete

**Evidence: host reproduced; existing Gate D remains open.**

The ESP accepted and offered an envelope whose age exactly equalled its lifetime. More broadly, its stored records do not accumulate residence age while powered on. This confirms the existing expiry gap rather than implying Gate D was previously complete.

The pressure probe also showed a new control record evicting a text record with copy budget **one**. ADR 0007 describes replacement of a redundant copy, but the selector does not check redundancy. This does not establish that the globally last payload copy was lost; it establishes a mismatch between the documented policy and local selection rule.

Source: `hypha_fixed_node.ino:443–458,538–573,623–633,1445–1531`.

**Repair gate:** implement the declared monotonic expiry contract and powered-off-time policy. Separately choose and document whether control admission may evict a single-copy courier record, and test that policy. Keep receipt reserves, admission authorization, and expiry as distinct controls.

### D07 — P2: Android backup/recovery policy is unspecified for device-bound encrypted state

**Evidence: source and merged debug manifest inspected; platform default verified. No device restore was run.**

Neither manifest declares `allowBackup`, `fullBackupContent`, or `dataExtractionRules`. Android enables Auto Backup by default. Meanwhile, message and E2E state rely on non-exportable Android Keystore keys. The stores generate a storage key when its alias is absent and then attempt to decrypt existing rows; the inspected path has no complete recovery/export contract for a restored database without its original keys.

This leaves a concrete policy gap: which files may leave the device through backup or device transfer, and what happens when encrypted state returns without usable keys. It does not prove that a user's data was uploaded or exposed in plaintext.

Source: `AndroidManifest.xml:26–32`; `RelayMessageStore.kt:589–604`; `RelayMeshStore.kt:2931–2949` and its storage-key helper. [Android Auto Backup documentation](https://developer.android.com/identity/data/autobackup) confirms the default and manufacturer-specific device-transfer behavior.

**Repair gate:** explicitly choose cloud-backup and device-transfer rules for databases, identities, preferences, and payloads. Add missing-key/restore startup handling that preserves data and avoids pretending to recover identity. Device backup/restore and any deliberate encrypted export need their own acceptance tests.

### D08 — P2: Android inbound GATT lacks the ESP connection guard's equivalent

**Evidence: source verified; no phone resource-exhaustion test performed.**

The Android client has operation deadlines. The server-side transfer maps lack equivalent idle/authentication deadlines or aggregate connection/transfer budgets in the inspected path. `handleStartFrame()` allocates up to 65,000 bytes for a mesh transfer before checking an established session; `IncomingTransfer.startedAtMs` is recorded but not used to expire incoming transfers. Invalid secure payload processing closes the secure session, while framing errors generally return GATT failure without a connection-level resource policy.

Source: `RelayGattLink.kt:44–54,99–117,2317–2348,2374–2409,4315–4321`.

Individual frame/transfer lengths are bounded. This finding is the missing session-level availability policy, not a demonstrated unlimited-memory attack or measured phone denial of service.

**Repair gate:** add bounded inbound session/transfer lifetimes, aggregate and per-encounter budgets, cleanup, and fair recovery, preserving anonymous encounters and legitimate slow links. Test abandoned/repeated starts, malformed sequences, stalled identity exchange, and normal message progress afterward.

## Architecture and positive checks

### Live routing implementations are separate

Rust provides wire, E2E, message, and secure-session functionality through JNI. However, the Android JNI crate does not depend on `relay-core` or `relay-router`: live Android custody/routing is implemented in Kotlin, and ESP custody/routing separately in C++. Rust core/simulator results cannot establish that Android or ESP follows every routing invariant.

The age/hop-limit differences found here justify a shared cross-language conformance corpus. Extract a small stable custody/transport boundary; avoid a broad phone-protocol rewrite merely to begin LoRa.

### Delivery state remains tied to authenticated endpoint processing in the traced paths

The direct sender checks an encrypted recipient receipt against the message ID before committing Delivered. Mesh receipt application binds the outgoing message to its contact. HAR1 additionally binds object, plan, and recipient before its durable pending application fact. The Flutter mesh-sync handler reloads durable state rather than interpreting generic node-sync success as delivery.

Source reviewed: `RelayGattLink.kt:3936–3986`; `RelayMeshStore.kt:2240–2458`; Flutter `messenger_controller.dart:1535–1550`.

No false-Delivered reproduction was produced. This does not close broader interruption or device gates.

### Attachments retain useful safety boundaries

The inspected direct attachment path bounds imported size/chunk count, encrypts chunks, verifies digests and plaintext before READY, flushes temporary chunk files before publication, and exports verified content. FileProvider exposes one verified-export cache directory. The courier attachment store has separate quotas/reserves, recovery, monotonic age bookkeeping, and bounded tombstones.

These source checks preserve the earlier focused attachment milestone. They do not replace the incomplete repeated large-file, storage-pressure, and physical interruption matrix.

### Packaged native surface matches Kotlin declarations

All **35** declared native methods have corresponding exports in the checked-in library; no missing or extra binding was found. The binary is AArch64 and the only checked-in ABI is `arm64-v8a`.

Library SHA-256: `69f30e30ac7da22321da706c71e0549f821ae921229dca2eec10519e7cecfae3`.

This is a symbol-surface check, not proof of JNI argument layout, reproducible provenance, or phone execution. Keep an exact packaged-binary self-test in the physical release gate.

### LoRa and USB remain separate missing adapters

The implemented phone-to-node and node-to-node links are BLE. No live LoRa driver/transport or Android USB-host/serial implementation was found. A BLE-to-LoRa lab proof and a phone-powered USB dongle are separate software milestones. Keep the selected development board; its existing Meshtastic software does not supply Hypha's custody, encryption, and receipt contract.

## Verification summary

| Check | Result |
| --- | --- |
| ESP audit harness | Eight observations: two normal controls, four invariant violations, one pressure-policy mismatch, one existing expiry gap |
| Android opt-in probes | Six executed: three controls passed, three invariant tests failed as documented above |
| Rust formatting | `cargo fmt --all --check` passed |
| Strict Rust Clippy | Failed on five existing simulator lint diagnostics: function length, two checked-division suggestions, two missing `const fn` suggestions |
| Native export surface | 35 declared / 35 exported; no missing or extra methods |
| Normal Android suite after audit isolation | **117 tests, 24 suites, zero failures/errors/skips**; fresh XML dated 25 October; audit probe class absent |
| 24 October baseline | Historical here: 58 Rust / 117 Android / 38 Flutter / 31 operator-tool tests passed; Flutter analysis clean; ESP firmware compiled at 95% app partition |
| Physical checks this audit | None: no flash, install, profile clear, node purge, RF range test, or physical power-cut test |

Simulator lint failures are maintenance-gate failures, not evidence of broken cryptography. The failing Android probes are functional defects. This is not an all-green audit.

Instructions: [audit tools](../tools/audit/README.md). Selected raw outputs: evidence directory (private engineering archive). Generated binaries and translation units remain under ignored `artifacts/deep-audit-2026-10-25/`.

## Build sequence to follow

1. **Repair local custody durability and time first:** D01 and D03, with interruption tests. Fix D04/D05 alongside the bounded storage/validation changes. Re-run existing suites and compile legacy firmware before installation.
2. **Close the handoff contract:** design D02's durable acknowledgement/reservation behavior and cross-language fault-injection vectors. Implement across participating paths with an explicit compatibility plan. Do not count custody as delivery or reduce budgets on unproven inventory claims.
3. **Finish bounded-node behavior:** Gate D expiry, chosen pressure policy, Android inbound guards, and explicit backup/recovery policy. Continue Gate B physical acceptance and Gate C signed policy/issuance separately. Resolve the admission-policy `HAP1` naming collision identified in the first review.
4. **Add the narrow LoRa adapter:** two firmware profiles, common object/custody semantics, bounded authenticated fragmentation, fair nonblocking radio work, loss recovery, and airtime accounting. Keep ESP-only compatibility. Start with text and authentic recipient receipts.
5. **Prove two LoRa endpoints, then the mixed network:** isolate BLE so it cannot bypass LoRa; test forward delivery and return receipts independently; then disconnect/reboot/pressure/soak behavior. Add USB phone attachment as a separate bounded adapter if pursuing the dongle workflow.

Calls, groups, large LoRa media, the custom PCB, and large-fleet optimization remain outside this repair milestone. The first implementation package is **custody durability plus monotonic-age fixes**, with failing probes ready to use.
