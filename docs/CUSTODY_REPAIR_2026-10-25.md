# Custody reliability repair — 25 October 2026

The first repair batch is **source complete** on `codex/custody-reliability`.
Checkpoint `b7e5c94` preserves the preceding website, PCB references, roadmap, and
deep-audit work. The working ESP-only BLE build remains the target for these repairs.
The chosen ESP32-plus-LoRa development modules are the later radio target; ordering
or manufacturing the custom PCB is not a prerequisite.

This batch repairs demonstrated recovery, age, allocation, and validation defects.
It does not close the lost-acknowledgement protocol defect or establish physical
acceptance. [The original audit](DEEP_AUDIT_2026-10-25.md) and its evidence remain
unchanged as a baseline.

## What changed

| Audit finding | Current implementation | Remaining gate |
| --- | --- | --- |
| D01: ESP backup recovery | Validates object IDs, constructs absolute `/mesh/` paths, validates final/backup records, restores the valid backup before removing temporary files, and checks recovery results | Physical power cuts; automatic full-store eviction recovery |
| D03: Android age reset at commit | Commits from the current stored envelope and monotonic residence age; preserves age accumulated during the ACK wait and maintenance; rejects expired in-flight work; repeated commits are idempotent | Phone lifecycle/interop acceptance |
| D04: ESP allocation before bounds | Checks header, payload limit, and exact file length before allocating the payload | Physical corrupt-storage testing |
| D05: ESP immutable-field mismatch | Includes immutable `hopLimit` in duplicate comparison while allowing mutable age, hops taken, and copy budget | Mixed Android/ESP acceptance |

Android keeps the original record creation time when committing a retained copy.
These changes do not alter the database schema, service UUIDs, wire formats, or
recipient-authenticated delivery semantics.

Recovery preserves an invalid final/backup pair for diagnosis and leaves custody
unavailable. An interrupted pressure eviction can restore the old victim while
retaining a newly published record, leaving 193 records against the 192-record
quota. This batch preserves both and blocks new custody and offers, including the
outbound node-client path. A durable eviction journal is still needed to recover
automatically within quota. Preservation with unavailable custody is a deliberate
bounded failure response, not a claim of complete eviction recovery.

## Validation actually run

| Check | Result | Scope |
| --- | --- | --- |
| Normal Android unit suite | 124 tests, 24 suites; zero failures, errors, or skips | Actual Kotlin/SQLite implementation under Robolectric; excludes the opt-in audit class |
| Focused Android reliability suite | 13 tests passed, including seven new forwarding regressions | Delayed/late ACKs, repeated commit, concurrent maintenance, reopen, elapsed-clock reset, and immutable plan conflict |
| ESP host harness | 12 cases: seven repaired regressions, two controls, three labelled open observations | Verbatim extracted firmware functions; real SHA-256; simulated filesystem operations |
| Replacement interruptions | Nine mutation checkpoints passed | Recovery returns a valid original or replacement record; repeated recovery is stable |
| Recovery interruptions | Three mutation checkpoints passed | A second interrupted recovery still recovers the valid record |
| Opt-in Android audit | Four tests: three passed, one failed on D02 | The open lost-ACK defect remains visible; the repaired age probes moved into the normal suite |
| ESP32 firmware compile | Passed for `esp32:esp32:esp32`, Arduino core 3.3.11 | 1,247,555 bytes program storage (95%); 42,532 bytes static RAM (12%) |

Commands and prerequisites are in [the audit tool instructions](../tools/audit/README.md).
Raw results, source hashes, Android suite hashes, and the firmware build manifest are in
[the repair evidence](../evidence/custody-repair-2026-10-25/README.md).
Generated executables and firmware binaries remain local under ignored `artifacts/`.

The host filesystem models basename and absolute-path API semantics and injects
interruptions after logical mutations. It does not model torn flash sectors, wear,
NVS, radio traffic, watchdogs, or real power cuts. Robolectric is not a phone test.
No phone was installed/reset and no board was flashed by this batch. Historical
physical results retain their original dates.

## Next actionable build slice

1. Write the custody handoff decision and state machine for D02 before changing the
   exchange. Define a durable sender reservation before transfer, receiver deduplication,
   stable transfer identifiers, acknowledgement replay, restart recovery, and bounded
   reservation cleanup. A receiver's inventory claim alone must not debit sender custody.
   Preserve anonymous phones, authenticated node identities, and explicit compatibility
   with the existing RMS2/BLE path; do not silently add a persistent phone identifier.
2. Turn the existing lost-ACK reproductions into acceptance assertions across Android and
   ESP. Cover ACK loss after receiver persistence, sender/receiver restart at each durable
   transition, repeated offers/ACKs, changed sessions/peer tokens, and mixed-version peers.
   The starting allowance of eight must never become twelve; uncertain reservations must
   neither become new forwarding credit nor silently discard acknowledged custody.
3. Add a durable ESP eviction transaction journal, then close live-time expiry, exact-boundary
   rejection, and the documented redundancy requirement for pressure victims. Extend the
   host interruption tests before the physical power-cut matrix.
4. Repeat the preserved BLE text/receipt baseline on phones and ESP-only nodes, with
   interruptions and reconnects, without clearing identity or unrelated records. Use
   disposable test messages and preserve the working firmware image for recovery.
5. Bring up LoRa as a separate firmware target: radio send/receive first, bounded text/receipt
   adapter next, mixed BLE-only/LoRa nodes after custody invariants pass. BLE remains the
   existing phone link; phone USB attachment still requires its own adapter.

Android backup/Keystore recovery policy, inbound GATT resource bounds, and the wider
Venue Pilot security and physical gates remain open. The [production roadmap](HYPHA_PRODUCTION_ROADMAP.md)
keeps the broader sequence; these fixes do not promote the prototype to production.
