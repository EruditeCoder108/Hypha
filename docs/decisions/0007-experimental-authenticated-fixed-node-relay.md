# ADR 0007: Experimental authenticated fixed-node relay

Date: 2026-08-11
Status: Controlled three-node BLE text/receipt chain physically proven; production gates pending

## Context

ADR 0006 proved one ESP32 as a bounded blind text/receipt courier. A fixed venue chain needs
nodes to exchange opaque courier records without depending on a person carrying a phone between
every encounter area. This extension must remain additive, preserve the proven phone mesh, and
must not turn node custody into recipient delivery.

ESP32-WROOM constraints remain 4 MB flash, no PSRAM, no trusted powered-off clock, and no
production protected identity/update path. This is therefore an experimental BLE relay, not a
shipping fixed-node design.

## Decision

### Compatibility and transport

- Reuse the additive ADR 0006 fixed-node BLE UUIDs and HNH1/HNS1 secure-session framing.
- Do not change any phone BLE UUID, phone Noise behavior, RMS2/RLY1 encoding, discovery,
  background service, or direct Wi-Fi behavior.
- Use BLE for this experiment. ESP-NOW, Wi-Fi, LoRa, files, media, and last-copy private routing
  remain outside scope.
- Automatic node-client work yields to admitted phone/server work.

### Node authentication

- Both nodes prove possession of their persistent P-256 identities inside the already encrypted,
  encounter-bound ephemeral ECDH/HKDF/AES-GCM session.
- Canonical encrypted HNA1/HNX1 messages bind the two node identities to the active session.
- Authentication, sequence, framing, or identity failure accepts no record and closes the session.
- Node trust is still experimental TOFU. Production deployment requires operator verification,
  inventory, rotation, revocation, replacement, and recovery.

### Inventory and copy conservation

- The client first sends its bounded inventory without offers.
- The server returns its planned offers and its authenticated inventory.
- The acknowledgement contains client offers planned against that server inventory.
- Completion returns only IDs actually accepted by the server.
- A retained copy budget changes only for an actually accepted new-peer offer.
- Records accepted earlier in the same exchange are added to effective peer inventory so neither
  side echoes them immediately.
- Repeated unchanged syncs must not change copy budgets or record counts.
- Last-copy records remain fail-closed because the fixed nodes cannot privately recognize the
  final endpoint.

### Scheduling and storage

- Control/receipt envelopes are offered first, but at most eight control envelopes occupy the
  first portion of a twelve-offer exchange. Ordinary text receives a bounded opportunity before
  remaining control work.
- The store is bounded to 192 records of at most 4,352 bytes, with 24 slots reserved for control/
  receipts. When genuinely full, control may atomically replace a lower-priority redundant copy.
- `NODE_SYNC` permits local controlled diagnosis. `STATUS` reports `node_relay`, `node_syncs`,
  and `node_failures` without exposing record contents or endpoint data.
- A node-to-node accepted ID is durable custody only. It cannot display Delivered or justify
  deleting every other copy.

## Cleanup consequence

The current fixed-node/phone exchange cannot safely distinguish an anonymous courier phone from
the final recipient. A node therefore does not delete a record merely because any phone accepts
it. Copies remain bounded by conserved copy budget, hop limit, lifetime, quotas, priority eviction,
and explicit maintenance. Immediate delivery-driven purge needs a separately authenticated
cleanup/final-recipient proof and a privacy review.

Android-to-Android private route-probe delivery is different: the sending courier knows the
authenticated peer recognized the private destination and durably accepted the full envelope.
That Android courier may delete its delivered copy. The original sender still retains its source
copy until the real recipient receipt returns.

## Verification state

Source and automated checks on 2026-08-11:

- firmware compiles with Arduino ESP32 core 3.3.11 at 1,237,499 bytes (about 94% flash) and
  41,980 bytes (about 12% static RAM);
- Android debug Kotlin compilation passes;
- the complete Android suite passes 100 tests in 21 suites;
- the complete Flutter suite passes 29 tests and Dart analysis reports no issues.

Physical two-node proof:

```text
A001 -> ESP1/COM10 -> ESP2/COM12 -> Samsung
Samsung -> ESP2/COM12 -> ESP1/COM10 -> A001 -> Delivered
```

ESP2 copied the record from ESP1 while both phones were off. Samsung later received it exactly
once. Samsung's encrypted receipt increased ESP2's durable store, then crossed to ESP1 after it
was reconnected, and A001 changed to Delivered only after authenticating that receipt.

Two defects found during proof are fixed:

1. repeated offers without authenticated peer inventory could drain the client's copy budget;
2. a large control history could indefinitely hide ordinary text.

The inventory-first/no-echo/actual-acceptance protocol fixes the first. Bounded control/text
fairness fixes the second. Repeated empty syncs then stabilized record counts with zero failures.

Physical three-node proof:

```text
A001 -> ESP32-1 -> ESP32-2 -> ESP32-3 -> Samsung
Samsung -> ESP32-3 -> ESP32-2 -> ESP32-1 -> A001 -> Delivered
```

Only the required adjacent pair was powered at each relay stage to make hop attribution
unambiguous. This was test isolation, not a protocol route restriction. Each forward receiving
node reached one durable record. Samsung's authenticated fixed-node logs reported
`received=1 delivered=1`, followed by `sent=1` when its encrypted receipt entered node custody.
Each return receiving node reached two records. A001 then reported `received=1 receiptsApplied=1`
and changed to Delivered; subsequent syncs applied no second receipt. Observed `node_failures`
remained zero, and one intermediate board retained its records through a normal reset in both
directions.

## Remaining acceptance gates

1. Repeat after one node power loss and under store/control pressure.
2. Measure latency, coverage, power behavior, duplicate rate, and multi-day stability.
3. Complete the Venue Pilot provisioning, protected identity, secure boot/update/recovery,
   revocation, health, enclosure/power, and field-maintenance gates before any production claim.
