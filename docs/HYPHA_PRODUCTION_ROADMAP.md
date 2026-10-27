# Hypha roadmap

This is the public execution summary for the first clean, noncommercial source release.
Historical device results describe tested setups and do not establish general production readiness.

## Present baseline

- Verified Android contacts, private direct text, replies and recipient-authenticated receipts.
- Phone store/carry/forward, with recorded three-phone delivery and receipt-return tests.
- Encrypted direct Wi-Fi attachments; focused phone-courier attachment proof, with the wider interruption matrix pending.
- Experimental ESP32 BLE text/receipt couriers, including recorded controlled node chains.
- Source repairs for ESP record recovery/validation and Android forwarding age.

## Next work

1. Fix lost-ACK custody reconciliation with durable, idempotent handoff state; preserve anonymous phones and explicit protocol compatibility.
2. Finish automatic ESP eviction recovery, live-time expiry, exact expiry boundaries, and redundancy-aware pressure policy.
3. Repeat interruption/restart/receipt tests on physical Android phones and BLE-only ESP nodes.
4. Add a separate LoRa text/receipt target for the selected development modules, then test mixed BLE/LoRa nodes.
5. Continue venue provisioning, protected identity/update, admission, inbound-resource, and Android backup/recovery gates.

LoRa messaging and phone USB attachment are not implemented in this release. Custom-board experiments and vendor reference bundles remain outside this initial public source snapshot.

## Evidence states

Use planned, in progress, source complete, physically passed, and production hardened as separate states. A compiler, simulator, host test or Robolectric pass does not establish physical-radio or phone recovery behavior.

See [the custody repair](CUSTODY_REPAIR_2026-10-25.md), [protocol invariants](../PROTOCOL_INVARIANTS.md), [threat model](../THREAT_MODEL.md), and [architecture decisions](decisions/).
