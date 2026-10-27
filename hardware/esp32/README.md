# Hypha ESP32 fixed node

This folder contains two sketches:

- `hypha_node_diagnostics`: serial-only durable opaque-store bring-up.
- `hypha_fixed_node`: the first authenticated BLE fixed-courier prototype.

`hypha_fixed_node/hypha_node_peer.h` adds the mutually authenticated experimental BLE
fixed-node relay described by ADR 0007.

`hypha_fixed_node/hypha_ble_session_guard.h` adds the deterministic server connection policy
described by ADR 0009 Gate A.

`hypha_fixed_node/hypha_venue_inventory.h` adds the signed HVI1 Lab/Managed Venue decision
described by ADR 0010 Gate B.

## Current fixed-node scope

Target: ESP32-WROOM, 4 MB flash, no PSRAM, Arduino ESP32 core 3.3.11.

The fixed node:

- advertises a rotating-on-boot 8-byte encounter token;
- proves possession of a persistent P-256 node identity;
- derives an ephemeral ECDH session and carries records with directional AES-256-GCM;
- receives the existing deterministic RMS2 exchange and stores only validated RLY1 opaque
  envelopes;
- commits an envelope to LittleFS before returning its accepted ID;
- deduplicates by 16-byte object ID and rejects a conflicting opaque payload;
- uses a bounded 192-record, 4,352-byte-per-record store, with 24 slots reserved for
  receipt/control traffic;
- offers receipt/control envelopes before ordinary text and may replace a lower-priority
  courier copy when the full store must admit control traffic; the redundancy check
  promised by the storage policy remains an open audit finding;
- conserves multi-copy routing budgets when the custody acknowledgement arrives;
  durable reconciliation after a lost acknowledgement remains an open audit finding;
- mutually authenticates another fixed node inside the encrypted encounter session and exchanges
  bounded inventory-first RMS2 records over BLE;
- commits retained copy-budget changes only for records actually accepted by a new node peer;
- gives control/receipts priority while reserving a bounded opportunity for ordinary text;
- disconnects stalled, silent, over-budget, overlong, or malformed GATT clients under bounded
  monotonic connection rules; a bounded per-radio availability table exists only in volatile RAM
  and its addresses are never logged, persisted, exported, or treated as identity;
- keeps the proven compatibility path in clearly labelled Lab mode, while optional Managed Venue
  mode rejects unknown, revoked, replaced, rolled-back, or unavailable-policy node identities
  before node inventory or custody;
- survives reboot without automatically formatting an initialized store;
- reconstructs absolute recovery paths from validated object IDs and validates final/backup
  records before discarding a backup; an unrecoverable backup or over-quota recovery keeps
  custody unavailable, with both server and node-client paths blocked;
- never enables Wi-Fi and never receives plaintext, contact keys, filenames, or conversations.

The existing phone-to-phone BLE service and characteristic UUIDs are unchanged. The additive
fixed-node UUIDs are:

- service: `7e57d014-2b97-4d12-9f65-53a4c7a36c81`
- transfer: `7e57d015-2b97-4d12-9f65-53a4c7a36c81`

## Important experimental limits

- Only multi-copy text/receipt courier flow is enabled. Last-copy private route probes stay on
  the phone and fail closed.
- Files, attachment chunks, ESP-NOW, Wi-Fi node links, and LoRa are not implemented. The current
  node-to-node experiment uses the same additive fixed-node BLE service only.
- The phone is anonymous to the node. Lab mode accepts any node identity that proves possession.
  Managed Venue mode uses an offline operator-signed HVI1 list; its physical provisioning and
  revocation gate has not yet been reported passed.
- The node private identity is in NVS. Production hardware still needs secure boot, flash
  encryption or a secure element, signed updates, and recovery policy.
- HVI1 approval does not authorize an opaque envelope, enforce lifetime expiry, protect the serial
  maintenance path, or protect the node key/firmware. Those remain separate gates.
- Lifetime aging while powered on and rejection at the exact expiry boundary remain open.
  Aging while powered off also needs an explicit policy because this board has no trusted
  clock. This prototype must not be described as production expiry enforcement.
- The 25 October recovery/validation repair is source complete with host regressions and a
  firmware compile; physical power-cut acceptance is pending. Interrupted full-store eviction
  can preserve 193 records and block custody; automatic recovery needs a transaction journal.
  See [the repair checkpoint](../../docs/CUSTODY_REPAIR_2026-10-25.md).
- Custody/accepted IDs never mean Delivered. Only recipient E2E processing can create a delivery
  receipt, and only that receipt can change sender status to Delivered.

## Venue Pilot roadmap relation

The focused Android HAR1 attachment receipt slice is closed, so this text/receipt courier is now
a primary hardening track for the supervised Hypha Venue Pilot. The present board and firmware are
still experimental. Promotion requires verified operator provisioning, protected identity, secure
boot and signed update/recovery, explicitly governed bounded storage, revocation/replacement,
power-loss and multi-day field tests, enclosure/power review, and measured coverage.

ADR 0009 now separates the five audit findings into staged gates. Gate A's source bounds encrypted
session confirmation to 15 seconds, authenticated idle to 65 seconds, total connection life to five
minutes, one hello, eight transfers, 64 KiB of declared client payload, 8,192 writes, and 8,192
reads per connection. A volatile 16-entry table limits one radio to eight connection starts per 60
seconds. Excess starts from that radio do not consume the separate aggregate allowance of 96
connections per 60 seconds or cause global backoff. The same anonymous aggregate window caps 512
KiB declared payload and 65,536 reads/writes. Other guard failures can still produce the bounded
five-second advertising backoff. Compile-time deterministic checks and the firmware compile pass.
The normal phone text/receipt path and isolation from one noisy remembered client pass physically;
the remaining hostile-client and node recovery matrix is still pending.

One node covers only its measured BLE encounter area. ADR 0007 now provides physically proven
two-node and controlled three-node authenticated BLE text/receipt chains, but production
provisioning, field topology, power, latency, and coverage are still pending. Venue Pilot
prioritization does not authorize files, media, Wi-Fi, ESP-NOW, or LoRa on the node.

## Compile and flash

Use board `ESP32 Dev Module` (`esp32:esp32:esp32`). The source currently occupies about 95% of
the default application partition and 12% of static RAM (1,247,555 bytes flash and 42,532 bytes
static RAM in the 25 October 2026 verified compile, core 3.3.11). This build was not flashed.

```powershell
& 'C:\Program Files\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe' compile --fqbn esp32:esp32:esp32 --warnings all --output-dir 'artifacts\esp32-build' 'hardware\esp32\hypha_fixed_node'

# Run from the repository root. Confirm the actual board port before an intentional upload.
# & 'C:\Program Files\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe' upload --fqbn esp32:esp32:esp32 --port COM10 'hardware\esp32\hypha_fixed_node'
```

Gate C has a compile-time-only RSA-PSS/SHA-384 feasibility probe. Never upload the probe as
production firmware:

```powershell
& 'D:\ArduinoIDE\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe' compile --fqbn esp32:esp32:esp32 --warnings all --build-property 'compiler.cpp.extra_flags=-DHYPHA_GATE_C_CRYPTO_PROBE=1' 'C:\Users\<user>\Downloads\SmartHome\hardware\esp32\hypha_fixed_node'
```

On 2026-08-15, before the independent Gate A radio-isolation change, the probe build was 1,265,931
bytes flash and 42,268 bytes static RAM: +20,372 flash and +56 static RAM over its then-current
ordinary build. The probe verifies the checked-in blind-issued HAT1 token only when the explicit
macro is enabled and prints parse/hash/verify codes plus elapsed microseconds at boot. A fresh
comparable probe build and on-board runtime success, timing, stack, and watchdog evidence remain
pending and cannot be inferred from that compilation.

Serial diagnostics use 115200 baud. `HELP` lists `PING`, `STATUS`, `IDENTITY`, `VENUE_STATUS`,
`VENUE_BEGIN`, `VENUE_CHUNK`, `VENUE_COMMIT`, `VENUE_ABORT`, the confirmed `VENUE_RESET`,
`NODE_SYNC`, `CLEAR_RECORDS`, and `REBOOT`. `CLEAR_RECORDS` deletes only durable courier records and preserves
the firmware and node identity. `STATUS` includes bounded node-relay sync/failure counters. The
commands never print the BLE MAC, stored RLY1 bytes, or node private key.

`STATUS` also reports `ble_guard`, aggregate guard disconnect/backoff counts, and the last coarse
guard reason. A forced disconnect prints only the coarse reason. Neither output records a client
address, endpoint identity, contact, conversation, token, or envelope content.

## Managed Venue setup (source ready, physical gate pending)

This is optional. If no HVI1 file is installed, the existing boards and app remain in Lab mode.

1. On each ESP32, run `IDENTITY`. Copy the `NODE_IDENTITY_P256` public value. It is safe to share
   with the venue operator; the private key is never printed.
2. Create `nodes.json` with one row per node, for example:

```json
[
  {"publicKey":"04...130 hex characters...","role":"courier","status":"active"}
]
```

3. Set `HYPHA_VENUE_KEY_PASSPHRASE`, then use `tools/hypha_venue_operator.mjs` to create one
   encrypted offline P-256 authority and an HVI1 inventory. Keep the private PEM offline.

```powershell
$env:HYPHA_VENUE_KEY_PASSPHRASE = Read-Host 'Venue key passphrase' -MaskInput
node .\tools\hypha_venue_operator.mjs create-authority --private venue-private.pem --public venue-public.pem
$venueId = node .\tools\hypha_venue_operator.mjs new-venue-id
node .\tools\hypha_venue_operator.mjs create-inventory --private venue-private.pem --venue-id $venueId --version 1 --nodes nodes.json --out venue-v1.hvi
node .\tools\hypha_venue_operator.mjs serial-script --inventory venue-v1.hvi --out venue-v1-serial.txt
```
4. In Hypha, open **Settings > Advanced settings > Venue ESP approval** and choose the HVI1 file.
5. Generate bounded serial commands with the tool's `serial-script` command and send that script
   to every active board at 115200 baud. `VENUE_COMMIT_OK` and `VENUE_STATUS mode=managed
   policy=ready` confirm only installation, not the physical relay gate.
6. For revocation or replacement, create a higher inventory version. Mark the old public key
   `revoked` or `replaced`, add the new key as `active`, then update phones and active boards.

HVI1 updates keep the same venue ID and authority and must increase the version. A corrupt policy
stays Managed/unavailable and blocks relay rather than falling back to Lab. The separately
confirmed reset returns only venue trust to Lab; it preserves courier records and node identity.

## BLE connection-guard physical gate (partially passed)

On 2026-08-15 the normal Lab-mode phone flow and the one-noisy-radio isolation case passed on COM10.
A001 obtained custody in about 4–5 seconds while one stale Windows client caused 414 rejected
connections; Samsung received in about 2 seconds and A001 quickly applied the genuine recipient
receipt. Final status showed zero aggregate guard backoffs. Windows had remembered the board's old
`SmartPad` pairing; forgetting it stopped the reconnect loop while laptop Bluetooth stayed enabled.
Reflashing changes firmware and advertised behavior but normally preserves the physical Bluetooth
controller address, so stale host pairings should be removed during test-bench repurposing.

Do not mark all of Gate A passed. The user must still prove that a silent connection and stalled
handshake disconnect at the declared bound, malformed traffic disconnects without a crash,
rotating-address/aggregate flooding causes only bounded backoff, normal sync recovers afterward,
and authenticated node-to-node sync still completes under contention.

The command was physically verified on 2026-08-10: seven records were removed and the following
`STATUS` reported `records=0`, `storage=ready`, and `identity=ready`.

## Physical text/receipt test

This full test passed on 2026-08-10 with A001 as sender and Samsung as recipient. The message was
delivered exactly once through the ESP32, and the recipient-authenticated receipt later returned
through the ESP32 and changed A001 from Waiting to Delivered.

1. Keep the ESP32 powered from the laptop or a USB power source.
2. Run the current Hypha source on the sending phone and the recipient phone.
3. Ensure the sender and recipient are already verified Hypha contacts.
4. Turn off or move the recipient out of BLE range.
5. Send a short mesh text from the sender, then bring only the sender near the ESP32.
6. Wait for a `fixed_node_sync_completed` event in Android logs.
7. Move the sender away and bring only the recipient near the ESP32.
8. Confirm the recipient receives and decrypts the text.
9. Keep the recipient near the node until another `fixed_node_sync_completed` event carries the
   recipient-generated receipt into node custody.
10. Move the recipient away and bring the sender near the node again.
11. Confirm the sender changes to Delivered only after ingesting that E2E receipt.

The current scheduling is deliberately conservative. A newly received message creates its receipt
after that sync request was prepared, so the recipient needs a later encounter to upload it and the
sender then needs another encounter to retrieve it. Allow roughly 15 seconds per automatic resync
during testing. Reducing this delay without starving the proven phone mesh is future work.

After `CLEAR_RECORDS`, use a newly created message. A phone remembers which object IDs it already
forwarded to this persistent node identity and may correctly avoid resending an old test message.

## Physical two-node text/receipt chain

This separate ADR 0007 gate passed on 2026-08-11:

```text
A001 -> ESP1/COM10 -> ESP2/COM12 -> Samsung
Samsung -> ESP2/COM12 -> ESP1/COM10 -> A001 -> Delivered
```

The nodes mutually authenticated, ESP2 durably copied the opaque message from ESP1 while the
phones were off, and Samsung later received it exactly once. Samsung's encrypted receipt returned
through both nodes; A001 remained Waiting until it authenticated that receipt. Repeated unchanged
node syncs left copy budgets and record counts stable.

## Physical three-node text/receipt chain

This controlled ADR 0007 gate passed on 2026-08-11:

```text
A001 -> ESP32-1 -> ESP32-2 -> ESP32-3 -> Samsung
Samsung -> ESP32-3 -> ESP32-2 -> ESP32-1 -> A001 -> Delivered
```

Only the required adjacent pair was powered at each relay stage to prevent a proof-time hop skip.
This is not a firmware route restriction: in normal operation all powered authenticated nearby
nodes may exchange automatically. Samsung received the message once, uploaded one authenticated
receipt, and A001 applied exactly one receipt before displaying Delivered. Serial status showed
durable records at every hop and zero node failures. One intermediate node retained the records
through a normal reset in both directions.

Do not infer a production chain from this proof. Never clear stores while a message or receipt is
in flight. See ADR 0007 and `docs/HANDOFF_2026-08-11.md` for the exact next work.

Useful read-only log filter:

```powershell
adb logcat -s HyphaFixedNodeLink RelayGattLink RelayMetrics flutter
```
