# ADR 0009: Fixed-node Venue Pilot security boundaries

- Status: accepted staged design; Gates A-B source complete; Gate A normal/noisy-peer physical
  path passed, adversarial remainder and Gate B physical gate pending
- Date: 2026-08-13

## Context

ADRs 0006 and 0007 proved a bounded blind ESP32 text/receipt courier over BLE. That proof
authenticates possession of node keys and preserves recipient-only delivery, but it does not make
the fixed nodes safe to operate as venue infrastructure. A focused audit identified five separate
release gates:

1. venue-authorized provisioning, rotation, revocation, replacement, and recovery;
2. privacy-safe admission and spam/resource limits for opaque envelopes;
3. phone-facing BLE connection-starvation protection;
4. accumulated monotonic residence expiry, including reboot and powered-off policy; and
5. protected node keys, verified secure boot, signed anti-rollback updates, and recovery.

These gates must not be blurred together. In particular, an authenticated hop is not admission,
a self-signed node is not venue-approved, a parsed lifetime is not enforced expiry, and ESP-NOW
would not solve any of these trust or resource boundaries.

## Decision

Implement the audit findings as five independently testable gates. Preserve the existing phone BLE
UUIDs, fixed-node UUIDs, HNH1/HNS1/HNF1/HND1/HNR1 framing, HNA1/HNX1 node authentication,
RMS2/RLY1 envelopes, copy conservation, blind custody, and recipient-only Delivered semantics
unless a later accepted ADR explicitly versions a change.

### Gate A: BLE connection guard

The fixed-node GATT server applies a local connection policy without changing any wire value:

- complete the encrypted session confirmation within 15 seconds of connection;
- after confirmation, disconnect a connection idle for 65 seconds;
- disconnect every connection after an absolute five-minute ceiling;
- allow at most one hello and eight transfer starts per connection;
- accept at most 64 KiB of declared client payload, 8,192 writes, and 8,192 reads per connection;
- retain at most 16 peer radio addresses only in volatile RAM for one minute, allow at most eight
  connection starts per address, and immediately isolate later starts without logging, persisting,
  exporting, or treating the address as an endpoint identity;
- across one anonymous 60-second resource window, count only starts still inside their peer
  allowance and allow at most 96 such connections, 512 KiB of declared client payload, 65,536
  writes, and 65,536 reads; rotating/churning addresses remain bounded by this aggregate ceiling;
- treat malformed framing, CRC, sequence, authentication, and protocol order as a terminal
  connection violation;
- perform forced disconnect from the main loop, outside BLE callbacks;
- peer-window disconnects do not poison the aggregate connection count or trigger an aggregate
  advertising pause; after three other guard disconnects in a rolling 60-second window, pause
  server advertising for five seconds;
- keep privacy-safe aggregate reason, disconnect, and backoff counters in `STATUS`.

The 65-second idle limit is deliberately just above Android's existing 60-second bounded transfer
timeout. The normal phone exchange uses five transfer starts; the mutually authenticated node
exchange uses six. The per-connection, per-radio, and anonymous window ceilings retain headroom
above the current maximum bounded RMS2 exchange while making drip-fed or reconnecting work finite.
The short peer table is an availability control, not identity: it is erased by expiry/reboot, never
leaves RAM, and is not exposed in diagnostics. A rotating or spoofed address can evade its peer
entry but not the larger aggregate bound; deliberate radio jamming remains out of scope.

This gate does not decide whether an envelope is authorized, does not approve a node, and does not
delete or expire custody. A malicious client that completes the encrypted confirmation can still
consume its bounded connection window, so admission remains a separate gate.

Deterministic source checks cover every per-connection, per-peer, and anonymous-window disconnect
reason, peer isolation, a second peer remaining admitted, peer-window expiry, exact time
boundaries, a legitimate bounded session, and unsigned 32-bit monotonic wrap. Automated verification requires those checks
to compile with the firmware plus the existing Android fixed-node/session regressions. Physical
silent-client, stalled-handshake, malformed-client, recovery, phone-sync, and node-sync checks stay
pending until the user runs them on the compiled image.

On 2026-08-15 a real tethered laptop reconnect loop exposed the original aggregate-only design: one
address connected every one to two seconds, filled the 24-start window, and delayed legitimate
phones for minutes. With per-peer isolation flashed, the same laptop produced 414 bounded
`peer_connections` disconnects and zero aggregate backoffs while A001 stored a new message in four
to five seconds, Samsung received it in about two seconds, and A001 quickly applied the genuine
recipient receipt. This passes the normal and noisy-peer compatibility path only. Silent, stalled,
malformed, address-rotation, node-to-node contention/recovery, and long-soak checks remain pending.

Source verification on 2026-08-13 passes: the policy checks compile into a warning-clean firmware
image at 1,239,627 bytes (94% flash) and 42,076 bytes (12% static RAM); 12/12 focused Android
fixed-node tests pass; and the complete Android suite passes 105/105 with zero failures, errors, or
skips. No board was flashed and this evidence does not satisfy the physical gate.

### Gate B: operator-approved node inventory

Before changing node trust, define a versioned signed provisioning object and recovery process.
The operator inventory must bind venue, node identity, role, status, version, and validity policy.
Unknown and revoked keys must fail before inventory or custody; replacement and rotation must not
fabricate custody or recipient delivery. Factory reset and recovery require an explicit physical or
administrator-authorized action. TOFU may remain only as a clearly labelled lab mode.

Deterministic tests must cover unprovisioned, revoked, rotated, replacement, reset, corrupt
inventory, rollback, and version-skew cases across reboot before physical provisioning begins.

ADR 0010 defines the HVI1 signed inventory, explicit Lab and Managed Venue modes, rollback fence,
local bootstrap/update/recovery surface, and fail-closed decision point. Its implementation is the
next bounded source milestone.

### Gate C: privacy-safe envelope admission

Structural RLY1 validity and hop encryption are insufficient admission. Before public phone
deposits or production node offers, define a versioned recipient-private or capability-based proof
that authorizes coarse object class and resource use without revealing stable sender, recipient,
contact, conversation, or route identity.

Admission must bind priority so arbitrary clients cannot forge control traffic. It must enforce
bounded per-session/capability/object-class/origin-equivalent quotas, duplicate accounting,
same-ID conflict handling, failed-proof backoff, and congestion rules that preserve legitimate
security control, receipts, and text. The exact proof and unlinkability properties require focused
privacy and cryptographic review before implementation.

Deterministic adversarial tests must include valid-looking junk, forged control priority, duplicate
floods, same-ID conflicts, rotating radios, store pressure, and legitimate progress under attack.

ADR 0011 now proposes the verifier-to-policy contract, privacy boundary, replay/conflict behavior,
quota/reserve ordering, revocation, and fail-closed semantics. Its standalone deterministic model
does not select a cryptographic proof or change live RLY1 admission, priority, custody, cleanup,
routing, or transport. Those changes remain blocked on focused privacy/cryptographic review and a
versioned proof decision.

### Gate D: accumulated monotonic expiry

Residence age must advance from monotonic elapsed time while powered, persist crash-consistently,
be added to the age sent on every offer, and durably remove expired records. A delayed duplicate
must not resurrect an expired object during the governed tombstone/seen window.

The selected shipping hardware must define powered-off time honestly. Without a trusted clock, the
node must use an explicit fail-safe maximum-offline policy or require trusted operator time during
maintenance; it must not silently claim that unplugged time was measured.

Tests must cover continuous uptime, millis wrap, repeated forwarding, reboot at every persistence
boundary, maximum lifetime, pressure, delayed duplicates, wall-clock changes, and the chosen
powered-off policy.

### Gate E: protected identity and update recovery

The current raw P-256 key in Preferences/NVS remains prototype-only. Production hardware must use
verified secure boot, encrypted/protected key storage appropriate to the selected ESP32, signed
versioned firmware, anti-rollback, authenticated or physically gated maintenance, and a tested
recovery image/process. Debug access and manufacturing/provisioning lifecycle must be documented.

Acceptance requires the actual provisioned hardware to reject unsigned, modified, and downgraded
images; protect node keys and encrypted records from supported maintenance/debug interfaces; and
complete rotation/recovery without false custody or Delivered state. This cannot be proven by a
debug Arduino build alone.

## Ordering

Implement Gate A first because it is additive, closes a direct availability defect, and does not
require a new wire object. Design and review Gate B before Gate C so admission capabilities can be
issued by an explicit venue authority. Implement Gate D independently of routing or automatic
cleanup. Select the shipping hardware and update lifecycle before claiming Gate E.

Power-loss, store-pressure, corruption recovery, dense scheduling, multi-day soak, enclosure,
power, maintenance, and measured coverage remain additional Venue Pilot gates after these five.
Managed 30-50-node routing, delivery tombstones, ESP-NOW, and media each require their own later ADR
and cannot be smuggled into an audit fix.

## Consequences

The first source slice can make a silent or malformed BLE client finite without invalidating the
accepted one-, two-, or three-node proofs. It does not make the node production-secure and it does
not mark any physical gate passed. Later gates may require protocol versioning and hardware choices,
but they now have explicit boundaries and deterministic acceptance requirements before code changes.
