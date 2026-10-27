# ADR 0010: Managed Venue node inventory

- Status: accepted; source complete, physical gate pending
- Date: 2026-08-14

## Context

The fixed-node handshake already proves possession of a persistent P-256 node identity. It does
not prove that the venue operator approved that identity. Accepting every self-authenticated node
is suitable only for the existing supervised lab/demo proof.

The Venue Pilot needs revocation and replacement without changing the proven BLE UUIDs, rotating
advertisement token, encrypted session, opaque RMS2/RLY1 custody, or recipient-only Delivered
contract. Provisioning must also fail closed after a corrupt or rolled-back policy instead of
silently returning to lab behavior.

## Decision

Hypha has two explicit fixed-node trust modes:

- **Lab mode** is the compatibility default. A node that proves its P-256 identity may relay, but
  it is reported as lab-authenticated and must never be described as operator-approved.
- **Managed Venue mode** admits only active courier keys in the installed operator-signed
  inventory. Unknown, revoked, replaced, unavailable-policy, and invalid-policy identities fail
  after identity proof but before inventory disclosure, envelope offers, custody, or copy-budget
  changes.

Entering Managed Venue mode is an explicit local administrator action. It is not triggered by a
radio peer. Returning to Lab mode requires a separately confirmed local reset action. A parse,
signature, storage, or reboot error leaves the managed marker in place and fails closed.

### HVI1 signed inventory

The versioned binary object is named `HVI1`. All integers are unsigned big-endian. Its exact form
is:

| Field | Bytes | Rule |
| --- | ---: | --- |
| magic | 4 | ASCII `HVI1` |
| schema | 1 | `1` |
| validity policy | 1 | `1` = valid until a higher operator version |
| reserved | 2 | zero |
| inventory version | 8 | `1..2^63-1`, strictly increasing |
| venue id | 16 | non-zero opaque random identifier |
| authority P-256 public key | 65 | uncompressed secp256r1 point |
| entry count | 2 | `1..64` |
| entries | 67 each | public key (65), role (1), status (1) |
| signature length | 2 | DER ECDSA length `1..80` |
| signature | variable | SHA-256 ECDSA by the authority key |

The signature transcript is the UTF-8 domain `Hypha venue inventory v1\0` followed by every HVI1
byte through the last entry, excluding signature length and signature. Entries are strictly sorted
by unsigned public-key bytes and unique. The only v1 role is `1 = blind courier`. Status is
`1 = active`, `2 = revoked`, or `3 = replaced`; revoked and replaced both reject relay access.
At least one entry must be active.

Version 1 intentionally uses a manual, version-based validity policy. ESP32 nodes do not have a
trusted wall clock, so HVI1 does not invent calendar expiry. Time-based operator credentials need
a later version and a trusted-time design.

### Bootstrap, update, recovery, and reset

On first installation, a local administrator explicitly authorizes bootstrap of the authority
key, venue id, and highest accepted version. Updates must use the same authority and venue and a
higher version. The authority, venue, managed marker, and highest-version fence are stored
separately from the active inventory so a missing or corrupt inventory cannot downgrade trust.

An ESP32 accepts an inventory only when its own node key is active in that inventory. A phone does
not need a node entry, but applies the same signature, authority, venue, and rollback checks. A
failed update keeps the last valid active policy. If storage fails between the rollback fence and
policy activation, the device stays managed and unavailable; the exact fenced version may be
reinstalled as recovery, but an older version may not.

Node replacement is a higher inventory version containing the new key as active and the old key as
replaced or revoked. Other nodes and managed phones reject the old key before mesh exchange. The
revoked device does not need to cooperate for revocation to take effect.

The pilot operator surface is deliberately local: an offline tool creates and signs HVI1; Android
accepts it through a local platform method; and ESP32 accepts bounded chunks over its physical
serial maintenance connection. Serial can expose node public identity but never its private key.
Gate E must protect this maintenance path, authority-key lifecycle, node keys, boot, updates, and
recovery before production claims.

## Deterministic acceptance

Tests must cover active, unknown, revoked, replaced, bad signature, malformed and duplicate
entries, wrong venue, wrong authority, rollback, equal-version replay, version update, corrupt
policy across restart, explicit bootstrap, explicit reset, local-node omission, local-node
revocation, and supported-version rejection.

Android and ESP32 must make the allow/reject decision before RMS2 inventory or RLY1 custody. The
existing lab path and all compatibility identifiers remain unchanged. Physical provisioning,
revocation, replacement, reboot, and recovery stay pending until the user performs them.

## Consequences

Existing boards and APK behavior remain demoable because Lab mode is the default. A venue becomes
stricter only after its signed inventory is deliberately installed. Operator work increases: node
public keys must be collected, an offline authority key must be protected, and every participating
phone and node must receive inventory updates. That complexity is limited to managed deployments
and is the cost of real approval and revocation.

## Source checkpoint

On 2026-08-14 the Android and ESP32 decisions, fail-closed persistence, local controls, offline
operator tool, and deterministic coverage are source-complete. Dart analysis is clean; Flutter
passes 38/38; Android passes 112/112 including 7/7 HVI1 trust tests; operator-tool tests pass 3/3;
and warning-clean ESP32 compilation passes at 1,245,559 bytes (95% flash) and 42,212 bytes (12%
static RAM).

No app was installed, no board was flashed or provisioned, no ESP records were cleared, and no
physical proof was repeated. Lab compatibility plus managed bootstrap, approval, revocation,
replacement, restart, recovery, and reset therefore remain physically pending.
