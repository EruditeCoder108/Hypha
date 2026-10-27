# Project Relay threat model



Status: Updated through ADR 0009; cryptographic design remains subject to specialist review and audit.



## Protected assets



- message and attachment contents;

- long-term identity and device private keys;

- contact relationships and group membership;

- conversation metadata, location patterns, and encounter history;

- integrity of delivery state and group membership;

- phone storage, battery, radio airtime, CPU, and memory.



## Adversaries in scope



### Passive radio observer



Records BLE and Wi-Fi traffic over time and attempts to correlate a person, device, room, or social graph. Discovery therefore exposes only rotating, unlinkable material and coarse padded size classes.



### Malicious nearby peer



Sends malformed frames, replays traffic, lies about capabilities or queue state, opens expensive handshakes, and attempts resource exhaustion. All input is bounded, authenticated where possible, rate-limited, and fuzzed.



For the experimental fixed-node GATT server, ADR 0009 Gate A now makes a connection finite: a

stalled encrypted-session confirmation, authenticated idle client, overlong connection, excess

transfer/byte/read/write use, or malformed protocol is forcibly disconnected. A bounded one-minute

per-radio table lives only in RAM so one reconnecting address can be isolated without consuming the

aggregate allowance or backoff for other peers. The address is never persisted, logged, exported,

or treated as identity. Other repeated guard failures can cause a short aggregate advertising

backoff. This reduces BLE connection starvation; rotating/spoofed addresses remain only globally

bounded, deliberate radio jamming remains out of scope, and the guard does not prove that an opaque

envelope is authorized.



### Malicious courier



Stores, duplicates, delays, reorders, withholds, or drops envelopes. End-to-end authentication prevents forgery; copy diversity and receipts improve availability. A courier can still deny service.



### Compromised or counterfeit fixed courier



An attacker may replace a fixed node, steal its persistent key, extract unprotected NVS,

install hostile firmware, or exploit trust on first use. A fixed node may also record

encounter timing, drop/replay/delay envelopes, lie about custody, or consume phone radio

and battery. Recipient E2E authentication keeps message contents and delivery receipts

opaque and unforgeable, while the signed encounter handshake proves only possession of

the presented node key. ADR 0010 Managed Venue mode adds an offline operator-signed HVI1 inventory;

only active listed node keys pass before mesh inventory or custody. Lab mode deliberately remains

self-authenticated and must not be described as operator-approved.



The experimental ESP32 is therefore not a production trust anchor. Release hardware

requires secure boot, signed updates, flash encryption or a secure element, protected

provisioning and recovery, anti-rollback, resource-abuse testing, and an offline expiry

design that does not rely on an untrusted wall clock. A seized node can still reveal

its own encounter history and deny service even after those controls.



ADR 0009 separates these remaining controls into operator inventory, privacy-safe admission,

monotonic expiry, and protected identity/update gates. Gate A's BLE guard and ADR 0010's Gate B

Lab/Managed Venue inventory decisions are implemented in source. Gate A's normal one-node Lab path

and noisy-single-radio isolation passed physically on 2026-08-15; silent, stalled, malformed,

rotating-address, node-to-node recovery, and all Gate B Managed Venue physical evidence remain

pending. ADR 0011 now selects the bounded HAT1 Blind RSA profile and has desktop/Android vectors plus

ESP compile evidence, but signed admission policy, blind issuance, replay persistence, and live

custody admission remain open; Gates D-E also remain open. HVI1 limits which proven node key may

join; it does not protect that key from extraction, protect the serial maintenance path, admit

opaque envelopes by itself, enforce trusted expiry, or make hostile firmware safe.



The development serial port also exposes a deliberate local record-purge command. Physical

or host access can therefore erase queued custody copies and deny service, but the command

does not reveal their contents or replace the persistent node identity. Production hardware

must authenticate or physically gate maintenance access and audit administrative purges.



An authenticated fixed-node peer may still be malicious or compromised. It can lie about

inventory, accept then discard custody, replay offers, withhold receipts, or try to consume copy

budgets and storage. The experimental node link therefore authenticates both persistent node

identities inside the encrypted encounter, bounds inventory and offers, rejects same-ID payload

conflicts, prevents same-exchange echo, and commits retained copy-budget changes only for records

actually accepted. These controls prevent forgery and unbounded duplicate amplification; they do

not make a hostile courier deliver or make TOFU an operator-approved trust decision.



Because a fixed node sees phones only as anonymous couriers, accepting a record from or handing a

record to a phone does not prove that phone was the final recipient. The node must retain bounded

custody rather than delete on that event. A future delivery-driven tombstone or purge protocol is

a new privacy/security boundary: it must authenticate final completion without exposing stable

endpoint identity, contact relationships, conversation membership, or a cross-venue tracking tag.



### Sybil swarm



Creates many cheap public identities to consume queue and radio capacity. HAT1 does not use radio

identity as authority. The supervised Venue Pilot instead bounds blind-signing requests per approved

issuer session/class/epoch, and nodes separately bound sessions, proof failures, tickets, classes,

bytes, and total storage. Rotating BLE addresses cannot mint a valid issuer signature, although a

compromised operator or repeatedly fooled supervisor can still authorize abuse.



### Compromised contact or captured unlocked phone



A valid member can leak content they legitimately receive. Forward secrecy limits past-message exposure after later key compromise; post-compromise recovery limits future exposure after a clean ratchet. An unlocked captured phone remains a severe risk until locked or remotely unrecoverable keys are destroyed.



### Malicious attachment or parser input



Ciphertext can contain hostile media or encoded structures after decryption. Format limits, safe decoders, content isolation, and platform media hardening remain required above transport security.



## Explicit non-goals



- defeating radio jamming or a geographic absence of relay devices;

- hiding that a phone is transmitting any radio signal from a global physical observer;

- guaranteeing background execution where the operating system forbids it;

- protecting plaintext after a recipient intentionally exports, screenshots, or photographs it;

- recovering data after local keys are destroyed without a user-created recovery export;

- claiming anonymity against a global adversary before independent metadata analysis.

- preventing a physically present fixed courier from observing that nearby radios encountered it.



## Security release gates



Before a 1.0 security claim: parser fuzzing, state-machine property tests, group-fork model tests, reproducible builds, dependency review, real-device metadata testing, and an independent protocol/cryptographic audit must pass.

