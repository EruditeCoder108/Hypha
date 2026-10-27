# Hypha review and next execution steps



Reviewed: 24 October 2026, Asia/Calcutta. This is a review and proposed execution order, not an implementation or physical acceptance record.



Follow-up: [the 25 October deep audit](DEEP_AUDIT_2026-10-25.md) adds host and Android

failure reproductions, confirms the lost-ACK concern, and identifies record-recovery and

age-preservation defects. Follow its repair order before live LoRa custody integration.

The findings and test counts below remain the dated 24 October record.



## Assessment



Hypha is a substantial Android/BLE engineering prototype with recorded real-device messaging, phone-courier, fixed-node, and limited attachment proofs. It is still before the supervised Venue Pilot release gate. The most useful next milestone is a **mixed BLE/LoRa text-and-receipt engineering alpha**, while continuing the existing venue-security work separately.



The selected hardware direction is an ESP32-plus-LoRa development module of the kind used for Meshtastic. The user has selected it. The custom PCB is deferred and does not block this milestone. The ESP-only nodes remain part of the network and must retain their working BLE behavior. Exact board pin and power configuration belongs in the implementation profile when firmware work starts.



The correct addition is a LoRa node-to-node transport for Hypha's opaque objects. There is no existing Hypha LoRa messaging firmware to simply flash today.



## What was inspected



- Git history through `30ef099`, on `codex/horizontal-usb-pcb`, including the September software changes in `0ade555`.

- The production roadmap, current navigation handoff, protocol invariants, threat model, fixed-node decisions, evidence manifest, historical test summary, and field log.

- Rust envelope/core/router/security/E2E implementation and tests; Android discovery, scheduling, fixed-node client, transport policy, admission verifier, and test inventory; Flutter project and dependency/build configuration.

- ESP32 storage, framing, node-to-node BLE exchange, authentication, inventory policy, connection guard, maintenance, and watchdog code.

- The custom PCB release overview and diagnostic-firmware scope only. This was not a fresh electrical, RF, manufacturing, or physical-board review.



Existing untracked website, image, hardware-reference, and routing-script work was preserved. No application or firmware source was changed, and no device was installed, flashed, reset, or cleared.



## Current capability and evidence



| Area | Current state | Evidence boundary |

| --- | --- | --- |

| Direct private Android text and replies | Implemented, durable, recipient-authenticated receipts | Historical physical passes on the tested phones |

| Phone store-and-forward | Implemented for opaque recipient-encrypted messages | Historical three-phone forward and receipt-return passes |

| Background, reboot, dense encounters, long conversations | Implemented and iteratively corrected | Historical device-specific passes; broader soak remains open |

| Direct Wi-Fi Direct attachments | Implemented with encryption, resume, cancellation, and priority controls | Historical physical passes; throughput is setup-specific |

| Phone-courier attachments | Focused opaque-file path and HAR1 receipt/cleanup implemented | One recorded 11-chunk proof; repeated large-file matrix remains open |

| ESP-only fixed courier | Authenticated BLE text/receipt custody and node-to-node exchange | Historical one-, two-, and controlled three-node proofs |

| September radio/scheduling fixes | Present in current source | Commit records automated passes and explicitly says not yet physically tested |

| Managed Venue approval, HVI1 | Operator tool and Android/ESP enforcement implemented | Physical bootstrap, revocation, replacement, and recovery gates remain open |

| Opaque-envelope authorization, HAT1 | Isolated verifiers, vectors, policy model, and ESP probe source | Not connected to live custody; not a deployed admission system |

| ESP monotonic expiry | Parses envelope age/lifetime | Does not implement accumulated residence age and durable expiry |

| Protected node identity and updates | Prototype identity in ordinary NVS | Secure boot/key protection/signed update/recovery gate remains open |

| LoRa messaging | Absent from the live phone/fixed-node implementation | New adapter and physical acceptance required |

| Custom PCB firmware | USB/radio diagnostic source | Not Hypha messaging; no verified messaging binary or physical board proof |



The September evidence manifest explicitly lacks a fresh same-session three-node log, ESP serial log, and measured latency samples. Older handoffs describe earlier physical successes; these should remain historical evidence rather than being combined into a fictional current run.



Primary records: [production roadmap](HYPHA_PRODUCTION_ROADMAP.md), navigation handoff (private engineering archive), evidence manifest (private engineering archive), historical tests (private engineering archive), [ESP firmware guide](../hardware/esp32/README.md).



## Architecture to preserve



The phone retains endpoint identity, contacts, plaintext, and recipient encryption/decryption. Nodes retain only opaque courier records. Radio changes must preserve the distinction between durable custody and recipient delivery.



```text

Phone A -- BLE -- ESP-only node -- BLE -- LoRa node A

                                           |

                                          LoRa

                                           |

Phone B -- BLE ----------------------- LoRa node B



The authenticated recipient receipt must return through an available path.

```



The first LoRa proof can omit the ESP-only intermediate node. The later mixed-node proof must include it. An ESP-only node participates over BLE; it does not acquire a LoRa radio through a firmware update.



Use the existing RLY1/E2E object semantics and a common custody store, with separate BLE and LoRa link implementations. Preserve the existing phone BLE UUIDs, fixed-node BLE behavior, and receipt rules. Add a distinct firmware build profile for the chosen development board; the legacy build must compile with LoRa disabled and without requiring its radio library.



The full Hypha Link multiplexer is still a target architecture. Current Android `RelayTransportPolicy` chooses BLE text and Wi-Fi attachments directly; no complete generic transport interface was found. Extract the small node boundary needed for LoRa rather than rewriting all phone transports as a prerequisite.



## Findings that change the plan



### 1. Reproduce the current BLE baseline before extending it



The source is newer than the main handoff's product snapshot. September's `0ade555` reduces repeated SQLite work in discovery callbacks, adds fairer peer servicing, gives fixed nodes a turn after phone-link quiet, and restores the Hypha node sketch with a watchdog. Those are relevant changes to exactly the mixed phone/node behavior now being planned. Their commit documents build/test success, but no physical acceptance.



Capture the working installed firmware/APK versions and available known-good artifacts first. Preserve the current node identity, records, and phone profiles. Use spare hardware or a reversible build/deployment plan for new firmware. Re-run direct text, one-ESP custody, recipient receipt return, and dense-phone/node fairness before relying on this checkout as the reference.



**Source-level interruption gap to reproduce first:** node-to-node copy conservation spans a lossy acknowledgement. `hypha_node_peer.h` stores a received offer before sending its accepted ID (lines 402–414). The offering server reduces its retained budget only when it processes that acknowledgement (`hypha_fixed_node.ino`, lines 1577–1581). If an offer transfers four of eight copies and that acknowledgement never arrives, the receiver can retain four while the sender retains eight. On the next encounter, the receiver's inventory contains the object ID, so normal offer planning skips it; no durable handoff-reconciliation record was found in the inspected path. This is a source-derived failure scenario, not a physical reproduction from this review. Add ACK-loss/reboot fault injection and an explicit crash-safe reconciliation design before using the same flow over LoRa. Existing local split-conservation tests do not establish distributed conservation across this failure.



### 2. LoRa needs its own bounded object transport



The existing node exchange is built around BLE characteristics and relatively large RMS2 exchanges. It cannot be sent unchanged as one radio packet. RadioLib's ordinary SX126x/SX127x packet interfaces expose a 255-byte maximum; the exact selected radio and profile still determine usable payload and airtime.



Hypha's current maximum typed-reply RLY1 object is 4,196 bytes. Even an ideal 255-byte payload needs at least 17 fragments before transport headers, authentication, acknowledgements, and retries. The future 422-byte HAT1 sidecar would make the same record at least 4,618 bytes, or 19 ideal fragments. These are lower-bound byte calculations, not airtime or latency predictions.



Define and test:



- a versioned node-link handshake with transport/transcript binding and reviewed cryptography;

- bounded authenticated fragment identity, length, count, reassembly, and expiry;

- duplicate, loss, reordering, conflicting fragment, replay, and retry behavior;

- durable whole-object custody acknowledgement, distinct from packet acknowledgement;

- recovery if custody succeeds but its acknowledgement is lost;

- idempotent copy-budget commits across BLE and LoRa encounters;

- incremental bounded inventory rather than frequent full-store broadcasts;

- receipt/text priority, airtime accounting, collision backoff, and BLE service fairness.



Prefer a nonblocking radio integration. The current BLE node-client path performs synchronous scans and transfers; adding long blocking radio waits to that path would threaten phone service and watchdog behavior. A library interrupt callback should hand off bounded work, rather than perform crypto or storage inside the interrupt.



CRC detects accidental damage and does not authorize custody or authenticate a peer. Retain both recipient E2E protection and an authenticated node-link design. Do not publish persistent Hypha identities or plaintext in new over-air headers.



Upstream references: [RadioLib SX126x packet limit](https://github.com/jgromes/RadioLib/blob/master/src/modules/SX126x/SX126x.h), [SX127x packet limit](https://github.com/jgromes/RadioLib/blob/master/src/modules/SX127x/SX127x.h), [interrupt receive example](https://github.com/jgromes/RadioLib/blob/master/examples/SX126x/SX126x_Receive_Interrupt/SX126x_Receive_Interrupt.ino). These support radio API constraints; the proposed Hypha transport design is an engineering recommendation.



### 3. Flash and record budgets need explicit profiles



The fresh compile in this review confirms the legacy firmware at 1,246,915 bytes of application flash and 42,532 bytes of static RAM, near 95% of its default app partition. That does not establish remaining runtime heap or the new board's capacity. Record flash layout, storage, update/recovery room, and peak runtime memory for each target before adding the radio and admission code.



The legacy store limits are 192 records, 4,352 bytes per record, with 24 slots reserved for receipt/control traffic. HAT1 does not fit alongside the largest current reply within that ceiling. The eventual compound record must be versioned and all parser, storage, and framing bounds reviewed together. Keep RLY1 itself compatible.



The checked-in Android release build currently uses the debug signing configuration. Proper release signing remains part of the release-artifact work; a successful debug build does not close it.



### 4. Venue security remains a separate unfinished track



| Gate | State | Concrete next acceptance |

| --- | --- | --- |

| A: connection/resource guard | Implemented; one noisy-radio case historically passed | Silent/stalled/malformed clients, rotating-radio pressure, and legitimate node recovery under contention |

| B: approved node inventory | Source complete | Physical approved/unknown/revoked/replaced node tests, reboot, corrupt policy, and rollback recovery |

| C: authorized opaque deposits | Profile/model/verifier feasibility | Signed policy, key lifecycle, supervised blind issuance, phone client vectors; then compound custody and crash-safe replay/accounting |

| D: expiry | Open in firmware | Accumulated monotonic residence age, reboot persistence, durable purge, and explicit powered-off-time policy |

| E: protected identity/update | Open | Hardware-specific key/boot/update/recovery design and physical validation |



A supervised LoRa lab experiment can proceed alongside these gates. Exposing an unattended public relay or making a venue-security claim requires the gates to pass. LoRa airtime makes junk admission, expiry, and bounded retries especially consequential.



One concrete naming issue should be resolved before Gate C implementation: ADR 0011 calls its proposed admission policy `HAP1`, but `crates/relay-wire/src/attachment.rs` already uses `HAP1` for an attachment plan. Select a distinct policy name/magic in the ADR before adding another wire object. This is a design ambiguity, not evidence of a currently deployed parser vulnerability.



### 5. The written roadmap needs a current execution view



The canonical roadmap has useful invariants and release gates, but its top-level date/startup reference and numbered immediate backlog still reflect August work, including already completed attachment steps. `.project/STATE.md` and `.project/ROADMAP.md` describe a landing-page project, not the messaging project's current engineering position. The September handoff also contains another machine's checkout path and an obsolete dirty-tree snapshot.



The root README claims 30 MB/s and kilometer-scale ESP/LoRa extension. The inspected evidence does not establish those as current Hypha results; the historical direct-file observation is around 5–6 MB/s for that setup, and the implemented fixed-node path is BLE. Update the public wording against measured capability.



Keep the longer-term roadmap, but add a dated top-level state table and next acceptance gate. Move completed attachment work into history and put the new mixed-node milestone ahead of optional future transports. Keep PCB status in its own hardware release records.



## Recommended execution order



### Before the new modules arrive



1. **Establish a reproducible reference build.** Record the checkout, toolchain versions, locked dependencies, existing APK/native-library/firmware identities, build commands, size reports, and automated results. Preserve the working installed setup. The checked-in Android JNI library should be traceable to its Rust source/build, rather than assumed current because host tests pass.

2. **Write the small LoRa adapter ADR and failure model.** Limit this milestone to text and genuine recipient receipts. Define the fragment, retry, acknowledgement, bounded storage, peer authorization, and scheduler contracts above. Keep radio constants and pins in the new board profile.

3. **Implement deterministic transport/storage tests before RF integration.** Reproduce and resolve the existing lost-custody-ACK budget scenario first. Cover maximum-size current replies, duplicate/lost/out-of-order fragments, malformed lengths, authentication failures, ACK loss, power-loss recovery, repeat encounters, and simultaneous BLE/LoRa views of the same object. Require exact-once recipient presentation and no false Delivered state.

4. **Preserve two build targets.** Keep ESP-only BLE as the default reference and add an opt-in BLE+LoRa target sharing object validation/custody logic. Compile and size both. Avoid maintaining two independent copies of the complete storage/router/security implementation.

5. **Continue venue hardening in bounded slices.** Physically close Gate B when hardware is available; continue Gate C signed policy/issuance and Gate D expiry work with explicit evidence. Keep reversible lab firmware until the board-specific recovery/update plan is settled.



### When the modules arrive



At least two LoRa-capable radios are required to demonstrate a LoRa hop. One new module plus ESP-only boards can test BLE integration and one-board radio initialization, but cannot demonstrate a radio-to-radio link without another compatible LoRa endpoint.



| Stage | Controlled topology | Pass condition |

| --- | --- | --- |

| 1 | Two development modules | Radio initialization and bidirectional test packets; count loss and record configuration |

| 2 | Phone A → BLE → LoRa A → LoRa → LoRa B → BLE → Phone B | One authenticated text presentation; real recipient receipt returns and only then Delivered |

| 3 | Same topology, interrupted | Recover missing fragments, disconnects, and node reboot without duplicated presentation or premature custody/delivery |

| 4 | Phone A → ESP-only → LoRa A → LoRa B → Phone B | Existing BLE nodes interoperate; isolate links so a nearby phone/BLE path cannot accidentally bypass the LoRa hop |

| 5 | BLE and LoRa simultaneously available | Same object deduplicates across both paths; copy accounting and phone service remain bounded |

| 6 | Several nodes and sustained traffic | Full-store behavior, receipt reserves, fair scheduling, power/reboot recovery, and a documented soak pass |

| 7 | Named outdoor/venue path | Measure configuration-specific delivery ratio, payload size, latency percentiles, receipt-return latency, retries, airtime, power, and coverage |



Test both directions. Keep the recipient away/offline for the custody stage, then restore it for delivery. Test the receipt return as a separate requirement: forward delivery alone is insufficient to prove sender completion. Record software versions, topology, sample size, failures, and raw sanitized logs with each physical run.



## Scope to defer



Keep PCB manufacture, full LoRa media/files, calls, groups, iOS, global route optimization, and 30–50-node fleet claims outside this immediate milestone. The existing plan also makes small Bluetooth media a Venue Pilot gate; a text-only supervised pilot would need an explicit scope revision before being presented as meeting that existing gate. Block/delete/retention/relay-resource controls and broader device/accessibility checks remain product work before public release.



## Current-turn validation



Validation results and any local environment limitations are recorded below before delivery. Historical test counts elsewhere in the repository are not substitutes for these results.



- Operator/admission tools: `node --test tools/tests/*.test.mjs` passed **31/31**.

- Flutter package restore: offline restore confirmed missing cached dependencies; online `pub get --enforce-lockfile` restored the locked dependencies successfully. No dependency upgrade was requested.

- Rust: `cargo test --workspace --offline --locked` passed **58/58**, with no test failures. Initial default linking could not find `dlltool`, then encountered the LLVM-MinGW/GCC runtime mismatch. The successful run used the installed Rust linker and self-contained runtime with process-local flags; no repository compiler configuration was changed:



```powershell

$env:PATH = 'D:\Projects 2\Hypha\.toolchains\llvm-mingw-20260616-ucrt-x86_64\bin;C:\Users\<user>\.cargo\bin;' + $env:PATH

$env:RUSTFLAGS = '-C linker=C:\Users\<user>\.rustup\toolchains\1.97.1-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\rust-lld.exe -C linker-flavor=ld.lld -C link-self-contained=yes'

cargo test --workspace --offline --locked

```



- Flutter analysis: **no issues** after dependency restore.

- Flutter tests: **38/38 passed**, using the installed SDK's `flutter_tools.snapshot` with `test --no-pub --reporter expanded`.

- ESP-only firmware: `arduino-cli compile --fqbn esp32:esp32:esp32 --warnings all hardware/esp32/hypha_fixed_node` **passed** with installed Arduino CLI 1.5.1 / ESP32 core 3.3.11. Output: **1,246,915 / 1,310,720 bytes application flash (95%)**, **42,532 bytes static RAM (12%)**. No flash/upload was performed; dynamic peak heap and hardware behavior were not measured.

- Android unit tests: **117/117 passed across 24 suites, zero failures/errors/skips**, confirmed from freshly written XML results after `gradlew.bat --no-daemon --console=plain -Dorg.gradle.jvmargs=-Xmx2g :app:testDebugUnitTest --rerun`. The first successful Gradle run reused September's results, so it was not counted as fresh execution; the explicit rerun executed the test task. Initial offline attempts exposed absent Flutter packages and AndroidX artifacts, which were restored without changing the tracked dependency lockfiles.

- Existing Gradle/Kotlin compatibility and deprecation warnings remain. No new APK was installed or phone/ESP physical acceptance performed. These automated results do not close any hardware, range, lifecycle, or venue-security gate.



## First concrete work package



**Reproducible BLE baseline, custody-ACK-loss reconciliation, and the versioned LoRa text/receipt adapter contract with deterministic failure tests.** This can start before the modules arrive, preserves the useful working network, and makes the first hardware session an end-to-end acceptance test with clear evidence to collect.

