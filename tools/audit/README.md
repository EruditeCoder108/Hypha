# Custody regression tests and opt-in audit probes

These tools run against the current implementation without changing installed device data.
Repaired paths assert the intended invariants; still-open findings remain explicitly labelled.
The pre-repair audit and its raw outputs are preserved in checkpoint `b7e5c94` and
`evidence/deep-audit-2026-10-25/`.

## ESP32 custody and storage

From the repository root:

```powershell
node tools/audit/run_esp32_custody_audit.mjs artifacts/custody-repair-2026-10-25
```

Requires the existing `.toolchains/llvm-mingw-20260616-ucrt-x86_64` compiler and installed
Arduino ESP32 core 3.3.11. Override `HYPHA_AUDIT_CXX` or `HYPHA_AUDIT_ESP32_VFS` if their paths
change. The tool extracts the actual storage, codec, offer, inventory, and acknowledgement
functions verbatim from firmware into a generated host translation unit; it records source hashes.
Its filesystem double follows the basename and absolute-path semantics checked in the installed
ESP32 implementation. SHA-256 is supplied by Windows BCrypt.

The command above writes generated artifacts under `artifacts/custody-repair-2026-10-25/`.
A zero exit means the regression assertions and remaining audit observations completed.
**An `invariant_violation_reproduced` result is a defect observation, not a passing
correctness test.** This is not a hardware,
flash-sector atomicity, NVS, radio, watchdog, or cryptographic-handshake test.

The twelve cases include backup restoration, invalid-record allocation bounds, immutable-field
conflicts, nine replacement interruption checkpoints, three interruption checkpoints during
recovery, corrupt final/backup combinations, and a fail-closed over-quota pressure recovery case.
Repaired cases report `regression_passed`. The lost-ACK, expiry, and pressure-policy observations
remain open and retain their audit labels. When fixing those paths, replace the expected
defective observations with intended invariant assertions.

## Android store invariants

From `apps/mobile/android`:

```powershell
.\gradlew.bat --offline --no-daemon --console=plain '-Dorg.gradle.jvmargs=-Xmx2g' `
  -I '..\..\..\tools\audit\android-audit.init.gradle' `
  :app:testDebugUnitTest --rerun --tests '*RelayStoreAuditTest'
```

The init script adds only `tools/audit/android` to the test source set for this invocation.
Robolectric uses disposable test data. Four tests remain in the opt-in set; the lost-ACK
invariant is still expected to fail. The repaired age/late-ACK cases moved into the normal
`RelayMeshStoreReliabilityTest` suite alongside five additional commit/restart regressions.
Normal Gradle runs do not include the open lost-ACK probe.
Copy XML results before another test run overwrites the standard test-results directory.

## Packaged native surface and backup configuration

```powershell
node tools/audit/check_android_surface.mjs
```

Checks native Kotlin declarations against the checked-in ARM64 library's exported symbols,
records its SHA-256, and inspects source/merged debug manifest backup attributes. Symbol agreement
does not prove JNI argument compatibility, binary reproducibility, or execution on a phone.
