import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const output = resolve(root, process.argv[2] ?? 'artifacts/deep-audit-2026-10-25');
const sketchPath = join(root, 'hardware/esp32/hypha_fixed_node/hypha_fixed_node.ino');
const peerPath = join(root, 'hardware/esp32/hypha_fixed_node/hypha_node_peer.h');
const sketch = await readFile(sketchPath, 'utf8');
const peer = await readFile(peerPath, 'utf8');
const hash = text => createHash('sha256').update(text).digest('hex');
const vfsPath = process.env.HYPHA_AUDIT_ESP32_VFS ?? join(process.env.USERPROFILE,
  'AppData/Local/Arduino15/packages/esp32/hardware/esp32/3.3.11/libraries/FS/src/vfs_api.cpp');
const vfs = await readFile(vfsPath, 'utf8');
// Pin the assumptions used by the filesystem double to the installed source.
if (!vfs.includes('return pathToFileName(path());') || !vfs.includes("fpath[0] != '/'")) {
  throw new Error('Installed ESP32 filesystem semantics changed; review the host double');
}
const sections = [];
function take(text, from, until, path) {
  const start = text.indexOf(from);
  const end = text.indexOf(until, start + from.length);
  if (start < 0 || end < 0) throw new Error(`Firmware extraction anchor missing: ${from}`);
  const line = text.slice(0, start).split('\n').length;
  sections.push({ path: path.replaceAll('\\', '/'), line, from, until });
  return `\n#line ${line} "${path.replaceAll('\\', '/')}"\n${text.slice(start, end)}\n`;
}
const body = [
  '#include "esp32_host_runtime.hpp"\n',
  take(sketch, 'constexpr uint32_t kSerialBaud', 'struct VenueAnchor', sketchPath),
  take(sketch, 'enum class StoreOutcome', 'std::array<uint8_t, kAdvertisementTokenBytes>', sketchPath),
  'bool storageReady = true; bool nodePeerAuthenticated = true; std::vector<PendingOffer> pendingOffers;\n',
  'bool venueRelayAllowed() { return true; }\n',
  take(sketch, 'uint16_t readU16(', 'uint32_t crc32(', sketchPath),
  take(sketch, 'bool fixedEquals(', 'int hardwareRandom(', sketchPath),
  take(sketch, 'void bytesToHex(', 'bool clearStoredRecords(', sketchPath),
  take(sketch, 'StoreOutcome storeEnvelope(', 'bool initializeStorage(', sketchPath),
  take(sketch, 'struct ExchangeView', 'std::vector<ObjectId> nodePeerInventory();', sketchPath),
  take(peer, 'std::vector<ObjectId> nodePeerInventory()', 'bool synchronizeNodePeer(', peerPath),
  take(sketch, 'bool processMeshRequest(', 'void setOutbound(', sketchPath),
  '#line 1 "esp32_custody_cases.cpp"\n#include "esp32_custody_cases.cpp"\n',
].join('\n');
await mkdir(output, { recursive: true });
const generated = join(output, 'firmware-under-audit.cpp');
const binary = join(output, 'esp32-custody-audit.exe');
await writeFile(generated, body);
const compiler = process.env.HYPHA_AUDIT_CXX ?? join(root, '.toolchains/llvm-mingw-20260616-ucrt-x86_64/bin/clang++.exe');
const args = ['-std=c++20', '-O0', '-g', '-static', '-Wall', '-Wextra', '-Wno-unused-parameter',
  '-I', here, generated, '-o', binary, '-lbcrypt'];
const built = spawnSync(compiler, args, { cwd: root, encoding: 'utf8', timeout: 120_000, windowsHide: true });
await writeFile(join(output, 'host-build.log'), `${built.stdout ?? ''}${built.stderr ?? ''}`);
if (built.error || built.status !== 0) {
  throw new Error(`Host build failed: ${built.error?.message ?? built.stderr}`);
}
const run = spawnSync(binary, [], { cwd: root, encoding: 'utf8', timeout: 30_000, windowsHide: true });
await writeFile(join(output, 'host-cases.jsonl'), run.stdout ?? '');
if (run.error || run.status !== 0) throw new Error(`Host cases failed: ${run.error?.message ?? run.stderr}`);
const cases = run.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
if (cases.length !== 12) throw new Error(`Expected 12 audit/regression observations, got ${cases.length}`);
const result = {
  scope: 'Verbatim firmware storage/offer/ack functions; orchestrated encounters; in-memory filesystem with ESP32 basename/absolute-path semantics; real host SHA-256.',
  limitations: 'No ESP hardware, BLE, flash-sector atomicity/wear, NVS, crypto-handshake, scheduler, or physical reboot proof.',
  source: { sketch: { path: sketchPath, sha256: hash(sketch) }, peer: { path: peerPath, sha256: hash(peer) },
    filesystemApi: { path: vfsPath, sha256: hash(vfs), verifiedSemantics: 'basename names and absolute filesystem paths' } },
  extractedSections: sections,
  cases,
};
await writeFile(join(output, 'esp32-custody-findings.json'), `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result, null, 2));
