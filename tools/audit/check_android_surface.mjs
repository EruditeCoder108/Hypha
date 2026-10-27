import { createHash } from 'node:crypto';
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const android = join(root, 'apps/mobile/android/app/src/main');
const kotlin = await readFile(join(android, 'kotlin/app/projectrelay/relay_mobile/RelayNative.kt'), 'utf8');
const libraryPath = join(android, 'jniLibs/arm64-v8a/librelay_jni.so');
const library = await readFile(libraryPath);
const readobj = join(root, '.toolchains/llvm-mingw-20260616-ucrt-x86_64/bin/llvm-readobj.exe');
const binary = spawnSync(readobj, ['--file-headers', '--dyn-symbols', libraryPath],
  { encoding: 'utf8', windowsHide: true, timeout: 30_000 });
if (binary.error || binary.status !== 0) throw new Error(binary.error?.message ?? binary.stderr);
const prefix = 'Java_app_projectrelay_relay_1mobile_RelayNative_';
const declared = [...kotlin.matchAll(/\bexternal\s+fun\s+(\w+)\s*\(/g)].map(m => `${prefix}${m[1]}`);
const exported = [...binary.stdout.matchAll(/Name:\s+(Java_app_projectrelay_relay_1mobile_RelayNative_\w+)/g)].map(m => m[1]);
const sourceManifest = await readFile(join(android, 'AndroidManifest.xml'), 'utf8');
const mergedPath = join(root, 'apps/mobile/build/app/intermediates/merged_manifests/debug/processDebugManifest/AndroidManifest.xml');
const mergedManifest = await readFile(mergedPath, 'utf8').catch(() => null);
const attributes = text => Object.fromEntries(['allowBackup', 'fullBackupContent', 'dataExtractionRules']
  .map(key => [key, text?.match(new RegExp(`android:${key}="([^"]+)"`))?.[1] ?? null]));
const output = {
  scope: 'Static Android/JNI surface only; no packaged ARM64 execution or backup/restore test.',
  jni: {
    declaredMethods: declared.length, exportedMethods: exported.length,
    missing: declared.filter(name => !exported.includes(name)),
    extra: exported.filter(name => !declared.includes(name)),
    librarySha256: createHash('sha256').update(library).digest('hex'),
    shippedAbis: (await readdir(join(android, 'jniLibs'), { withFileTypes: true })).filter(e => e.isDirectory()).map(e => e.name),
    elfFormat: binary.stdout.match(/Format:\s+([^\r\n]+)/)?.[1],
  },
  backup: { source: attributes(sourceManifest), mergedDebug: attributes(mergedManifest), mergedManifestPresent: mergedManifest !== null },
  usbHostImplementation: 'Separate source search required; native symbol matching does not establish USB support.',
};
const outDir = join(root, 'artifacts/deep-audit-2026-10-25');
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'android-surface.json'), `${JSON.stringify(output, null, 2)}\n`);
console.log(JSON.stringify(output, null, 2));
if (output.jni.missing.length || output.jni.extra.length) process.exitCode = 1;
