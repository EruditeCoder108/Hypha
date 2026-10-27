#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const HVI_DOMAIN = Buffer.from('Hypha venue inventory v1\0', 'utf8');
export const MAX_ENTRIES = 64;
const HEADER_BYTES = 99;
const ENTRY_BYTES = 67;
const STATUS_TO_WIRE = new Map([
  ['active', 1],
  ['revoked', 2],
  ['replaced', 3],
]);
const WIRE_TO_STATUS = new Map([...STATUS_TO_WIRE].map(([name, value]) => [value, name]));

function requireBuffer(value, bytes, label) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (buffer.length !== bytes) throw new Error(`${label} must be ${bytes} bytes.`);
  return buffer;
}

function base64Url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

export function rawPublicKey(key) {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  const jwk = publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('Authority must be a P-256 key.');
  }
  return Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

export function publicKeyFromRaw(encoded) {
  const raw = requireBuffer(encoded, 65, 'P-256 public key');
  if (raw[0] !== 4) throw new Error('P-256 public key must be uncompressed.');
  return createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: base64Url(raw.subarray(1, 33)),
      y: base64Url(raw.subarray(33, 65)),
    },
  });
}

export function nodeFingerprint(publicKey) {
  const digest = createHash('sha256')
    .update(Buffer.from('Hypha fixed node identity v1\0', 'utf8'))
    .update(requireBuffer(publicKey, 65, 'Node public key'))
    .digest();
  return `NODE-${[...digest].map((byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join('-')}`;
}

export function buildInventory({ authorityPrivateKey, venueId, version, entries }) {
  const venue = requireBuffer(venueId, 16, 'Venue id');
  if (venue.every((byte) => byte === 0)) throw new Error('Venue id cannot be all zero.');
  const parsedVersion = BigInt(version);
  if (parsedVersion < 1n || parsedVersion > 0x7fffffffffffffffn) {
    throw new Error('Inventory version must be between 1 and 2^63-1.');
  }
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_ENTRIES) {
    throw new Error(`Inventory must contain 1-${MAX_ENTRIES} entries.`);
  }
  const encodedEntries = entries.map((entry) => {
    const publicKey = Buffer.from(entry.publicKey, 'hex');
    publicKeyFromRaw(publicKey);
    if (entry.role !== undefined && entry.role !== 'courier') {
      throw new Error('HVI1 supports only the courier role.');
    }
    const status = STATUS_TO_WIRE.get(entry.status);
    if (!status) throw new Error(`Unsupported node status: ${entry.status}`);
    return Buffer.concat([publicKey, Buffer.from([1, status])]);
  }).sort(Buffer.compare);
  for (let index = 1; index < encodedEntries.length; index += 1) {
    if (encodedEntries[index - 1].subarray(0, 65).equals(encodedEntries[index].subarray(0, 65))) {
      throw new Error('Inventory node public keys must be unique.');
    }
  }
  if (!encodedEntries.some((entry) => entry[66] === 1)) {
    throw new Error('Inventory must contain at least one active courier.');
  }
  const unsigned = Buffer.alloc(HEADER_BYTES + encodedEntries.length * ENTRY_BYTES);
  unsigned.write('HVI1', 0, 'ascii');
  unsigned[4] = 1;
  unsigned[5] = 1;
  unsigned.writeBigUInt64BE(parsedVersion, 8);
  venue.copy(unsigned, 16);
  rawPublicKey(createPublicKey(authorityPrivateKey)).copy(unsigned, 32);
  unsigned.writeUInt16BE(encodedEntries.length, 97);
  encodedEntries.forEach((entry, index) => entry.copy(unsigned, HEADER_BYTES + index * ENTRY_BYTES));
  const signature = sign('sha256', Buffer.concat([HVI_DOMAIN, unsigned]), authorityPrivateKey);
  if (signature.length < 1 || signature.length > 80) throw new Error('Authority signature is oversized.');
  const length = Buffer.alloc(2);
  length.writeUInt16BE(signature.length);
  return Buffer.concat([unsigned, length, signature]);
}

export function parseInventory(encoded) {
  const wire = Buffer.from(encoded);
  if (wire.length < HEADER_BYTES + ENTRY_BYTES + 3 || wire.subarray(0, 4).toString('ascii') !== 'HVI1') {
    throw new Error('HVI1 inventory is truncated or has an invalid prefix.');
  }
  if (wire[4] !== 1 || wire[5] !== 1 || wire.readUInt16BE(6) !== 0) {
    throw new Error('HVI1 schema, validity policy, or reserved field is unsupported.');
  }
  const version = wire.readBigUInt64BE(8);
  if (version < 1n || version > 0x7fffffffffffffffn) throw new Error('HVI1 version is invalid.');
  const venueId = wire.subarray(16, 32);
  if (venueId.every((byte) => byte === 0)) throw new Error('HVI1 venue id is invalid.');
  const authorityPublicKey = wire.subarray(32, 97);
  const authority = publicKeyFromRaw(authorityPublicKey);
  const count = wire.readUInt16BE(97);
  if (count < 1 || count > MAX_ENTRIES) throw new Error('HVI1 entry count is invalid.');
  const entriesEnd = HEADER_BYTES + count * ENTRY_BYTES;
  if (entriesEnd + 2 > wire.length) throw new Error('HVI1 entries are truncated.');
  const entries = [];
  let prior = null;
  for (let index = 0; index < count; index += 1) {
    const offset = HEADER_BYTES + index * ENTRY_BYTES;
    const publicKey = wire.subarray(offset, offset + 65);
    publicKeyFromRaw(publicKey);
    if (prior && Buffer.compare(prior, publicKey) >= 0) {
      throw new Error('HVI1 entries must be sorted and unique.');
    }
    prior = publicKey;
    if (wire[offset + 65] !== 1 || !WIRE_TO_STATUS.has(wire[offset + 66])) {
      throw new Error('HVI1 node role or status is unsupported.');
    }
    entries.push({
      publicKey: publicKey.toString('hex'),
      fingerprint: nodeFingerprint(publicKey),
      role: 'courier',
      status: WIRE_TO_STATUS.get(wire[offset + 66]),
    });
  }
  if (!entries.some((entry) => entry.status === 'active')) {
    throw new Error('HVI1 inventory has no active courier.');
  }
  const signatureBytes = wire.readUInt16BE(entriesEnd);
  if (signatureBytes < 1 || signatureBytes > 80 || entriesEnd + 2 + signatureBytes !== wire.length) {
    throw new Error('HVI1 signature length is invalid.');
  }
  const signature = wire.subarray(entriesEnd + 2);
  if (!verify('sha256', Buffer.concat([HVI_DOMAIN, wire.subarray(0, entriesEnd)]), authority, signature)) {
    throw new Error('HVI1 authority signature is invalid.');
  }
  return {
    schema: 1,
    validityPolicy: 'until_higher_version',
    version: version.toString(),
    venueId: venueId.toString('hex'),
    authorityPublicKey: authorityPublicKey.toString('hex'),
    entries,
  };
}

export function serialProvisioningCommands(encoded) {
  const wire = Buffer.from(encoded);
  parseInventory(wire);
  const commands = [`VENUE_BEGIN ${wire.length}`];
  for (let offset = 0; offset < wire.length; offset += 32) {
    commands.push(`VENUE_CHUNK ${wire.subarray(offset, offset + 32).toString('hex')}`);
  }
  commands.push('VENUE_COMMIT', 'VENUE_STATUS');
  return commands;
}

function argumentsMap(argumentsList) {
  const result = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const name = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!name?.startsWith('--') || value === undefined) throw new Error(`Invalid option near ${name ?? 'end'}.`);
    result.set(name.slice(2), value);
  }
  return result;
}

function required(options, name) {
  const value = options.get(name);
  if (!value) throw new Error(`--${name} is required.`);
  return value;
}

function readAuthorityPrivate(path) {
  const passphrase = process.env.HYPHA_VENUE_KEY_PASSPHRASE;
  if (!passphrase) throw new Error('Set HYPHA_VENUE_KEY_PASSPHRASE before using the authority key.');
  return createPrivateKey({ key: readFileSync(path), format: 'pem', passphrase });
}

function usage() {
  return [
    'Hypha Venue operator tool',
    '',
    'create-authority --private venue-private.pem --public venue-public.pem',
    'new-venue-id',
    'create-inventory --private venue-private.pem --venue-id 32hex --version N --nodes nodes.json --out venue.hvi',
    'inspect --inventory venue.hvi',
    'serial-script --inventory venue.hvi --out provision.txt',
    '',
    'Set HYPHA_VENUE_KEY_PASSPHRASE for create-authority/create-inventory.',
  ].join('\n');
}

export function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  if (!command || command === 'help' || command === '--help') {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const options = argumentsMap(rest);
  if (command === 'new-venue-id') {
    process.stdout.write(`${randomBytes(16).toString('hex')}\n`);
    return;
  }
  if (command === 'create-authority') {
    const passphrase = process.env.HYPHA_VENUE_KEY_PASSPHRASE;
    if (!passphrase) throw new Error('Set HYPHA_VENUE_KEY_PASSPHRASE before creating an authority.');
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privatePem = pair.privateKey.export({
      format: 'pem',
      type: 'pkcs8',
      cipher: 'aes-256-cbc',
      passphrase,
    });
    const publicPem = pair.publicKey.export({ format: 'pem', type: 'spki' });
    writeFileSync(required(options, 'private'), privatePem, { flag: 'wx', mode: 0o600 });
    writeFileSync(required(options, 'public'), publicPem, { flag: 'wx', mode: 0o644 });
    process.stdout.write('Created an encrypted offline P-256 venue authority.\n');
    return;
  }
  if (command === 'create-inventory') {
    const authorityPrivateKey = readAuthorityPrivate(required(options, 'private'));
    const nodes = JSON.parse(readFileSync(required(options, 'nodes'), 'utf8'));
    const encoded = buildInventory({
      authorityPrivateKey,
      venueId: Buffer.from(required(options, 'venue-id'), 'hex'),
      version: required(options, 'version'),
      entries: nodes,
    });
    writeFileSync(required(options, 'out'), encoded, { flag: 'wx' });
    process.stdout.write(`${JSON.stringify(parseInventory(encoded), null, 2)}\n`);
    return;
  }
  if (command === 'inspect') {
    process.stdout.write(`${JSON.stringify(parseInventory(readFileSync(required(options, 'inventory'))), null, 2)}\n`);
    return;
  }
  if (command === 'serial-script') {
    const encoded = readFileSync(required(options, 'inventory'));
    const commands = serialProvisioningCommands(encoded);
    writeFileSync(required(options, 'out'), `${commands.join('\r\n')}\r\n`, { flag: 'wx' });
    process.stdout.write(`Created ${commands.length} bounded serial commands.\n`);
    return;
  }
  throw new Error(`Unknown command: ${command}\n${usage()}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`ERROR ${error.message}\n`);
    process.exitCode = 1;
  }
}
