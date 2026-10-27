import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import {
  buildInventory,
  nodeFingerprint,
  parseInventory,
  rawPublicKey,
  serialProvisioningCommands,
} from '../hypha_venue_operator.mjs';

function keyPair() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

function entry(pair, status) {
  return { publicKey: rawPublicKey(pair.publicKey).toString('hex'), role: 'courier', status };
}

test('HVI1 signs sorted active revoked and replaced node decisions', () => {
  const authority = keyPair();
  const active = keyPair();
  const revoked = keyPair();
  const replaced = keyPair();
  const encoded = buildInventory({
    authorityPrivateKey: authority.privateKey,
    venueId: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
    version: 7,
    entries: [entry(replaced, 'replaced'), entry(active, 'active'), entry(revoked, 'revoked')],
  });
  const parsed = parseInventory(encoded);
  assert.equal(parsed.version, '7');
  assert.deepEqual(new Set(parsed.entries.map(({ status }) => status)), new Set(['active', 'revoked', 'replaced']));
  assert.ok(parsed.entries.every(({ fingerprint }) => fingerprint.startsWith('NODE-')));
  assert.equal(nodeFingerprint(rawPublicKey(active.publicKey)).split('-').length, 33);
});

test('HVI1 rejects tampering duplicate keys and inventories without an active courier', () => {
  const authority = keyPair();
  const active = keyPair();
  const base = {
    authorityPrivateKey: authority.privateKey,
    venueId: Buffer.alloc(16, 3),
    version: 1,
  };
  const encoded = buildInventory({ ...base, entries: [entry(active, 'active')] });
  const tampered = Buffer.from(encoded);
  tampered[16] ^= 1;
  assert.throws(() => parseInventory(tampered), /signature/i);
  assert.throws(
    () => buildInventory({ ...base, entries: [entry(active, 'active'), entry(active, 'revoked')] }),
    /unique/i,
  );
  assert.throws(
    () => buildInventory({ ...base, entries: [entry(keyPair(), 'revoked')] }),
    /active courier/i,
  );
});

test('serial provisioning script is bounded and reconstructs the exact signed inventory', () => {
  const authority = keyPair();
  const active = keyPair();
  const encoded = buildInventory({
    authorityPrivateKey: authority.privateKey,
    venueId: Buffer.alloc(16, 9),
    version: 1,
    entries: [entry(active, 'active')],
  });
  const commands = serialProvisioningCommands(encoded);
  assert.equal(commands[0], `VENUE_BEGIN ${encoded.length}`);
  assert.equal(commands.at(-2), 'VENUE_COMMIT');
  assert.equal(commands.at(-1), 'VENUE_STATUS');
  assert.ok(commands.every((command) => command.length <= 97));
  const reconstructed = Buffer.concat(
    commands
      .filter((command) => command.startsWith('VENUE_CHUNK '))
      .map((command) => Buffer.from(command.slice('VENUE_CHUNK '.length), 'hex')),
  );
  assert.deepEqual(reconstructed, encoded);
});
