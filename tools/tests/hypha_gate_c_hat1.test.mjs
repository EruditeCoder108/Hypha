import assert from 'node:assert/strict';
import test from 'node:test';

import {
  HAT1_BYTES,
  HAT1_CLASS,
  HAT1_HEADER_BYTES,
  encodeHat1,
  encodeHat1Header,
  hat1TokenChallenge,
  parseHat1Header,
  rly1AdmissionCommitment,
  verifyHat1,
} from '../hypha_gate_c_hat1.mjs';
import {
  encodedRly1,
  hat1Header,
  initialCopyBudget,
  issuerPublicKeySpki,
  operatorEpoch,
  token,
  tokenChallenge,
  venueId,
} from './fixtures/hypha_hat1_blind_issuance_vector_1.mjs';

const encodedHat1 = encodeHat1(hat1Header, token);

function verify(overrides = {}) {
  return verifyHat1({
    encodedHat1,
    encodedRly1,
    issuerPublicKeySpki,
    expectedVenueId: venueId,
    expectedOperatorEpoch: operatorEpoch,
    expectedObjectClass: HAT1_CLASS.TEXT,
    initialDeposit: true,
    ...overrides,
  });
}

function changed(source, index) {
  const result = Buffer.from(source);
  result[index] ^= 1;
  return result;
}

test('blind-issued HAT1 golden vector is byte-exact and verifies', () => {
  assert.equal(hat1Header.length, HAT1_HEADER_BYTES);
  assert.equal(encodedHat1.length, HAT1_BYTES);
  assert.deepEqual(
    encodeHat1Header({
      objectClass: HAT1_CLASS.TEXT,
      venueId,
      operatorEpoch,
      initialCopyBudget,
      encodedRly1,
    }),
    hat1Header,
  );
  assert.deepEqual(hat1TokenChallenge(hat1Header), tokenChallenge);
  assert.deepEqual(verify(), { ok: true, reason: 'accepted' });
});

test('safe portable routing mutations preserve the immutable binding', () => {
  const forwarded = Buffer.from(encodedRly1);
  forwarded.writeBigUInt64BE(10_000n, 48);
  forwarded[57] = 2;
  forwarded.writeUInt16BE(2, 58);
  assert.deepEqual(
    rly1AdmissionCommitment(forwarded, initialCopyBudget),
    rly1AdmissionCommitment(encodedRly1, initialCopyBudget),
  );
  assert.deepEqual(verify({ encodedRly1: forwarded, initialDeposit: false }), {
    ok: true,
    reason: 'accepted',
  });
  assert.deepEqual(verify({ encodedRly1: forwarded }), {
    ok: false,
    reason: 'non_initial_deposit',
  });
});

test('immutable envelope changes cannot reuse a ticket', () => {
  for (const offset of [8, 24, 40, 56, 64]) {
    assert.equal(verify({ encodedRly1: changed(encodedRly1, offset) }).ok, false);
  }
});

test('copy rollback and malformed routing state fail before token verification', () => {
  const rolledBack = Buffer.from(encodedRly1);
  rolledBack.writeUInt16BE(initialCopyBudget + 1, 58);
  assert.deepEqual(verify({ encodedRly1: rolledBack, initialDeposit: false }), {
    ok: false,
    reason: 'copy_budget_rollback',
  });
  const badHops = Buffer.from(encodedRly1);
  badHops[57] = badHops[56] + 1;
  assert.deepEqual(verify({ encodedRly1: badHops }), {
    ok: false,
    reason: 'rly1_hops',
  });
});

test('venue, monotonic epoch, and class-specific issuer policy fail closed', () => {
  assert.deepEqual(verify({ expectedVenueId: Buffer.alloc(16, 9) }), {
    ok: false,
    reason: 'wrong_venue',
  });
  assert.deepEqual(verify({ expectedOperatorEpoch: operatorEpoch + 1n }), {
    ok: false,
    reason: 'wrong_epoch',
  });
  assert.deepEqual(verify({ expectedObjectClass: HAT1_CLASS.RECIPIENT_RECEIPT }), {
    ok: false,
    reason: 'wrong_class_key',
  });
});

test('forged class priority, reserved bytes, and security-control grants are rejected', () => {
  assert.deepEqual(parseHat1Header(changed(hat1Header, 6)), {
    ok: false,
    reason: 'hat1_priority',
  });
  assert.deepEqual(parseHat1Header(changed(hat1Header, 34)), {
    ok: false,
    reason: 'hat1_reserved',
  });
  const controlRly1 = Buffer.from(encodedRly1);
  controlRly1[5] = 0;
  assert.throws(
    () => encodeHat1Header({
      objectClass: 0,
      venueId,
      operatorEpoch,
      initialCopyBudget,
      encodedRly1: controlRly1,
    }),
    /unsupported public admission class/,
  );
});

test('header, challenge, key, and authenticator mutations are rejected', () => {
  assert.equal(verify({ encodedHat1: changed(encodedHat1, 36) }).ok, false);
  assert.deepEqual(verify({ issuerPublicKeySpki: changed(issuerPublicKeySpki, 100) }), {
    ok: false,
    reason: 'key_id_mismatch',
  });
  assert.deepEqual(verify({ encodedHat1: changed(encodedHat1, encodedHat1.length - 1) }), {
    ok: false,
    reason: 'invalid_signature',
  });
});
