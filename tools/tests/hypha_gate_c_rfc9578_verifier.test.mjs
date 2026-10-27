import assert from 'node:assert/strict';
import test from 'node:test';
import {
  RFC9578_BLIND_RSA_TOKEN_BYTES,
  parseRfc9578BlindRsaToken,
  verifyRfc9578BlindRsaToken,
} from '../hypha_gate_c_rfc9578_verifier.mjs';
import {
  issuerPublicKeySpki,
  token,
  tokenChallenge,
} from './fixtures/rfc9578_blind_rsa_vector_1.mjs';

function verify(overrides = {}) {
  return verifyRfc9578BlindRsaToken({
    token,
    issuerPublicKeySpki,
    tokenChallenge,
    ...overrides,
  });
}

function changed(source, index) {
  const result = Buffer.from(source);
  result[index] ^= 0x01;
  return result;
}

test('official RFC 9578 Blind RSA vector parses and verifies', () => {
  assert.equal(token.length, RFC9578_BLIND_RSA_TOKEN_BYTES);
  assert.equal(issuerPublicKeySpki.length, 342);
  assert.deepEqual(verify(), { ok: true, reason: 'accepted' });
});

test('wrong length and token type fail before cryptographic work', () => {
  assert.deepEqual(parseRfc9578BlindRsaToken(token.subarray(0, -1)), {
    ok: false,
    reason: 'invalid_length',
  });
  assert.deepEqual(verify({ token: changed(token, 1) }), {
    ok: false,
    reason: 'unsupported_type',
  });
});

test('challenge mutation fails closed', () => {
  assert.deepEqual(verify({ tokenChallenge: changed(tokenChallenge, 5) }), {
    ok: false,
    reason: 'challenge_mismatch',
  });
});

test('key-id mutation fails before signature acceptance', () => {
  assert.deepEqual(verify({ token: changed(token, 2 + 32 + 32) }), {
    ok: false,
    reason: 'key_id_mismatch',
  });
});

test('authenticator mutation is rejected as an invalid signature', () => {
  assert.deepEqual(verify({ token: changed(token, token.length - 1) }), {
    ok: false,
    reason: 'invalid_signature',
  });
});

test('invalid key and challenge inputs return bounded errors', () => {
  assert.deepEqual(verify({ issuerPublicKeySpki: Buffer.alloc(0) }), {
    ok: false,
    reason: 'invalid_key',
  });
  assert.deepEqual(verify({ tokenChallenge: 'not-bytes' }), {
    ok: false,
    reason: 'invalid_challenge',
  });
});
