import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CURRENT_ESP_MAX_RECORD_BYTES,
  CURRENT_MAX_TYPED_REPLY_RLY1_BYTES,
  arcP256PresentationBytes,
  hat1Bytes,
  inlineBudget,
  rfc9578BlindRsaTokenBytes,
} from '../hypha_gate_c_candidate_budget.mjs';

test('RFC 9578 public Blind RSA token is exactly 354 bytes', () => {
  assert.equal(rfc9578BlindRsaTokenBytes(), 354);
});

test('selected HAT1 sidecar is 422 bytes and needs a reviewed record ceiling', () => {
  assert.equal(hat1Bytes(), 422);
  assert.deepEqual(
    inlineBudget(
      CURRENT_MAX_TYPED_REPLY_RLY1_BYTES,
      hat1Bytes(),
      CURRENT_ESP_MAX_RECORD_BYTES,
    ),
    { totalBytes: 4618, fits: false, remainingBytes: -266 },
  );
});

test('current maximum typed reply cannot carry an inline RFC 9578 token', () => {
  assert.deepEqual(
    inlineBudget(
      CURRENT_MAX_TYPED_REPLY_RLY1_BYTES,
      rfc9578BlindRsaTokenBytes(),
      CURRENT_ESP_MAX_RECORD_BYTES,
    ),
    { totalBytes: 4550, fits: false, remainingBytes: -198 },
  );
});

test('current record ceiling leaves at most 3998 bytes for RLY1 with that token', () => {
  const maximumRly1Bytes = CURRENT_ESP_MAX_RECORD_BYTES - rfc9578BlindRsaTokenBytes();
  assert.equal(maximumRly1Bytes, 3998);
  assert.equal(inlineBudget(maximumRly1Bytes, 354, 4352).fits, true);
});

test('ARC draft presentation formula is explicit and larger for useful limits', () => {
  assert.equal(arcP256PresentationBytes(1), 357);
  assert.equal(arcP256PresentationBytes(2), 486);
  assert.equal(arcP256PresentationBytes(8), 744);
  assert.equal(arcP256PresentationBytes(16), 873);
  assert.throws(() => arcP256PresentationBytes(0), /positive safe integer/);
});
