import { createHash, timingSafeEqual } from 'node:crypto';

import {
  RFC9578_BLIND_RSA_TOKEN_BYTES,
  verifyRfc9578BlindRsaToken,
} from './hypha_gate_c_rfc9578_verifier.mjs';

export const HAT1_MAGIC = Buffer.from('HAT1', 'ascii');
export const HAT1_VERSION = 1;
export const HAT1_HEADER_BYTES = 68;
export const HAT1_BYTES = HAT1_HEADER_BYTES + RFC9578_BLIND_RSA_TOKEN_BYTES;
export const HAT1_ISSUER_NAME = 'admission.hypha.invalid';

export const HAT1_CLASS = Object.freeze({
  RECIPIENT_RECEIPT: 1,
  TEXT: 2,
  MANIFEST: 3,
  BULK: 4,
});

export const HAT1_CLASS_PRIORITY = Object.freeze({
  [HAT1_CLASS.RECIPIENT_RECEIPT]: 0,
  [HAT1_CLASS.TEXT]: 2,
  [HAT1_CLASS.MANIFEST]: 4,
  [HAT1_CLASS.BULK]: 5,
});

const RLY1_HEADER_BYTES = 64;
const RLY1_MAX_CIPHERTEXT_BYTES = 64 * 1024;
const RLY1_MAX_LIFETIME_MS = 30n * 24n * 60n * 60n * 1000n;
const RLY1_MAX_COPY_BUDGET = 64;
const BINDING_DOMAIN = Buffer.from('Hypha/RLY1-admission-binding/v1\0', 'ascii');

function sha256(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function fixedBuffer(value, bytes, label) {
  if (!Buffer.isBuffer(value) || value.length !== bytes) {
    throw new TypeError(`${label} must contain exactly ${bytes} bytes`);
  }
  return value;
}

function canonicalIssuerName(issuerName) {
  if (issuerName !== HAT1_ISSUER_NAME) {
    throw new TypeError(`issuerName must be ${HAT1_ISSUER_NAME}`);
  }
  return Buffer.from(issuerName, 'ascii');
}

export function parseRly1ForAdmission(encoded) {
  if (!Buffer.isBuffer(encoded) || encoded.length < RLY1_HEADER_BYTES) {
    return { ok: false, reason: 'rly1_truncated' };
  }
  if (!encoded.subarray(0, 4).equals(Buffer.from('RLY1', 'ascii'))) {
    return { ok: false, reason: 'rly1_magic' };
  }
  if (encoded[4] !== 1 || encoded[6] !== 0 || encoded[7] !== 0) {
    return { ok: false, reason: 'rly1_header' };
  }
  if (encoded[5] > 5) return { ok: false, reason: 'rly1_priority' };

  const lifetimeMs = encoded.readBigUInt64BE(40);
  const ageMs = encoded.readBigUInt64BE(48);
  const hopLimit = encoded[56];
  const hopsTaken = encoded[57];
  const copyBudget = encoded.readUInt16BE(58);
  const ciphertextBytes = encoded.readUInt32BE(60);
  if (lifetimeMs === 0n || lifetimeMs > RLY1_MAX_LIFETIME_MS || ageMs > lifetimeMs) {
    return { ok: false, reason: 'rly1_lifetime' };
  }
  if (hopLimit === 0 || hopsTaken > hopLimit) {
    return { ok: false, reason: 'rly1_hops' };
  }
  if (copyBudget === 0 || copyBudget > RLY1_MAX_COPY_BUDGET) {
    return { ok: false, reason: 'rly1_copy_budget' };
  }
  if (
    ciphertextBytes === 0 ||
    ciphertextBytes > RLY1_MAX_CIPHERTEXT_BYTES ||
    encoded.length !== RLY1_HEADER_BYTES + ciphertextBytes
  ) {
    return { ok: false, reason: 'rly1_length' };
  }
  return {
    ok: true,
    priority: encoded[5],
    lifetimeMs,
    ageMs,
    hopLimit,
    hopsTaken,
    copyBudget,
    ciphertextBytes,
    ciphertext: encoded.subarray(RLY1_HEADER_BYTES),
  };
}

export function rly1AdmissionCommitment(encodedRly1, initialCopyBudget) {
  const parsed = parseRly1ForAdmission(encodedRly1);
  if (!parsed.ok) throw new TypeError(parsed.reason);
  if (
    !Number.isInteger(initialCopyBudget) ||
    initialCopyBudget < 1 ||
    initialCopyBudget > RLY1_MAX_COPY_BUDGET ||
    parsed.copyBudget > initialCopyBudget
  ) {
    throw new TypeError('invalid initial copy budget');
  }
  const initialCopyBytes = Buffer.alloc(2);
  initialCopyBytes.writeUInt16BE(initialCopyBudget);
  return sha256(
    BINDING_DOMAIN,
    encodedRly1.subarray(0, 48),
    encodedRly1.subarray(56, 57),
    initialCopyBytes,
    encodedRly1.subarray(60, 64),
    sha256(parsed.ciphertext),
  );
}

export function encodeHat1Header({
  objectClass,
  venueId,
  operatorEpoch,
  initialCopyBudget,
  encodedRly1,
}) {
  const priority = HAT1_CLASS_PRIORITY[objectClass];
  if (priority === undefined) throw new TypeError('unsupported public admission class');
  fixedBuffer(venueId, 16, 'venueId');
  if (typeof operatorEpoch !== 'bigint' || operatorEpoch < 1n || operatorEpoch > 0xffffffffffffffffn) {
    throw new TypeError('operatorEpoch must be a positive uint64');
  }
  const parsed = parseRly1ForAdmission(encodedRly1);
  if (!parsed.ok) throw new TypeError(parsed.reason);
  if (parsed.priority !== priority) throw new TypeError('class and RLY1 priority do not match');

  const output = Buffer.alloc(HAT1_HEADER_BYTES);
  HAT1_MAGIC.copy(output, 0);
  output[4] = HAT1_VERSION;
  output[5] = objectClass;
  output[6] = priority;
  output[7] = 0;
  venueId.copy(output, 8);
  output.writeBigUInt64BE(operatorEpoch, 24);
  output.writeUInt16BE(initialCopyBudget, 32);
  output.writeUInt16BE(0, 34);
  rly1AdmissionCommitment(encodedRly1, initialCopyBudget).copy(output, 36);
  return output;
}

export function parseHat1Header(header) {
  if (!Buffer.isBuffer(header) || header.length !== HAT1_HEADER_BYTES) {
    return { ok: false, reason: 'hat1_header_length' };
  }
  if (!header.subarray(0, 4).equals(HAT1_MAGIC)) return { ok: false, reason: 'hat1_magic' };
  if (header[4] !== HAT1_VERSION) return { ok: false, reason: 'hat1_version' };
  const objectClass = header[5];
  const priority = HAT1_CLASS_PRIORITY[objectClass];
  if (priority === undefined) return { ok: false, reason: 'hat1_class' };
  if (header[6] !== priority) return { ok: false, reason: 'hat1_priority' };
  if (header[7] !== 0 || header[34] !== 0 || header[35] !== 0) {
    return { ok: false, reason: 'hat1_reserved' };
  }
  const operatorEpoch = header.readBigUInt64BE(24);
  const initialCopyBudget = header.readUInt16BE(32);
  if (operatorEpoch === 0n) return { ok: false, reason: 'hat1_epoch' };
  if (initialCopyBudget < 1 || initialCopyBudget > RLY1_MAX_COPY_BUDGET) {
    return { ok: false, reason: 'hat1_copy_budget' };
  }
  return {
    ok: true,
    objectClass,
    priority,
    venueId: header.subarray(8, 24),
    operatorEpoch,
    initialCopyBudget,
    envelopeCommitment: header.subarray(36, 68),
  };
}

export function hat1TokenChallenge(header, issuerName = HAT1_ISSUER_NAME) {
  const parsed = parseHat1Header(header);
  if (!parsed.ok) throw new TypeError(parsed.reason);
  const issuer = canonicalIssuerName(issuerName);
  const output = Buffer.alloc(2 + 2 + issuer.length + 1 + 32 + 2);
  let offset = 0;
  output.writeUInt16BE(0x0002, offset);
  offset += 2;
  output.writeUInt16BE(issuer.length, offset);
  offset += 2;
  issuer.copy(output, offset);
  offset += issuer.length;
  output[offset++] = 32;
  sha256(header).copy(output, offset);
  offset += 32;
  output.writeUInt16BE(0, offset);
  return output;
}

export function encodeHat1(header, token) {
  fixedBuffer(header, HAT1_HEADER_BYTES, 'HAT1 header');
  fixedBuffer(token, RFC9578_BLIND_RSA_TOKEN_BYTES, 'RFC 9578 token');
  return Buffer.concat([header, token]);
}

export function verifyHat1({
  encodedHat1,
  encodedRly1,
  issuerPublicKeySpki,
  expectedVenueId,
  expectedOperatorEpoch,
  expectedObjectClass,
  initialDeposit = false,
}) {
  if (!Buffer.isBuffer(encodedHat1) || encodedHat1.length !== HAT1_BYTES) {
    return { ok: false, reason: 'hat1_length' };
  }
  const header = encodedHat1.subarray(0, HAT1_HEADER_BYTES);
  const parsedHeader = parseHat1Header(header);
  if (!parsedHeader.ok) return parsedHeader;
  const parsedRly1 = parseRly1ForAdmission(encodedRly1);
  if (!parsedRly1.ok) return parsedRly1;
  if (!Buffer.isBuffer(expectedVenueId) || expectedVenueId.length !== 16) {
    return { ok: false, reason: 'policy_venue' };
  }
  if (!timingSafeEqual(parsedHeader.venueId, expectedVenueId)) {
    return { ok: false, reason: 'wrong_venue' };
  }
  if (parsedHeader.operatorEpoch !== expectedOperatorEpoch) {
    return { ok: false, reason: 'wrong_epoch' };
  }
  if (parsedHeader.objectClass !== expectedObjectClass) {
    return { ok: false, reason: 'wrong_class_key' };
  }
  if (parsedRly1.priority !== parsedHeader.priority) {
    return { ok: false, reason: 'priority_mismatch' };
  }
  if (parsedRly1.copyBudget > parsedHeader.initialCopyBudget) {
    return { ok: false, reason: 'copy_budget_rollback' };
  }
  if (
    initialDeposit &&
    (parsedRly1.ageMs !== 0n ||
      parsedRly1.hopsTaken !== 0 ||
      parsedRly1.copyBudget !== parsedHeader.initialCopyBudget)
  ) {
    return { ok: false, reason: 'non_initial_deposit' };
  }
  let commitment;
  try {
    commitment = rly1AdmissionCommitment(encodedRly1, parsedHeader.initialCopyBudget);
  } catch {
    return { ok: false, reason: 'binding_input' };
  }
  if (!timingSafeEqual(commitment, parsedHeader.envelopeCommitment)) {
    return { ok: false, reason: 'envelope_mismatch' };
  }
  const tokenResult = verifyRfc9578BlindRsaToken({
    token: encodedHat1.subarray(HAT1_HEADER_BYTES),
    issuerPublicKeySpki,
    tokenChallenge: hat1TokenChallenge(header),
  });
  return tokenResult.ok ? { ok: true, reason: 'accepted' } : tokenResult;
}
