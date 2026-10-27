import {
  constants,
  createHash,
  createPublicKey,
  verify,
} from 'node:crypto';

export const RFC9578_BLIND_RSA_TOKEN_TYPE = 0x0002;
export const RFC9578_BLIND_RSA_TOKEN_BYTES = 354;

const TYPE_BYTES = 2;
const NONCE_BYTES = 32;
const DIGEST_BYTES = 32;
const KEY_ID_BYTES = 32;
const AUTHENTICATOR_BYTES = 256;

export function parseRfc9578BlindRsaToken(encoded) {
  if (!Buffer.isBuffer(encoded) || encoded.length !== RFC9578_BLIND_RSA_TOKEN_BYTES) {
    return { ok: false, reason: 'invalid_length' };
  }
  const tokenType = encoded.readUInt16BE(0);
  if (tokenType !== RFC9578_BLIND_RSA_TOKEN_TYPE) {
    return { ok: false, reason: 'unsupported_type' };
  }
  let offset = TYPE_BYTES;
  const nonce = encoded.subarray(offset, offset += NONCE_BYTES);
  const challengeDigest = encoded.subarray(offset, offset += DIGEST_BYTES);
  const tokenKeyId = encoded.subarray(offset, offset += KEY_ID_BYTES);
  const authenticator = encoded.subarray(offset, offset + AUTHENTICATOR_BYTES);
  return {
    ok: true,
    tokenType,
    nonce,
    challengeDigest,
    tokenKeyId,
    authenticator,
    authenticatorInput: encoded.subarray(0, TYPE_BYTES + NONCE_BYTES + DIGEST_BYTES + KEY_ID_BYTES),
  };
}

export function verifyRfc9578BlindRsaToken({
  token,
  issuerPublicKeySpki,
  tokenChallenge,
}) {
  const parsed = parseRfc9578BlindRsaToken(token);
  if (!parsed.ok) return parsed;
  if (!Buffer.isBuffer(issuerPublicKeySpki) || issuerPublicKeySpki.length === 0) {
    return { ok: false, reason: 'invalid_key' };
  }
  if (!Buffer.isBuffer(tokenChallenge)) {
    return { ok: false, reason: 'invalid_challenge' };
  }

  const expectedChallengeDigest = createHash('sha256').update(tokenChallenge).digest();
  if (!expectedChallengeDigest.equals(parsed.challengeDigest)) {
    return { ok: false, reason: 'challenge_mismatch' };
  }
  const expectedKeyId = createHash('sha256').update(issuerPublicKeySpki).digest();
  if (!expectedKeyId.equals(parsed.tokenKeyId)) {
    return { ok: false, reason: 'key_id_mismatch' };
  }

  let publicKey;
  try {
    publicKey = createPublicKey({ key: issuerPublicKeySpki, format: 'der', type: 'spki' });
  } catch {
    return { ok: false, reason: 'invalid_key' };
  }
  let validSignature = false;
  try {
    validSignature = verify(
      'sha384',
      parsed.authenticatorInput,
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 48,
      },
      parsed.authenticator,
    );
  } catch {
    return { ok: false, reason: 'verification_failure' };
  }
  return validSignature
    ? { ok: true, reason: 'accepted' }
    : { ok: false, reason: 'invalid_signature' };
}
