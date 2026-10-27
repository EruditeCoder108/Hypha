/**
 * Deterministic byte-budget calculations for ADR 0011 research candidates.
 *
 * This is not a token parser, verifier, wire format, or production parameter
 * selection. Constants mirror the cited RFC/draft and current ESP record bounds
 * so feasibility assumptions fail visibly when they do not fit.
 */

export const CURRENT_ESP_MAX_RECORD_BYTES = 4352;
export const CURRENT_MAX_TYPED_REPLY_RLY1_BYTES = 4196;
export const HAT1_HEADER_BYTES = 68;

export function rfc9578BlindRsaTokenBytes() {
  return 2 + 32 + 32 + 32 + 256;
}

export function hat1Bytes() {
  return HAT1_HEADER_BYTES + rfc9578BlindRsaTokenBytes();
}

export function arcP256PresentationBytes(presentationLimit) {
  if (!Number.isSafeInteger(presentationLimit) || presentationLimit < 1) {
    throw new Error('Presentation limit must be a positive safe integer.');
  }
  const elementBytes = 33;
  const scalarBytes = 32;
  const rangeBits = Math.ceil(Math.log2(presentationLimit));
  const proofBytes = rangeBits * elementBytes
    + (6 + 3 * rangeBits) * scalarBytes;
  return 5 * elementBytes + proofBytes;
}

export function inlineBudget(recordBytes, authorizationBytes, ceilingBytes) {
  for (const [label, value] of Object.entries({ recordBytes, authorizationBytes, ceilingBytes })) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer.`);
    }
  }
  const totalBytes = recordBytes + authorizationBytes;
  return {
    totalBytes,
    fits: totalBytes <= ceilingBytes,
    remainingBytes: ceilingBytes - totalBytes,
  };
}
