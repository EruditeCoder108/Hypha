/// Returns a compact six-digit short authentication string derived from the
/// authenticated, symmetric SHA-256 safety fingerprint produced natively.
///
/// Both phones receive the same fingerprint because the native layer hashes
/// the two persistent public keys in unsigned sorted order. The six digits are
/// a convenient in-person comparison, while the full fingerprint remains
/// available for higher-assurance verification.
String shortSafetyCode(String fingerprint) {
  final normalized = fingerprint
      .replaceAll(RegExp('[^0-9A-Fa-f]'), '')
      .toUpperCase();

  final BigInt material;
  if (normalized.isNotEmpty) {
    material = BigInt.parse(normalized, radix: 16);
  } else {
    // Defensive compatibility for malformed diagnostic fixtures. Production
    // identity fingerprints are always hexadecimal SHA-256 values.
    var hash = 0x811c9dc5;
    for (final unit in fingerprint.codeUnits) {
      hash ^= unit;
      hash = (hash * 0x01000193) & 0x7FFFFFFF;
    }
    material = BigInt.from(hash);
  }

  final digits = (material % BigInt.from(1000000)).toString().padLeft(6, '0');
  return '${digits.substring(0, 2)} ${digits.substring(2, 4)} ${digits.substring(4, 6)}';
}
