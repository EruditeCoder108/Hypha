package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec

/** Isolated Gate C HAT1 feasibility verifier. It is not wired into live relay admission. */
internal object HyphaAdmissionTicket {
    const val HEADER_BYTES = 68
    const val TOKEN_BYTES = 354
    const val ENCODED_BYTES = HEADER_BYTES + TOKEN_BYTES
    const val CLASS_RECIPIENT_RECEIPT = 1
    const val CLASS_TEXT = 2
    const val CLASS_MANIFEST = 3
    const val CLASS_BULK = 4

    private const val MAX_CIPHERTEXT_BYTES = 64 * 1024
    private const val MAX_COPY_BUDGET = 64
    private const val MAX_LIFETIME_MS = 30L * 24L * 60L * 60L * 1_000L
    private const val ISSUER_NAME = "admission.hypha.invalid"
    private val HAT1_MAGIC = "HAT1".toByteArray(Charsets.US_ASCII)
    private val RLY1_MAGIC = "RLY1".toByteArray(Charsets.US_ASCII)
    private val BINDING_DOMAIN = "Hypha/RLY1-admission-binding/v1\u0000".toByteArray(Charsets.US_ASCII)

    data class Verification(val accepted: Boolean, val reason: String)

    private data class Header(
        val objectClass: Int,
        val priority: Int,
        val venueId: ByteArray,
        val operatorEpoch: Long,
        val initialCopyBudget: Int,
        val envelopeCommitment: ByteArray,
    )

    private data class Envelope(
        val priority: Int,
        val ageMs: Long,
        val hopLimit: Int,
        val hopsTaken: Int,
        val copyBudget: Int,
        val ciphertext: ByteArray,
    )

    fun verify(
        encodedHat1: ByteArray,
        encodedRly1: ByteArray,
        issuerPublicKeySpki: ByteArray,
        expectedVenueId: ByteArray,
        expectedOperatorEpoch: Long,
        expectedObjectClass: Int,
        initialDeposit: Boolean,
    ): Verification {
        if (encodedHat1.size != ENCODED_BYTES) return rejected("hat1_length")
        val headerBytes = encodedHat1.copyOfRange(0, HEADER_BYTES)
        val header = parseHeader(headerBytes) ?: return rejected(headerFailure(headerBytes))
        val envelope = parseEnvelope(encodedRly1) ?: return rejected(envelopeFailure(encodedRly1))
        if (expectedVenueId.size != 16) return rejected("policy_venue")
        if (!MessageDigest.isEqual(header.venueId, expectedVenueId)) return rejected("wrong_venue")
        if (header.operatorEpoch != expectedOperatorEpoch) return rejected("wrong_epoch")
        if (header.objectClass != expectedObjectClass) return rejected("wrong_class_key")
        if (header.priority != envelope.priority) return rejected("priority_mismatch")
        if (envelope.copyBudget > header.initialCopyBudget) return rejected("copy_budget_rollback")
        if (
            initialDeposit &&
            (envelope.ageMs != 0L || envelope.hopsTaken != 0 ||
                envelope.copyBudget != header.initialCopyBudget)
        ) {
            return rejected("non_initial_deposit")
        }
        val commitment = envelopeCommitment(encodedRly1, envelope, header.initialCopyBudget)
        if (!MessageDigest.isEqual(commitment, header.envelopeCommitment)) {
            return rejected("envelope_mismatch")
        }
        return verifyToken(
            encodedHat1.copyOfRange(HEADER_BYTES, encodedHat1.size),
            tokenChallenge(headerBytes),
            issuerPublicKeySpki,
        )
    }

    internal fun tokenChallenge(header: ByteArray): ByteArray {
        require(parseHeader(header) != null) { "invalid HAT1 header" }
        val issuer = ISSUER_NAME.toByteArray(Charsets.US_ASCII)
        return ByteBuffer.allocate(2 + 2 + issuer.size + 1 + 32 + 2)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(2)
            .putShort(issuer.size.toShort())
            .put(issuer)
            .put(32)
            .put(sha256(header))
            .putShort(0)
            .array()
    }

    private fun verifyToken(token: ByteArray, challenge: ByteArray, spki: ByteArray): Verification {
        if (token.size != TOKEN_BYTES) return rejected("invalid_length")
        val input = ByteBuffer.wrap(token).order(ByteOrder.BIG_ENDIAN)
        if (input.short.toInt() and 0xffff != 2) return rejected("unsupported_type")
        input.position(input.position() + 32)
        val challengeDigest = ByteArray(32).also(input::get)
        if (!MessageDigest.isEqual(challengeDigest, sha256(challenge))) {
            return rejected("challenge_mismatch")
        }
        val keyId = ByteArray(32).also(input::get)
        if (!MessageDigest.isEqual(keyId, sha256(spki))) return rejected("key_id_mismatch")
        return try {
            val keySpec = X509EncodedKeySpec(spki)
            val publicKey = try {
                KeyFactory.getInstance("RSASSA-PSS").generatePublic(keySpec)
            } catch (_: Exception) {
                KeyFactory.getInstance("RSA").generatePublic(keySpec)
            }
            val verifier = Signature.getInstance("RSASSA-PSS")
            verifier.initVerify(publicKey)
            verifier.setParameter(
                PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1),
            )
            verifier.update(token, 0, 98)
            if (verifier.verify(token, 98, 256)) accepted() else rejected("invalid_signature")
        } catch (_: Exception) {
            rejected("verification_failure")
        }
    }

    private fun parseHeader(header: ByteArray): Header? {
        if (header.size != HEADER_BYTES || !header.copyOfRange(0, 4).contentEquals(HAT1_MAGIC)) {
            return null
        }
        if (header[4].toInt() and 0xff != 1) return null
        val objectClass = header[5].toInt() and 0xff
        val priority = classPriority(objectClass) ?: return null
        if (header[6].toInt() and 0xff != priority) return null
        if (header[7].toInt() != 0 || header[34].toInt() != 0 || header[35].toInt() != 0) {
            return null
        }
        val input = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val epoch = input.getLong(24)
        val initialCopyBudget = input.getShort(32).toInt() and 0xffff
        if (epoch <= 0 || initialCopyBudget !in 1..MAX_COPY_BUDGET) return null
        return Header(
            objectClass = objectClass,
            priority = priority,
            venueId = header.copyOfRange(8, 24),
            operatorEpoch = epoch,
            initialCopyBudget = initialCopyBudget,
            envelopeCommitment = header.copyOfRange(36, 68),
        )
    }

    private fun parseEnvelope(encoded: ByteArray): Envelope? {
        if (encoded.size < 64 || !encoded.copyOfRange(0, 4).contentEquals(RLY1_MAGIC)) return null
        if (encoded[4].toInt() and 0xff != 1 || encoded[6].toInt() != 0 || encoded[7].toInt() != 0) {
            return null
        }
        val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val priority = encoded[5].toInt() and 0xff
        val lifetimeMs = input.getLong(40)
        val ageMs = input.getLong(48)
        val hopLimit = encoded[56].toInt() and 0xff
        val hopsTaken = encoded[57].toInt() and 0xff
        val copyBudget = input.getShort(58).toInt() and 0xffff
        val ciphertextBytes = input.getInt(60)
        if (priority !in 0..5) return null
        if (lifetimeMs !in 1..MAX_LIFETIME_MS || ageMs < 0 || ageMs > lifetimeMs) return null
        if (hopLimit == 0 || hopsTaken > hopLimit) return null
        if (copyBudget !in 1..MAX_COPY_BUDGET) return null
        if (ciphertextBytes !in 1..MAX_CIPHERTEXT_BYTES || encoded.size != 64 + ciphertextBytes) {
            return null
        }
        return Envelope(
            priority,
            ageMs,
            hopLimit,
            hopsTaken,
            copyBudget,
            encoded.copyOfRange(64, encoded.size),
        )
    }

    private fun envelopeCommitment(
        encoded: ByteArray,
        envelope: Envelope,
        initialCopyBudget: Int,
    ): ByteArray {
        val initialCopy = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
            .putShort(initialCopyBudget.toShort()).array()
        return sha256(
            BINDING_DOMAIN,
            encoded.copyOfRange(0, 48),
            encoded.copyOfRange(56, 57),
            initialCopy,
            encoded.copyOfRange(60, 64),
            sha256(envelope.ciphertext),
        )
    }

    private fun classPriority(objectClass: Int): Int? = when (objectClass) {
        CLASS_RECIPIENT_RECEIPT -> 0
        CLASS_TEXT -> 2
        CLASS_MANIFEST -> 4
        CLASS_BULK -> 5
        else -> null
    }

    private fun headerFailure(header: ByteArray): String = when {
        header.size != HEADER_BYTES -> "hat1_header_length"
        !header.copyOfRange(0, 4).contentEquals(HAT1_MAGIC) -> "hat1_magic"
        header[4].toInt() and 0xff != 1 -> "hat1_version"
        classPriority(header[5].toInt() and 0xff) == null -> "hat1_class"
        header[6].toInt() and 0xff != classPriority(header[5].toInt() and 0xff) -> "hat1_priority"
        header[7].toInt() != 0 || header[34].toInt() != 0 || header[35].toInt() != 0 ->
            "hat1_reserved"
        else -> "hat1_bounds"
    }

    private fun envelopeFailure(encoded: ByteArray): String =
        if (encoded.size < 64) "rly1_truncated" else "rly1_invalid"

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        parts.forEach(digest::update)
        return digest.digest()
    }

    private fun accepted() = Verification(true, "accepted")

    private fun rejected(reason: String) = Verification(false, reason)
}
