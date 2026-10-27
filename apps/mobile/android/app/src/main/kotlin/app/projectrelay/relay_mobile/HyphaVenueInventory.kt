package app.projectrelay.relay_mobile

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/** Parsed, operator-signed HVI1 node inventory defined by ADR 0010. */
internal class HyphaVenueInventory private constructor(
    private val venueIdBytes: ByteArray,
    private val authorityBytes: ByteArray,
    val version: Long,
    private val statusByPublicKey: Map<String, NodeStatus>,
) {
    enum class NodeStatus {
        ACTIVE,
        REVOKED,
        REPLACED,
        UNKNOWN,
    }

    fun statusFor(identityPublicKey: ByteArray): NodeStatus {
        if (identityPublicKey.size != P256_PUBLIC_BYTES) return NodeStatus.UNKNOWN
        return statusByPublicKey[identityPublicKey.toHex()] ?: NodeStatus.UNKNOWN
    }

    fun venueId(): ByteArray = venueIdBytes.copyOf()

    fun authorityPublicKey(): ByteArray = authorityBytes.copyOf()

    internal companion object {
        const val MAX_ENTRIES = 64
        private const val HEADER_BYTES = 99
        private const val ENTRY_BYTES = 67
        private const val P256_PUBLIC_BYTES = 65
        private const val MAX_SIGNATURE_BYTES = 80
        private const val ROLE_COURIER = 1
        private const val STATUS_ACTIVE = 1
        private const val STATUS_REVOKED = 2
        private const val STATUS_REPLACED = 3
        private val MAGIC = "HVI1".encodeToByteArray()
        private val DOMAIN = "Hypha venue inventory v1\u0000".encodeToByteArray()
        private val curveParameters by lazy {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            (generator.generateKeyPair().public as ECPublicKey).params
        }

        fun parseAndVerify(encoded: ByteArray): HyphaVenueInventory {
            require(encoded.size >= HEADER_BYTES + ENTRY_BYTES + 3) {
                "HVI1 inventory is truncated."
            }
            val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            val magic = ByteArray(MAGIC.size).also(input::get)
            require(magic.contentEquals(MAGIC)) { "HVI1 inventory has an invalid prefix." }
            require(input.get().toInt() and 0xff == 1) { "HVI1 schema is unsupported." }
            require(input.get().toInt() and 0xff == 1) {
                "HVI1 validity policy is unsupported."
            }
            require(input.short.toInt() and 0xffff == 0) { "HVI1 reserved field is invalid." }
            val version = input.long
            require(version > 0L) { "HVI1 inventory version is invalid." }
            val venueId = ByteArray(16).also(input::get)
            require(venueId.any { it != 0.toByte() }) { "HVI1 venue id is invalid." }
            val authority = ByteArray(P256_PUBLIC_BYTES).also(input::get)
            requireValidPublicKey(authority, "authority")
            val entryCount = input.short.toInt() and 0xffff
            require(entryCount in 1..MAX_ENTRIES) { "HVI1 entry count is invalid." }
            val entriesEnd = HEADER_BYTES + entryCount * ENTRY_BYTES
            require(entriesEnd + 2 <= encoded.size) { "HVI1 entries are truncated." }

            val statusByKey = linkedMapOf<String, NodeStatus>()
            var previous: ByteArray? = null
            var activeCount = 0
            repeat(entryCount) {
                val publicKey = ByteArray(P256_PUBLIC_BYTES).also(input::get)
                requireValidPublicKey(publicKey, "node")
                previous?.let { prior ->
                    require(compareUnsigned(prior, publicKey) < 0) {
                        "HVI1 node entries must be sorted and unique."
                    }
                }
                previous = publicKey
                require(input.get().toInt() and 0xff == ROLE_COURIER) {
                    "HVI1 node role is unsupported."
                }
                val status = when (input.get().toInt() and 0xff) {
                    STATUS_ACTIVE -> NodeStatus.ACTIVE.also { activeCount += 1 }
                    STATUS_REVOKED -> NodeStatus.REVOKED
                    STATUS_REPLACED -> NodeStatus.REPLACED
                    else -> throw IllegalArgumentException("HVI1 node status is unsupported.")
                }
                statusByKey[publicKey.toHex()] = status
            }
            require(activeCount > 0) { "HVI1 inventory has no active courier." }

            val signatureBytes = input.short.toInt() and 0xffff
            require(signatureBytes in 1..MAX_SIGNATURE_BYTES && input.position() + signatureBytes == encoded.size) {
                "HVI1 signature length is invalid."
            }
            val signature = ByteArray(signatureBytes).also(input::get)
            val verified = runCatching {
                Signature.getInstance("SHA256withECDSA").run {
                    initVerify(decodePublicKey(authority))
                    update(DOMAIN)
                    update(encoded, 0, entriesEnd)
                    verify(signature)
                }
            }.getOrDefault(false)
            require(verified) { "HVI1 authority signature is invalid." }
            return HyphaVenueInventory(venueId, authority, version, statusByKey)
        }

        private fun requireValidPublicKey(encoded: ByteArray, label: String) {
            require(runCatching { decodePublicKey(encoded) }.isSuccess) {
                "HVI1 $label P-256 public key is invalid."
            }
        }

        private fun decodePublicKey(encoded: ByteArray): ECPublicKey {
            require(encoded.size == P256_PUBLIC_BYTES && encoded[0] == 0x04.toByte())
            return KeyFactory.getInstance("EC").generatePublic(
                ECPublicKeySpec(
                    ECPoint(
                        BigInteger(1, encoded.copyOfRange(1, 33)),
                        BigInteger(1, encoded.copyOfRange(33, 65)),
                    ),
                    curveParameters,
                ),
            ) as ECPublicKey
        }

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            left.indices.forEach { index ->
                val difference = (left[index].toInt() and 0xff) -
                    (right[index].toInt() and 0xff)
                if (difference != 0) return difference
            }
            return left.size - right.size
        }

        private fun ByteArray.toHex(): String = joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
    }
}
