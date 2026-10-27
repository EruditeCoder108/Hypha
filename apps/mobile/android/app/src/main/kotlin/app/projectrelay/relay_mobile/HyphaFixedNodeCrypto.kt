package app.projectrelay.relay_mobile

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Node-authenticated, phone-anonymous session for the experimental fixed courier.
 *
 * The primitives are platform implementations. This protocol is additive and does not replace
 * the Noise/device-identity contract used by phone-to-phone RelayGattLink sessions.
 */
internal class HyphaFixedNodeCrypto(
    private val advertisementToken: ByteArray,
    private val clientNonce: ByteArray = randomBytes(NONCE_BYTES),
    private val ephemeralKeyPair: KeyPair = generateEphemeralKeyPair(),
) : AutoCloseable {
    init {
        require(advertisementToken.size == ADVERTISEMENT_TOKEN_BYTES) {
            "Fixed-node advertisement token is invalid."
        }
        require(clientNonce.size == NONCE_BYTES) { "Fixed-node client nonce is invalid." }
    }

    val hello: ByteArray = HELLO_MAGIC + advertisementToken + clientNonce +
        encodePublicKey(ephemeralKeyPair.public as ECPublicKey)

    var nodeFingerprint: String? = null
        private set

    private var authenticatedNodeIdentity: ByteArray? = null

    private var clientToNodeKey: ByteArray? = null
    private var nodeToClientKey: ByteArray? = null
    private var nextClientSequence = 0L
    private var expectedNodeSequence = 0L

    fun acceptHelloResponse(encoded: ByteArray): String {
        check(clientToNodeKey == null && nodeToClientKey == null) {
            "Fixed-node hello response was already accepted."
        }
        val minimumBytes = HELLO_RESPONSE_MAGIC.size + ADVERTISEMENT_TOKEN_BYTES + NONCE_BYTES +
            (P256_PUBLIC_BYTES * 2) + U16_BYTES + 1
        require(encoded.size >= minimumBytes) { "Fixed-node hello response is truncated." }
        var offset = 0
        require(encoded.copyOfRange(offset, offset + HELLO_RESPONSE_MAGIC.size)
            .contentEquals(HELLO_RESPONSE_MAGIC)) {
            "Fixed-node hello response has an invalid prefix."
        }
        offset += HELLO_RESPONSE_MAGIC.size
        val returnedToken = encoded.copyOfRange(offset, offset + ADVERTISEMENT_TOKEN_BYTES)
        offset += ADVERTISEMENT_TOKEN_BYTES
        require(returnedToken.contentEquals(advertisementToken)) {
            "Fixed-node response belongs to a different advertisement."
        }
        val nodeNonce = encoded.copyOfRange(offset, offset + NONCE_BYTES)
        offset += NONCE_BYTES
        val nodeEphemeralEncoded = encoded.copyOfRange(offset, offset + P256_PUBLIC_BYTES)
        offset += P256_PUBLIC_BYTES
        val nodeIdentityEncoded = encoded.copyOfRange(offset, offset + P256_PUBLIC_BYTES)
        offset += P256_PUBLIC_BYTES
        val signatureBytes = readU16(encoded, offset)
        offset += U16_BYTES
        require(signatureBytes in 1..MAX_SIGNATURE_BYTES && offset + signatureBytes == encoded.size) {
            "Fixed-node identity signature has an invalid length."
        }
        val signature = encoded.copyOfRange(offset, encoded.size)
        val clientPublic = encodePublicKey(ephemeralKeyPair.public as ECPublicKey)
        val transcript = HANDSHAKE_DOMAIN + advertisementToken + clientNonce + nodeNonce +
            clientPublic + nodeEphemeralEncoded + nodeIdentityEncoded
        val identityKey = decodePublicKey(nodeIdentityEncoded)
        require(Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(identityKey)
            update(transcript)
            verify(signature)
        }) { "Fixed-node identity signature is invalid." }

        val agreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        agreement.init(ephemeralKeyPair.private)
        agreement.doPhase(decodePublicKey(nodeEphemeralEncoded), true)
        val sharedSecret = agreement.generateSecret().leftPad(SHARED_SECRET_BYTES)
        val sessionKeys = hkdfSha256(
            salt = clientNonce + nodeNonce,
            inputKeyMaterial = sharedSecret,
            info = SESSION_DOMAIN + advertisementToken,
            outputBytes = AES_KEY_BYTES * 2,
        )
        sharedSecret.fill(0)
        clientToNodeKey = sessionKeys.copyOfRange(0, AES_KEY_BYTES)
        nodeToClientKey = sessionKeys.copyOfRange(AES_KEY_BYTES, sessionKeys.size)
        sessionKeys.fill(0)
        nextClientSequence = 0L
        expectedNodeSequence = 0L
        authenticatedNodeIdentity = nodeIdentityEncoded.copyOf()
        return fixedNodeFingerprint(nodeIdentityEncoded).also { nodeFingerprint = it }
    }

    fun nodeIdentityPublicKey(): ByteArray = checkNotNull(authenticatedNodeIdentity) {
        "Fixed-node identity is not authenticated."
    }.copyOf()

    fun encrypt(plaintext: ByteArray): ByteArray {
        require(plaintext.isNotEmpty() && plaintext.size <= MAX_PLAINTEXT_BYTES) {
            "Fixed-node plaintext has an invalid length."
        }
        val key = checkNotNull(clientToNodeKey) { "Fixed-node session is not established." }
        check(nextClientSequence >= 0L && nextClientSequence < Long.MAX_VALUE) {
            "Fixed-node client sequence is exhausted."
        }
        val sequence = nextClientSequence
        val sequenceBytes = encodeU64(sequence)
        val encrypted = Cipher.getInstance(CIPHER_TRANSFORMATION).run {
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, AES_ALGORITHM),
                GCMParameterSpec(GCM_TAG_BITS, CLIENT_NONCE_PREFIX + sequenceBytes),
            )
            updateAAD(RECORD_DOMAIN + advertisementToken + sequenceBytes)
            doFinal(plaintext)
        }
        nextClientSequence += 1L
        return sequenceBytes + encrypted
    }

    fun decrypt(encoded: ByteArray): ByteArray {
        require(encoded.size > U64_BYTES + GCM_TAG_BYTES) {
            "Fixed-node encrypted response is truncated."
        }
        val key = checkNotNull(nodeToClientKey) { "Fixed-node session is not established." }
        val sequence = readU64(encoded, 0)
        require(sequence == expectedNodeSequence) {
            "Fixed-node response sequence is invalid."
        }
        val sequenceBytes = encoded.copyOfRange(0, U64_BYTES)
        val plaintext = Cipher.getInstance(CIPHER_TRANSFORMATION).run {
            init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, AES_ALGORITHM),
                GCMParameterSpec(GCM_TAG_BITS, NODE_NONCE_PREFIX + sequenceBytes),
            )
            updateAAD(RECORD_DOMAIN + advertisementToken + sequenceBytes)
            doFinal(encoded, U64_BYTES, encoded.size - U64_BYTES)
        }
        expectedNodeSequence += 1L
        return plaintext
    }

    override fun close() {
        clientToNodeKey?.fill(0)
        nodeToClientKey?.fill(0)
        clientToNodeKey = null
        nodeToClientKey = null
        authenticatedNodeIdentity?.fill(0)
        authenticatedNodeIdentity = null
        clientNonce.fill(0)
    }

    internal companion object {
        const val ADVERTISEMENT_TOKEN_BYTES = 8
        const val MAX_PLAINTEXT_BYTES = 12 * 1024
        val FINISH_MAGIC = "HNF1".encodeToByteArray()
        val WELCOME_MAGIC = "HNW1".encodeToByteArray()
        val DONE_MAGIC = "HNO1".encodeToByteArray()

        private const val NONCE_BYTES = 16
        private const val P256_PUBLIC_BYTES = 65
        private const val SHARED_SECRET_BYTES = 32
        private const val AES_KEY_BYTES = 32
        private const val GCM_TAG_BYTES = 16
        private const val GCM_TAG_BITS = GCM_TAG_BYTES * 8
        private const val U16_BYTES = 2
        private const val U64_BYTES = 8
        private const val MAX_SIGNATURE_BYTES = 80
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val KEY_AGREEMENT_ALGORITHM = "ECDH"
        private const val AES_ALGORITHM = "AES"
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val CURVE_NAME = "secp256r1"
        private val HELLO_MAGIC = "HNH1".encodeToByteArray()
        private val HELLO_RESPONSE_MAGIC = "HNS1".encodeToByteArray()
        private val HANDSHAKE_DOMAIN = "Hypha fixed node handshake v1\u0000".encodeToByteArray()
        private val SESSION_DOMAIN = "Hypha fixed node session v1\u0000".encodeToByteArray()
        private val RECORD_DOMAIN = "Hypha fixed node record v1\u0000".encodeToByteArray()
        private val FINGERPRINT_DOMAIN = "Hypha fixed node identity v1\u0000".encodeToByteArray()
        private val CLIENT_NONCE_PREFIX = byteArrayOf('C'.code.toByte(), '2'.code.toByte(), 'N'.code.toByte(), 1)
        private val NODE_NONCE_PREFIX = byteArrayOf('N'.code.toByte(), '2'.code.toByte(), 'C'.code.toByte(), 1)

        private fun generateEphemeralKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec(CURVE_NAME))
            generateKeyPair()
        }

        private fun randomBytes(bytes: Int): ByteArray = ByteArray(bytes).also {
            java.security.SecureRandom().nextBytes(it)
        }

        private fun encodePublicKey(publicKey: ECPublicKey): ByteArray =
            byteArrayOf(0x04) + publicKey.w.affineX.toFixedUnsigned(32) +
                publicKey.w.affineY.toFixedUnsigned(32)

        private fun decodePublicKey(encoded: ByteArray): ECPublicKey {
            require(encoded.size == P256_PUBLIC_BYTES && encoded[0] == 0x04.toByte()) {
                "Fixed-node P-256 public key is invalid."
            }
            val template = generateEphemeralKeyPair().public as ECPublicKey
            val point = ECPoint(
                BigInteger(1, encoded.copyOfRange(1, 33)),
                BigInteger(1, encoded.copyOfRange(33, 65)),
            )
            return KeyFactory.getInstance("EC").generatePublic(
                ECPublicKeySpec(point, template.params),
            ) as ECPublicKey
        }

        private fun fixedNodeFingerprint(identityPublicKey: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(
                FINGERPRINT_DOMAIN + identityPublicKey,
            )
            return "NODE-" + digest.joinToString("-") { byte ->
                "%02X".format(byte.toInt() and 0xff)
            }
        }

        private fun hkdfSha256(
            salt: ByteArray,
            inputKeyMaterial: ByteArray,
            info: ByteArray,
            outputBytes: Int,
        ): ByteArray {
            require(outputBytes in 1..(255 * 32)) { "HKDF output length is invalid." }
            val extract = Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(salt, "HmacSHA256"))
                doFinal(inputKeyMaterial)
            }
            val output = ByteArray(outputBytes)
            var previous = byteArrayOf()
            var offset = 0
            var counter = 1
            while (offset < outputBytes) {
                previous = Mac.getInstance("HmacSHA256").run {
                    init(SecretKeySpec(extract, "HmacSHA256"))
                    update(previous)
                    update(info)
                    update(counter.toByte())
                    doFinal()
                }
                val copied = minOf(previous.size, outputBytes - offset)
                previous.copyInto(output, offset, 0, copied)
                offset += copied
                counter += 1
            }
            extract.fill(0)
            previous.fill(0)
            return output
        }

        private fun readU16(source: ByteArray, offset: Int): Int =
            ((source[offset].toInt() and 0xff) shl 8) or (source[offset + 1].toInt() and 0xff)

        private fun readU64(source: ByteArray, offset: Int): Long =
            ByteBuffer.wrap(source, offset, U64_BYTES).order(ByteOrder.BIG_ENDIAN).long

        private fun encodeU64(value: Long): ByteArray = ByteBuffer.allocate(U64_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(value)
            .array()

        private fun BigInteger.toFixedUnsigned(bytes: Int): ByteArray {
            val encoded = toByteArray()
            val unsigned = if (encoded.size > 1 && encoded[0] == 0.toByte()) {
                encoded.copyOfRange(1, encoded.size)
            } else {
                encoded
            }
            require(unsigned.size <= bytes) { "P-256 coordinate is oversized." }
            return ByteArray(bytes - unsigned.size) + unsigned
        }

        private fun ByteArray.leftPad(bytes: Int): ByteArray {
            require(size <= bytes) { "ECDH shared secret is oversized." }
            return if (size == bytes) copyOf() else ByteArray(bytes - size) + this
        }
    }
}
