package app.projectrelay.relay_mobile

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HyphaFixedNodeCryptoTest {
    @Test
    fun nodeSignatureAndDirectionalRecordsInteroperate() {
        val token = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        HyphaFixedNodeCrypto(token).use { phone ->
            val hello = phone.hello
            assertArrayEquals("HNH1".encodeToByteArray(), hello.copyOfRange(0, 4))
            assertArrayEquals(token, hello.copyOfRange(4, 12))
            val clientNonce = hello.copyOfRange(12, 28)
            val clientPublic = hello.copyOfRange(28, 93)

            val nodeIdentity = generateP256()
            val nodeEphemeral = generateP256()
            val nodeNonce = ByteArray(16) { index -> (0x40 + index).toByte() }
            val nodeEphemeralPublic = encodePublic(nodeEphemeral.public as ECPublicKey)
            val nodeIdentityPublic = encodePublic(nodeIdentity.public as ECPublicKey)
            val transcript = HANDSHAKE_DOMAIN + token + clientNonce + nodeNonce + clientPublic +
                nodeEphemeralPublic + nodeIdentityPublic
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(nodeIdentity.private)
                update(transcript)
                sign()
            }
            val response = ByteBuffer.allocate(4 + 8 + 16 + 65 + 65 + 2 + signature.size)
                .order(ByteOrder.BIG_ENDIAN)
                .put("HNS1".encodeToByteArray())
                .put(token)
                .put(nodeNonce)
                .put(nodeEphemeralPublic)
                .put(nodeIdentityPublic)
                .putShort(signature.size.toShort())
                .put(signature)
                .array()
            assertTrue(phone.acceptHelloResponse(response).startsWith("NODE-"))

            val agreement = KeyAgreement.getInstance("ECDH").run {
                init(nodeEphemeral.private)
                doPhase(decodePublic(clientPublic, nodeEphemeral), true)
                generateSecret().leftPad(32)
            }
            val keys = hkdf(
                salt = clientNonce + nodeNonce,
                input = agreement,
                info = SESSION_DOMAIN + token,
                outputBytes = 64,
            )
            agreement.fill(0)

            val encryptedFinish = phone.encrypt(HyphaFixedNodeCrypto.FINISH_MAGIC)
            assertArrayEquals(
                HyphaFixedNodeCrypto.FINISH_MAGIC,
                decrypt(
                    key = keys.copyOfRange(0, 32),
                    encoded = encryptedFinish,
                    noncePrefix = CLIENT_NONCE_PREFIX,
                    token = token,
                ),
            )

            val encryptedWelcome = encrypt(
                key = keys.copyOfRange(32, 64),
                sequence = 0,
                plaintext = HyphaFixedNodeCrypto.WELCOME_MAGIC,
                noncePrefix = NODE_NONCE_PREFIX,
                token = token,
            )
            assertArrayEquals(HyphaFixedNodeCrypto.WELCOME_MAGIC, phone.decrypt(encryptedWelcome))
            keys.fill(0)
        }
    }

    private fun generateP256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun encodePublic(key: ECPublicKey): ByteArray =
        byteArrayOf(4) + key.w.affineX.fixed(32) + key.w.affineY.fixed(32)

    private fun decodePublic(encoded: ByteArray, template: KeyPair): ECPublicKey {
        val parameters = (template.public as ECPublicKey).params
        return KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(
                ECPoint(
                    BigInteger(1, encoded.copyOfRange(1, 33)),
                    BigInteger(1, encoded.copyOfRange(33, 65)),
                ),
                parameters,
            ),
        ) as ECPublicKey
    }

    private fun encrypt(
        key: ByteArray,
        sequence: Long,
        plaintext: ByteArray,
        noncePrefix: ByteArray,
        token: ByteArray,
    ): ByteArray {
        val sequenceBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(sequence).array()
        val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, noncePrefix + sequenceBytes),
            )
            updateAAD(RECORD_DOMAIN + token + sequenceBytes)
            doFinal(plaintext)
        }
        return sequenceBytes + ciphertext
    }

    private fun decrypt(
        key: ByteArray,
        encoded: ByteArray,
        noncePrefix: ByteArray,
        token: ByteArray,
    ): ByteArray {
        val sequenceBytes = encoded.copyOfRange(0, 8)
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, noncePrefix + sequenceBytes),
            )
            updateAAD(RECORD_DOMAIN + token + sequenceBytes)
            doFinal(encoded, 8, encoded.size - 8)
        }
    }

    private fun hkdf(
        salt: ByteArray,
        input: ByteArray,
        info: ByteArray,
        outputBytes: Int,
    ): ByteArray {
        val extracted = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(salt, "HmacSHA256"))
            doFinal(input)
        }
        val output = ByteArray(outputBytes)
        var previous = byteArrayOf()
        var offset = 0
        var counter = 1
        while (offset < output.size) {
            previous = Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(extracted, "HmacSHA256"))
                update(previous)
                update(info)
                update(counter.toByte())
                doFinal()
            }
            val copied = minOf(previous.size, output.size - offset)
            previous.copyInto(output, offset, 0, copied)
            offset += copied
            counter += 1
        }
        extracted.fill(0)
        previous.fill(0)
        return output
    }

    private fun BigInteger.fixed(bytes: Int): ByteArray {
        val encoded = toByteArray().let { value ->
            if (value.size > 1 && value[0] == 0.toByte()) value.copyOfRange(1, value.size) else value
        }
        return ByteArray(bytes - encoded.size) + encoded
    }

    private fun ByteArray.leftPad(bytes: Int): ByteArray =
        if (size == bytes) copyOf() else ByteArray(bytes - size) + this

    private companion object {
        val HANDSHAKE_DOMAIN = "Hypha fixed node handshake v1\u0000".encodeToByteArray()
        val SESSION_DOMAIN = "Hypha fixed node session v1\u0000".encodeToByteArray()
        val RECORD_DOMAIN = "Hypha fixed node record v1\u0000".encodeToByteArray()
        val CLIENT_NONCE_PREFIX = byteArrayOf('C'.code.toByte(), '2'.code.toByte(), 'N'.code.toByte(), 1)
        val NODE_NONCE_PREFIX = byteArrayOf('N'.code.toByte(), '2'.code.toByte(), 'C'.code.toByte(), 1)
    }
}
