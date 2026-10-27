package app.projectrelay.relay_mobile

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/** Persistent signing identity whose private key never leaves Android Keystore. */
internal class RelayDeviceIdentity(
    private val packageManager: PackageManager,
) {
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    init {
        ensureKeyExists()
    }

    val publicKeyEncoded: ByteArray
        @Synchronized get() = requireNotNull(keyStore.getCertificate(KEY_ALIAS)) {
            "Relay identity certificate is unavailable."
        }.publicKey.encoded.copyOf()

    val protection: String
        @Synchronized get() {
            val privateKey = requireNotNull(keyStore.getKey(KEY_ALIAS, null)) {
                "Relay identity private key is unavailable."
            }
            val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(privateKey, KeyInfo::class.java)
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    else -> "software"
                }
            } else if (info.isInsideSecureHardware) {
                "hardware"
            } else {
                "software"
            }
        }

    @Synchronized
    fun createProof(handshakeHash: ByteArray, role: IdentityRole): ByteArray {
        require(handshakeHash.size == HANDSHAKE_HASH_BYTES) {
            "Noise handshake hash must contain exactly $HANDSHAKE_HASH_BYTES bytes."
        }
        val publicKey = publicKeyEncoded
        require(publicKey.size in 1..MAX_PUBLIC_KEY_BYTES) { "Identity public key is too large." }
        val privateKey = requireNotNull(keyStore.getKey(KEY_ALIAS, null)) {
            "Relay identity private key is unavailable."
        }
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey as java.security.PrivateKey)
            update(signingInput(handshakeHash, role))
            sign()
        }
        require(signature.size in 1..MAX_SIGNATURE_BYTES) { "Identity signature is too large." }
        return encodeProof(role, publicKey, signature)
    }

    fun verifyProof(
        encoded: ByteArray,
        handshakeHash: ByteArray,
        expectedRole: IdentityRole,
    ): RemoteIdentity {
        require(handshakeHash.size == HANDSHAKE_HASH_BYTES) {
            "Noise handshake hash must contain exactly $HANDSHAKE_HASH_BYTES bytes."
        }
        val proof = decodeProof(encoded)
        require(proof.role == expectedRole) { "Identity proof role is invalid." }
        val publicKey = KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(
            X509EncodedKeySpec(proof.publicKey),
        )
        val valid = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(publicKey)
            update(signingInput(handshakeHash, expectedRole))
            verify(proof.signature)
        }
        require(valid) { "Identity proof signature is invalid." }
        return RemoteIdentity(proof.publicKey.copyOf())
    }

    fun safetyFingerprint(remotePublicKey: ByteArray): String {
        require(remotePublicKey.size in 1..MAX_PUBLIC_KEY_BYTES) { "Remote public key is invalid." }
        val local = publicKeyEncoded
        val ordered = if (compareUnsigned(local, remotePublicKey) <= 0) {
            arrayOf(local, remotePublicKey)
        } else {
            arrayOf(remotePublicKey, local)
        }
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(SAFETY_DOMAIN)
            ordered.forEach { key ->
                update(byteArrayOf((key.size ushr 8).toByte(), key.size.toByte()))
                update(key)
            }
        }.digest()
        return digest.joinToString(separator = "-") { byte ->
            "%02X".format(byte.toInt() and 0xFF)
        }
    }

    private fun ensureKeyExists() {
        if (keyStore.containsAlias(KEY_ALIAS)) return
        val preferStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (preferStrongBox) {
            try {
                generateKey(strongBox = true)
                return
            } catch (_: ProviderException) {
                // Some devices advertise StrongBox but reject a specific key configuration.
            }
        }
        generateKey(strongBox = false)
    }

    private fun generateKey(strongBox: Boolean) {
        val generator = KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)
        val parameters = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE_NAME))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        generator.initialize(parameters)
        generator.generateKeyPair()
    }

    private fun signingInput(handshakeHash: ByteArray, role: IdentityRole): ByteArray =
        SIGNING_DOMAIN + byteArrayOf(role.wireValue) + handshakeHash

    private fun encodeProof(
        role: IdentityRole,
        publicKey: ByteArray,
        signature: ByteArray,
    ): ByteArray = ByteArray(PROOF_HEADER_BYTES + publicKey.size + signature.size).also { target ->
        target[0] = PROOF_MAGIC_0
        target[1] = PROOF_MAGIC_1
        target[2] = PROOF_VERSION
        target[3] = role.wireValue
        putU16(target, 4, publicKey.size)
        putU16(target, 6, signature.size)
        publicKey.copyInto(target, destinationOffset = PROOF_HEADER_BYTES)
        signature.copyInto(target, destinationOffset = PROOF_HEADER_BYTES + publicKey.size)
    }

    private fun decodeProof(encoded: ByteArray): DecodedProof {
        require(encoded.size in (PROOF_HEADER_BYTES + 2)..MAX_PROOF_BYTES) {
            "Identity proof length is invalid."
        }
        require(
            encoded[0] == PROOF_MAGIC_0 && encoded[1] == PROOF_MAGIC_1 &&
                encoded[2] == PROOF_VERSION,
        ) { "Identity proof prefix is invalid." }
        val role = IdentityRole.fromWire(encoded[3])
        val publicKeyBytes = readU16(encoded, 4)
        val signatureBytes = readU16(encoded, 6)
        require(publicKeyBytes in 1..MAX_PUBLIC_KEY_BYTES) { "Identity public key length is invalid." }
        require(signatureBytes in 1..MAX_SIGNATURE_BYTES) { "Identity signature length is invalid." }
        require(encoded.size == PROOF_HEADER_BYTES + publicKeyBytes + signatureBytes) {
            "Identity proof has trailing or missing data."
        }
        return DecodedProof(
            role = role,
            publicKey = encoded.copyOfRange(PROOF_HEADER_BYTES, PROOF_HEADER_BYTES + publicKeyBytes),
            signature = encoded.copyOfRange(PROOF_HEADER_BYTES + publicKeyBytes, encoded.size),
        )
    }

    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        val common = minOf(left.size, right.size)
        for (index in 0 until common) {
            val comparison = (left[index].toInt() and 0xFF).compareTo(right[index].toInt() and 0xFF)
            if (comparison != 0) return comparison
        }
        return left.size.compareTo(right.size)
    }

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private fun readU16(source: ByteArray, offset: Int): Int =
        ((source[offset].toInt() and 0xFF) shl 8) or (source[offset + 1].toInt() and 0xFF)

    internal enum class IdentityRole(val wireValue: Byte) {
        INITIATOR(0x01),
        RESPONDER(0x02);

        companion object {
            fun fromWire(value: Byte): IdentityRole = entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Identity proof role is unknown.")
        }
    }

    internal data class RemoteIdentity(val publicKey: ByteArray)

    private data class DecodedProof(
        val role: IdentityRole,
        val publicKey: ByteArray,
        val signature: ByteArray,
    )

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "project_relay_identity_p256_v1"
        const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val CURVE_NAME = "secp256r1"
        const val HANDSHAKE_HASH_BYTES = 32
        const val PROOF_HEADER_BYTES = 8
        const val MAX_PUBLIC_KEY_BYTES = 192
        const val MAX_SIGNATURE_BYTES = 96
        const val MAX_PROOF_BYTES = PROOF_HEADER_BYTES + MAX_PUBLIC_KEY_BYTES + MAX_SIGNATURE_BYTES
        const val PROOF_MAGIC_0: Byte = 0x52
        const val PROOF_MAGIC_1: Byte = 0x49
        const val PROOF_VERSION: Byte = 0x01
        val SIGNING_DOMAIN = "ProjectRelay identity proof v1\u0000".encodeToByteArray()
        val SAFETY_DOMAIN = "ProjectRelay safety fingerprint v1\u0000".encodeToByteArray()
    }
}
