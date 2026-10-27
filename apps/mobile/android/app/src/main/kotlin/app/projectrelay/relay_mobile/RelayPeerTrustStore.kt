package app.projectrelay.relay_mobile

import android.content.Context
import android.util.Base64
import java.security.MessageDigest

/** Stores only public peer identities and explicit local verification decisions. */
internal class RelayPeerTrustStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun stateFor(publicKey: ByteArray): PeerTrustState {
        require(publicKey.isNotEmpty()) { "Peer public key is empty." }
        val keyId = keyId(publicKey)
        if (!preferences.getBoolean(verifiedKey(keyId), false)) {
            return PeerTrustState.AUTHENTICATED
        }
        val stored = preferences.getString(publicKeyKey(keyId), null)
            ?: return PeerTrustState.AUTHENTICATED
        val storedBytes = runCatching { Base64.decode(stored, Base64.NO_WRAP) }.getOrNull()
            ?: return PeerTrustState.AUTHENTICATED
        return if (storedBytes.contentEquals(publicKey)) {
            PeerTrustState.VERIFIED
        } else {
            PeerTrustState.AUTHENTICATED
        }
    }

    @Synchronized
    fun markVerified(publicKey: ByteArray) {
        require(publicKey.isNotEmpty()) { "Peer public key is empty." }
        val keyId = keyId(publicKey)
        val committed = preferences.edit()
            .putString(publicKeyKey(keyId), Base64.encodeToString(publicKey, Base64.NO_WRAP))
            .putBoolean(verifiedKey(keyId), true)
            .commit()
        check(committed) { "Peer verification could not be committed to storage." }
    }

    private fun keyId(publicKey: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(publicKey).joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xFF)
        }

    private fun publicKeyKey(keyId: String): String = "peer.$keyId.public"

    private fun verifiedKey(keyId: String): String = "peer.$keyId.verified"

    internal enum class PeerTrustState(val wireValue: String) {
        AUTHENTICATED("authenticated"),
        VERIFIED("verified"),
    }

    private companion object {
        const val PREFERENCES_NAME = "project_relay_peer_trust_v1"
    }
}
