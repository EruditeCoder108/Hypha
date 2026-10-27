package app.projectrelay.relay_mobile

import android.os.SystemClock

/** Single-use capability issued only through a verified BLE/Noise session. */
internal data class RelayWifiUpgradeAuthorization(
    val offerId: ByteArray,
    val psk: ByteArray,
    val initiatorToken: ByteArray,
    val responderToken: ByteArray,
    val peerFingerprint: String,
    val isInitiator: Boolean,
    val createdAtElapsedMs: Long = SystemClock.elapsedRealtime(),
) {
    fun isExpired(nowElapsedMs: Long = SystemClock.elapsedRealtime()): Boolean =
        nowElapsedMs - createdAtElapsedMs !in 0..MAX_AGE_MS

    fun remoteToken(): ByteArray = if (isInitiator) responderToken else initiatorToken

    fun localToken(): ByteArray = if (isInitiator) initiatorToken else responderToken

    fun destroySecret() {
        psk.fill(0)
    }

    private companion object {
        const val MAX_AGE_MS = 2 * 60 * 1_000L
    }
}
