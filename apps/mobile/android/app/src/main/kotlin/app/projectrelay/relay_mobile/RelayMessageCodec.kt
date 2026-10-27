package app.projectrelay.relay_mobile

import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/** Rust-validated application messages carried inside an authenticated Noise channel. */
internal object RelayMessageCodec {
    private val random = SecureRandom()

    data class TextMessage(
        val id: ByteArray,
        val text: String,
        val replyToMessageId: ByteArray? = null,
        val replyPreview: String? = null,
        val encoded: ByteArray,
    ) {
        init {
            require((replyToMessageId == null) == (replyPreview == null)) {
                "Reply ID and preview must be present together."
            }
        }

        fun replyMap(): Map<String, String> = replyToMessageId?.let { replyId ->
            mapOf(
                "replyToMessageId" to idHex(replyId),
                "replyPreview" to requireNotNull(replyPreview),
            )
        } ?: emptyMap()
    }

    data class WifiUpgradeOffer(
        val offerId: ByteArray,
        val psk: ByteArray,
        val initiatorToken: ByteArray,
        val responderToken: ByteArray,
        val encoded: ByteArray,
    )

    fun create(
        text: String,
        replyToMessageIdHex: String? = null,
        replyPreview: String? = null,
    ): TextMessage {
        val id = ByteArray(MESSAGE_ID_BYTES).also(random::nextBytes)
        return restore(
            id,
            text,
            replyToMessageIdHex?.let(::idBytes),
            replyPreview,
        )
    }

    /** Rebuilds the exact wire message for a durable outbox retry without changing its ID. */
    fun restore(
        id: ByteArray,
        text: String,
        replyToMessageId: ByteArray? = null,
        replyPreview: String? = null,
    ): TextMessage {
        require(id.size == MESSAGE_ID_BYTES) { "Message ID must be 16 bytes." }
        require((replyToMessageId == null) == (replyPreview == null)) {
            "Reply ID and preview must be present together."
        }
        val stableId = id.copyOf()
        val encoded = if (replyToMessageId == null) {
            RelayNative.encodeTextMessage(
                stableId,
                text.toByteArray(StandardCharsets.UTF_8),
            )
        } else {
            RelayNative.encodeReplyMessage(
                stableId,
                text.toByteArray(StandardCharsets.UTF_8),
                replyToMessageId,
                requireNotNull(replyPreview).toByteArray(StandardCharsets.UTF_8),
            )
        }
        return decode(encoded)
    }

    fun decode(encoded: ByteArray): TextMessage {
        check(RelayNative.validateTextMessage(encoded)) { "Invalid Relay text message." }
        return decodeTrusted(encoded)
    }

    /** Parses bytes that were already authenticated and validated by Rust. */
    internal fun decodeTrusted(encoded: ByteArray): TextMessage {
        check(encoded.size >= MESSAGE_HEADER_BYTES) { "Truncated Relay text message." }
        check(encoded.copyOfRange(0, 4).contentEquals(MESSAGE_MAGIC)) {
            "Invalid Relay text magic."
        }
        val id = encoded.copyOfRange(MESSAGE_ID_OFFSET, MESSAGE_ID_OFFSET + MESSAGE_ID_BYTES)
        return when (encoded[VERSION_OFFSET].toInt()) {
            CONTENT_VERSION -> {
                val textBytes = readU16(encoded, TEXT_LENGTH_OFFSET)
                check(textBytes > 0 && MESSAGE_HEADER_BYTES + textBytes == encoded.size) {
                    "Invalid Relay text length."
                }
                val text = String(
                    encoded,
                    MESSAGE_HEADER_BYTES,
                    textBytes,
                    StandardCharsets.UTF_8,
                )
                TextMessage(id, text, null, null, encoded.copyOf())
            }
            REPLY_CONTENT_VERSION -> {
                check(encoded.size >= REPLY_MESSAGE_HEADER_BYTES) {
                    "Truncated Relay reply message."
                }
                val textBytes = readU16(encoded, TEXT_LENGTH_OFFSET)
                val replyTo = encoded.copyOfRange(REPLY_ID_OFFSET, REPLY_ID_OFFSET + MESSAGE_ID_BYTES)
                val previewBytes = readU16(encoded, REPLY_PREVIEW_LENGTH_OFFSET)
                val previewStart = REPLY_MESSAGE_HEADER_BYTES
                val textStart = previewStart + previewBytes
                check(textStart + textBytes == encoded.size) { "Invalid Relay reply lengths." }
                TextMessage(
                    id = id,
                    text = String(encoded, textStart, textBytes, StandardCharsets.UTF_8),
                    replyToMessageId = replyTo,
                    replyPreview = String(encoded, previewStart, previewBytes, StandardCharsets.UTF_8),
                    encoded = encoded.copyOf(),
                )
            }
            else -> error("Unsupported Relay text version.")
        }
    }

    fun createReceipt(messageId: ByteArray): ByteArray =
        RelayNative.encodeDeliveryReceipt(messageId)

    fun receiptMatches(receipt: ByteArray, messageId: ByteArray): Boolean =
        RelayNative.validateDeliveryReceipt(receipt, messageId)

    fun idHex(messageId: ByteArray): String = messageId.joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    fun idBytes(messageIdHex: String): ByteArray {
        require(messageIdHex.length == MESSAGE_ID_BYTES * 2 && messageIdHex.all { it.isHexDigit() }) {
            "Message ID must contain 32 hexadecimal characters."
        }
        return ByteArray(MESSAGE_ID_BYTES) { index ->
            messageIdHex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    fun createWifiUpgradeOffer(
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): WifiUpgradeOffer {
        require(initiatorToken.size == WIFI_TOKEN_BYTES && responderToken.size == WIFI_TOKEN_BYTES) {
            "Wi-Fi upgrade tokens must be 8 bytes."
        }
        val offerId = ByteArray(OFFER_ID_BYTES).also(random::nextBytes)
        val psk = ByteArray(UPGRADE_PSK_BYTES).also(random::nextBytes)
        val encoded = RelayNative.encodeWifiUpgradeOffer(
            offerId,
            psk,
            initiatorToken,
            responderToken,
        )
        return WifiUpgradeOffer(offerId, psk, initiatorToken, responderToken, encoded)
    }

    fun decodeWifiUpgradeOffer(encoded: ByteArray): WifiUpgradeOffer {
        check(RelayNative.validateWifiUpgradeOffer(encoded)) { "Invalid Wi-Fi upgrade offer." }
        return WifiUpgradeOffer(
            offerId = encoded.copyOfRange(8, 24),
            psk = encoded.copyOfRange(24, 56),
            initiatorToken = encoded.copyOfRange(56, 64),
            responderToken = encoded.copyOfRange(64, 72),
            encoded = encoded.copyOf(),
        )
    }

    fun createWifiUpgradeAck(
        offer: WifiUpgradeOffer,
        responderToken: ByteArray,
    ): ByteArray {
        require(responderToken.size == WIFI_TOKEN_BYTES && responderToken.any { it != 0.toByte() }) {
            "Resolved Wi-Fi responder token must be non-zero."
        }
        return RelayNative.encodeWifiUpgradeAck(offer.encoded, responderToken)
    }

    fun wifiUpgradeAckResponderToken(
        ack: ByteArray,
        offer: WifiUpgradeOffer,
    ): ByteArray? = if (RelayNative.validateWifiUpgradeAck(ack, offer.encoded)) {
        ack.copyOfRange(ACK_RESPONDER_TOKEN_OFFSET, ACK_RESPONDER_TOKEN_OFFSET + WIFI_TOKEN_BYTES)
    } else {
        null
    }

    private fun readU16(encoded: ByteArray, offset: Int): Int =
        ((encoded[offset].toInt() and 0xFF) shl 8) or (encoded[offset + 1].toInt() and 0xFF)

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private const val VERSION_OFFSET = 4
    private val MESSAGE_MAGIC = byteArrayOf(
        'R'.code.toByte(),
        'M'.code.toByte(),
        'S'.code.toByte(),
        'G'.code.toByte(),
    )
    private const val CONTENT_VERSION = 1
    private const val REPLY_CONTENT_VERSION = 2
    private const val MESSAGE_ID_OFFSET = 8
    private const val MESSAGE_ID_BYTES = 16
    private const val TEXT_LENGTH_OFFSET = 24
    private const val MESSAGE_HEADER_BYTES = 26
    private const val REPLY_ID_OFFSET = 26
    private const val REPLY_PREVIEW_LENGTH_OFFSET = 42
    private const val REPLY_MESSAGE_HEADER_BYTES = 44
    private const val OFFER_ID_BYTES = 16
    private const val UPGRADE_PSK_BYTES = 32
    private const val WIFI_TOKEN_BYTES = 8
    private const val ACK_RESPONDER_TOKEN_OFFSET = 32
}
