package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** A user-visible name bound to one authenticated, contact-specific E2E bundle. */
internal data class RelayContactCard(
    val displayName: String,
    val bundle: ByteArray,
) {
    init {
        require(bundle.size == CONTACT_BUNDLE_BYTES) { "Invalid Relay contact bundle." }
        validateDisplayName(displayName)
        // Rust verifies the bundle signature and derives the stable Relay ID.
        RelayNative.e2eRelayId(bundle)
    }

    fun encode(): ByteArray {
        val name = displayName.toByteArray(StandardCharsets.UTF_8)
        return ByteBuffer.allocate(HEADER_BYTES + name.size + bundle.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(byteArrayOf(0, 0, 0))
            .putShort(name.size.toShort())
            .put(name)
            .put(bundle)
            .array()
    }

    companion object {
        const val CONTACT_BUNDLE_BYTES = 200
        const val MAX_DISPLAY_NAME_BYTES = 64
        private const val HEADER_BYTES = 10
        private val MAGIC = "RCC1".toByteArray(StandardCharsets.US_ASCII)
        private const val VERSION: Byte = 1

        fun decode(encoded: ByteArray): RelayContactCard {
            require(encoded.size in (HEADER_BYTES + 1)..(HEADER_BYTES + MAX_DISPLAY_NAME_BYTES + CONTACT_BUNDLE_BYTES)) {
                "Relay contact card has an invalid length."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Relay contact card has an invalid prefix."
            }
            require(buffer.get() == VERSION) { "Relay contact card version is unsupported." }
            require(ByteArray(3).also(buffer::get).all { it == 0.toByte() }) {
                "Relay contact card reserved bytes are not zero."
            }
            val nameLength = buffer.short.toInt() and 0xFFFF
            require(nameLength in 1..MAX_DISPLAY_NAME_BYTES) {
                "Relay display name has an invalid length."
            }
            require(buffer.remaining() == nameLength + CONTACT_BUNDLE_BYTES) {
                "Relay contact card length does not match its fields."
            }
            val nameBytes = ByteArray(nameLength).also(buffer::get)
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val displayName = decoder.decode(ByteBuffer.wrap(nameBytes)).toString()
            val bundle = ByteArray(CONTACT_BUNDLE_BYTES).also(buffer::get)
            return RelayContactCard(displayName, bundle)
        }

        fun normalizedDisplayName(raw: String): String {
            val normalized = raw.trim().replace(Regex("\\s+"), " ")
            validateDisplayName(normalized)
            return normalized
        }

        private fun validateDisplayName(value: String) {
            val utf8 = value.toByteArray(StandardCharsets.UTF_8)
            require(value.isNotBlank() && utf8.size in 1..MAX_DISPLAY_NAME_BYTES) {
                "Relay display name must contain 1 to 64 UTF-8 bytes."
            }
            require(value.none { it.isISOControl() }) {
                "Relay display name cannot contain control characters."
            }
        }
    }
}
