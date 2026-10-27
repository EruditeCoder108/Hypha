package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/** Strict Kotlin view of relay-wire's bounded opaque courier envelope. */
internal data class RelayMeshEnvelope(
    val messageId: ByteArray,
    val destinationHint: ByteArray,
    val lifetimeMs: Long,
    val ageMs: Long,
    val hopLimit: Int,
    val hopsTaken: Int,
    val copyBudget: Int,
    val priority: Int,
    val ciphertext: ByteArray,
) {
    init {
        require(messageId.size == MESSAGE_ID_BYTES) { "Invalid mesh message ID." }
        require(destinationHint.size == DESTINATION_HINT_BYTES) { "Invalid destination hint." }
        require(lifetimeMs in 1..MAX_LIFETIME_MS) { "Invalid mesh lifetime." }
        require(ageMs in 0..lifetimeMs) { "Mesh envelope is expired or has an invalid age." }
        require(hopLimit in 1..U8_MAX && hopsTaken in 0..hopLimit) { "Invalid mesh hop state." }
        require(copyBudget in 1..MAX_COPY_BUDGET) { "Invalid mesh copy budget." }
        require(priority in MIN_PRIORITY..MAX_PRIORITY) { "Invalid mesh priority." }
        require(ciphertext.size in 1..MAX_CIPHERTEXT_BYTES) { "Invalid mesh ciphertext size." }
    }

    fun encode(): ByteArray = ByteBuffer.allocate(HEADER_BYTES + ciphertext.size)
        .order(ByteOrder.BIG_ENDIAN)
        .put(MAGIC)
        .put(VERSION)
        .put(priority.toByte())
        .putShort(0)
        .put(messageId)
        .put(destinationHint)
        .putLong(lifetimeMs)
        .putLong(ageMs)
        .put(hopLimit.toByte())
        .put(hopsTaken.toByte())
        .putShort(copyBudget.toShort())
        .putInt(ciphertext.size)
        .put(ciphertext)
        .array()

    fun forForward(transferredCopies: Int): RelayMeshEnvelope {
        require(transferredCopies in 1 until copyBudget) {
            "A courier transfer must conserve at least one local copy."
        }
        require(hopsTaken < hopLimit) { "Mesh envelope reached its hop limit." }
        return copy(
            hopsTaken = hopsTaken + 1,
            copyBudget = transferredCopies,
        )
    }

    fun withRetainedCopies(retainedCopies: Int): RelayMeshEnvelope {
        require(retainedCopies in 1 until copyBudget) { "Invalid retained mesh copy count." }
        return copy(copyBudget = retainedCopies)
    }

    /**
     * Advances the portable age by time spent in this store. A null result means the
     * envelope has reached its authenticated lifetime and must not be offered again.
     */
    fun agedBy(residentMs: Long): RelayMeshEnvelope? {
        val elapsed = residentMs.coerceAtLeast(0L)
        val remaining = lifetimeMs - ageMs
        if (elapsed >= remaining) return null
        return copy(ageMs = ageMs + elapsed)
    }

    /** Header-only private hint. The destination MAC never covers ciphertext or mutable hop state. */
    fun asRouteProbe(): RelayMeshEnvelope {
        require(copyBudget == 1) { "Only a last-copy envelope needs a destination probe." }
        return copy(ciphertext = RelayMeshSyncCodec.ROUTE_PROBE_CIPHERTEXT.copyOf())
    }

    /** Sends the final copy only after the peer proved that its private route recognizes the hint. */
    fun forRecognizedDestination(): RelayMeshEnvelope {
        require(copyBudget == 1) { "Recognized destination transfer requires a last copy." }
        require(hopsTaken < hopLimit) { "Mesh envelope reached its hop limit." }
        return copy(hopsTaken = hopsTaken + 1)
    }

    fun idHex(): String = messageId.joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    companion object {
        const val HEADER_BYTES = 64
        const val MESSAGE_ID_BYTES = 16
        const val MAX_ENCODED_BYTES = HEADER_BYTES + 64 * 1024
        private const val DESTINATION_HINT_BYTES = 16
        private const val MAX_CIPHERTEXT_BYTES = 64 * 1024
        private const val MAX_LIFETIME_MS = 30L * 24L * 60L * 60L * 1_000L
        private const val MAX_COPY_BUDGET = 64
        private const val U8_MAX = 255
        private const val MIN_PRIORITY = 0
        private const val MAX_PRIORITY = 5
        private val MAGIC = "RLY1".toByteArray(StandardCharsets.US_ASCII)
        private const val VERSION: Byte = 1

        fun decode(encoded: ByteArray): RelayMeshEnvelope {
            require(encoded.size in (HEADER_BYTES + 1)..MAX_ENCODED_BYTES) {
                "Mesh envelope has an invalid length."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Mesh envelope has an invalid prefix."
            }
            require(buffer.get() == VERSION) { "Mesh envelope version is unsupported." }
            val priority = buffer.get().toInt() and 0xFF
            require(buffer.short.toInt() == 0) { "Mesh envelope reserved bits are set." }
            val messageId = ByteArray(MESSAGE_ID_BYTES).also(buffer::get)
            val destinationHint = ByteArray(DESTINATION_HINT_BYTES).also(buffer::get)
            val lifetimeMs = buffer.long
            val ageMs = buffer.long
            val hopLimit = buffer.get().toInt() and 0xFF
            val hopsTaken = buffer.get().toInt() and 0xFF
            val copyBudget = buffer.short.toInt() and 0xFFFF
            val ciphertextLength = buffer.int
            require(ciphertextLength > 0 && ciphertextLength == buffer.remaining()) {
                "Mesh ciphertext length does not match the envelope."
            }
            val ciphertext = ByteArray(ciphertextLength).also(buffer::get)
            return RelayMeshEnvelope(
                messageId = messageId,
                destinationHint = destinationHint,
                lifetimeMs = lifetimeMs,
                ageMs = ageMs,
                hopLimit = hopLimit,
                hopsTaken = hopsTaken,
                copyBudget = copyBudget,
                priority = priority,
                ciphertext = ciphertext,
            )
        }
    }
}
