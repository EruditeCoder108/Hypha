package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Sender-authorized courier cleanup created only after the sender authenticates HAR1.
 * The secret is already committed by HAP1 and travels only inside an authenticated hop.
 */
internal data class RelayCourierAttachmentCleanup(
    val objectId: ByteArray,
    val planSha256: ByteArray,
    val cancellationSecret: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier cleanup object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier cleanup plan digest is invalid."
        }
        require(cancellationSecret.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier cleanup secret is invalid."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(ENCODED_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(byteArrayOf(0, 0, 0))
            .put(objectId)
            .put(planSha256)
            .put(cancellationSecret)
            .array()
    }

    companion object {
        const val ENCODED_BYTES = 88
        private const val VERSION: Byte = 1
        private val MAGIC = "HCL1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierAttachmentCleanup {
            require(encoded.size == ENCODED_BYTES) { "Courier cleanup length is invalid." }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Courier cleanup prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Courier cleanup version is unsupported." }
            require(ByteArray(3).also(buffer::get).all { it == 0.toByte() }) {
                "Courier cleanup reserved bits are set."
            }
            return RelayCourierAttachmentCleanup(
                objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get),
                planSha256 = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES).also(buffer::get),
                cancellationSecret = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES)
                    .also(buffer::get),
            ).also(RelayCourierAttachmentCleanup::validate)
        }
    }
}

/** Exact durable cleanup acknowledgement; it never means recipient delivery by itself. */
internal data class RelayCourierAttachmentCleanupAck(
    val objectId: ByteArray,
    val planSha256: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier cleanup acknowledgement object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier cleanup acknowledgement plan digest is invalid."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(ENCODED_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(APPLIED_STATUS)
            .putShort(0)
            .put(objectId)
            .put(planSha256)
            .array()
    }

    companion object {
        const val ENCODED_BYTES = 56
        private const val VERSION: Byte = 1
        private const val APPLIED_STATUS: Byte = 1
        private val MAGIC = "HCA1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierAttachmentCleanupAck {
            require(encoded.size == ENCODED_BYTES) {
                "Courier cleanup acknowledgement length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Courier cleanup acknowledgement prefix is invalid."
            }
            require(buffer.get() == VERSION) {
                "Courier cleanup acknowledgement version is unsupported."
            }
            require(buffer.get() == APPLIED_STATUS) {
                "Courier cleanup acknowledgement status is invalid."
            }
            require(buffer.short.toInt() == 0) {
                "Courier cleanup acknowledgement reserved bits are set."
            }
            return RelayCourierAttachmentCleanupAck(
                objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get),
                planSha256 = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES).also(buffer::get),
            ).also(RelayCourierAttachmentCleanupAck::validate)
        }
    }
}
