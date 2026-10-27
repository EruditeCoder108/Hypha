package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Authenticated BLE control offer carrying only a recipient-encrypted RLY1 manifest and HAP1 plan.
 *
 * Chunk transport capability remains zero in this slice: no attachment bytes belong in this
 * record or on BLE. The two non-zero capability versions are visible only after Noise decrypts
 * the offer.
 */
internal data class RelayAttachmentPlanOffer(
    val encodedManifest: ByteArray,
    val encodedPlan: ByteArray,
) {
    fun validate() {
        val manifest = RelayMeshEnvelope.decode(encodedManifest)
        val plan = RelayCourierAttachmentPlan.decode(encodedPlan)
        require(manifest.encode().contentEquals(encodedManifest)) {
            "Attachment plan offer manifest is not canonical."
        }
        require(manifest.messageId.contentEquals(plan.objectId)) {
            "Attachment plan offer object IDs differ."
        }
        require(manifest.priority == MANIFEST_PRIORITY) {
            "Attachment plan offer manifest has the wrong priority."
        }
        val totalBytes = Math.addExact(
            HEADER_BYTES,
            Math.addExact(encodedManifest.size, encodedPlan.size),
        )
        require(totalBytes <= MAX_ENCODED_BYTES) {
            "Attachment plan offer exceeds the BLE control bound."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(HEADER_BYTES + encodedManifest.size + encodedPlan.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(OFFER_MAGIC)
            .put(VERSION)
            .put(OBJECT_PLAN_CAPABILITY_VERSION)
            .put(CUSTODY_CAPABILITY_VERSION)
            .put(NO_CHUNK_TRANSPORT_CAPABILITY)
            .putShort(0)
            .putShort(encodedManifest.size.toShort())
            .putShort(encodedPlan.size.toShort())
            .put(encodedManifest)
            .put(encodedPlan)
            .array()
    }

    companion object {
        const val HEADER_BYTES = 14
        const val MAX_ENCODED_BYTES = 32_768
        private const val MANIFEST_PRIORITY = 4
        private const val VERSION: Byte = 1
        private const val OBJECT_PLAN_CAPABILITY_VERSION: Byte = 1
        private const val CUSTODY_CAPABILITY_VERSION: Byte = 1
        private const val NO_CHUNK_TRANSPORT_CAPABILITY: Byte = 0
        private val OFFER_MAGIC = "HAO1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayAttachmentPlanOffer {
            require(encoded.size in (HEADER_BYTES + 1)..MAX_ENCODED_BYTES) {
                "Attachment plan offer length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(OFFER_MAGIC.size).also(buffer::get).contentEquals(OFFER_MAGIC)) {
                "Attachment plan offer prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Attachment plan offer version is unsupported." }
            require(buffer.get() == OBJECT_PLAN_CAPABILITY_VERSION) {
                "Attachment plan capability is unsupported."
            }
            require(buffer.get() == CUSTODY_CAPABILITY_VERSION) {
                "Attachment custody capability is unsupported."
            }
            require(buffer.get() == NO_CHUNK_TRANSPORT_CAPABILITY) {
                "Attachment chunk transport capability is unsupported."
            }
            require(buffer.short.toInt() == 0) { "Attachment plan offer reserved bits are set." }
            val manifestBytes = buffer.short.toInt() and 0xFFFF
            val planBytes = buffer.short.toInt() and 0xFFFF
            val expectedBytes = Math.addExact(
                HEADER_BYTES,
                Math.addExact(manifestBytes, planBytes),
            )
            require(expectedBytes == encoded.size) {
                "Attachment plan offer has trailing or missing data."
            }
            require(manifestBytes > 0 && planBytes > 0) {
                "Attachment plan offer contains an empty record."
            }
            val offer = RelayAttachmentPlanOffer(
                encodedManifest = ByteArray(manifestBytes).also(buffer::get),
                encodedPlan = ByteArray(planBytes).also(buffer::get),
            )
            require(!buffer.hasRemaining()) { "Attachment plan offer has trailing data." }
            offer.validate()
            require(offer.encode().contentEquals(encoded)) {
                "Attachment plan offer is not canonical."
            }
            return offer
        }
    }
}

/** Durable store admission result used by the authenticated GATT control path. */
internal object RelayAttachmentPlanControl {
    sealed interface Outcome {
        data class Custodied(
            val encodedCustody: ByteArray,
            val objectId: ByteArray,
            val planSha256: ByteArray,
            val chunkCount: Int,
            val missingBitmap: ByteArray,
            val missingChunks: List<Int>,
            val inserted: Boolean,
        ) : Outcome

        data class Declined(val reason: DeclineReason) : Outcome
    }

    enum class DeclineReason {
        STORE_FULL,
        EXPIRED,
        TERMINAL,
    }

    fun accept(
        store: RelayCourierAttachmentStore,
        encodedOffer: ByteArray,
    ): Outcome {
        val offer = RelayAttachmentPlanOffer.decode(encodedOffer)
        val plan = RelayCourierAttachmentPlan.decode(offer.encodedPlan)
        return when (val acceptance = store.acceptPlan(offer.encodedManifest, offer.encodedPlan)) {
            is RelayCourierAttachmentStore.PlanAcceptance.Accepted -> {
                val custody = RelayCourierAttachmentCustody.decode(acceptance.custody)
                require(custody.planCommitted) {
                    "Courier returned custody before committing the attachment plan."
                }
                require(custody.objectId.contentEquals(plan.objectId)) {
                    "Courier custody belongs to another object."
                }
                require(MessageDigest.isEqual(custody.planSha256, plan.sha256())) {
                    "Courier custody plan digest does not match."
                }
                require(custody.chunkCount == plan.chunks.size) {
                    "Courier custody chunk count does not match."
                }
                Outcome.Custodied(
                    encodedCustody = acceptance.custody.copyOf(),
                    objectId = custody.objectId.copyOf(),
                    planSha256 = custody.planSha256.copyOf(),
                    chunkCount = custody.chunkCount,
                    missingBitmap = custody.missingBitmap(),
                    missingChunks = custody.missingChunks(),
                    inserted = acceptance.inserted,
                )
            }
            RelayCourierAttachmentStore.PlanAcceptance.StoreFull ->
                Outcome.Declined(DeclineReason.STORE_FULL)
            RelayCourierAttachmentStore.PlanAcceptance.Expired ->
                Outcome.Declined(DeclineReason.EXPIRED)
            RelayCourierAttachmentStore.PlanAcceptance.Terminal ->
                Outcome.Declined(DeclineReason.TERMINAL)
        }
    }
}
