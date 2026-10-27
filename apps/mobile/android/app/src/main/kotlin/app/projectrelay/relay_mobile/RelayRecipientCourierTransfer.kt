package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal data class RelayRecipientWifiPull(
    val objectId: ByteArray,
    val planSha256: ByteArray,
) {
    fun encode(): ByteArray {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Recipient pull object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Recipient pull plan digest is invalid."
        }
        return MAGIC + byteArrayOf(VERSION, 0, 0, 0) + objectId + planSha256
    }

    companion object {
        const val ENCODED_BYTES = 56
        private const val VERSION: Byte = 1
        private val MAGIC = "HXP1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayRecipientWifiPull {
            require(encoded.size == ENCODED_BYTES) { "Recipient pull length is invalid." }
            require(encoded.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
                "Recipient pull prefix is invalid."
            }
            require(encoded[4] == VERSION && encoded.sliceArray(5..7).all { it == 0.toByte() }) {
                "Recipient pull version or reserved bits are invalid."
            }
            return RelayRecipientWifiPull(
                objectId = encoded.copyOfRange(8, 24),
                planSha256 = encoded.copyOfRange(24, 56),
            ).also { pull ->
                require(pull.encode().contentEquals(encoded)) { "Recipient pull is not canonical." }
            }
        }
    }
}

/** Courier-visible plan plus public GCM nonces; private HAM1 fields never enter this record. */
internal data class RelayRecipientCourierDescriptor(
    val plan: RelayCourierAttachmentPlan,
    val nonces: List<ByteArray>,
) {
    fun validate() {
        plan.validate()
        require(nonces.size == plan.chunks.size) {
            "Recipient courier descriptor nonce count is invalid."
        }
        require(nonces.all { it.size == RelayCourierAttachmentChunk.NONCE_BYTES }) {
            "Recipient courier descriptor nonce is invalid."
        }
    }

    fun encode(): ByteArray {
        validate()
        val encodedPlan = plan.encode()
        return ByteBuffer.allocate(
            HEADER_BYTES + encodedPlan.size + nonces.size * RelayCourierAttachmentChunk.NONCE_BYTES,
        ).order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(0)
            .putShort(nonces.size.toShort())
            .put(plan.objectId)
            .putShort(encodedPlan.size.toShort())
            .putShort(0)
            .put(encodedPlan)
            .also { buffer -> nonces.forEach(buffer::put) }
            .array()
    }

    companion object {
        const val HEADER_BYTES = 28
        const val MAX_ENCODED_BYTES = HEADER_BYTES + RelayCourierAttachmentPlan.MAX_PLAN_BYTES +
            RelayCourierAttachmentPlan.MAX_CHUNKS * RelayCourierAttachmentChunk.NONCE_BYTES
        private const val VERSION: Byte = 1
        private val MAGIC = "HRD1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayRecipientCourierDescriptor {
            require(encoded.size in (HEADER_BYTES + RelayCourierAttachmentPlan.PLAN_HEADER_BYTES +
                RelayCourierAttachmentChunk.NONCE_BYTES)..MAX_ENCODED_BYTES
            ) { "Recipient courier descriptor length is invalid." }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Recipient courier descriptor prefix is invalid."
            }
            require(buffer.get() == VERSION) {
                "Recipient courier descriptor version is unsupported."
            }
            require(buffer.get() == 0.toByte()) {
                "Recipient courier descriptor reserved bits are set."
            }
            val chunkCount = buffer.short.toInt() and 0xFFFF
            require(chunkCount in 1..RelayCourierAttachmentPlan.MAX_CHUNKS) {
                "Recipient courier descriptor chunk count is invalid."
            }
            val objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get)
            val planBytes = buffer.short.toInt() and 0xFFFF
            require(buffer.short.toInt() == 0) {
                "Recipient courier descriptor reserved bits are set."
            }
            require(
                planBytes in RelayCourierAttachmentPlan.PLAN_HEADER_BYTES..RelayCourierAttachmentPlan.MAX_PLAN_BYTES &&
                    encoded.size == HEADER_BYTES + planBytes +
                    chunkCount * RelayCourierAttachmentChunk.NONCE_BYTES,
            ) { "Recipient courier descriptor has trailing or missing data." }
            val plan = RelayCourierAttachmentPlan.decode(ByteArray(planBytes).also(buffer::get))
            require(plan.objectId.contentEquals(objectId) && plan.chunks.size == chunkCount) {
                "Recipient courier descriptor does not match its plan."
            }
            return RelayRecipientCourierDescriptor(
                plan = plan,
                nonces = List(chunkCount) {
                    ByteArray(RelayCourierAttachmentChunk.NONCE_BYTES).also(buffer::get)
                },
            ).also { descriptor ->
                require(!buffer.hasRemaining()) {
                    "Recipient courier descriptor has trailing data."
                }
                descriptor.validate()
                require(descriptor.encode().contentEquals(encoded)) {
                    "Recipient courier descriptor is not canonical."
                }
            }
        }
    }
}

/** Recipient durable-chunk bitmap used only for fast-hop resume; it is not HAR1. */
internal data class RelayRecipientChunkResume(
    val objectId: ByteArray,
    val planSha256: ByteArray,
    val chunkCount: Int,
    val chunkBitmap: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Recipient resume object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Recipient resume plan digest is invalid."
        }
        require(chunkCount in 1..RelayCourierAttachmentPlan.MAX_CHUNKS) {
            "Recipient resume chunk count is invalid."
        }
        require(chunkBitmap.size == bitmapBytes(chunkCount)) {
            "Recipient resume bitmap is invalid."
        }
        val usedBits = chunkCount % 8
        if (usedBits != 0) {
            val unusedMask = ((1 shl (8 - usedBits)) - 1) shl usedBits
            require((chunkBitmap.last().toInt() and unusedMask) == 0) {
                "Recipient resume bitmap has non-canonical bits."
            }
        }
    }

    fun hasChunk(index: Int): Boolean = index in 0 until chunkCount &&
        (chunkBitmap[index / 8].toInt() and (1 shl (index % 8))) != 0

    fun missingChunks(): List<Int> = (0 until chunkCount).filterNot(::hasChunk)

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(HEADER_BYTES + chunkBitmap.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(0)
            .putShort(chunkCount.toShort())
            .put(objectId)
            .put(planSha256)
            .putShort(chunkBitmap.size.toShort())
            .put(chunkBitmap)
            .array()
    }

    companion object {
        const val HEADER_BYTES = 58
        private const val VERSION: Byte = 1
        private val MAGIC = "HRQ1".toByteArray(StandardCharsets.US_ASCII)

        fun fromCommitted(
            plan: RelayCourierAttachmentPlan,
            committedIndices: Collection<Int>,
        ): RelayRecipientChunkResume {
            require(
                committedIndices.size <= plan.chunks.size &&
                    committedIndices.all { it in plan.chunks.indices },
            ) { "Recipient resume contains an invalid chunk index." }
            val bitmap = ByteArray(bitmapBytes(plan.chunks.size))
            committedIndices.toSet().forEach { index ->
                bitmap[index / 8] = (bitmap[index / 8].toInt() or (1 shl (index % 8))).toByte()
            }
            return RelayRecipientChunkResume(
                objectId = plan.objectId.copyOf(),
                planSha256 = plan.sha256(),
                chunkCount = plan.chunks.size,
                chunkBitmap = bitmap,
            ).also(RelayRecipientChunkResume::validate)
        }

        fun decode(encoded: ByteArray): RelayRecipientChunkResume {
            require(encoded.size in (HEADER_BYTES + 1)..(HEADER_BYTES + 64)) {
                "Recipient resume length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Recipient resume prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Recipient resume version is unsupported." }
            require(buffer.get() == 0.toByte()) { "Recipient resume reserved bits are set." }
            val chunkCount = buffer.short.toInt() and 0xFFFF
            val objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get)
            val planSha256 = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES).also(buffer::get)
            val bitmapLength = buffer.short.toInt() and 0xFFFF
            require(bitmapLength == buffer.remaining()) { "Recipient resume bitmap length is invalid." }
            return RelayRecipientChunkResume(
                objectId = objectId,
                planSha256 = planSha256,
                chunkCount = chunkCount,
                chunkBitmap = ByteArray(bitmapLength).also(buffer::get),
            ).also { resume ->
                resume.validate()
                require(resume.encode().contentEquals(encoded)) {
                    "Recipient resume is not canonical."
                }
            }
        }

        private fun bitmapBytes(chunkCount: Int): Int = (chunkCount + 7) / 8
    }
}

internal object RelayRecipientCourierTransferPolicy {
    fun descriptor(
        plan: RelayCourierAttachmentPlan,
        nonces: List<ByteArray>,
    ): RelayRecipientCourierDescriptor = RelayRecipientCourierDescriptor(
        plan = plan,
        nonces = nonces.map(ByteArray::copyOf),
    ).also(RelayRecipientCourierDescriptor::validate)

    /** Reconstructs endpoint-private HYA1 only on the authenticated recipient. */
    fun materialize(
        recipient: RelayRecipientAttachmentManifest,
        descriptor: RelayRecipientCourierDescriptor,
    ): RelayAttachmentManifest {
        recipient.validate()
        descriptor.validate()
        val plan = descriptor.plan
        require(
            recipient.objectId.contentEquals(plan.objectId) &&
                MessageDigest.isEqual(recipient.courierPlanSha256, plan.sha256()),
        ) { "Recipient manifest does not authenticate this courier plan." }
        return RelayAttachmentManifest(
            attachmentId = recipient.objectId.copyOf(),
            kind = recipient.kind,
            fileName = recipient.fileName,
            mimeType = recipient.mimeType,
            plaintextBytes = recipient.plaintextBytes,
            chunkSize = RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES,
            contentKey = recipient.contentKey.copyOf(),
            plaintextSha256 = recipient.plaintextSha256.copyOf(),
            chunks = plan.chunks.mapIndexed { index, chunk ->
                RelayAttachmentManifest.Chunk(
                    index = index,
                    plaintextBytes = chunk.ciphertextBytes - RelayAttachmentManifest.GCM_TAG_BYTES,
                    nonce = descriptor.nonces[index].copyOf(),
                    ciphertextBytes = chunk.ciphertextBytes,
                    ciphertextSha256 = chunk.ciphertextSha256.copyOf(),
                )
            },
        ).also(RelayAttachmentManifest::validate)
    }
}
