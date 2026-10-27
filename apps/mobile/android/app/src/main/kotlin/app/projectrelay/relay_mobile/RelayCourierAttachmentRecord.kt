package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Kotlin view of relay-wire's bounded, courier-visible attachment records. */
internal data class RelayCourierAttachmentPlan(
    val objectId: ByteArray,
    val cancellationCommitment: ByteArray,
    val totalCiphertextBytes: Long,
    val chunks: List<ChunkDescriptor>,
) {
    data class ChunkDescriptor(
        val ciphertextBytes: Int,
        val ciphertextSha256: ByteArray,
    )

    fun validate() {
        require(objectId.size == OBJECT_ID_BYTES) { "Courier object ID is invalid." }
        require(cancellationCommitment.size == SHA256_BYTES) {
            "Courier cancellation commitment is invalid."
        }
        require(chunks.size in 1..MAX_CHUNKS) { "Courier chunk count is invalid." }
        var actualTotal = 0L
        chunks.forEachIndexed { index, descriptor ->
            require(descriptor.ciphertextBytes in MIN_CHUNK_CIPHERTEXT_BYTES..MAX_CHUNK_CIPHERTEXT_BYTES) {
                "Courier chunk length is invalid."
            }
            require(index == chunks.lastIndex || descriptor.ciphertextBytes == MAX_CHUNK_CIPHERTEXT_BYTES) {
                "Only the final courier chunk may be short."
            }
            require(descriptor.ciphertextSha256.size == SHA256_BYTES) {
                "Courier chunk digest is invalid."
            }
            actualTotal = Math.addExact(actualTotal, descriptor.ciphertextBytes.toLong())
        }
        require(actualTotal == totalCiphertextBytes) { "Courier ciphertext total is invalid." }
        require(totalCiphertextBytes in 1..MAX_ATTACHMENT_CIPHERTEXT_BYTES) {
            "Courier attachment exceeds its size limit."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(PLAN_HEADER_BYTES + chunks.size * CHUNK_DESCRIPTOR_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(PLAN_MAGIC)
            .put(VERSION)
            .put(0)
            .putShort(chunks.size.toShort())
            .put(objectId)
            .put(cancellationCommitment)
            .putLong(totalCiphertextBytes)
            .also { buffer ->
                chunks.forEach { descriptor ->
                    buffer.putInt(descriptor.ciphertextBytes)
                    buffer.put(descriptor.ciphertextSha256)
                }
            }
            .array()
    }

    fun sha256(): ByteArray = digest(encode())

    fun requiredStoredBytes(): Long = Math.addExact(
        encode().size.toLong(),
        Math.addExact(
            totalCiphertextBytes,
            Math.multiplyExact(chunks.size.toLong(), RelayCourierAttachmentChunk.HEADER_BYTES.toLong()),
        ),
    )

    companion object {
        const val OBJECT_ID_BYTES = 16
        const val SHA256_BYTES = 32
        const val MAX_CHUNKS = 512
        const val CHUNK_PLAINTEXT_BYTES = 192 * 1024
        const val GCM_TAG_BYTES = 16
        const val MIN_CHUNK_CIPHERTEXT_BYTES = GCM_TAG_BYTES + 1
        const val MAX_CHUNK_CIPHERTEXT_BYTES = CHUNK_PLAINTEXT_BYTES + GCM_TAG_BYTES
        const val MAX_ATTACHMENT_PLAINTEXT_BYTES = 96L * 1024L * 1024L
        const val MAX_ATTACHMENT_CIPHERTEXT_BYTES =
            MAX_ATTACHMENT_PLAINTEXT_BYTES + GCM_TAG_BYTES * MAX_CHUNKS
        const val PLAN_HEADER_BYTES = 64
        const val CHUNK_DESCRIPTOR_BYTES = 36
        const val MAX_PLAN_BYTES = PLAN_HEADER_BYTES + MAX_CHUNKS * CHUNK_DESCRIPTOR_BYTES
        private const val VERSION: Byte = 1
        private val PLAN_MAGIC = "HAP1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierAttachmentPlan {
            require(encoded.size in PLAN_HEADER_BYTES..MAX_PLAN_BYTES) {
                "Courier plan length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(PLAN_MAGIC.size).also(buffer::get).contentEquals(PLAN_MAGIC)) {
                "Courier plan prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Courier plan version is unsupported." }
            require(buffer.get() == 0.toByte()) { "Courier plan reserved bits are set." }
            val chunkCount = buffer.short.toInt() and 0xFFFF
            require(chunkCount in 1..MAX_CHUNKS) { "Courier chunk count is invalid." }
            val expectedBytes = Math.addExact(
                PLAN_HEADER_BYTES,
                Math.multiplyExact(chunkCount, CHUNK_DESCRIPTOR_BYTES),
            )
            require(encoded.size == expectedBytes) { "Courier plan has trailing or missing data." }
            val plan = RelayCourierAttachmentPlan(
                objectId = ByteArray(OBJECT_ID_BYTES).also(buffer::get),
                cancellationCommitment = ByteArray(SHA256_BYTES).also(buffer::get),
                totalCiphertextBytes = buffer.long,
                chunks = List(chunkCount) {
                    ChunkDescriptor(
                        ciphertextBytes = buffer.int,
                        ciphertextSha256 = ByteArray(SHA256_BYTES).also(buffer::get),
                    )
                },
            )
            require(!buffer.hasRemaining()) { "Courier plan has trailing data." }
            plan.validate()
            require(plan.encode().contentEquals(encoded)) { "Courier plan is not canonical." }
            return plan
        }

        internal fun digest(bytes: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}

/** Exact nonce plus ciphertext record stored and forwarded without decryption. */
internal data class RelayCourierAttachmentChunk(
    val objectId: ByteArray,
    val chunkIndex: Int,
    val nonce: ByteArray,
    val ciphertextSha256: ByteArray,
    val ciphertext: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier chunk object ID is invalid."
        }
        require(chunkIndex in 0 until RelayCourierAttachmentPlan.MAX_CHUNKS) {
            "Courier chunk index is invalid."
        }
        require(nonce.size == NONCE_BYTES) { "Courier chunk nonce is invalid." }
        require(ciphertextSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier chunk digest is invalid."
        }
        require(
            ciphertext.size in RelayCourierAttachmentPlan.MIN_CHUNK_CIPHERTEXT_BYTES..
                RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES,
        ) { "Courier chunk ciphertext length is invalid." }
    }

    fun verifyAgainst(plan: RelayCourierAttachmentPlan) {
        validate()
        require(objectId.contentEquals(plan.objectId)) { "Courier chunk belongs to another object." }
        val descriptor = plan.chunks.getOrNull(chunkIndex)
            ?: throw IllegalArgumentException("Courier chunk index is outside its plan.")
        require(descriptor.ciphertextBytes == ciphertext.size) {
            "Courier chunk length disagrees with its plan."
        }
        require(descriptor.ciphertextSha256.contentEquals(ciphertextSha256)) {
            "Courier chunk digest disagrees with its plan."
        }
        require(RelayCourierAttachmentPlan.digest(ciphertext).contentEquals(ciphertextSha256)) {
            "Courier chunk ciphertext is corrupt."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(HEADER_BYTES + ciphertext.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(CHUNK_MAGIC)
            .put(VERSION)
            .put(0)
            .putShort(chunkIndex.toShort())
            .put(objectId)
            .put(nonce)
            .putInt(ciphertext.size)
            .put(ciphertextSha256)
            .put(ciphertext)
            .array()
    }

    companion object {
        const val NONCE_BYTES = 12
        const val HEADER_BYTES = 72
        private const val VERSION: Byte = 1
        private val CHUNK_MAGIC = "HAC1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierAttachmentChunk {
            require(
                encoded.size in
                    (HEADER_BYTES + RelayCourierAttachmentPlan.MIN_CHUNK_CIPHERTEXT_BYTES)..
                    (HEADER_BYTES + RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES),
            ) { "Courier chunk record length is invalid." }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(CHUNK_MAGIC.size).also(buffer::get).contentEquals(CHUNK_MAGIC)) {
                "Courier chunk prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Courier chunk version is unsupported." }
            require(buffer.get() == 0.toByte()) { "Courier chunk reserved bits are set." }
            val chunk = RelayCourierAttachmentChunk(
                chunkIndex = buffer.short.toInt() and 0xFFFF,
                objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get),
                nonce = ByteArray(NONCE_BYTES).also(buffer::get),
                ciphertextSha256 = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES).also {
                    val ciphertextBytes = buffer.int
                    require(ciphertextBytes == buffer.remaining() - it.size) {
                        "Courier chunk ciphertext length does not match."
                    }
                    buffer.get(it)
                },
                ciphertext = ByteArray(buffer.remaining()).also(buffer::get),
            )
            chunk.validate()
            require(chunk.encode().contentEquals(encoded)) { "Courier chunk is not canonical." }
            return chunk
        }
    }
}

/** Hop-authenticated durable custody bitmap. This record never means recipient delivery. */
internal data class RelayCourierAttachmentCustody(
    val objectId: ByteArray,
    val planSha256: ByteArray,
    val planCommitted: Boolean,
    val chunkCount: Int,
    val chunkBitmap: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier custody object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier custody plan digest is invalid."
        }
        require(chunkCount in 1..RelayCourierAttachmentPlan.MAX_CHUNKS) {
            "Courier custody chunk count is invalid."
        }
        require(chunkBitmap.size == bitmapBytes(chunkCount)) { "Courier custody bitmap is invalid." }
        val usedBits = chunkCount % 8
        if (usedBits != 0) {
            val unusedMask = ((1 shl (8 - usedBits)) - 1) shl usedBits
            require((chunkBitmap.last().toInt() and unusedMask) == 0) {
                "Courier custody bitmap has non-canonical bits."
            }
        }
        require(planCommitted || chunkBitmap.all { it == 0.toByte() }) {
            "Courier chunks cannot be acknowledged before their plan."
        }
    }

    fun hasChunk(index: Int): Boolean = index in 0 until chunkCount &&
        (chunkBitmap[index / 8].toInt() and (1 shl (index % 8))) != 0

    fun missingChunks(): List<Int> = (0 until chunkCount).filterNot(::hasChunk)

    /** Exact missing-bit view derived from the durable HCU1 stored-chunk bitmap. */
    fun missingBitmap(): ByteArray = ByteArray(chunkBitmap.size).also { missing ->
        for (index in 0 until chunkCount) {
            if (!hasChunk(index)) {
                missing[index / 8] =
                    (missing[index / 8].toInt() or (1 shl (index % 8))).toByte()
            }
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(HEADER_BYTES + chunkBitmap.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(CUSTODY_MAGIC)
            .put(VERSION)
            .put(if (planCommitted) 1 else 0)
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
        private val CUSTODY_MAGIC = "HCU1".toByteArray(StandardCharsets.US_ASCII)

        fun fromCommitted(plan: RelayCourierAttachmentPlan, storedIndices: Collection<Int>):
            RelayCourierAttachmentCustody {
            require(storedIndices.size <= plan.chunks.size && storedIndices.all { it in plan.chunks.indices }) {
                "Courier custody contains an invalid chunk index."
            }
            val bitmap = ByteArray(bitmapBytes(plan.chunks.size))
            storedIndices.toSet().forEach { index ->
                bitmap[index / 8] = (bitmap[index / 8].toInt() or (1 shl (index % 8))).toByte()
            }
            return RelayCourierAttachmentCustody(
                objectId = plan.objectId.copyOf(),
                planSha256 = plan.sha256(),
                planCommitted = true,
                chunkCount = plan.chunks.size,
                chunkBitmap = bitmap,
            ).also(RelayCourierAttachmentCustody::validate)
        }

        fun decode(encoded: ByteArray): RelayCourierAttachmentCustody {
            require(encoded.size in (HEADER_BYTES + 1)..(HEADER_BYTES + 64)) {
                "Courier custody record length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(CUSTODY_MAGIC.size).also(buffer::get).contentEquals(CUSTODY_MAGIC)) {
                "Courier custody prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Courier custody version is unsupported." }
            val flags = buffer.get().toInt() and 0xFF
            require(flags and 0xFE == 0) { "Courier custody reserved bits are set." }
            val chunkCount = buffer.short.toInt() and 0xFFFF
            val objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get)
            val planSha256 = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES).also(buffer::get)
            val bitmapLength = buffer.short.toInt() and 0xFFFF
            require(bitmapLength == buffer.remaining()) { "Courier custody bitmap length is invalid." }
            return RelayCourierAttachmentCustody(
                objectId = objectId,
                planSha256 = planSha256,
                planCommitted = flags and 1 != 0,
                chunkCount = chunkCount,
                chunkBitmap = ByteArray(bitmapLength).also(buffer::get),
            ).also(RelayCourierAttachmentCustody::validate)
        }

        private fun bitmapBytes(chunkCount: Int): Int = (chunkCount + 7) / 8
    }
}

/** Deterministic quota and monotonic-age rules shared by the SQLite store and unit tests. */
internal object RelayCourierAttachmentPolicy {
    const val ENGINEERING_QUOTA_BYTES = 128L * 1024L * 1024L
    const val MIN_FREE_SPACE_BYTES = 32L * 1024L * 1024L
    const val MAX_ACTIVE_PLANS = 64

    data class AgeResult(
        val ageMs: Long,
        val anchorElapsedMs: Long,
        val expired: Boolean,
        val rebootDetected: Boolean,
    )

    fun advanceAge(
        ageMs: Long,
        lifetimeMs: Long,
        anchorElapsedMs: Long,
        nowElapsedMs: Long,
    ): AgeResult {
        require(lifetimeMs > 0L && ageMs in 0..lifetimeMs && anchorElapsedMs >= 0L && nowElapsedMs >= 0L) {
            "Courier age state is invalid."
        }
        val rebootDetected = nowElapsedMs < anchorElapsedMs
        val elapsed = if (rebootDetected) 0L else nowElapsedMs - anchorElapsedMs
        val advanced = ageMs.saturatingAdd(elapsed).coerceAtMost(lifetimeMs)
        return AgeResult(
            ageMs = advanced,
            anchorElapsedMs = nowElapsedMs,
            expired = advanced >= lifetimeMs,
            rebootDetected = rebootDetected,
        )
    }

    fun canAdmit(
        usedBytes: Long,
        incomingBytes: Long,
        quotaBytes: Long,
        usableSpaceBytes: Long,
    ): Boolean {
        if (usedBytes < 0L || incomingBytes <= 0L || quotaBytes <= 0L || usableSpaceBytes < 0L) {
            return false
        }
        return incomingBytes <= quotaBytes - usedBytes.coerceAtMost(quotaBytes) &&
            incomingBytes <= usableSpaceBytes - MIN_FREE_SPACE_BYTES.coerceAtMost(usableSpaceBytes)
    }

    private fun Long.saturatingAdd(other: Long): Long =
        if (Long.MAX_VALUE - this < other) Long.MAX_VALUE else this + other
}
