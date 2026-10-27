package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Additive BLE authorization for an opaque courier Wi-Fi hop. */
internal data class RelayCourierWifiUpgradeRequest(
    val objectId: ByteArray,
    val planSha256: ByteArray,
    val encodedWifiOffer: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier Wi-Fi object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier Wi-Fi plan digest is invalid."
        }
        require(encodedWifiOffer.size == WIFI_OFFER_BYTES) {
            "Courier Wi-Fi authorization is invalid."
        }
        require(encodedWifiOffer.copyOfRange(0, WIFI_OFFER_MAGIC.size).contentEquals(WIFI_OFFER_MAGIC)) {
            "Courier Wi-Fi authorization prefix is invalid."
        }
        require(
            encodedWifiOffer[4] == WIFI_OFFER_VERSION &&
                encodedWifiOffer.sliceArray(5..7).all { it == 0.toByte() },
        ) {
            "Courier Wi-Fi authorization version or reserved bits are invalid."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(HEADER_BYTES + encodedWifiOffer.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(0)
            .putShort(encodedWifiOffer.size.toShort())
            .put(objectId)
            .put(planSha256)
            .put(encodedWifiOffer)
            .array()
    }

    companion object {
        const val HEADER_BYTES = 56
        const val MAX_WIFI_OFFER_BYTES = 512
        private const val WIFI_OFFER_BYTES = 72
        private const val WIFI_OFFER_VERSION: Byte = 1
        private const val VERSION: Byte = 1
        private val MAGIC = "HWF1".toByteArray(StandardCharsets.US_ASCII)
        private val WIFI_OFFER_MAGIC = "RWUO".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierWifiUpgradeRequest {
            require(encoded.size in (HEADER_BYTES + 1)..(HEADER_BYTES + MAX_WIFI_OFFER_BYTES)) {
                "Courier Wi-Fi request length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Courier Wi-Fi request prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Courier Wi-Fi request version is unsupported." }
            require(buffer.get() == 0.toByte()) { "Courier Wi-Fi request reserved bits are set." }
            val offerBytes = buffer.short.toInt() and 0xFFFF
            require(offerBytes > 0 && encoded.size == HEADER_BYTES + offerBytes) {
                "Courier Wi-Fi request has trailing or missing data."
            }
            val request = RelayCourierWifiUpgradeRequest(
                objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get),
                planSha256 = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES).also(buffer::get),
                encodedWifiOffer = ByteArray(offerBytes).also(buffer::get),
            )
            require(!buffer.hasRemaining()) { "Courier Wi-Fi request has trailing data." }
            request.validate()
            require(request.encode().contentEquals(encoded)) {
                "Courier Wi-Fi request is not canonical."
            }
            return request
        }
    }
}

/** Bounded framing around one canonical HAC1 record inside the fast Noise session. */
internal data class RelayCourierWifiChunkStart(
    val objectId: ByteArray,
    val chunkIndex: Int,
    val recordBytes: Int,
) {
    fun validate() {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier Wi-Fi chunk object ID is invalid."
        }
        require(chunkIndex in 0 until RelayCourierAttachmentPlan.MAX_CHUNKS) {
            "Courier Wi-Fi chunk index is invalid."
        }
        require(
            recordBytes in MIN_RECORD_BYTES..MAX_RECORD_BYTES,
        ) { "Courier Wi-Fi chunk record length is invalid." }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(ENCODED_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(0)
            .putShort(chunkIndex.toShort())
            .put(objectId)
            .putInt(recordBytes)
            .array()
    }

    companion object {
        const val ENCODED_BYTES = 28
        const val MIN_RECORD_BYTES =
            RelayCourierAttachmentChunk.HEADER_BYTES + RelayCourierAttachmentPlan.MIN_CHUNK_CIPHERTEXT_BYTES
        const val MAX_RECORD_BYTES =
            RelayCourierAttachmentChunk.HEADER_BYTES + RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES
        private const val VERSION: Byte = 1
        private val MAGIC = "HXS1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierWifiChunkStart {
            require(encoded.size == ENCODED_BYTES) { "Courier Wi-Fi chunk start length is invalid." }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MAGIC.size).also(buffer::get).contentEquals(MAGIC)) {
                "Courier Wi-Fi chunk start prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Courier Wi-Fi chunk start version is unsupported." }
            require(buffer.get() == 0.toByte()) { "Courier Wi-Fi chunk start reserved bits are set." }
            return RelayCourierWifiChunkStart(
                chunkIndex = buffer.short.toInt() and 0xFFFF,
                objectId = ByteArray(RelayCourierAttachmentPlan.OBJECT_ID_BYTES).also(buffer::get),
                recordBytes = buffer.int,
            ).also {
                require(!buffer.hasRemaining()) { "Courier Wi-Fi chunk start has trailing data." }
                it.validate()
                require(it.encode().contentEquals(encoded)) {
                    "Courier Wi-Fi chunk start is not canonical."
                }
            }
        }
    }
}

internal data class RelayCourierWifiDone(val objectId: ByteArray) {
    fun encode(): ByteArray {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier Wi-Fi completion object ID is invalid."
        }
        return MAGIC + byteArrayOf(VERSION, 0, 0, 0) + objectId
    }

    companion object {
        const val ENCODED_BYTES = 24
        private const val VERSION: Byte = 1
        private val MAGIC = "HXD1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayCourierWifiDone {
            require(encoded.size == ENCODED_BYTES) { "Courier Wi-Fi completion length is invalid." }
            require(encoded.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
                "Courier Wi-Fi completion prefix is invalid."
            }
            require(encoded[4] == VERSION && encoded.sliceArray(5..7).all { it == 0.toByte() }) {
                "Courier Wi-Fi completion version or reserved bits are invalid."
            }
            return RelayCourierWifiDone(encoded.copyOfRange(8, encoded.size)).also {
                require(it.encode().contentEquals(encoded)) {
                    "Courier Wi-Fi completion is not canonical."
                }
            }
        }
    }
}

/** Pure validation shared by the socket path and focused tests. */
internal object RelayCourierWifiTransferPolicy {
    fun requireResumeDoesNotRegress(
        previous: RelayCourierAttachmentCustody,
        current: RelayCourierAttachmentCustody,
    ) {
        previous.validate()
        current.validate()
        require(
            current.objectId.contentEquals(previous.objectId) &&
                MessageDigest.isEqual(current.planSha256, previous.planSha256) &&
                current.chunkCount == previous.chunkCount,
        ) { "Courier Wi-Fi custody belongs to another plan." }
        require(previous.chunkBitmap.indices.all { index ->
            (current.chunkBitmap[index].toInt() and previous.chunkBitmap[index].toInt()) ==
                previous.chunkBitmap[index].toInt()
        }) { "Courier Wi-Fi custody regressed." }
    }

    fun buildChunk(
        manifest: RelayAttachmentManifest,
        chunkIndex: Int,
        ciphertext: ByteArray,
    ): RelayCourierAttachmentChunk {
        manifest.validate()
        val descriptor = manifest.chunks.getOrNull(chunkIndex)
            ?: throw IllegalArgumentException("Courier Wi-Fi chunk index is invalid.")
        return RelayCourierAttachmentChunk(
            objectId = manifest.attachmentId.copyOf(),
            chunkIndex = descriptor.index,
            nonce = descriptor.nonce.copyOf(),
            ciphertextSha256 = descriptor.ciphertextSha256.copyOf(),
            ciphertext = ciphertext.copyOf(),
        ).also {
            require(descriptor.index == chunkIndex) { "Attachment chunks are not canonical." }
            it.validate()
            require(ciphertext.size == descriptor.ciphertextBytes) {
                "Courier Wi-Fi ciphertext length disagrees with its manifest."
            }
            require(MessageDigest.isEqual(RelayCourierAttachmentPlan.digest(ciphertext), descriptor.ciphertextSha256)) {
                "Courier Wi-Fi ciphertext digest disagrees with its manifest."
            }
        }
    }
}
