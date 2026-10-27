package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Endpoint-only metadata. This record must never enter courier storage or diagnostics. */
internal data class RelayRecipientAttachmentManifest(
    val objectId: ByteArray,
    val kind: RelayAttachmentManifest.Kind,
    val courierPlanSha256: ByteArray,
    val contentKey: ByteArray,
    val plaintextBytes: Long,
    val plaintextSha256: ByteArray,
    val mimeType: String,
    val fileName: String,
) {
    fun validate() {
        require(objectId.size == OBJECT_ID_BYTES) { "Recipient attachment object ID is invalid." }
        require(courierPlanSha256.size == SHA256_BYTES) {
            "Recipient attachment plan digest is invalid."
        }
        require(contentKey.size == CONTENT_KEY_BYTES) { "Recipient attachment key is invalid." }
        require(plaintextSha256.size == SHA256_BYTES) {
            "Recipient attachment plaintext digest is invalid."
        }
        require(plaintextBytes in 1..kind.maximumBytes) {
            "Recipient attachment size is outside limits."
        }
        val mimeBytes = mimeType.toByteArray(StandardCharsets.US_ASCII)
        require(
            mimeType.all { it.code <= 0x7F } &&
                mimeBytes.size in 3..MAX_MIME_BYTES &&
                MIME_PATTERN.matches(mimeType),
        ) { "Recipient attachment MIME type is invalid." }
        val nameBytes = fileName.toByteArray(StandardCharsets.UTF_8)
        require(nameBytes.size in 1..MAX_FILE_NAME_BYTES) {
            "Recipient attachment file name is invalid."
        }
        require(
            fileName.trim { it.isWhitespace() } == fileName &&
                !fileName.startsWith('.') &&
                !fileName.endsWith('.') &&
                fileName.codePoints().allMatch { codePoint ->
                    !Character.isISOControl(codePoint) && codePoint != '/'.code && codePoint != '\\'.code
                },
        ) { "Recipient attachment file name is unsafe." }
    }

    fun encode(): ByteArray {
        validate()
        val mimeBytes = mimeType.toByteArray(StandardCharsets.US_ASCII)
        val nameBytes = fileName.toByteArray(StandardCharsets.UTF_8)
        return ByteBuffer.allocate(HEADER_BYTES + mimeBytes.size + nameBytes.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MANIFEST_MAGIC)
            .put(VERSION)
            .put(kind.wireValue)
            .putShort(0)
            .put(objectId)
            .put(courierPlanSha256)
            .put(contentKey)
            .putLong(plaintextBytes)
            .put(plaintextSha256)
            .putShort(mimeBytes.size.toShort())
            .putShort(nameBytes.size.toShort())
            .put(mimeBytes)
            .put(nameBytes)
            .array()
    }

    companion object {
        const val OBJECT_ID_BYTES = 16
        const val SHA256_BYTES = 32
        const val CONTENT_KEY_BYTES = 32
        const val MAX_MIME_BYTES = 96
        const val MAX_FILE_NAME_BYTES = 128
        const val HEADER_BYTES = 132
        const val MAX_ENCODED_BYTES = HEADER_BYTES + MAX_MIME_BYTES + MAX_FILE_NAME_BYTES
        private const val VERSION: Byte = 1
        private val MANIFEST_MAGIC = "HAM1".toByteArray(StandardCharsets.US_ASCII)
        private val MIME_PATTERN = Regex("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+")

        fun decode(encoded: ByteArray): RelayRecipientAttachmentManifest {
            require(encoded.size in HEADER_BYTES..MAX_ENCODED_BYTES) {
                "Recipient attachment manifest length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(MANIFEST_MAGIC.size).also(buffer::get).contentEquals(MANIFEST_MAGIC)) {
                "Recipient attachment manifest prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Recipient attachment manifest version is unsupported." }
            val kind = RelayAttachmentManifest.Kind.fromWire(buffer.get())
            require(buffer.short.toInt() == 0) {
                "Recipient attachment manifest reserved bits are set."
            }
            val objectId = ByteArray(OBJECT_ID_BYTES).also(buffer::get)
            val planDigest = ByteArray(SHA256_BYTES).also(buffer::get)
            val contentKey = ByteArray(CONTENT_KEY_BYTES).also(buffer::get)
            val plaintextBytes = buffer.long
            val plaintextDigest = ByteArray(SHA256_BYTES).also(buffer::get)
            val mimeLength = buffer.short.toInt() and 0xFFFF
            val nameLength = buffer.short.toInt() and 0xFFFF
            require(mimeLength in 3..MAX_MIME_BYTES && nameLength in 1..MAX_FILE_NAME_BYTES) {
                "Recipient attachment text field length is invalid."
            }
            require(encoded.size == HEADER_BYTES + mimeLength + nameLength) {
                "Recipient attachment manifest has trailing or missing data."
            }
            val manifest = RelayRecipientAttachmentManifest(
                objectId = objectId,
                kind = kind,
                courierPlanSha256 = planDigest,
                contentKey = contentKey,
                plaintextBytes = plaintextBytes,
                plaintextSha256 = plaintextDigest,
                mimeType = decodeUtf8(buffer, mimeLength),
                fileName = decodeUtf8(buffer, nameLength),
            )
            require(!buffer.hasRemaining()) { "Recipient attachment manifest has trailing data." }
            manifest.validate()
            require(manifest.encode().contentEquals(encoded)) {
                "Recipient attachment manifest is not canonical."
            }
            return manifest
        }

        private fun decodeUtf8(buffer: ByteBuffer, length: Int): String {
            val bytes = ByteArray(length).also(buffer::get)
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        }
    }
}

/** Only this recipient-authenticated record can complete sender delivery. */
internal data class RelayRecipientAttachmentReceipt(
    val objectId: ByteArray,
    val courierPlanSha256: ByteArray,
) {
    fun validate() {
        require(objectId.size == RelayRecipientAttachmentManifest.OBJECT_ID_BYTES) {
            "Recipient attachment receipt object ID is invalid."
        }
        require(courierPlanSha256.size == RelayRecipientAttachmentManifest.SHA256_BYTES) {
            "Recipient attachment receipt plan digest is invalid."
        }
    }

    fun encode(): ByteArray {
        validate()
        return ByteBuffer.allocate(ENCODED_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(RECEIPT_MAGIC)
            .put(VERSION)
            .put(COMPLETE_STATUS)
            .putShort(0)
            .put(objectId)
            .put(courierPlanSha256)
            .array()
    }

    fun confirms(expectedObjectId: ByteArray, expectedPlanSha256: ByteArray): Boolean =
        objectId.contentEquals(expectedObjectId) && courierPlanSha256.contentEquals(expectedPlanSha256)

    companion object {
        const val ENCODED_BYTES = 56
        private const val VERSION: Byte = 1
        private const val COMPLETE_STATUS: Byte = 1
        private val RECEIPT_MAGIC = "HAR1".toByteArray(StandardCharsets.US_ASCII)

        fun decode(encoded: ByteArray): RelayRecipientAttachmentReceipt {
            require(encoded.size == ENCODED_BYTES) { "Recipient attachment receipt length is invalid." }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(RECEIPT_MAGIC.size).also(buffer::get).contentEquals(RECEIPT_MAGIC)) {
                "Recipient attachment receipt prefix is invalid."
            }
            require(buffer.get() == VERSION) { "Recipient attachment receipt version is unsupported." }
            require(buffer.get() == COMPLETE_STATUS) { "Recipient attachment receipt status is invalid." }
            require(buffer.short.toInt() == 0) {
                "Recipient attachment receipt reserved bits are set."
            }
            return RelayRecipientAttachmentReceipt(
                objectId = ByteArray(RelayRecipientAttachmentManifest.OBJECT_ID_BYTES).also(buffer::get),
                courierPlanSha256 = ByteArray(RelayRecipientAttachmentManifest.SHA256_BYTES)
                    .also(buffer::get),
            ).also(RelayRecipientAttachmentReceipt::validate)
        }
    }
}
