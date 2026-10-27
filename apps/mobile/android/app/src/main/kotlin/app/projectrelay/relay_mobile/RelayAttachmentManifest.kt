package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Strict, bounded metadata for content-addressed encrypted attachment chunks. */
internal data class RelayAttachmentManifest(
    val attachmentId: ByteArray,
    val kind: Kind,
    val fileName: String,
    val mimeType: String,
    val plaintextBytes: Long,
    val chunkSize: Int,
    val contentKey: ByteArray,
    val plaintextSha256: ByteArray,
    val chunks: List<Chunk>,
) {
    enum class Kind(val wireValue: Byte, val maximumBytes: Long) {
        IMAGE(1, MAX_IMAGE_BYTES),
        FILE(2, MAX_FILE_BYTES);

        companion object {
            fun fromWire(value: Byte): Kind = entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("Unsupported attachment kind.")
        }
    }

    data class Chunk(
        val index: Int,
        val plaintextBytes: Int,
        val nonce: ByteArray,
        val ciphertextBytes: Int,
        val ciphertextSha256: ByteArray,
    )

    fun encode(): ByteArray {
        validate()
        val nameBytes = fileName.toByteArray(StandardCharsets.UTF_8)
        val mimeBytes = mimeType.toByteArray(StandardCharsets.US_ASCII)
        return ByteBuffer.allocate(
            HEADER_BYTES + mimeBytes.size + nameBytes.size + chunks.size * CHUNK_DESCRIPTOR_BYTES,
        ).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            put(VERSION)
            put(kind.wireValue)
            putShort(0)
            put(attachmentId)
            putLong(plaintextBytes)
            putInt(chunkSize)
            putInt(chunks.size)
            putShort(mimeBytes.size.toShort())
            putShort(nameBytes.size.toShort())
            put(contentKey)
            put(plaintextSha256)
            put(mimeBytes)
            put(nameBytes)
            chunks.forEach { chunk ->
                putInt(chunk.index)
                putInt(chunk.plaintextBytes)
                put(chunk.nonce)
                putInt(chunk.ciphertextBytes)
                put(chunk.ciphertextSha256)
            }
        }.array()
    }

    fun validate() {
        require(attachmentId.size == ATTACHMENT_ID_BYTES) { "Attachment ID must be 16 bytes." }
        require(contentKey.size == CONTENT_KEY_BYTES) { "Attachment key must be 32 bytes." }
        require(plaintextSha256.size == SHA256_BYTES) { "Attachment digest must be 32 bytes." }
        require(plaintextBytes in 1..kind.maximumBytes) { "Attachment size is outside limits." }
        require(chunkSize == CHUNK_PLAINTEXT_BYTES) { "Attachment chunk size is unsupported." }
        val expectedChunks = ((plaintextBytes + chunkSize - 1) / chunkSize).toInt()
        require(expectedChunks in 1..MAX_CHUNKS && chunks.size == expectedChunks) {
            "Attachment chunk count is invalid."
        }
        val nameBytes = fileName.toByteArray(StandardCharsets.UTF_8)
        require(nameBytes.isNotEmpty() && nameBytes.size <= MAX_FILE_NAME_BYTES) {
            "Attachment file name is invalid."
        }
        require(fileName == normalizedFileName(fileName)) { "Attachment file name is unsafe." }
        val mimeBytes = mimeType.toByteArray(StandardCharsets.US_ASCII)
        require(mimeBytes.size in 3..MAX_MIME_BYTES && MIME_PATTERN.matches(mimeType)) {
            "Attachment MIME type is invalid."
        }
        if (kind == Kind.IMAGE) require(mimeType in SAFE_IMAGE_MIME_TYPES) {
            "This image format is not supported."
        }
        chunks.forEachIndexed { index, chunk ->
            val expectedPlaintext = if (index == chunks.lastIndex) {
                (plaintextBytes - index.toLong() * chunkSize).toInt()
            } else {
                chunkSize
            }
            require(chunk.index == index && chunk.plaintextBytes == expectedPlaintext) {
                "Attachment chunk sequence is invalid."
            }
            require(chunk.nonce.size == NONCE_BYTES) { "Attachment chunk nonce is invalid." }
            require(chunk.ciphertextBytes == expectedPlaintext + GCM_TAG_BYTES) {
                "Attachment chunk ciphertext size is invalid."
            }
            require(chunk.ciphertextSha256.size == SHA256_BYTES) {
                "Attachment chunk digest is invalid."
            }
        }
    }

    companion object {
        const val CHUNK_PLAINTEXT_BYTES = 192 * 1024
        const val MAX_IMAGE_BYTES = 25L * 1024 * 1024
        const val MAX_FILE_BYTES = 96L * 1024 * 1024
        const val MAX_CHUNKS = 512
        const val MAX_FILE_NAME_BYTES = 128
        const val MAX_MIME_BYTES = 96
        const val ATTACHMENT_ID_BYTES = 16
        const val CONTENT_KEY_BYTES = 32
        const val NONCE_BYTES = 12
        const val SHA256_BYTES = 32
        const val GCM_TAG_BYTES = 16

        private const val HEADER_BYTES = 108
        private const val CHUNK_DESCRIPTOR_BYTES = 56
        private const val VERSION: Byte = 1
        private val MAGIC = byteArrayOf(0x48, 0x59, 0x41, 0x31)
        private val MIME_PATTERN = Regex("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+")
        val SAFE_IMAGE_MIME_TYPES = setOf(
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "image/heic",
            "image/heif",
            "image/avif",
        )

        fun decode(encoded: ByteArray): RelayAttachmentManifest {
            require(encoded.size in HEADER_BYTES..maximumManifestBytes()) {
                "Attachment manifest length is invalid."
            }
            val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            val magic = ByteArray(MAGIC.size).also(buffer::get)
            require(magic.contentEquals(MAGIC) && buffer.get() == VERSION) {
                "Attachment manifest prefix is invalid."
            }
            val kind = Kind.fromWire(buffer.get())
            require(buffer.short.toInt() == 0) { "Attachment manifest reserved bits are set." }
            val id = ByteArray(ATTACHMENT_ID_BYTES).also(buffer::get)
            val plaintextBytes = buffer.long
            val chunkSize = buffer.int
            val chunkCount = buffer.int
            val mimeLength = buffer.short.toInt() and 0xFFFF
            val nameLength = buffer.short.toInt() and 0xFFFF
            val key = ByteArray(CONTENT_KEY_BYTES).also(buffer::get)
            val plaintextDigest = ByteArray(SHA256_BYTES).also(buffer::get)
            require(chunkCount in 1..MAX_CHUNKS) { "Attachment chunk count is invalid." }
            require(mimeLength in 3..MAX_MIME_BYTES && nameLength in 1..MAX_FILE_NAME_BYTES) {
                "Attachment text field length is invalid."
            }
            val expectedBytes = HEADER_BYTES + mimeLength + nameLength +
                chunkCount * CHUNK_DESCRIPTOR_BYTES
            require(expectedBytes == encoded.size) { "Attachment manifest has trailing data." }
            val mime = decodeUtf8(buffer, mimeLength).lowercase()
            val name = decodeUtf8(buffer, nameLength)
            val chunks = List(chunkCount) {
                Chunk(
                    index = buffer.int,
                    plaintextBytes = buffer.int,
                    nonce = ByteArray(NONCE_BYTES).also(buffer::get),
                    ciphertextBytes = buffer.int,
                    ciphertextSha256 = ByteArray(SHA256_BYTES).also(buffer::get),
                )
            }
            require(!buffer.hasRemaining()) { "Attachment manifest has trailing data." }
            return RelayAttachmentManifest(
                attachmentId = id,
                kind = kind,
                fileName = name,
                mimeType = mime,
                plaintextBytes = plaintextBytes,
                chunkSize = chunkSize,
                contentKey = key,
                plaintextSha256 = plaintextDigest,
                chunks = chunks,
            ).also(RelayAttachmentManifest::validate)
        }

        fun normalizedFileName(raw: String): String {
            val leaf = raw.substringAfterLast('/').substringAfterLast('\\')
            val safe = leaf.filter { character ->
                character.code >= 0x20 && character != '\u007f' && character != '/' && character != '\\'
            }.trim().trim('.').ifEmpty { "attachment" }
            val output = StringBuilder()
            var usedBytes = 0
            safe.codePoints().forEach { codePoint ->
                val text = String(Character.toChars(codePoint))
                val bytes = text.toByteArray(StandardCharsets.UTF_8).size
                if (usedBytes + bytes <= MAX_FILE_NAME_BYTES) {
                    output.append(text)
                    usedBytes += bytes
                }
            }
            return output.toString().ifEmpty { "attachment" }
        }

        fun normalizedMimeType(raw: String?, kind: Kind): String {
            val candidate = raw?.trim()?.lowercase().orEmpty()
            return when {
                kind == Kind.IMAGE && candidate in SAFE_IMAGE_MIME_TYPES -> candidate
                kind == Kind.IMAGE -> throw IllegalArgumentException("This image format is not supported.")
                candidate.length <= MAX_MIME_BYTES && MIME_PATTERN.matches(candidate) -> candidate
                else -> "application/octet-stream"
            }
        }

        private fun decodeUtf8(buffer: ByteBuffer, length: Int): String {
            val bytes = ByteArray(length).also(buffer::get)
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        }

        private fun maximumManifestBytes(): Int = HEADER_BYTES + MAX_MIME_BYTES +
            MAX_FILE_NAME_BYTES + MAX_CHUNKS * CHUNK_DESCRIPTOR_BYTES
    }
}
