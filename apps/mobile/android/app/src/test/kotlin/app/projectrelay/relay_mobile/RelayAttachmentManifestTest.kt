package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayAttachmentManifestTest {
    @Test
    fun `manifest round trips strict encrypted chunk metadata`() {
        val manifest = sampleManifest(plaintextBytes = RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES + 7L)
        val decoded = RelayAttachmentManifest.decode(manifest.encode())

        assertTrue(decoded.attachmentId.contentEquals(manifest.attachmentId))
        assertEquals("photo.jpg", decoded.fileName)
        assertEquals("image/jpeg", decoded.mimeType)
        assertEquals(2, decoded.chunks.size)
        assertEquals(7, decoded.chunks.last().plaintextBytes)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `manifest rejects trailing bytes`() {
        RelayAttachmentManifest.decode(sampleManifest(42).encode() + 0)
    }

    @Test
    fun `file names cannot escape the private export directory`() {
        assertEquals("photo.jpg", RelayAttachmentManifest.normalizedFileName("../../photo.jpg"))
        assertEquals("attachment", RelayAttachmentManifest.normalizedFileName(".."))
    }

    private fun sampleManifest(plaintextBytes: Long): RelayAttachmentManifest {
        val chunkSize = RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES
        val count = ((plaintextBytes + chunkSize - 1) / chunkSize).toInt()
        return RelayAttachmentManifest(
            attachmentId = ByteArray(16) { it.toByte() },
            kind = RelayAttachmentManifest.Kind.IMAGE,
            fileName = "photo.jpg",
            mimeType = "image/jpeg",
            plaintextBytes = plaintextBytes,
            chunkSize = chunkSize,
            contentKey = ByteArray(32) { (it + 1).toByte() },
            plaintextSha256 = ByteArray(32) { (it + 2).toByte() },
            chunks = List(count) { index ->
                val plain = if (index == count - 1) {
                    (plaintextBytes - index.toLong() * chunkSize).toInt()
                } else {
                    chunkSize
                }
                RelayAttachmentManifest.Chunk(
                    index = index,
                    plaintextBytes = plain,
                    nonce = ByteArray(12) { (index + it).toByte() },
                    ciphertextBytes = plain + 16,
                    ciphertextSha256 = ByteArray(32) { (index + it + 3).toByte() },
                )
            },
        )
    }
}
