package app.projectrelay.relay_mobile

import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayCourierWifiTransferTest {
    @Test
    fun courierWifiAuthorizationIsCanonicalAndBindsObjectPlanAndExistingOffer() {
        val wifi = ByteArray(72).also {
            "RWUO".toByteArray(Charsets.US_ASCII).copyInto(it)
            it[4] = 1
            ByteArray(64) { index -> (index + 1).toByte() }.copyInto(it, destinationOffset = 8)
        }
        val request = RelayCourierWifiUpgradeRequest(
            objectId = ByteArray(16) { 2 },
            planSha256 = ByteArray(32) { 3 },
            encodedWifiOffer = wifi,
        )

        val encoded = request.encode()
        assertEquals("HWF1", encoded.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        val decoded = RelayCourierWifiUpgradeRequest.decode(encoded)
        assertArrayEquals(request.objectId, decoded.objectId)
        assertArrayEquals(request.planSha256, decoded.planSha256)
        assertArrayEquals(wifi, decoded.encodedWifiOffer)
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierWifiUpgradeRequest.decode(encoded.copyOf().also { it[5] = 1 })
        }
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierWifiUpgradeRequest.decode(encoded.copyOf().also { it[56] = 'X'.code.toByte() })
        }
    }

    @Test
    fun chunkAndCompletionFramesAreStrictAndBounded() {
        val objectId = ByteArray(16) { 4 }
        val start = RelayCourierWifiChunkStart(
            objectId,
            chunkIndex = 7,
            recordBytes = RelayCourierWifiChunkStart.MIN_RECORD_BYTES,
        )
        assertEquals("HXS1", start.encode().copyOfRange(0, 4).toString(Charsets.US_ASCII))
        val decodedStart = RelayCourierWifiChunkStart.decode(start.encode())
        assertArrayEquals(start.objectId, decodedStart.objectId)
        assertEquals(start.chunkIndex, decodedStart.chunkIndex)
        assertEquals(start.recordBytes, decodedStart.recordBytes)

        val done = RelayCourierWifiDone(objectId)
        assertEquals("HXD1", done.encode().copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertArrayEquals(objectId, RelayCourierWifiDone.decode(done.encode()).objectId)
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierWifiChunkStart(objectId, 0, RelayCourierWifiChunkStart.MAX_RECORD_BYTES + 1)
                .encode()
        }
    }

    @Test
    fun onlyManifestBoundCiphertextCanBecomeHac1() {
        val ciphertext = ByteArray(33) { 5 }
        val digest = MessageDigest.getInstance("SHA-256").digest(ciphertext)
        val manifest = manifest(ciphertext.size, digest)

        val chunk = RelayCourierWifiTransferPolicy.buildChunk(manifest, 0, ciphertext)
        assertEquals("HAC1", chunk.encode().copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertArrayEquals(manifest.attachmentId, chunk.objectId)
        assertArrayEquals(manifest.chunks.single().nonce, chunk.nonce)
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierWifiTransferPolicy.buildChunk(
                manifest,
                0,
                ciphertext.copyOf().also { it[0] = 9 },
            )
        }
    }

    @Test
    fun resumeCustodyMayAdvanceButNeverRegressOrChangePlan() {
        val plan = plan()
        val none = RelayCourierAttachmentCustody.fromCommitted(plan, emptySet())
        val first = RelayCourierAttachmentCustody.fromCommitted(plan, setOf(0))
        val complete = RelayCourierAttachmentCustody.fromCommitted(plan, setOf(0, 1))

        RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(none, first)
        RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(first, complete)
        assertTrue(complete.missingChunks().isEmpty())
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(complete, first)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(
                first,
                first.copy(planSha256 = ByteArray(32) { 8 }),
            )
        }
    }

    private fun manifest(ciphertextBytes: Int, ciphertextSha256: ByteArray): RelayAttachmentManifest =
        RelayAttachmentManifest(
            attachmentId = ByteArray(16) { 6 },
            kind = RelayAttachmentManifest.Kind.FILE,
            fileName = "private.bin",
            mimeType = "application/octet-stream",
            plaintextBytes = (ciphertextBytes - 16).toLong(),
            chunkSize = RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES,
            contentKey = ByteArray(32) { 7 },
            plaintextSha256 = ByteArray(32) { 8 },
            chunks = listOf(
                RelayAttachmentManifest.Chunk(
                    index = 0,
                    plaintextBytes = ciphertextBytes - 16,
                    nonce = ByteArray(12) { 9 },
                    ciphertextBytes = ciphertextBytes,
                    ciphertextSha256 = ciphertextSha256,
                ),
            ),
        ).also(RelayAttachmentManifest::validate)

    private fun plan(): RelayCourierAttachmentPlan = RelayCourierAttachmentPlan(
        objectId = ByteArray(16) { 10 },
        cancellationCommitment = ByteArray(32) { 11 },
        totalCiphertextBytes =
            RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES.toLong() + 33,
        chunks = listOf(
            RelayCourierAttachmentPlan.ChunkDescriptor(
                RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES,
                ByteArray(32) { 12 },
            ),
            RelayCourierAttachmentPlan.ChunkDescriptor(33, ByteArray(32) { 13 }),
        ),
    )
}
