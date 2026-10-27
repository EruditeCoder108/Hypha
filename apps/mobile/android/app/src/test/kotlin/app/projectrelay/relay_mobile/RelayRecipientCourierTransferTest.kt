package app.projectrelay.relay_mobile

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayRecipientCourierTransferTest {
    @Test
    fun descriptorIsCanonicalBoundedAndContainsNoPrivateMetadata() {
        val plan = plan()
        val descriptor = RelayRecipientCourierTransferPolicy.descriptor(
            plan,
            listOf(ByteArray(12) { 7 }, ByteArray(12) { 8 }),
        )
        val encoded = descriptor.encode()
        assertEquals("HRD1", encoded.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        val decoded = RelayRecipientCourierDescriptor.decode(encoded)
        assertArrayEquals(plan.encode(), decoded.plan.encode())
        assertArrayEquals(descriptor.nonces[1], decoded.nonces[1])
        assertTrue(!encoded.contains("private.bin".toByteArray()))
        assertThrows(IllegalArgumentException::class.java) {
            RelayRecipientCourierDescriptor.decode(encoded.copyOf().also { it[5] = 1 })
        }
    }

    @Test
    fun materializationRequiresTheRecipientAuthenticatedPlan() {
        val plan = plan()
        val recipient = recipient(plan)
        val descriptor = RelayRecipientCourierTransferPolicy.descriptor(
            plan,
            listOf(ByteArray(12) { 9 }, ByteArray(12) { 10 }),
        )
        val materialized = RelayRecipientCourierTransferPolicy.materialize(recipient, descriptor)
        assertEquals(recipient.fileName, materialized.fileName)
        assertEquals(recipient.mimeType, materialized.mimeType)
        assertArrayEquals(recipient.contentKey, materialized.contentKey)
        assertArrayEquals(descriptor.nonces[0], materialized.chunks[0].nonce)
        assertThrows(IllegalArgumentException::class.java) {
            RelayRecipientCourierTransferPolicy.materialize(
                recipient.copy(courierPlanSha256 = ByteArray(32) { 99 }),
                descriptor,
            )
        }
    }

    @Test
    fun recipientResumeReportsOnlyDurableMissingChunksAndRejectsNonCanonicalBits() {
        val plan = plan()
        val first = RelayRecipientChunkResume.fromCommitted(plan, setOf(0))
        assertEquals(listOf(1), first.missingChunks())
        val decoded = RelayRecipientChunkResume.decode(first.encode())
        assertTrue(decoded.hasChunk(0))
        assertArrayEquals(plan.sha256(), decoded.planSha256)
        assertThrows(IllegalArgumentException::class.java) {
            RelayRecipientChunkResume.decode(first.encode().copyOf().also { it[it.lastIndex] = 0x7F })
        }
    }

    private fun plan(): RelayCourierAttachmentPlan = RelayCourierAttachmentPlan(
        objectId = ByteArray(16) { 1 },
        cancellationCommitment = ByteArray(32) { 2 },
        totalCiphertextBytes =
            RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES.toLong() + 33,
        chunks = listOf(
            RelayCourierAttachmentPlan.ChunkDescriptor(
                RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES,
                ByteArray(32) { 3 },
            ),
            RelayCourierAttachmentPlan.ChunkDescriptor(33, ByteArray(32) { 4 }),
        ),
    ).also(RelayCourierAttachmentPlan::validate)

    private fun recipient(plan: RelayCourierAttachmentPlan) = RelayRecipientAttachmentManifest(
        objectId = plan.objectId.copyOf(),
        kind = RelayAttachmentManifest.Kind.FILE,
        courierPlanSha256 = plan.sha256(),
        contentKey = ByteArray(32) { 5 },
        plaintextBytes = plan.totalCiphertextBytes -
            plan.chunks.size * RelayAttachmentManifest.GCM_TAG_BYTES,
        plaintextSha256 = ByteArray(32) { 6 },
        mimeType = "application/octet-stream",
        fileName = "private.bin",
    ).also(RelayRecipientAttachmentManifest::validate)

    private fun ByteArray.contains(needle: ByteArray): Boolean = indices.any { start ->
        start + needle.size <= size &&
            copyOfRange(start, start + needle.size).contentEquals(needle)
    }
}
