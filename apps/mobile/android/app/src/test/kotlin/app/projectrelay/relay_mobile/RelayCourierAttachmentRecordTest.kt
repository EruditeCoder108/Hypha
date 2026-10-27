package app.projectrelay.relay_mobile

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayCourierAttachmentRecordTest {
    @Test
    fun planMatchesTheRustGoldenVectorExactly() {
        val plan = twoChunkPlan()
        val encoded = plan.encode()

        assertEquals(
            "4841503101000002" +
                "11111111111111111111111111111111" +
                "2222222222222222222222222222222222222222222222222222222222222222" +
                "0000000000030031" +
                "00030010" +
                "3333333333333333333333333333333333333333333333333333333333333333" +
                "00000021" +
                "4444444444444444444444444444444444444444444444444444444444444444",
            encoded.toHex(),
        )
        assertTrue(RelayCourierAttachmentPlan.decode(encoded).encode().contentEquals(encoded))
    }

    @Test
    fun maximumPlanAndChunkBoundsAreExact() {
        val maximumChunkBytes = RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES
        val maximum = RelayCourierAttachmentPlan(
            objectId = ByteArray(16) { 1 },
            cancellationCommitment = ByteArray(32) { 2 },
            totalCiphertextBytes = RelayCourierAttachmentPlan.MAX_ATTACHMENT_CIPHERTEXT_BYTES,
            chunks = List(RelayCourierAttachmentPlan.MAX_CHUNKS) {
                RelayCourierAttachmentPlan.ChunkDescriptor(
                    ciphertextBytes = maximumChunkBytes,
                    ciphertextSha256 = ByteArray(32) { 3 },
                )
            },
        )
        val encodedPlan = maximum.encode()
        assertEquals(RelayCourierAttachmentPlan.MAX_PLAN_BYTES, encodedPlan.size)
        assertTrue(RelayCourierAttachmentPlan.decode(encodedPlan).encode().contentEquals(encodedPlan))

        val ciphertext = ByteArray(maximumChunkBytes) { 4 }
        val chunk = chunk(maximum.objectId, RelayCourierAttachmentPlan.MAX_CHUNKS - 1, ciphertext)
        val encodedChunk = chunk.encode()
        assertEquals(RelayCourierAttachmentChunk.HEADER_BYTES + maximumChunkBytes, encodedChunk.size)
        assertTrue(RelayCourierAttachmentChunk.decode(encodedChunk).encode().contentEquals(encodedChunk))
    }

    @Test
    fun chunkMustMatchPlanLengthDigestAndCiphertext() {
        val ciphertext = ByteArray(33) { 5 }
        val valid = chunk(ByteArray(16) { 6 }, 0, ciphertext)
        val plan = RelayCourierAttachmentPlan(
            objectId = valid.objectId,
            cancellationCommitment = ByteArray(32) { 7 },
            totalCiphertextBytes = ciphertext.size.toLong(),
            chunks = listOf(
                RelayCourierAttachmentPlan.ChunkDescriptor(
                    ciphertextBytes = ciphertext.size,
                    ciphertextSha256 = valid.ciphertextSha256,
                ),
            ),
        )
        valid.verifyAgainst(plan)

        val corrupt = valid.copy(ciphertext = valid.ciphertext.copyOf().also { it[0] = 9 })
        assertThrows(IllegalArgumentException::class.java) { corrupt.verifyAgainst(plan) }
        val wrongObject = valid.copy(objectId = ByteArray(16) { 8 })
        assertThrows(IllegalArgumentException::class.java) { wrongObject.verifyAgainst(plan) }
    }

    @Test
    fun custodyBitmapIsCanonicalAndNeverARecipientReceipt() {
        val plan = twoChunkPlan()
        val custody = RelayCourierAttachmentCustody.fromCommitted(plan, listOf(1))
        assertFalse(custody.hasChunk(0))
        assertTrue(custody.hasChunk(1))
        assertEquals(listOf(0), custody.missingChunks())
        assertTrue(
            RelayCourierAttachmentCustody.decode(custody.encode())
                .encode()
                .contentEquals(custody.encode()),
        )

        val nonCanonical = custody.copy(chunkBitmap = byteArrayOf(0b1000_0010.toByte()))
        assertThrows(IllegalArgumentException::class.java) { nonCanonical.validate() }
    }

    @Test
    fun completionProofAndAcknowledgementAreStrictCanonicalRecords() {
        val cleanup = RelayCourierAttachmentCleanup(
            objectId = ByteArray(16) { 1 },
            planSha256 = ByteArray(32) { 2 },
            cancellationSecret = ByteArray(32) { 3 },
        )
        val encodedCleanup = cleanup.encode()
        assertEquals(RelayCourierAttachmentCleanup.ENCODED_BYTES, encodedCleanup.size)
        assertTrue(
            RelayCourierAttachmentCleanup.decode(encodedCleanup)
                .encode()
                .contentEquals(encodedCleanup),
        )
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierAttachmentCleanup.decode(encodedCleanup.copyOf().also { it[5] = 1 })
        }

        val acknowledgement = RelayCourierAttachmentCleanupAck(
            objectId = cleanup.objectId,
            planSha256 = cleanup.planSha256,
        )
        val encodedAcknowledgement = acknowledgement.encode()
        assertEquals(RelayCourierAttachmentCleanupAck.ENCODED_BYTES, encodedAcknowledgement.size)
        assertTrue(
            RelayCourierAttachmentCleanupAck.decode(encodedAcknowledgement)
                .encode()
                .contentEquals(encodedAcknowledgement),
        )
        assertThrows(IllegalArgumentException::class.java) {
            RelayCourierAttachmentCleanupAck.decode(
                encodedAcknowledgement.copyOf().also { it[7] = 1 },
            )
        }
    }

    @Test
    fun quotaAndMonotonicAgeHandlePressureAndRebootDeterministically() {
        assertTrue(
            RelayCourierAttachmentPolicy.canAdmit(
                usedBytes = 10,
                incomingBytes = 20,
                quotaBytes = 30,
                usableSpaceBytes = RelayCourierAttachmentPolicy.MIN_FREE_SPACE_BYTES + 20,
            ),
        )
        assertFalse(
            RelayCourierAttachmentPolicy.canAdmit(
                usedBytes = 11,
                incomingBytes = 20,
                quotaBytes = 30,
                usableSpaceBytes = Long.MAX_VALUE,
            ),
        )
        assertFalse(
            RelayCourierAttachmentPolicy.canAdmit(
                usedBytes = 0,
                incomingBytes = 20,
                quotaBytes = 100,
                usableSpaceBytes = RelayCourierAttachmentPolicy.MIN_FREE_SPACE_BYTES + 19,
            ),
        )

        val advanced = RelayCourierAttachmentPolicy.advanceAge(
            ageMs = 100,
            lifetimeMs = 1_000,
            anchorElapsedMs = 500,
            nowElapsedMs = 900,
        )
        assertEquals(500, advanced.ageMs)
        assertFalse(advanced.expired)
        assertFalse(advanced.rebootDetected)

        val rebooted = RelayCourierAttachmentPolicy.advanceAge(
            ageMs = advanced.ageMs,
            lifetimeMs = 1_000,
            anchorElapsedMs = advanced.anchorElapsedMs,
            nowElapsedMs = 25,
        )
        assertEquals(advanced.ageMs, rebooted.ageMs)
        assertEquals(25, rebooted.anchorElapsedMs)
        assertTrue(rebooted.rebootDetected)

        val expired = RelayCourierAttachmentPolicy.advanceAge(
            ageMs = rebooted.ageMs,
            lifetimeMs = 1_000,
            anchorElapsedMs = rebooted.anchorElapsedMs,
            nowElapsedMs = 525,
        )
        assertTrue(expired.expired)
        assertEquals(1_000, expired.ageMs)
    }

    private fun twoChunkPlan(): RelayCourierAttachmentPlan = RelayCourierAttachmentPlan(
        objectId = ByteArray(16) { 0x11 },
        cancellationCommitment = ByteArray(32) { 0x22 },
        totalCiphertextBytes = 0x0003_0031,
        chunks = listOf(
            RelayCourierAttachmentPlan.ChunkDescriptor(
                ciphertextBytes = RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES,
                ciphertextSha256 = ByteArray(32) { 0x33 },
            ),
            RelayCourierAttachmentPlan.ChunkDescriptor(
                ciphertextBytes = 33,
                ciphertextSha256 = ByteArray(32) { 0x44 },
            ),
        ),
    )

    private fun chunk(objectId: ByteArray, index: Int, ciphertext: ByteArray):
        RelayCourierAttachmentChunk = RelayCourierAttachmentChunk(
        objectId = objectId,
        chunkIndex = index,
        nonce = ByteArray(RelayCourierAttachmentChunk.NONCE_BYTES) { 9 },
        ciphertextSha256 = MessageDigest.getInstance("SHA-256").digest(ciphertext),
        ciphertext = ciphertext,
    )

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }
}
