package app.projectrelay.relay_mobile

import android.content.Context
import java.io.File
import java.security.MessageDigest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class RelayCourierAttachmentStoreTest {
    private lateinit var context: Context
    private var elapsedMs = 1_000L
    private var store: RelayCourierAttachmentStore? = null

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        clearStore()
    }

    @After
    fun tearDown() {
        store?.close()
        clearStore()
    }

    @Test
    fun planAndChunkSurviveCloseAndRebootWithExactCustody() {
        val fixture = fixture()
        val first = newStore()
        val acceptedPlan = first.acceptPlan(fixture.manifest, fixture.plan.encode())
            as RelayCourierAttachmentStore.PlanAcceptance.Accepted
        assertTrue(acceptedPlan.inserted)
        assertEquals(1, first.manifestsForMesh().size)
        assertTrue(first.manifestsForMesh().single().contentEquals(fixture.manifest))
        assertEquals(
            listOf(0),
            RelayCourierAttachmentCustody.decode(acceptedPlan.custody).missingChunks(),
        )

        val acceptedChunk = first.acceptChunk(fixture.chunk.encode())
            as RelayCourierAttachmentStore.ChunkAcceptance.Accepted
        assertTrue(acceptedChunk.inserted)
        assertTrue(
            RelayCourierAttachmentCustody.decode(acceptedChunk.custody).missingChunks().isEmpty(),
        )
        val duplicate = first.acceptChunk(fixture.chunk.encode())
            as RelayCourierAttachmentStore.ChunkAcceptance.Accepted
        assertFalse(duplicate.inserted)
        first.close()
        store = null

        elapsedMs = 25L // elapsedRealtime reset proves reboot does not create a negative age.
        val reopened = newStore()
        val custody = RelayCourierAttachmentCustody.decode(
            requireNotNull(reopened.custody(fixture.plan.objectId)),
        )
        assertTrue(custody.missingChunks().isEmpty())
        assertTrue(reopened.readChunk(fixture.plan.objectId, 0).contentEquals(fixture.chunk.encode()))
        assertEquals(1, reopened.usage().storedChunks)
    }

    @Test
    fun fullObjectReservationRefusesPlanBeforeAnyCustody() {
        val fixture = fixture()
        val required = fixture.plan.requiredStoredBytes() + fixture.manifest.size
        val limited = newStore(quotaBytes = required - 1)

        assertEquals(
            RelayCourierAttachmentStore.PlanAcceptance.StoreFull,
            limited.acceptPlan(fixture.manifest, fixture.plan.encode()),
        )
        assertEquals(0, limited.usage().activePlans)
        assertNull(limited.custody(fixture.plan.objectId))
    }

    @Test
    fun validCancellationDeletesChunksAndBlocksReplay() {
        val cancelSecret = ByteArray(32) { 7 }
        val fixture = fixture(cancelSecret = cancelSecret)
        val active = newStore()
        assertTrue(
            active.acceptPlan(fixture.manifest, fixture.plan.encode())
                is RelayCourierAttachmentStore.PlanAcceptance.Accepted,
        )
        assertTrue(
            active.acceptChunk(fixture.chunk.encode())
                is RelayCourierAttachmentStore.ChunkAcceptance.Accepted,
        )

        assertThrows(IllegalArgumentException::class.java) {
            active.applyCancellation(fixture.plan.objectId, ByteArray(32) { 8 })
        }
        assertNotNull(active.custody(fixture.plan.objectId))
        assertTrue(active.applyCancellation(fixture.plan.objectId, cancelSecret))
        assertNull(active.custody(fixture.plan.objectId))
        assertEquals(0, active.usage().storedChunks)
        assertEquals(
            RelayCourierAttachmentStore.PlanAcceptance.Terminal,
            active.acceptPlan(fixture.manifest, fixture.plan.encode()),
        )
    }

    @Test
    fun expiryCreatesReplayTombstoneAndCleansPayload() {
        val fixture = fixture(lifetimeMs = 100, ageMs = 90)
        val active = newStore()
        assertTrue(
            active.acceptPlan(fixture.manifest, fixture.plan.encode())
                is RelayCourierAttachmentStore.PlanAcceptance.Accepted,
        )
        assertTrue(
            active.acceptChunk(fixture.chunk.encode())
                is RelayCourierAttachmentStore.ChunkAcceptance.Accepted,
        )

        elapsedMs += 11
        val cleanup = active.recover()
        assertEquals(1, cleanup.expiredPlans)
        assertNull(active.custody(fixture.plan.objectId))
        assertEquals(
            RelayCourierAttachmentStore.PlanAcceptance.Terminal,
            active.acceptPlan(fixture.manifest, fixture.plan.encode()),
        )
    }

    @Test
    fun restartDropsCorruptChunkRowAndReturnsItToMissingInventory() {
        val fixture = fixture()
        val active = newStore()
        active.acceptPlan(fixture.manifest, fixture.plan.encode())
        active.acceptChunk(fixture.chunk.encode())
        active.close()
        store = null

        val chunkFile = File(
            File(context.filesDir, CHUNKS_DIRECTORY),
            "${fixture.plan.objectId.toHex()}/0.record",
        )
        assertTrue(chunkFile.isFile)
        chunkFile.writeBytes(ByteArray(chunkFile.length().toInt()) { 9 })

        val reopened = newStore()
        val cleanup = reopened.recover()
        assertEquals(1, cleanup.invalidChunks)
        val custody = RelayCourierAttachmentCustody.decode(
            requireNotNull(reopened.custody(fixture.plan.objectId)),
        )
        assertEquals(listOf(0), custody.missingChunks())
        assertEquals(0, reopened.usage().storedChunks)
    }

    @Test
    fun recipientReceiptRequiresExactPlanDigestBeforeCleanup() {
        val fixture = fixture()
        val active = newStore()
        active.acceptPlan(fixture.manifest, fixture.plan.encode())
        active.acceptChunk(fixture.chunk.encode())

        assertThrows(IllegalArgumentException::class.java) {
            active.applyRecipientReceipt(fixture.plan.objectId, ByteArray(32) { 9 })
        }
        assertNotNull(active.custody(fixture.plan.objectId))
        assertTrue(active.applyRecipientReceipt(fixture.plan.objectId, fixture.plan.sha256()))
        assertNull(active.custody(fixture.plan.objectId))
        assertEquals(0, active.usage().activePlans)
        assertNotNull(active.recover())
    }

    @Test
    fun senderCompletionRequiresCommittedSecretAndIsIdempotentAfterDeletion() {
        val cancelSecret = ByteArray(32) { 7 }
        val fixture = fixture(cancelSecret = cancelSecret)
        val active = newStore()
        active.acceptPlan(fixture.manifest, fixture.plan.encode())
        active.acceptChunk(fixture.chunk.encode())

        assertThrows(IllegalArgumentException::class.java) {
            active.applyRecipientCompletion(
                RelayCourierAttachmentCleanup(
                    fixture.plan.objectId,
                    fixture.plan.sha256(),
                    ByteArray(32) { 8 },
                ),
            )
        }
        assertNotNull(active.custody(fixture.plan.objectId))
        val cleanup = RelayCourierAttachmentCleanup(
            fixture.plan.objectId,
            fixture.plan.sha256(),
            cancelSecret,
        )
        assertEquals(
            RelayCourierAttachmentStore.CompletionResult.REMOVED,
            active.applyRecipientCompletion(cleanup),
        )
        assertNull(active.custody(fixture.plan.objectId))
        assertEquals(
            RelayCourierAttachmentStore.CompletionResult.ALREADY_REMOVED,
            active.applyRecipientCompletion(cleanup),
        )
    }

    private fun newStore(
        quotaBytes: Long = RelayCourierAttachmentPolicy.ENGINEERING_QUOTA_BYTES,
    ): RelayCourierAttachmentStore = RelayCourierAttachmentStore(
        context = context,
        quotaBytes = quotaBytes,
        elapsedRealtimeMs = { elapsedMs },
        usableSpaceOverride = {
            RelayCourierAttachmentPolicy.MIN_FREE_SPACE_BYTES +
                RelayCourierAttachmentPolicy.ENGINEERING_QUOTA_BYTES
        },
    ).also { store = it }

    private fun fixture(
        cancelSecret: ByteArray = ByteArray(32) { 3 },
        lifetimeMs: Long = 60_000,
        ageMs: Long = 0,
    ): Fixture {
        val objectId = ByteArray(16) { 1 }
        val ciphertext = ByteArray(33) { 2 }
        val chunk = RelayCourierAttachmentChunk(
            objectId = objectId,
            chunkIndex = 0,
            nonce = ByteArray(12) { 4 },
            ciphertextSha256 = sha256(ciphertext),
            ciphertext = ciphertext,
        )
        val plan = RelayCourierAttachmentPlan(
            objectId = objectId,
            cancellationCommitment = sha256(cancelSecret),
            totalCiphertextBytes = ciphertext.size.toLong(),
            chunks = listOf(
                RelayCourierAttachmentPlan.ChunkDescriptor(
                    ciphertextBytes = ciphertext.size,
                    ciphertextSha256 = chunk.ciphertextSha256,
                ),
            ),
        )
        val manifest = RelayMeshEnvelope(
            messageId = objectId,
            destinationHint = ByteArray(16) { 5 },
            lifetimeMs = lifetimeMs,
            ageMs = ageMs,
            hopLimit = 16,
            hopsTaken = 1,
            copyBudget = 1,
            priority = 4,
            ciphertext = ByteArray(64) { 6 },
        ).encode()
        return Fixture(plan, chunk, manifest)
    }

    private fun clearStore() {
        runCatching { context.deleteDatabase(DATABASE_NAME) }
        runCatching { File(context.filesDir, CHUNKS_DIRECTORY).deleteRecursively() }
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    private data class Fixture(
        val plan: RelayCourierAttachmentPlan,
        val chunk: RelayCourierAttachmentChunk,
        val manifest: ByteArray,
    )

    private companion object {
        const val DATABASE_NAME = "relay_courier_attachments.db"
        const val CHUNKS_DIRECTORY = "relay_courier_attachment_chunks_v1"
    }
}
