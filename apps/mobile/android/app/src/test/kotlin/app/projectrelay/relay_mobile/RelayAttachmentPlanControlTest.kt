package app.projectrelay.relay_mobile

import android.content.Context
import java.io.File
import java.security.MessageDigest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
class RelayAttachmentPlanControlTest {
    private lateinit var context: Context
    private var elapsedMs = 1_000L
    private val stores = mutableListOf<RelayCourierAttachmentStore>()

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        clearStore()
    }

    @After
    fun tearDown() {
        stores.forEach { runCatching(it::close) }
        clearStore()
    }

    @Test
    fun offerIsCanonicalAndAdvertisesOnlyPlanAndCustodyCapabilities() {
        val fixture = fixture()
        val encoded = fixture.offer.encode()

        assertEquals("HAO1", encoded.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals(1, encoded[5].toInt())
        assertEquals(1, encoded[6].toInt())
        assertEquals(0, encoded[7].toInt())
        val decoded = RelayAttachmentPlanOffer.decode(encoded)
        assertArrayEquals(fixture.manifest, decoded.encodedManifest)
        assertArrayEquals(fixture.plan.encode(), decoded.encodedPlan)

        assertThrows(IllegalArgumentException::class.java) {
            RelayAttachmentPlanOffer.decode(encoded + byteArrayOf(0))
        }
        val falseChunkCapability = encoded.copyOf().also { it[7] = 1 }
        assertThrows(IllegalArgumentException::class.java) {
            RelayAttachmentPlanOffer.decode(falseChunkCapability)
        }
    }

    @Test
    fun durableAcceptanceReturnsExactMissingBitmapAndDuplicateResumeState() {
        val fixture = fixture()
        val store = newStore()

        val first = RelayAttachmentPlanControl.accept(store, fixture.offer.encode())
            as RelayAttachmentPlanControl.Outcome.Custodied
        assertTrue(first.inserted)
        assertArrayEquals(byteArrayOf(0x01), first.missingBitmap)
        assertEquals(listOf(0), first.missingChunks)
        assertTrue(RelayCourierAttachmentCustody.decode(first.encodedCustody).planCommitted)
        assertEquals(
            "HCU1",
            first.encodedCustody.copyOfRange(0, 4).toString(Charsets.US_ASCII),
        )

        val acceptedChunk = store.acceptChunk(fixture.chunk.encode())
        assertTrue(acceptedChunk is RelayCourierAttachmentStore.ChunkAcceptance.Accepted)
        val duplicate = RelayAttachmentPlanControl.accept(store, fixture.offer.encode())
            as RelayAttachmentPlanControl.Outcome.Custodied
        assertFalse(duplicate.inserted)
        assertArrayEquals(byteArrayOf(0x00), duplicate.missingBitmap)
        assertTrue(duplicate.missingChunks.isEmpty())
        assertArrayEquals(fixture.plan.sha256(), duplicate.planSha256)
    }

    @Test
    fun quotaRefusalReturnsNoCustody() {
        val fixture = fixture()
        val requiredBytes = fixture.plan.requiredStoredBytes() + fixture.manifest.size
        val store = newStore(quotaBytes = requiredBytes - 1)

        assertEquals(
            RelayAttachmentPlanControl.Outcome.Declined(
                RelayAttachmentPlanControl.DeclineReason.STORE_FULL,
            ),
            RelayAttachmentPlanControl.accept(store, fixture.offer.encode()),
        )
        assertNull(store.custody(fixture.plan.objectId))
    }

    @Test
    fun lowStorageRefusalReturnsNoCustody() {
        val fixture = fixture()
        val store = newStore(
            usableSpaceBytes = RelayCourierAttachmentPolicy.MIN_FREE_SPACE_BYTES,
        )

        assertEquals(
            RelayAttachmentPlanControl.Outcome.Declined(
                RelayAttachmentPlanControl.DeclineReason.STORE_FULL,
            ),
            RelayAttachmentPlanControl.accept(store, fixture.offer.encode()),
        )
        assertNull(store.custody(fixture.plan.objectId))
    }

    @Test
    fun cancelledObjectReturnsTerminalWithoutCustody() {
        val fixture = fixture()
        val store = newStore()
        assertTrue(
            RelayAttachmentPlanControl.accept(store, fixture.offer.encode())
                is RelayAttachmentPlanControl.Outcome.Custodied,
        )
        assertTrue(store.applyCancellation(fixture.plan.objectId, fixture.cancelSecret))

        assertEquals(
            RelayAttachmentPlanControl.Outcome.Declined(
                RelayAttachmentPlanControl.DeclineReason.TERMINAL,
            ),
            RelayAttachmentPlanControl.accept(store, fixture.offer.encode()),
        )
        assertNull(store.custody(fixture.plan.objectId))
    }

    @Test
    fun conflictingObjectReuseAndExpiredOfferFailClosed() {
        val fixture = fixture()
        val store = newStore()
        assertTrue(
            RelayAttachmentPlanControl.accept(store, fixture.offer.encode())
                is RelayAttachmentPlanControl.Outcome.Custodied,
        )
        val conflictingPlan = fixture.plan.copy(
            cancellationCommitment = ByteArray(32) { 9 },
        )
        val conflictingOffer = RelayAttachmentPlanOffer(
            fixture.manifest,
            conflictingPlan.encode(),
        )
        assertThrows(IllegalArgumentException::class.java) {
            RelayAttachmentPlanControl.accept(store, conflictingOffer.encode())
        }

        store.close()
        stores.remove(store)
        clearStore()
        val expired = fixture(lifetimeMs = 100, ageMs = 100)
        val expiredStore = newStore()
        assertEquals(
            RelayAttachmentPlanControl.Outcome.Declined(
                RelayAttachmentPlanControl.DeclineReason.EXPIRED,
            ),
            RelayAttachmentPlanControl.accept(expiredStore, expired.offer.encode()),
        )
        assertNull(expiredStore.custody(expired.plan.objectId))
    }

    private fun newStore(
        quotaBytes: Long = RelayCourierAttachmentPolicy.ENGINEERING_QUOTA_BYTES,
        usableSpaceBytes: Long =
            RelayCourierAttachmentPolicy.MIN_FREE_SPACE_BYTES +
                RelayCourierAttachmentPolicy.ENGINEERING_QUOTA_BYTES,
    ): RelayCourierAttachmentStore = RelayCourierAttachmentStore(
        context = context,
        quotaBytes = quotaBytes,
        elapsedRealtimeMs = { elapsedMs },
        usableSpaceOverride = { usableSpaceBytes },
    ).also(stores::add)

    private fun fixture(
        lifetimeMs: Long = 60_000,
        ageMs: Long = 0,
    ): Fixture {
        val objectId = ByteArray(16) { 1 }
        val cancelSecret = ByteArray(32) { 3 }
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
        return Fixture(
            plan = plan,
            chunk = chunk,
            cancelSecret = cancelSecret,
            manifest = manifest,
            offer = RelayAttachmentPlanOffer(manifest, plan.encode()),
        )
    }

    private fun clearStore() {
        runCatching { context.deleteDatabase(DATABASE_NAME) }
        runCatching { File(context.filesDir, CHUNKS_DIRECTORY).deleteRecursively() }
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private data class Fixture(
        val plan: RelayCourierAttachmentPlan,
        val chunk: RelayCourierAttachmentChunk,
        val cancelSecret: ByteArray,
        val manifest: ByteArray,
        val offer: RelayAttachmentPlanOffer,
    )

    private companion object {
        const val DATABASE_NAME = "relay_courier_attachments.db"
        const val CHUNKS_DIRECTORY = "relay_courier_attachment_chunks_v1"
    }
}
