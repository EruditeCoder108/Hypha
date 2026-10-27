package app.projectrelay.relay_mobile

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Opt-in invariant probes, separate from the normal suite. Known defects should fail. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class RelayStoreAuditTest {
    private lateinit var context: Context
    private lateinit var store: RelayMeshStore
    private var elapsedMs = 1_000L
    private val key = SecretKeySpec(ByteArray(32) { 0x5A }, "AES")

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.deleteDatabase("relay_mesh.db")
        store = RelayMeshStore(context, { key }, { elapsedMs })
    }

    @After
    fun tearDown() {
        store.close()
        context.deleteDatabase("relay_mesh.db")
    }

    @Test
    fun lostCustodyAckMustReconcileTheAlreadyAcceptedCopyBudget() {
        val original = envelope(lifetime = 180_000)
        insert(original)
        val offered = store.planForPeer(PEER_A, emptyList(), 4_096).single()
        val transferredBudget = RelayMeshEnvelope.decode(offered.wireEnvelope).copyBudget
        // The peer durably accepted these bytes, but its ACK never arrived. Its next
        // authenticated inventory contains this ID. Exercise the real sender path.
        assertTrue(store.planForPeer(PEER_A, listOf(original.messageId), 4_096).isEmpty())
        val retainedBudget = store.readableDatabase.rawQuery(
            "SELECT wire_envelope FROM envelopes LIMIT 1", null,
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            RelayMeshEnvelope.decode(cursor.getBlob(0)).copyBudget
        }
        assertEquals("Lost ACK inflated combined forwarding allowance", 8, retainedBudget + transferredBudget)
    }

    @Test
    fun exactExpiryBoundaryIsRejectedOnAndroid() {
        val expired = envelope(lifetime = 1_000).copy(ageMs = 1_000)
        assertTrue(store.ingestEnvelope(expired.encode()) is RelayMeshStore.IngestResult.Expired)
    }

    @Test
    fun immutableHopLimitConflictIsRejectedOnAndroid() {
        val original = envelope(lifetime = 180_000)
        insert(original)
        val conflict = original.copy(hopLimit = original.hopLimit + 1)
        val result = runCatching { store.ingestEnvelope(conflict.encode()) }
        assertTrue("Immutable hop-limit conflict should fail closed", result.isFailure)
    }

    @Test
    fun acknowledgedHandoffConservesBudgetWithoutDelay() {
        val original = envelope(lifetime = 180_000)
        insert(original)
        val offered = store.planForPeer(PEER_A, emptyList(), 4_096).single()
        store.commitForwarded(PEER_A, listOf(offered), listOf(original.messageId))
        assertEquals(4, offered.transferredCopies)
        val next = store.planForPeer(PEER_B, emptyList(), 4_096).single()
        assertEquals(4, next.previousCopyBudget)
    }

    private fun insert(envelope: RelayMeshEnvelope) {
        store.writableDatabase.insertOrThrow("envelopes", null, ContentValues().apply {
            put("message_id", envelope.messageId)
            put("wire_envelope", envelope.encode())
            put("age_ms", 0)
            put("age_anchor_elapsed_ms", elapsedMs)
            put("created_at_ms", 1)
        })
    }

    private fun envelope(lifetime: Long) = RelayMeshEnvelope(
        messageId = ByteArray(16) { 0x42 }, destinationHint = ByteArray(16) { 0x22 },
        lifetimeMs = lifetime, ageMs = 0, hopLimit = 16, hopsTaken = 0, copyBudget = 8,
        priority = 2, ciphertext = ByteArray(96) { 0x66 },
    )

    private companion object {
        const val PEER_A = "AA:BB:CC:DD:EE:FF:00:11"
        const val PEER_B = "AA:BB:CC:DD:EE:FF:00:22"
    }
}
