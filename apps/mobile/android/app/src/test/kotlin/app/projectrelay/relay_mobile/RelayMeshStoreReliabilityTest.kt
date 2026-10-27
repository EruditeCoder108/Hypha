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

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class RelayMeshStoreReliabilityTest {
    private lateinit var context: Context
    private val storageKey = SecretKeySpec(ByteArray(32) { 0x5A }, "AES")
    private var elapsedMs = 1_000L
    private var store: RelayMeshStore? = null

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
    fun envelopeResidenceAgeUsesElapsedTimeAndSurvivesElapsedClockReset() {
        val active = newStore()
        val database = active.writableDatabase
        val envelope = envelope(idByte = 0x61, lifetimeMs = 180_000L)
        insertEnvelope(database, envelope, createdAtMs = Long.MAX_VALUE / 2)

        elapsedMs = 61_000L
        val firstOffer = active.planForPeer(
            peerFingerprint = PEER_FINGERPRINT,
            peerInventory = emptyList(),
            maximumBytes = 4_096,
        ).single()
        assertEquals(60_000L, RelayMeshEnvelope.decode(firstOffer.wireEnvelope).ageMs)

        // elapsedRealtime resets after reboot. The already persisted age must not reset or use
        // the editable wall clock (created_at_ms above is deliberately nonsensical).
        elapsedMs = 100L
        val afterReboot = active.planForPeer(
            peerFingerprint = PEER_FINGERPRINT,
            peerInventory = emptyList(),
            maximumBytes = 4_096,
        ).single()
        assertEquals(60_000L, RelayMeshEnvelope.decode(afterReboot.wireEnvelope).ageMs)
    }

    @Test
    fun acknowledgedHandoffPreservesTimeAwaitingItsReceipt() {
        val active = newStore()
        val original = envelope(idByte = 0x62, lifetimeMs = 180_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()

        elapsedMs += 60_000L
        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))

        val next = active.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).single()
        assertEquals(60_000L, RelayMeshEnvelope.decode(next.wireEnvelope).ageMs)
        assertEquals(offer.retainedCopies, next.previousCopyBudget)
    }

    @Test
    fun expiredInFlightEnvelopeCannotBeRevivedByLateAcknowledgement() {
        val active = newStore()
        val original = envelope(idByte = 0x63, lifetimeMs = 1_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()

        elapsedMs += 2_000L
        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))

        assertTrue(active.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).isEmpty())
        assertEquals(0L, count(active.readableDatabase, "envelopes"))
        assertEquals(0L, count(active.readableDatabase, "forwarded_envelopes"))
    }

    @Test
    fun duplicateForwardCommitIsIdempotentAndDoesNotResetAge() {
        val active = newStore()
        val original = envelope(idByte = 0x64, lifetimeMs = 180_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()
        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))

        elapsedMs += 10_000L
        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))

        val next = active.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).single()
        assertEquals(offer.retainedCopies, next.previousCopyBudget)
        assertEquals(10_000L, RelayMeshEnvelope.decode(next.wireEnvelope).ageMs)
        assertEquals(1L, count(active.readableDatabase, "forwarded_envelopes"))
    }

    @Test
    fun forwardCommitPreservesAgeAdvancedByConcurrentMaintenance() {
        val active = newStore()
        val original = envelope(idByte = 0x65, lifetimeMs = 180_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()

        elapsedMs += 60_000L
        active.inventory()
        elapsedMs += 30_000L
        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))

        val next = active.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).single()
        assertEquals(90_000L, RelayMeshEnvelope.decode(next.wireEnvelope).ageMs)
    }

    @Test
    fun committedPortableAgeSurvivesDatabaseReopenAndClockReset() {
        val active = newStore()
        val original = envelope(idByte = 0x66, lifetimeMs = 180_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()
        elapsedMs += 60_000L
        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))
        active.close()
        elapsedMs = 100L
        val reopened = newStore()

        val next = reopened.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).single()
        assertEquals(60_000L, RelayMeshEnvelope.decode(next.wireEnvelope).ageMs)
        assertEquals(offer.retainedCopies, next.previousCopyBudget)
    }

    @Test
    fun forwardCommitRejectsAnImmutablePlanConflictWithoutChangingCustody() {
        val active = newStore()
        val original = envelope(idByte = 0x67, lifetimeMs = 180_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()
        val conflicting = RelayMeshEnvelope.decode(offer.retainedWireEnvelope)
            .copy(hopLimit = original.hopLimit + 1)
        val changed = offer.copy(retainedWireEnvelope = conflicting.encode())

        assertTrue(runCatching {
            active.commitForwarded(PEER_FINGERPRINT, listOf(changed), listOf(original.messageId))
        }.isFailure)

        val next = active.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).single()
        assertEquals(original.copyBudget, next.previousCopyBudget)
        assertEquals(0L, count(active.readableDatabase, "forwarded_envelopes"))
    }

    @Test
    fun forwardCommitAfterElapsedClockResetKeepsAlreadyPersistedAge() {
        val active = newStore()
        val original = envelope(idByte = 0x68, lifetimeMs = 180_000L)
        insertEnvelope(active.writableDatabase, original, createdAtMs = 1L)
        elapsedMs += 60_000L
        val offer = active.planForPeer(PEER_FINGERPRINT, emptyList(), 4_096).single()
        elapsedMs = 100L

        active.commitForwarded(PEER_FINGERPRINT, listOf(offer), listOf(original.messageId))

        val next = active.planForPeer(OTHER_PEER_FINGERPRINT, emptyList(), 4_096).single()
        assertEquals(60_000L, RelayMeshEnvelope.decode(next.wireEnvelope).ageMs)
    }

    @Test
    fun activeCustodyIsInventoriedAheadOfLargeHistoricalDuplicateSet() {
        val active = newStore()
        val database = active.writableDatabase
        val activeEnvelope = envelope(idByte = 0x7F, lifetimeMs = 180_000L)
        insertEnvelope(database, activeEnvelope, createdAtMs = 1L)

        repeat(512) { index ->
            val id = ByteArray(16).also {
                it[0] = (index ushr 8).toByte()
                it[1] = index.toByte()
            }
            database.insertOrThrow(
                "consumed_envelopes",
                null,
                ContentValues().apply {
                    put("message_id", id)
                    put("consumed_at_ms", System.currentTimeMillis())
                },
            )
        }

        val inventory = active.inventory(limit = 512)
        assertEquals(512, inventory.size)
        assertTrue(inventory.any { it.contentEquals(activeEnvelope.messageId) })
    }

    @Test
    fun generatedReceiptMarkerPreventsPrunedHistoryFromRegenerating() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        database.insertOrThrow(
            "mesh_messages",
            null,
            ContentValues().apply {
                put("message_id", ByteArray(16) { 0x33 })
                put("peer_fingerprint", PEER_FINGERPRINT)
                put("direction", 0)
                put("text_nonce", ByteArray(12) { 0x44 })
                put("text_ciphertext", ByteArray(32) { 0x55 })
                put("status", 2)
                put("ratchet_sequence", 1)
                put("receipt_generated", 1)
                put("created_at_ms", 1)
            },
        )

        active.inventory()

        assertEquals(0L, count(database, "delivery_receipts"))
    }

    @Test
    fun courierDeletesItsCopyAfterRecognizedDestinationAcceptsIt() {
        val active = newStore()
        val database = active.writableDatabase
        val courierCopy = envelope(idByte = 0x51, lifetimeMs = 180_000L).copy(copyBudget = 1)
        insertEnvelope(database, courierCopy, createdAtMs = 1L)

        active.commitProbed(
            peerFingerprint = PEER_FINGERPRINT,
            offers = listOf(
                RelayMeshStore.RouteProbeOffer(
                    messageId = courierCopy.messageId,
                    probeEnvelope = courierCopy.asRouteProbe().encode(),
                    fullEnvelope = courierCopy.encode(),
                ),
            ),
            acceptedIds = listOf(courierCopy.messageId),
        )

        assertEquals(0L, count(database, "envelopes"))
        assertEquals(0L, count(database, "forwarded_envelopes"))
    }

    @Test
    fun senderKeepsItsCopyUntilRecipientReceiptReturns() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val senderCopy = envelope(idByte = 0x52, lifetimeMs = 180_000L).copy(copyBudget = 1)
        insertEnvelope(database, senderCopy, createdAtMs = 1L)
        database.insertOrThrow(
            "mesh_messages",
            null,
            ContentValues().apply {
                put("message_id", senderCopy.messageId)
                put("peer_fingerprint", PEER_FINGERPRINT)
                put("direction", 1)
                put("text_nonce", ByteArray(12) { 0x21 })
                put("text_ciphertext", ByteArray(32) { 0x22 })
                put("status", 0)
                put("ratchet_sequence", 1)
                put("created_at_ms", 1)
            },
        )

        active.commitProbed(
            peerFingerprint = PEER_FINGERPRINT,
            offers = listOf(
                RelayMeshStore.RouteProbeOffer(
                    messageId = senderCopy.messageId,
                    probeEnvelope = senderCopy.asRouteProbe().encode(),
                    fullEnvelope = senderCopy.encode(),
                ),
            ),
            acceptedIds = listOf(senderCopy.messageId),
        )

        assertEquals(1L, count(database, "envelopes"))
        assertEquals(1L, count(database, "forwarded_envelopes"))
    }

    @Test
    fun versionFiveMigrationPreservesCustodyAndBackfillsReceiptMarker() {
        val raw = context.openOrCreateDatabase(DATABASE_NAME, Context.MODE_PRIVATE, null)
        raw.execSQL("CREATE TABLE contacts(device_fingerprint TEXT PRIMARY KEY)")
        raw.execSQL(
            "CREATE TABLE mesh_messages(" +
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, message_id BLOB UNIQUE, " +
                "peer_fingerprint TEXT, direction INTEGER, text_nonce BLOB, " +
                "text_ciphertext BLOB, status INTEGER, ratchet_sequence INTEGER, " +
                "created_at_ms INTEGER)",
        )
        raw.execSQL(
            "CREATE TABLE envelopes(message_id BLOB PRIMARY KEY, wire_envelope BLOB, " +
                "origin_fingerprint TEXT, created_at_ms INTEGER)",
        )
        raw.execSQL(
            "CREATE TABLE delivery_receipts(delivered_message_id BLOB PRIMARY KEY, " +
                "receipt_envelope_id BLOB UNIQUE, generated_at_ms INTEGER)",
        )
        val deliveredId = ByteArray(16) { 0x11 }
        raw.insertOrThrow(
            "mesh_messages",
            null,
            ContentValues().apply {
                put("message_id", deliveredId)
                put("peer_fingerprint", PEER_FINGERPRINT)
                put("direction", 0)
                put("text_nonce", ByteArray(12))
                put("text_ciphertext", byteArrayOf(1))
                put("status", 2)
                put("ratchet_sequence", 1)
                put("created_at_ms", 1)
            },
        )
        raw.insertOrThrow(
            "delivery_receipts",
            null,
            ContentValues().apply {
                put("delivered_message_id", deliveredId)
                put("receipt_envelope_id", ByteArray(16) { 0x22 })
                put("generated_at_ms", 1)
            },
        )
        val custody = envelope(idByte = 0x42, lifetimeMs = 180_000L)
        raw.insertOrThrow(
            "envelopes",
            null,
            ContentValues().apply {
                put("message_id", custody.messageId)
                put("wire_envelope", custody.encode())
                put("created_at_ms", 1)
            },
        )
        raw.version = 5
        raw.close()

        val migrated = newStore().writableDatabase

        assertEquals(8, migrated.version)
        assertEquals(1L, singleLong(migrated, "mesh_messages", "receipt_generated"))
        assertEquals(1L, singleLong(migrated, "mesh_messages", "is_read"))
        assertEquals(1L, singleLong(migrated, "mesh_messages", "content_version"))
        assertTrue(columnExists(migrated, "pending_mesh_texts", "content_version"))
        assertEquals(elapsedMs, singleLong(migrated, "envelopes", "age_anchor_elapsed_ms"))
        assertEquals(1L, count(migrated, "envelopes"))
    }

    private fun newStore(): RelayMeshStore = RelayMeshStore(
        context = context,
        storageKeyOverride = { storageKey },
        elapsedRealtimeMs = { elapsedMs },
    ).also { store = it }

    private fun insertEnvelope(
        database: SQLiteDatabase,
        envelope: RelayMeshEnvelope,
        createdAtMs: Long,
    ) {
        database.insertOrThrow(
            "envelopes",
            null,
            ContentValues().apply {
                put("message_id", envelope.messageId)
                put("wire_envelope", envelope.encode())
                put("age_ms", 0)
                put("age_anchor_elapsed_ms", elapsedMs)
                put("created_at_ms", createdAtMs)
            },
        )
    }

    private fun seedContact(database: SQLiteDatabase) {
        database.insertOrThrow(
            "contacts",
            null,
            ContentValues().apply {
                put("device_fingerprint", PEER_FINGERPRINT)
                put("display_name", "Reliability peer")
                put("local_nonce", ByteArray(12) { 1 })
                put("local_ciphertext", ByteArray(16) { 2 })
                put("verified", 1)
                put("next_outgoing_sequence", 1)
                put("highest_incoming_sequence", 1)
                put("created_at_ms", 1)
                put("updated_at_ms", 1)
            },
        )
    }

    private fun envelope(idByte: Int, lifetimeMs: Long): RelayMeshEnvelope = RelayMeshEnvelope(
        messageId = ByteArray(16) { idByte.toByte() },
        destinationHint = ByteArray(16) { 0x22 },
        lifetimeMs = lifetimeMs,
        ageMs = 0,
        hopLimit = 16,
        hopsTaken = 0,
        copyBudget = 4,
        priority = 2,
        ciphertext = ByteArray(96) { 0x66 },
    )

    private fun count(database: SQLiteDatabase, table: String): Long =
        database.rawQuery("SELECT COUNT(*) FROM $table", null).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private fun singleLong(database: SQLiteDatabase, table: String, column: String): Long =
        database.rawQuery("SELECT $column FROM $table LIMIT 1", null).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private fun columnExists(database: SQLiteDatabase, table: String, column: String): Boolean =
        database.rawQuery("PRAGMA table_info($table)", null).use { cursor ->
            val nameIndex = cursor.getColumnIndexOrThrow("name")
            var found = false
            while (cursor.moveToNext()) {
                found = found || cursor.getString(nameIndex) == column
            }
            found
        }

    private fun clearStore() {
        runCatching { context.deleteDatabase(DATABASE_NAME) }
    }

    private companion object {
        const val DATABASE_NAME = "relay_mesh.db"
        const val PEER_FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:11"
        const val OTHER_PEER_FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:22"
    }
}
