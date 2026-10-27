package app.projectrelay.relay_mobile

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
class RelayMeshSenderAttachmentStoreTest {
    private lateinit var context: Context
    private val storageKey = SecretKeySpec(ByteArray(32) { 0x5C }, "AES")
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
    fun offerRatchetAndProtectedCancellationCommitTogetherWithoutPrivateCourierColumns() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val attachment = attachment(1)
        val prepared = RelaySenderAttachmentPreparation.prepare(attachment, CANCELLATION_SECRET)

        val stored = inTransaction(database) {
            active.commitOutgoingAttachmentOffer(
                database = database,
                contact = contact(),
                sessionRole = true,
                encrypted = encrypted(prepared.plan),
                plan = prepared.plan,
                cancellationSecret = CANCELLATION_SECRET,
                ratchetSequence = 1,
            )
        }

        assertTrue(stored.objectId.contentEquals(attachment.attachmentId))
        assertTrue(active.setSenderAttachmentOfferEligible(stored.objectId, false))
        assertTrue(active.nextSenderAttachmentOffer() == null)
        assertTrue(active.setSenderAttachmentOfferEligible(stored.objectId, true))
        assertTrue(active.nextSenderAttachmentOffer() != null)
        assertEquals(2L, singleLong(database, "contacts", "next_outgoing_sequence"))
        assertEquals("new-session", singleBlob(database, "contacts", "session_pickle").decodeToString())
        database.query(
            TABLE_OFFERS,
            arrayOf("wire_manifest", "wire_plan", "cancel_nonce", "cancel_ciphertext"),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals(12, cursor.getBlob(2).size)
            for (index in 0..3) {
                val storedBytes = cursor.getBlob(index)
                assertFalse(storedBytes.contains(attachment.fileName.toByteArray()))
                assertFalse(storedBytes.contains(attachment.mimeType.toByteArray()))
                assertFalse(storedBytes.contains(attachment.contentKey))
            }
        }
    }

    @Test
    fun rollbackLeavesNoOfferOrRatchetAdvance() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val prepared = RelaySenderAttachmentPreparation.prepare(attachment(2), CANCELLATION_SECRET)
        database.beginTransaction()
        try {
            active.commitOutgoingAttachmentOffer(
                database,
                contact(),
                true,
                encrypted(prepared.plan),
                prepared.plan,
                CANCELLATION_SECRET,
                1,
            )
        } finally {
            database.endTransaction()
        }

        assertEquals(0L, count(database, TABLE_OFFERS))
        assertEquals(1L, singleLong(database, "contacts", "next_outgoing_sequence"))
        assertTrue(singleBlob(database, "contacts", "session_pickle").isEmpty())
    }

    @Test
    fun authenticatedCustodyPersistsAcrossRebootAndExactDuplicateIsIdempotent() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val prepared = RelaySenderAttachmentPreparation.prepare(attachment(3), CANCELLATION_SECRET)
        inTransaction(database) {
            active.commitOutgoingAttachmentOffer(
                database,
                contact(),
                true,
                encrypted(prepared.plan),
                prepared.plan,
                CANCELLATION_SECRET,
                1,
            )
        }
        val custody = RelayCourierAttachmentCustody.fromCommitted(prepared.plan, setOf(0))
        assertTrue(active.recordSenderAttachmentCustody(COURIER_FINGERPRINT, custody.encode()).inserted)
        assertFalse(active.recordSenderAttachmentCustody(COURIER_FINGERPRINT, custody.encode()).inserted)
        assertTrue(active.nextSenderAttachmentOffer(COURIER_FINGERPRINT) == null)

        active.close()
        store = null
        elapsedMs = 25L
        val reopened = newStore()
        val durable = reopened.senderAttachmentCustody(
            prepared.plan.objectId,
            COURIER_FINGERPRINT,
        )
        assertTrue(requireNotNull(durable).encode().contentEquals(custody.encode()))
        assertEquals(listOf(1), durable.missingChunks())
        assertEquals(0b00000010, durable.missingBitmap().single().toInt())
    }

    @Test
    fun mismatchedOrRegressingCustodyFailsClosedAndCannotCreateDeliveryState() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val prepared = RelaySenderAttachmentPreparation.prepare(attachment(4), CANCELLATION_SECRET)
        inTransaction(database) {
            active.commitOutgoingAttachmentOffer(
                database,
                contact(),
                true,
                encrypted(prepared.plan),
                prepared.plan,
                CANCELLATION_SECRET,
                1,
            )
        }
        val complete = RelayCourierAttachmentCustody.fromCommitted(prepared.plan, setOf(0, 1))
        active.recordSenderAttachmentCustody(COURIER_FINGERPRINT, complete.encode())
        val regressing = RelayCourierAttachmentCustody.fromCommitted(prepared.plan, setOf(0))
        assertThrows(IllegalArgumentException::class.java) {
            active.recordSenderAttachmentCustody(COURIER_FINGERPRINT, regressing.encode())
        }
        val wrong = complete.copy(planSha256 = ByteArray(32) { 9 })
        assertThrows(IllegalArgumentException::class.java) {
            active.recordSenderAttachmentCustody(OTHER_COURIER_FINGERPRINT, wrong.encode())
        }
        assertEquals(0L, count(database, "delivery_receipts"))
        assertEquals(0L, count(database, "mesh_messages"))
    }

    @Test
    fun authenticatedHar1BindsDeliveredThenAuthorizesExactCourierCleanup() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val prepared = RelaySenderAttachmentPreparation.prepare(attachment(5), CANCELLATION_SECRET)
        inTransaction(database) {
            active.commitOutgoingAttachmentOffer(
                database,
                contact(),
                true,
                encrypted(prepared.plan),
                prepared.plan,
                CANCELLATION_SECRET,
                1,
            )
        }
        active.recordSenderAttachmentCustody(
            COURIER_FINGERPRINT,
            RelayCourierAttachmentCustody.fromCommitted(
                prepared.plan,
                prepared.plan.chunks.indices.toSet(),
            ).encode(),
        )
        val receiptEnvelopeId = ByteArray(16) { 0x66 }
        val envelope = RelayMeshEnvelope(
            messageId = receiptEnvelopeId,
            destinationHint = ByteArray(16) { 7 },
            lifetimeMs = 60_000,
            ageMs = 0,
            hopLimit = 16,
            hopsTaken = 1,
            copyBudget = 1,
            priority = 0,
            ciphertext = ByteArray(64) { 8 },
        )
        val destination = contact().copy(
            sessionPickle = "new-session".toByteArray(),
            nextOutgoingSequence = 2,
        )
        val wrong = E2ePayloadResult.AttachmentReceipt(
            sessionPickle = "receipt-session".toByteArray(),
            sequence = 2,
            envelopeId = receiptEnvelopeId,
            receipt = RelayRecipientAttachmentReceipt(
                prepared.plan.objectId,
                ByteArray(32) { 9 },
            ),
        )
        database.beginTransaction()
        try {
            assertThrows(IllegalArgumentException::class.java) {
                active.applyAttachmentReceipt(database, destination, wrong, envelope)
            }
        } finally {
            database.endTransaction()
        }
        assertEquals(0L, count(database, TABLE_RECEIPTS))

        val received = wrong.copy(
            receipt = RelayRecipientAttachmentReceipt(
                prepared.plan.objectId,
                prepared.plan.sha256(),
            ),
        )
        val result = inTransaction(database) {
            active.applyAttachmentReceipt(database, destination, received, envelope)
        }
        assertTrue(result.inserted)
        assertTrue(active.nextSenderAttachmentOffer() == null)
        assertEquals(1, active.pendingSenderAttachmentReceipts().size)

        assertTrue(active.markSenderAttachmentReceiptLocallyApplied(prepared.plan.objectId))
        val cleanup = requireNotNull(active.nextSenderAttachmentCleanup(COURIER_FINGERPRINT))
        assertTrue(cleanup.objectId.contentEquals(prepared.plan.objectId))
        assertTrue(cleanup.planSha256.contentEquals(prepared.plan.sha256()))
        assertTrue(cleanup.cancellationSecret.contentEquals(CANCELLATION_SECRET))
        assertTrue(
            active.completeSenderAttachmentCleanup(
                COURIER_FINGERPRINT,
                RelayCourierAttachmentCleanupAck(cleanup.objectId, cleanup.planSha256),
            ),
        )
        assertEquals(0L, count(database, TABLE_OFFERS))
        assertEquals(0L, count(database, TABLE_CUSTODY))
        assertEquals(0L, count(database, TABLE_RECEIPTS))
        assertTrue(active.pendingSenderAttachmentReceipts().isEmpty())
    }

    @Test
    fun receiptConfirmedCourierCleanupRemovesOnlyTheOpaqueManifest() {
        val active = newStore()
        val database = active.writableDatabase
        val prepared = RelaySenderAttachmentPreparation.prepare(attachment(6), CANCELLATION_SECRET)
        val wireManifest = encrypted(prepared.plan).envelope
        database.insertOrThrow(
            "envelopes",
            null,
            ContentValues().apply {
                put("message_id", prepared.plan.objectId)
                put("wire_envelope", wireManifest)
                put("created_at_ms", 1L)
            },
        )

        assertTrue(active.removeReceiptConfirmedCourierManifest(prepared.plan.objectId))
        assertEquals(0L, count(database, "envelopes"))
        assertFalse(active.removeReceiptConfirmedCourierManifest(prepared.plan.objectId))
    }

    @Test
    fun versionThreeDatabaseMigratesAdditively() {
        val raw = context.openOrCreateDatabase(DATABASE_NAME, Context.MODE_PRIVATE, null)
        raw.execSQL("CREATE TABLE contacts(device_fingerprint TEXT PRIMARY KEY)")
        raw.version = 3
        raw.close()

        val migrated = newStore().writableDatabase
        assertEquals(8, migrated.version)
        assertTrue(tableExists(migrated, TABLE_OFFERS))
        assertTrue(tableExists(migrated, TABLE_CUSTODY))
        assertTrue(tableExists(migrated, TABLE_RECEIPTS))
    }

    private fun newStore(): RelayMeshStore = RelayMeshStore(
        context = context,
        storageKeyOverride = { storageKey },
        elapsedRealtimeMs = { elapsedMs },
    ).also { store = it }

    private fun seedContact(database: SQLiteDatabase) {
        database.insertOrThrow(
            "contacts",
            null,
            ContentValues().apply {
                put("device_fingerprint", CONTACT_FINGERPRINT)
                put("display_name", "Test contact")
                put("local_nonce", ByteArray(12) { 1 })
                put("local_ciphertext", ByteArray(16) { 2 })
                put("verified", 1)
                put("session_role", 1)
                put("session_pickle", ByteArray(0))
                put("next_outgoing_sequence", 1)
                put("highest_incoming_sequence", 0)
                put("created_at_ms", 1)
                put("updated_at_ms", 1)
            },
        )
    }

    private fun contact(): RelayMeshStore.Contact = RelayMeshStore.Contact(
        deviceFingerprint = CONTACT_FINGERPRINT,
        displayName = "Test contact",
        relayId = "relay-id",
        localBundle = ByteArray(200) { 5 },
        remoteBundle = ByteArray(200) { 6 },
        verified = true,
        sessionIsInitiator = true,
        sessionPickle = ByteArray(0),
        nextOutgoingSequence = 1,
        highestIncomingSequence = 0,
    )

    private fun attachment(value: Int): RelayAttachmentManifest {
        val objectId = ByteArray(16).also { it[0] = value.toByte() }
        val firstBytes = RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES
        val finalBytes = 37
        return RelayAttachmentManifest(
            attachmentId = objectId,
            kind = RelayAttachmentManifest.Kind.FILE,
            fileName = "private-$value.bin",
            mimeType = "application/octet-stream",
            plaintextBytes = firstBytes.toLong() + finalBytes,
            chunkSize = firstBytes,
            contentKey = ByteArray(32) { 0x33 },
            plaintextSha256 = ByteArray(32) { 0x44 },
            chunks = listOf(
                RelayAttachmentManifest.Chunk(0, firstBytes, ByteArray(12) { 1 }, firstBytes + 16, ByteArray(32) { 2 }),
                RelayAttachmentManifest.Chunk(1, finalBytes, ByteArray(12) { 3 }, finalBytes + 16, ByteArray(32) { 4 }),
            ),
        ).also(RelayAttachmentManifest::validate)
    }

    private fun encrypted(plan: RelayCourierAttachmentPlan): E2eEncryptResult = E2eEncryptResult(
        sessionPickle = "new-session".toByteArray(),
        envelope = RelayMeshEnvelope(
            messageId = plan.objectId.copyOf(),
            destinationHint = ByteArray(16) { 7 },
            lifetimeMs = 60_000,
            ageMs = 0,
            hopLimit = 16,
            hopsTaken = 0,
            copyBudget = 1,
            priority = 4,
            ciphertext = ByteArray(64) { 8 },
        ).encode(),
    )

    private fun <T> inTransaction(database: SQLiteDatabase, block: () -> T): T {
        database.beginTransaction()
        try {
            val result = block()
            database.setTransactionSuccessful()
            return result
        } finally {
            database.endTransaction()
        }
    }

    private fun count(database: SQLiteDatabase, table: String): Long =
        database.rawQuery("SELECT COUNT(*) FROM $table", null).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private fun singleBlob(database: SQLiteDatabase, table: String, column: String): ByteArray =
        database.rawQuery("SELECT $column FROM $table LIMIT 1", null).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getBlob(0)
        }

    private fun singleLong(database: SQLiteDatabase, table: String, column: String): Long =
        database.rawQuery("SELECT $column FROM $table LIMIT 1", null).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private fun tableExists(database: SQLiteDatabase, name: String): Boolean = database.rawQuery(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        arrayOf(name),
    ).use { it.moveToFirst() }

    private fun ByteArray.contains(needle: ByteArray): Boolean = needle.isNotEmpty() &&
        indices.any { start ->
            start + needle.size <= size &&
                copyOfRange(start, start + needle.size).contentEquals(needle)
        }

    private fun clearStore() {
        runCatching { context.deleteDatabase(DATABASE_NAME) }
    }

    private companion object {
        const val DATABASE_NAME = "relay_mesh.db"
        const val TABLE_OFFERS = "sender_attachment_offers"
        const val TABLE_CUSTODY = "sender_attachment_custody"
        const val TABLE_RECEIPTS = "sender_attachment_receipts"
        const val CONTACT_FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:11"
        const val COURIER_FINGERPRINT = "11:22:33:44:55:66:77:88"
        const val OTHER_COURIER_FINGERPRINT = "99:AA:BB:CC:DD:EE:FF:00"
        val CANCELLATION_SECRET = ByteArray(32) { 0x7A }
    }
}
