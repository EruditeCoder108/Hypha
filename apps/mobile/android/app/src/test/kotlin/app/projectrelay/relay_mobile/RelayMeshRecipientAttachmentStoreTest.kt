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
class RelayMeshRecipientAttachmentStoreTest {
    private lateinit var context: Context
    private val storageKey = SecretKeySpec(ByteArray(32) { 0x6A }, "AES")
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
    fun manifestRatchetAccountAndDuplicateMarkerCommitTogetherAndSurviveReboot() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        seedState(database, "old-account".toByteArray())
        val manifest = manifest(1)
        val received = received(manifest, sequence = 7)
        val envelope = envelope(manifest.objectId, lifetimeMs = 60_000, ageMs = 10)

        val result = inTransaction(database) {
            active.commitReceivedAttachmentManifest(
                database = database,
                destination = contact(),
                updatedAccountPickle = "new-account".toByteArray(),
                sessionRole = false,
                received = received,
                envelope = envelope,
            )
        }
        assertTrue(result.inserted)
        assertTrue(result.messageId.contentEquals(manifest.objectId))

        database.query(
            TABLE_PENDING,
            arrayOf("manifest_nonce", "manifest_ciphertext"),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals(12, cursor.getBlob(0).size)
            val ciphertext = cursor.getBlob(1)
            assertFalse(ciphertext.contains(manifest.fileName.toByteArray()))
            assertFalse(ciphertext.contains(manifest.mimeType.toByteArray()))
            assertFalse(ciphertext.contains(manifest.contentKey))
        }
        assertEquals("new-account", singleBlob(database, "mesh_state", "account_pickle").decodeToString())
        assertEquals("new-session", singleBlob(database, "contacts", "session_pickle").decodeToString())
        assertEquals(7L, singleLong(database, "contacts", "highest_incoming_sequence"))
        assertEquals(1L, count(database, "consumed_envelopes"))

        active.close()
        store = null
        elapsedMs = 25L // elapsedRealtime reset: persisted age must not become negative.
        val reopened = newStore()
        val pending = reopened.pendingRecipientAttachments()
        assertEquals(1, pending.size)
        assertEquals(CONTACT_FINGERPRINT, pending.single().peerFingerprint)
        assertTrue(pending.single().manifest.encode().contentEquals(manifest.encode()))
        assertEquals(7L, pending.single().ratchetSequence)
        assertEquals(10L, pending.single().ageMs)
    }

    @Test
    fun transactionRollbackLeavesNoManifestRatchetOrConsumedMarker() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        seedState(database, "old-account".toByteArray())
        val manifest = manifest(2)
        database.beginTransaction()
        try {
            active.commitReceivedAttachmentManifest(
                database = database,
                destination = contact(),
                updatedAccountPickle = "new-account".toByteArray(),
                sessionRole = false,
                received = received(manifest, sequence = 3),
                envelope = envelope(manifest.objectId),
            )
        } finally {
            database.endTransaction()
        }

        assertEquals(0L, count(database, TABLE_PENDING))
        assertEquals(0L, count(database, "consumed_envelopes"))
        assertEquals("old-account", singleBlob(database, "mesh_state", "account_pickle").decodeToString())
        assertEquals(0L, singleLong(database, "contacts", "highest_incoming_sequence"))
    }

    @Test
    fun conflictingObjectAndSixtyFifthPendingManifestFailClosed() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        for (value in 0 until 64) {
            val manifest = manifest(value)
            inTransaction(database) {
                active.commitReceivedAttachmentManifest(
                    database = database,
                    destination = contact(),
                    updatedAccountPickle = null,
                    sessionRole = true,
                    received = received(manifest, sequence = value + 1L),
                    envelope = envelope(manifest.objectId),
                )
            }
        }
        assertEquals(64L, count(database, TABLE_PENDING))

        val sixtyFifth = manifest(64)
        database.beginTransaction()
        try {
            assertThrows(IllegalStateException::class.java) {
                active.commitReceivedAttachmentManifest(
                    database = database,
                    destination = contact(),
                    updatedAccountPickle = null,
                    sessionRole = true,
                    received = received(sixtyFifth, sequence = 65),
                    envelope = envelope(sixtyFifth.objectId),
                )
            }
        } finally {
            database.endTransaction()
        }
        assertEquals(64L, count(database, TABLE_PENDING))

        database.delete(
            "consumed_envelopes",
            "hex(message_id) = ?",
            arrayOf(manifest(0).objectId.toSqlHex()),
        )
        val conflicting = manifest(0).copy(fileName = "different.bin")
        database.beginTransaction()
        try {
            assertThrows(IllegalStateException::class.java) {
                active.commitReceivedAttachmentManifest(
                    database = database,
                    destination = contact(),
                    updatedAccountPickle = null,
                    sessionRole = true,
                    received = received(conflicting, sequence = 1),
                    envelope = envelope(conflicting.objectId),
                )
            }
        } finally {
            database.endTransaction()
        }
        assertEquals(64L, count(database, TABLE_PENDING))
    }

    @Test
    fun monotonicResidenceExpiryDeletesOnlyPendingPrivateState() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        val manifest = manifest(9)
        inTransaction(database) {
            active.commitReceivedAttachmentManifest(
                database = database,
                destination = contact(),
                updatedAccountPickle = null,
                sessionRole = true,
                received = received(manifest, sequence = 1),
                envelope = envelope(manifest.objectId, lifetimeMs = 100, ageMs = 90),
            )
        }
        elapsedMs += 11
        assertTrue(active.pendingRecipientAttachments().isEmpty())
        assertEquals(1L, count(database, "consumed_envelopes"))
    }

    @Test
    fun readyHar1CommitsRatchetControlEnvelopeAndPendingRemovalTogether() {
        val active = newStore()
        val database = active.writableDatabase
        seedContact(database)
        seedState(database, "account".toByteArray())
        val manifest = manifest(10)
        inTransaction(database) {
            active.commitReceivedAttachmentManifest(
                database = database,
                destination = contact(),
                updatedAccountPickle = null,
                sessionRole = false,
                received = received(manifest, sequence = 7),
                envelope = envelope(manifest.objectId),
            )
        }
        val receipt = RelayRecipientAttachmentReceipt(
            manifest.objectId,
            manifest.courierPlanSha256,
        )
        val receiptEnvelopeId = ByteArray(16) { 0x66 }
        val encrypted = E2eEncryptResult(
            sessionPickle = "receipt-session".toByteArray(),
            envelope = RelayMeshEnvelope(
                messageId = receiptEnvelopeId,
                destinationHint = ByteArray(16) { 0x55 },
                lifetimeMs = 60_000,
                ageMs = 0,
                hopLimit = 16,
                hopsTaken = 0,
                copyBudget = 2,
                priority = 0,
                ciphertext = ByteArray(64) { 0x44 },
            ).encode(),
        )

        val queued = inTransaction(database) {
            active.commitReadyRecipientAttachmentReceipt(
                database = database,
                contact = contact().copy(
                    sessionIsInitiator = false,
                    sessionPickle = "new-session".toByteArray(),
                    highestIncomingSequence = 7,
                ),
                receipt = receipt,
                receiptEnvelopeId = receiptEnvelopeId,
                encrypted = encrypted,
            )
        }

        assertTrue(queued.objectId.contentEquals(manifest.objectId))
        assertEquals(0L, count(database, TABLE_PENDING))
        assertEquals(1L, count(database, "delivery_receipts"))
        assertEquals(1L, count(database, "envelopes"))
        assertEquals(2L, singleLong(database, "contacts", "next_outgoing_sequence"))
        assertEquals(
            "receipt-session",
            singleBlob(database, "contacts", "session_pickle").decodeToString(),
        )
    }

    @Test
    fun versionTwoDatabaseMigratesAdditively() {
        val raw = context.openOrCreateDatabase(DATABASE_NAME, Context.MODE_PRIVATE, null)
        raw.execSQL("CREATE TABLE contacts(device_fingerprint TEXT PRIMARY KEY)")
        raw.version = 2
        raw.close()

        val migrated = newStore().writableDatabase
        assertEquals(8, migrated.version)
        assertTrue(
            migrated.rawQuery(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                arrayOf(TABLE_PENDING),
            ).use { it.moveToFirst() },
        )
    }

    private fun newStore(): RelayMeshStore = RelayMeshStore(
        context = context,
        storageKeyOverride = { storageKey },
        elapsedRealtimeMs = { elapsedMs },
    ).also { store = it }

    private fun seedContact(database: SQLiteDatabase) {
        val values = ContentValues().apply {
            put("device_fingerprint", CONTACT_FINGERPRINT)
            put("display_name", "Test contact")
            put("local_nonce", ByteArray(12) { 1 })
            put("local_ciphertext", ByteArray(16) { 2 })
            put("verified", 1)
            put("next_outgoing_sequence", 1)
            put("highest_incoming_sequence", 0)
            put("created_at_ms", 1)
            put("updated_at_ms", 1)
        }
        database.insertOrThrow("contacts", null, values)
    }

    private fun seedState(database: SQLiteDatabase, accountPickle: ByteArray) {
        val values = ContentValues().apply {
            put("singleton", 1)
            put("key_nonce", ByteArray(12) { 3 })
            put("key_ciphertext", ByteArray(16) { 4 })
            put("account_pickle", accountPickle)
        }
        database.insertOrThrow("mesh_state", null, values)
    }

    private fun contact(): RelayMeshStore.Contact = RelayMeshStore.Contact(
        deviceFingerprint = CONTACT_FINGERPRINT,
        displayName = "Test contact",
        relayId = "relay-id",
        localBundle = ByteArray(200) { 5 },
        remoteBundle = ByteArray(200) { 6 },
        verified = true,
        sessionIsInitiator = null,
        sessionPickle = null,
        nextOutgoingSequence = 1,
        highestIncomingSequence = 0,
    )

    private fun manifest(value: Int): RelayRecipientAttachmentManifest {
        val objectId = ByteArray(16).also { it[0] = value.toByte() }
        return RelayRecipientAttachmentManifest(
            objectId = objectId,
            kind = RelayAttachmentManifest.Kind.FILE,
            courierPlanSha256 = ByteArray(32) { (value + 1).toByte() },
            contentKey = ByteArray(32) { 0x33 },
            plaintextBytes = 42,
            plaintextSha256 = ByteArray(32) { 0x44 },
            mimeType = "application/octet-stream",
            fileName = "private-$value.bin",
        )
    }

    private fun received(
        manifest: RelayRecipientAttachmentManifest,
        sequence: Long,
    ): E2ePayloadResult.AttachmentManifest = E2ePayloadResult.AttachmentManifest(
        sessionPickle = "new-session".toByteArray(),
        sequence = sequence,
        envelopeId = manifest.objectId,
        manifest = manifest,
    )

    private fun envelope(
        objectId: ByteArray,
        lifetimeMs: Long = 60_000,
        ageMs: Long = 0,
    ): RelayMeshEnvelope = RelayMeshEnvelope(
        messageId = objectId,
        destinationHint = ByteArray(16) { 7 },
        lifetimeMs = lifetimeMs,
        ageMs = ageMs,
        hopLimit = 16,
        hopsTaken = 1,
        copyBudget = 1,
        priority = 4,
        ciphertext = ByteArray(64) { 8 },
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

    private fun ByteArray.contains(needle: ByteArray): Boolean =
        needle.isNotEmpty() && indices.any { start ->
            start + needle.size <= size && copyOfRange(start, start + needle.size).contentEquals(needle)
        }

    private fun ByteArray.toSqlHex(): String = joinToString(separator = "") { byte ->
        "%02X".format(byte.toInt() and 0xFF)
    }

    private fun clearStore() {
        runCatching { context.deleteDatabase(DATABASE_NAME) }
    }

    private companion object {
        const val DATABASE_NAME = "relay_mesh.db"
        const val TABLE_PENDING = "recipient_attachment_manifests"
        const val CONTACT_FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:11"
    }
}
