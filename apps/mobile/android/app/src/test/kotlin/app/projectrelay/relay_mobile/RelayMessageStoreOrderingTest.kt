package app.projectrelay.relay_mobile

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class RelayMessageStoreOrderingTest {
    private lateinit var context: Context
    private lateinit var store: RelayMessageStore
    private val storageKey = SecretKeySpec(ByteArray(32) { 0x31 }, "AES")

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.deleteDatabase(DATABASE_NAME)
        store = RelayMessageStore(context) { storageKey }
    }

    @After
    fun tearDown() {
        store.close()
        context.deleteDatabase(DATABASE_NAME)
    }

    @Test
    fun newerMessageCannotBypassOlderMessageRetryBackoff() {
        val first = textMessage(0x11, "message 1")
        val second = textMessage(0x22, "message 2")
        store.storeOutgoing(first, PEER_FINGERPRINT)
        store.beginAttempt(first.id)
        val retryAt = requireNotNull(store.markRetryableFailure(first.id, "test_failure"))
        store.storeOutgoing(second, PEER_FINGERPRINT)

        assertTrue(store.hasQueuedOutgoingForPeer(PEER_FINGERPRINT))
        assertEquals(
            RelayMessageCodec.idHex(first.id),
            RelayMessageCodec.idHex(requireNotNull(store.oldestQueuedForPeer(PEER_FINGERPRINT)).id),
        )
        assertNull(store.oldestRetryEligibleForPeer(PEER_FINGERPRINT, retryAt - 1L))
        assertEquals(
            RelayMessageCodec.idHex(first.id),
            RelayMessageCodec.idHex(
                requireNotNull(store.oldestRetryEligibleForPeer(PEER_FINGERPRINT, retryAt)).id,
            ),
        )

        store.markDelivered(first.id)
        assertEquals(
            RelayMessageCodec.idHex(second.id),
            RelayMessageCodec.idHex(
                requireNotNull(store.oldestRetryEligibleForPeer(PEER_FINGERPRINT, retryAt)).id,
            ),
        )
        store.markDelivered(second.id)
        assertFalse(store.hasQueuedOutgoingForPeer(PEER_FINGERPRINT))
    }

    @Test
    fun conversationHistoryUsesStableBoundedKeysetPages() {
        repeat(5) { index ->
            store.storeOutgoing(
                textMessage(0x10 + index, "message $index"),
                PEER_FINGERPRINT,
            )
        }
        store.storeOutgoing(
            textMessage(0x7F, "other peer"),
            OTHER_PEER_FINGERPRINT,
        )

        val expected = store.listRecentPage(PEER_FINGERPRINT, limit = 10)
        val first = store.listRecentPage(PEER_FINGERPRINT, limit = 2)
        val firstCursor = first.last()
        val second = store.listRecentPage(
            peerFingerprint = PEER_FINGERPRINT,
            beforeCreatedAtMs = firstCursor.createdAtMs,
            beforeMessageIdHex = RelayMessageCodec.idHex(firstCursor.id),
            limit = 2,
        )
        val secondCursor = second.last()
        val third = store.listRecentPage(
            peerFingerprint = PEER_FINGERPRINT,
            beforeCreatedAtMs = secondCursor.createdAtMs,
            beforeMessageIdHex = RelayMessageCodec.idHex(secondCursor.id),
            limit = 2,
        )

        val pagedIds = (first + second + third).map { RelayMessageCodec.idHex(it.id) }
        assertEquals(expected.map { RelayMessageCodec.idHex(it.id) }, pagedIds)
        assertEquals(5, pagedIds.toSet().size)
        assertTrue((first + second + third).all { it.peerFingerprint == PEER_FINGERPRINT })
    }

    @Test
    fun incomingUnreadStateIsDurableUntilConversationIsOpened() {
        repeat(2) { index ->
            store.storeIncoming(
                textMessage(0x50 + index, "incoming $index"),
                PEER_FINGERPRINT,
            )
        }
        store.storeOutgoing(
            textMessage(0x60, "outgoing"),
            PEER_FINGERPRINT,
        )

        val beforeOpen = store.conversationSummaries().single()
        assertEquals(2, beforeOpen.unreadCount)
        assertEquals(2, store.markConversationRead(PEER_FINGERPRINT))

        val afterOpen = store.conversationSummaries().single()
        assertEquals(0, afterOpen.unreadCount)
        assertTrue(
            store.listRecentPage(PEER_FINGERPRINT, limit = 10)
                .filter { it.direction == RelayMessageStore.Direction.INCOMING }
                .all { it.isRead },
        )
    }

    @Test
    fun typedReplyMetadataIsEncryptedAndRestoredWithoutChangingTheBody() {
        val message = replyMessage(
            idByte = 0x71,
            text = "The actual reply body",
            replyIdByte = 0x41,
            preview = "Original message preview",
        )

        assertTrue(store.storeOutgoing(message, PEER_FINGERPRINT))
        val restored = store.listRecentPage(PEER_FINGERPRINT, limit = 1).single()

        assertEquals("The actual reply body", restored.text)
        assertArrayEquals(ByteArray(16) { 0x41 }, restored.replyToMessageId)
        assertEquals("Original message preview", restored.replyPreview)
        assertEquals(
            2L,
            store.readableDatabase.rawQuery(
                "SELECT content_version FROM messages",
                null,
            ).use {
                assertTrue(it.moveToFirst())
                it.getLong(0)
            },
        )
    }

    @Test
    fun versionThreeDatabaseMigratesReplyStorageAdditively() {
        store.close()
        val raw = context.openOrCreateDatabase(DATABASE_NAME, Context.MODE_PRIVATE, null)
        createVersionThreeMessagesTable(raw)
        raw.version = 3
        raw.close()

        store = RelayMessageStore(context) { storageKey }
        val migrated = store.writableDatabase
        assertEquals(4, migrated.version)
        assertTrue(
            migrated.rawQuery("PRAGMA table_info(messages)", null).use { cursor ->
                val nameIndex = cursor.getColumnIndexOrThrow("name")
                val defaultIndex = cursor.getColumnIndexOrThrow("dflt_value")
                var found = false
                while (cursor.moveToNext()) {
                    if (cursor.getString(nameIndex) == "content_version") {
                        assertEquals("1", cursor.getString(defaultIndex))
                        found = true
                    }
                }
                found
            },
        )
    }

    private fun textMessage(idByte: Int, text: String): RelayMessageCodec.TextMessage {
        val id = ByteArray(16) { idByte.toByte() }
        val body = text.encodeToByteArray()
        val encoded = ByteArray(26 + body.size)
        byteArrayOf(0x52, 0x4D, 0x53, 0x47, 1, 1, 0, 0).copyInto(encoded)
        id.copyInto(encoded, destinationOffset = 8)
        encoded[24] = (body.size ushr 8).toByte()
        encoded[25] = body.size.toByte()
        body.copyInto(encoded, destinationOffset = 26)
        return RelayMessageCodec.TextMessage(id = id, text = text, encoded = encoded)
    }

    private fun replyMessage(
        idByte: Int,
        text: String,
        replyIdByte: Int,
        preview: String,
    ): RelayMessageCodec.TextMessage {
        val id = ByteArray(16) { idByte.toByte() }
        val replyId = ByteArray(16) { replyIdByte.toByte() }
        val body = text.encodeToByteArray()
        val previewBytes = preview.encodeToByteArray()
        val encoded = ByteArray(44 + previewBytes.size + body.size)
        byteArrayOf(0x52, 0x4D, 0x53, 0x47, 2, 1, 1, 0).copyInto(encoded)
        id.copyInto(encoded, destinationOffset = 8)
        encoded[24] = (body.size ushr 8).toByte()
        encoded[25] = body.size.toByte()
        replyId.copyInto(encoded, destinationOffset = 26)
        encoded[42] = (previewBytes.size ushr 8).toByte()
        encoded[43] = previewBytes.size.toByte()
        previewBytes.copyInto(encoded, destinationOffset = 44)
        body.copyInto(encoded, destinationOffset = 44 + previewBytes.size)
        return RelayMessageCodec.TextMessage(
            id = id,
            text = text,
            replyToMessageId = replyId,
            replyPreview = preview,
            encoded = encoded,
        )
    }

    private fun createVersionThreeMessagesTable(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE messages (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL UNIQUE CHECK(length(message_id) = 16),
                peer_fingerprint TEXT NOT NULL,
                direction INTEGER NOT NULL CHECK(direction IN (0, 1)),
                nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                ciphertext BLOB NOT NULL,
                status INTEGER NOT NULL CHECK(status IN (0, 1, 2)),
                created_at_ms INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                last_attempt_at_ms INTEGER,
                next_attempt_at_ms INTEGER,
                last_error_code TEXT,
                is_read INTEGER NOT NULL DEFAULT 1 CHECK(is_read IN (0, 1))
            )
            """.trimIndent(),
        )
    }

    private companion object {
        const val DATABASE_NAME = "relay_messages.db"
        const val PEER_FINGERPRINT =
            "abababababababababababababababababababababababababababababababab"
        const val OTHER_PEER_FINGERPRINT =
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    }
}
