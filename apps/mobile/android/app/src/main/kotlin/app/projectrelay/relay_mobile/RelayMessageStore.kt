package app.projectrelay.relay_mobile

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Durable message metadata with text encrypted by a non-exportable Android Keystore key. */
internal class RelayMessageStore(
    context: Context,
    private val storageKeyOverride: (() -> SecretKey)? = null,
) :
    SQLiteOpenHelper(context.applicationContext, DATABASE_NAME, null, DATABASE_VERSION) {
    init {
        setWriteAheadLoggingEnabled(true)
    }

    data class StoredMessage(
        val id: ByteArray,
        val peerFingerprint: String,
        val direction: Direction,
        val text: String,
        val replyToMessageId: ByteArray?,
        val replyPreview: String?,
        val status: Status,
        val createdAtMs: Long,
        val attemptCount: Int,
        val lastAttemptAtMs: Long?,
        val nextAttemptAtMs: Long?,
        val lastErrorCode: String?,
        val isRead: Boolean,
    ) {
        fun toMap(): Map<String, Any> = buildMap {
            put("messageId", RelayMessageCodec.idHex(id))
            put("peerFingerprint", peerFingerprint)
            put("direction", direction.wireValue)
            put("text", text)
            replyToMessageId?.let {
                put("replyToMessageId", RelayMessageCodec.idHex(it))
                put("replyPreview", requireNotNull(replyPreview))
            }
            put("status", status.wireValue)
            put("createdAtMs", createdAtMs)
            put("attemptCount", attemptCount)
            lastAttemptAtMs?.let { put("lastAttemptAtMs", it) }
            nextAttemptAtMs?.let { put("nextAttemptAtMs", it) }
            lastErrorCode?.let { put("lastErrorCode", it) }
            put("isRead", isRead)
        }
    }

    data class ConversationSummary(
        val lastMessage: StoredMessage,
        val messageCount: Int,
        val unreadCount: Int,
    )

    enum class Direction(val databaseValue: Int, val wireValue: String) {
        INCOMING(0, "incoming"),
        OUTGOING(1, "outgoing");

        companion object {
            fun fromDatabase(value: Int): Direction = entries.first { it.databaseValue == value }
        }
    }

    enum class Status(val databaseValue: Int, val wireValue: String) {
        QUEUED(0, "queued"),
        DELIVERED(1, "delivered"),
        RECEIVED(2, "received");

        companion object {
            fun fromDatabase(value: Int): Status = entries.first { it.databaseValue == value }
        }
    }

    override fun onConfigure(database: SQLiteDatabase) {
        super.onConfigure(database)
        database.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(database: SQLiteDatabase) {
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
                is_read INTEGER NOT NULL DEFAULT 1 CHECK(is_read IN (0, 1)),
                content_version INTEGER NOT NULL DEFAULT 1 CHECK(content_version IN (1, 2))
            )
            """.trimIndent(),
        )
        database.execSQL("CREATE INDEX messages_peer_sequence ON messages(peer_fingerprint, sequence)")
        database.execSQL(
            "CREATE INDEX messages_outbox_due ON messages(direction, status, next_attempt_at_ms, sequence)",
        )
        createUnreadIndex(database)
    }

    override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        var version = oldVersion
        if (version == 1) {
            database.execSQL(
                "ALTER TABLE messages ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 " +
                    "CHECK(attempt_count >= 0)",
            )
            database.execSQL("ALTER TABLE messages ADD COLUMN last_attempt_at_ms INTEGER")
            database.execSQL("ALTER TABLE messages ADD COLUMN next_attempt_at_ms INTEGER")
            database.execSQL("ALTER TABLE messages ADD COLUMN last_error_code TEXT")
            database.execSQL(
                "CREATE INDEX messages_outbox_due " +
                    "ON messages(direction, status, next_attempt_at_ms, sequence)",
            )
            version = 2
        }
        if (version == 2) {
            database.execSQL(
                "ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 1 " +
                    "CHECK(is_read IN (0, 1))",
            )
            createUnreadIndex(database)
            version = 3
        }
        if (version == 3) {
            database.execSQL(
                "ALTER TABLE messages ADD COLUMN content_version INTEGER NOT NULL DEFAULT 1 " +
                    "CHECK(content_version IN (1, 2))",
            )
            version = 4
        }
        check(version == newVersion) {
            "Unsupported Relay message database migration $oldVersion to $newVersion"
        }
    }

    /**
     * Durably queues an outgoing message. Retrying the exact same ID and body is idempotent;
     * a mismatched reuse of an ID is still rejected as a collision.
     */
    fun storeOutgoing(message: RelayMessageCodec.TextMessage, peerFingerprint: String): Boolean =
        insert(
            message = message,
            peerFingerprint = peerFingerprint,
            direction = Direction.OUTGOING,
            status = Status.QUEUED,
            allowExactDuplicate = true,
        )

    /** Returns true only when a new inbound message was durably inserted. */
    fun storeIncoming(message: RelayMessageCodec.TextMessage, peerFingerprint: String): Boolean =
        insert(
            message = message,
            peerFingerprint = peerFingerprint,
            direction = Direction.INCOMING,
            status = Status.RECEIVED,
            allowExactDuplicate = true,
        )

    fun markDelivered(id: ByteArray) {
        val values = ContentValues().apply {
            put(COLUMN_STATUS, Status.DELIVERED.databaseValue)
            putNull(COLUMN_NEXT_ATTEMPT_AT)
            putNull(COLUMN_LAST_ERROR_CODE)
        }
        val updated = writableDatabase.update(
            TABLE_MESSAGES,
            values,
            "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_DIRECTION = ?",
            arrayOf(sqlHex(id), Direction.OUTGOING.databaseValue.toString()),
        )
        check(updated == 1) { "Outgoing message was not found for delivery receipt." }
    }

    fun queuedOutgoing(messageIdHex: String): StoredMessage? {
        if (messageIdHex.length != MESSAGE_ID_BYTES * 2 || !messageIdHex.all { it.isHexDigit() }) {
            return null
        }
        return findByHexId(readableDatabase, messageIdHex.uppercase())
            ?.takeIf { it.direction == Direction.OUTGOING && it.status == Status.QUEUED }
    }

    fun hasQueuedOutgoingForPeer(peerFingerprint: String): Boolean {
        require(peerFingerprint.isNotBlank()) { "Peer fingerprint is required." }
        return readableDatabase.query(
            TABLE_MESSAGES,
            arrayOf(COLUMN_MESSAGE_ID),
            "$COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ? AND $COLUMN_PEER_FINGERPRINT = ?",
            arrayOf(
                Direction.OUTGOING.databaseValue.toString(),
                Status.QUEUED.databaseValue.toString(),
                peerFingerprint,
            ),
            null,
            null,
            "$COLUMN_SEQUENCE ASC",
            "1",
        ).use(Cursor::moveToFirst)
    }

    fun oldestRetryEligible(nowMs: Long = System.currentTimeMillis()): StoredMessage? =
        oldestQueued()?.takeIf { oldest ->
            RelayRetryClockPolicy.isEligible(
                nextAttemptAtMs = oldest.nextAttemptAtMs,
                nowMs = nowMs,
                maximumLegitimateDelayMs = RETRY_MAX_MS,
            )
        }

    private fun oldestQueued(): StoredMessage? = readableDatabase.query(
            TABLE_MESSAGES,
            MESSAGE_PROJECTION,
            "$COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ?",
            arrayOf(
                Direction.OUTGOING.databaseValue.toString(),
                Status.QUEUED.databaseValue.toString(),
            ),
            null,
            null,
            "$COLUMN_SEQUENCE ASC",
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) readStoredMessage(cursor) else null }

    fun oldestRetryEligibleForPeer(
        peerFingerprint: String,
        nowMs: Long = System.currentTimeMillis(),
    ): StoredMessage? = oldestQueuedForPeer(peerFingerprint)?.takeIf { oldest ->
        RelayRetryClockPolicy.isEligible(
            nextAttemptAtMs = oldest.nextAttemptAtMs,
            nowMs = nowMs,
            maximumLegitimateDelayMs = RETRY_MAX_MS,
        )
    }

    fun oldestQueuedForPeer(peerFingerprint: String): StoredMessage? = readableDatabase.query(
        TABLE_MESSAGES,
        MESSAGE_PROJECTION,
        "$COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ? AND $COLUMN_PEER_FINGERPRINT = ?",
        arrayOf(
            Direction.OUTGOING.databaseValue.toString(),
            Status.QUEUED.databaseValue.toString(),
            peerFingerprint,
        ),
        null,
        null,
        "$COLUMN_SEQUENCE ASC",
        "1",
    ).use { cursor -> if (cursor.moveToFirst()) readStoredMessage(cursor) else null }

    /** Starts a bounded retry lease so an app crash cannot create a tight resend loop. */
    fun beginAttempt(id: ByteArray): Int {
        val existing = findById(writableDatabase, id)
            ?: throw IllegalStateException("Outgoing message was not found for retry.")
        check(existing.direction == Direction.OUTGOING && existing.status == Status.QUEUED) {
            "Only queued outgoing messages can be attempted."
        }
        val now = System.currentTimeMillis()
        val attempts = existing.attemptCount + 1
        val values = ContentValues().apply {
            put(COLUMN_ATTEMPT_COUNT, attempts)
            put(COLUMN_LAST_ATTEMPT_AT, now)
            put(COLUMN_NEXT_ATTEMPT_AT, now + ATTEMPT_LEASE_MS)
            putNull(COLUMN_LAST_ERROR_CODE)
        }
        check(
            writableDatabase.update(
                TABLE_MESSAGES,
                values,
                "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ?",
                arrayOf(
                    sqlHex(id),
                    Direction.OUTGOING.databaseValue.toString(),
                    Status.QUEUED.databaseValue.toString(),
                ),
            ) == 1,
        ) { "Queued message changed before its retry began." }
        return attempts
    }

    /** Returns the next wall-clock retry time, or null when this is no longer queued. */
    fun markRetryableFailure(id: ByteArray, code: String): Long? {
        val existing = findById(writableDatabase, id)
            ?.takeIf { it.direction == Direction.OUTGOING && it.status == Status.QUEUED }
            ?: return null
        val exponent = (existing.attemptCount - 1).coerceIn(0, MAX_BACKOFF_EXPONENT)
        val delayMs = (RETRY_BASE_MS shl exponent).coerceAtMost(RETRY_MAX_MS)
        val retryAt = System.currentTimeMillis() + delayMs
        val values = ContentValues().apply {
            put(COLUMN_NEXT_ATTEMPT_AT, retryAt)
            put(COLUMN_LAST_ERROR_CODE, code.take(MAX_ERROR_CODE_CHARS))
        }
        writableDatabase.update(
            TABLE_MESSAGES,
            values,
            "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ?",
            arrayOf(
                sqlHex(id),
                Direction.OUTGOING.databaseValue.toString(),
                Status.QUEUED.databaseValue.toString(),
            ),
        )
        return retryAt
    }

    fun listRecent(limit: Int = 200): List<StoredMessage> {
        val boundedLimit = limit.coerceIn(1, 500)
        val messages = mutableListOf<StoredMessage>()
        readableDatabase.query(
            TABLE_MESSAGES,
            arrayOf(
                *MESSAGE_PROJECTION,
            ),
            null,
            null,
            null,
            null,
            "$COLUMN_SEQUENCE DESC",
            boundedLimit.toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                messages += readStoredMessage(cursor)
            }
        }
        messages.reverse()
        return messages
    }

    /**
     * Returns one stable newest-first keyset page for a single conversation.
     *
     * The cursor deliberately uses the persisted wall-clock value only as an ordering key,
     * never for retry or expiry correctness. The random immutable message ID breaks timestamp
     * ties so inserting a newer message cannot shift or duplicate an older page.
     */
    fun listRecentPage(
        peerFingerprint: String,
        beforeCreatedAtMs: Long? = null,
        beforeMessageIdHex: String? = null,
        limit: Int = DEFAULT_HISTORY_PAGE_SIZE,
    ): List<StoredMessage> {
        require(peerFingerprint.isNotBlank()) { "Peer fingerprint is required." }
        require((beforeCreatedAtMs == null) == (beforeMessageIdHex == null)) {
            "Both history cursor values are required together."
        }
        val normalizedBeforeId = beforeMessageIdHex?.uppercase()?.also { id ->
            require(id.length == MESSAGE_ID_BYTES * 2 && id.all { it.isHexDigit() }) {
                "History cursor message ID is invalid."
            }
        }
        val boundedLimit = limit.coerceIn(1, MAX_HISTORY_PAGE_ITEMS)
        val selection = buildString {
            append("$COLUMN_PEER_FINGERPRINT = ?")
            if (beforeCreatedAtMs != null) {
                append(
                    " AND ($COLUMN_CREATED_AT < ? OR " +
                        "($COLUMN_CREATED_AT = ? AND hex($COLUMN_MESSAGE_ID) < ?))",
                )
            }
        }
        val selectionArgs = buildList {
            add(peerFingerprint)
            if (beforeCreatedAtMs != null) {
                add(beforeCreatedAtMs.toString())
                add(beforeCreatedAtMs.toString())
                add(requireNotNull(normalizedBeforeId))
            }
        }.toTypedArray()
        val messages = mutableListOf<StoredMessage>()
        readableDatabase.query(
            TABLE_MESSAGES,
            MESSAGE_PROJECTION,
            selection,
            selectionArgs,
            null,
            null,
            "$COLUMN_CREATED_AT DESC, hex($COLUMN_MESSAGE_ID) DESC",
            boundedLimit.toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) messages += readStoredMessage(cursor)
        }
        return messages
    }

    /** Decrypts only the latest preview for each durable direct conversation. */
    fun conversationSummaries(): List<ConversationSummary> {
        val fingerprints = mutableListOf<String>()
        readableDatabase.query(
            true,
            TABLE_MESSAGES,
            arrayOf(COLUMN_PEER_FINGERPRINT),
            null,
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) fingerprints += cursor.getString(0)
        }
        return fingerprints.mapNotNull { fingerprint ->
            val latest = listRecentPage(fingerprint, limit = 1).singleOrNull()
                ?: return@mapNotNull null
            val count = readableDatabase.rawQuery(
                "SELECT COUNT(*) FROM $TABLE_MESSAGES WHERE $COLUMN_PEER_FINGERPRINT = ?",
                arrayOf(fingerprint),
            ).use { cursor ->
                check(cursor.moveToFirst()) { "Conversation count query returned no row." }
                cursor.getInt(0)
            }
            val unreadCount = unreadCount(fingerprint)
            ConversationSummary(
                lastMessage = latest,
                messageCount = count,
                unreadCount = unreadCount,
            )
        }
    }

    fun markConversationRead(peerFingerprint: String): Int {
        require(peerFingerprint.isNotBlank()) { "Peer fingerprint is required." }
        return writableDatabase.update(
            TABLE_MESSAGES,
            ContentValues().apply { put(COLUMN_IS_READ, 1) },
            "$COLUMN_PEER_FINGERPRINT = ? AND $COLUMN_DIRECTION = ? AND $COLUMN_IS_READ = 0",
            arrayOf(peerFingerprint, Direction.INCOMING.databaseValue.toString()),
        )
    }

    fun unreadCount(peerFingerprint: String): Int = readableDatabase.rawQuery(
        "SELECT COUNT(*) FROM $TABLE_MESSAGES WHERE $COLUMN_PEER_FINGERPRINT = ? " +
            "AND $COLUMN_DIRECTION = ? AND $COLUMN_IS_READ = 0",
        arrayOf(peerFingerprint, Direction.INCOMING.databaseValue.toString()),
    ).use { cursor ->
        check(cursor.moveToFirst()) { "Unread count query returned no row." }
        cursor.getInt(0)
    }

    private fun insert(
        message: RelayMessageCodec.TextMessage,
        peerFingerprint: String,
        direction: Direction,
        status: Status,
        allowExactDuplicate: Boolean = false,
    ): Boolean {
        val id = message.id
        require(id.size == MESSAGE_ID_BYTES) { "Message ID must be 16 bytes." }
        val database = writableDatabase
        database.beginTransaction()
        try {
            findById(database, id)?.let { existing ->
                if (
                    allowExactDuplicate && existing.peerFingerprint == peerFingerprint &&
                    existing.direction == direction && existing.text == message.text &&
                    existing.replyToMessageId.contentEqualsNullable(message.replyToMessageId) &&
                    existing.replyPreview == message.replyPreview
                ) {
                    database.setTransactionSuccessful()
                    return false
                }
                throw IllegalStateException("Message ID collision or replay mismatch.")
            }
            val encrypted = encrypt(id, peerFingerprint, direction, message.encoded, LOCAL_CONTENT_VERSION)
            val values = ContentValues().apply {
                put(COLUMN_MESSAGE_ID, id)
                put(COLUMN_PEER_FINGERPRINT, peerFingerprint)
                put(COLUMN_DIRECTION, direction.databaseValue)
                put(COLUMN_NONCE, encrypted.nonce)
                put(COLUMN_CIPHERTEXT, encrypted.ciphertext)
                put(COLUMN_CONTENT_VERSION, LOCAL_CONTENT_VERSION)
                put(COLUMN_STATUS, status.databaseValue)
                put(COLUMN_CREATED_AT, System.currentTimeMillis())
                put(COLUMN_IS_READ, if (direction == Direction.INCOMING) 0 else 1)
            }
            check(database.insertOrThrow(TABLE_MESSAGES, null, values) > 0L) {
                "Message was not stored."
            }
            database.setTransactionSuccessful()
            return true
        } finally {
            database.endTransaction()
        }
    }

    private fun findById(database: SQLiteDatabase, id: ByteArray): StoredMessage? =
        findByHexId(database, sqlHex(id))

    private fun findByHexId(database: SQLiteDatabase, idHex: String): StoredMessage? =
        database.query(
            TABLE_MESSAGES,
            MESSAGE_PROJECTION,
            "hex($COLUMN_MESSAGE_ID) = ?",
            arrayOf(idHex),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            if (!cursor.moveToFirst()) return@use null
            readStoredMessage(cursor)
        }

    private fun readStoredMessage(cursor: Cursor): StoredMessage {
        val id = cursor.getBlob(0)
        val fingerprint = cursor.getString(1)
        val direction = Direction.fromDatabase(cursor.getInt(2))
        val contentVersion = cursor.getInt(12)
        val message = decryptMessage(
            id,
            fingerprint,
            direction,
            cursor.getBlob(3),
            cursor.getBlob(4),
            contentVersion,
        )
        return StoredMessage(
            id = id,
            peerFingerprint = fingerprint,
            direction = direction,
            text = message.text,
            replyToMessageId = message.replyToMessageId,
            replyPreview = message.replyPreview,
            status = Status.fromDatabase(cursor.getInt(5)),
            createdAtMs = cursor.getLong(6),
            attemptCount = cursor.getInt(7),
            lastAttemptAtMs = cursor.nullableLong(8),
            nextAttemptAtMs = cursor.nullableLong(9),
            lastErrorCode = if (cursor.isNull(10)) null else cursor.getString(10),
            isRead = cursor.getInt(11) == 1,
        )
    }

    private fun Cursor.nullableLong(index: Int): Long? = if (isNull(index)) null else getLong(index)

    private fun encrypt(
        id: ByteArray,
        fingerprint: String,
        direction: Direction,
        plaintext: ByteArray,
        contentVersion: Int,
    ): EncryptedValue {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, storageKey())
        cipher.updateAAD(aad(id, fingerprint, direction, contentVersion))
        return EncryptedValue(
            nonce = cipher.iv,
            ciphertext = cipher.doFinal(plaintext),
        )
    }

    private fun decryptMessage(
        id: ByteArray,
        fingerprint: String,
        direction: Direction,
        nonce: ByteArray,
        ciphertext: ByteArray,
        contentVersion: Int,
    ): RelayMessageCodec.TextMessage {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad(id, fingerprint, direction, contentVersion))
        val plaintext = cipher.doFinal(ciphertext)
        return when (contentVersion) {
            1 -> RelayMessageCodec.restore(id, String(plaintext, StandardCharsets.UTF_8))
            LOCAL_CONTENT_VERSION -> RelayMessageCodec.decodeTrusted(plaintext).also { message ->
                check(message.id.contentEquals(id)) { "Stored message ID is inconsistent." }
            }
            else -> error("Unsupported local message content version.")
        }
    }

    private fun storageKey(): SecretKey {
        storageKeyOverride?.let { return it() }
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private fun aad(
        id: ByteArray,
        fingerprint: String,
        direction: Direction,
        contentVersion: Int,
    ): ByteArray = DOMAIN + id + fingerprint.toByteArray(StandardCharsets.UTF_8) +
        direction.databaseValue.toByte() +
        if (contentVersion == 1) byteArrayOf() else byteArrayOf(contentVersion.toByte())

    private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean = when {
        this == null || other == null -> this == null && other == null
        else -> contentEquals(other)
    }

    private fun sqlHex(bytes: ByteArray): String = bytes.joinToString(separator = "") { byte ->
        "%02X".format(byte.toInt() and 0xFF)
    }

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private data class EncryptedValue(val nonce: ByteArray, val ciphertext: ByteArray)

    private companion object {
        const val DATABASE_NAME = "relay_messages.db"
        const val DATABASE_VERSION = 4
        const val LOCAL_CONTENT_VERSION = 2
        const val TABLE_MESSAGES = "messages"
        const val COLUMN_SEQUENCE = "sequence"
        const val COLUMN_MESSAGE_ID = "message_id"
        const val COLUMN_PEER_FINGERPRINT = "peer_fingerprint"
        const val COLUMN_DIRECTION = "direction"
        const val COLUMN_NONCE = "nonce"
        const val COLUMN_CIPHERTEXT = "ciphertext"
        const val COLUMN_STATUS = "status"
        const val COLUMN_CREATED_AT = "created_at_ms"
        const val COLUMN_ATTEMPT_COUNT = "attempt_count"
        const val COLUMN_LAST_ATTEMPT_AT = "last_attempt_at_ms"
        const val COLUMN_NEXT_ATTEMPT_AT = "next_attempt_at_ms"
        const val COLUMN_LAST_ERROR_CODE = "last_error_code"
        const val COLUMN_IS_READ = "is_read"
        const val COLUMN_CONTENT_VERSION = "content_version"
        const val MESSAGE_ID_BYTES = 16
        const val ATTEMPT_LEASE_MS = 15_000L
        const val RETRY_BASE_MS = 2_000L
        const val RETRY_MAX_MS = 60_000L
        const val MAX_BACKOFF_EXPONENT = 5
        const val MAX_ERROR_CODE_CHARS = 80
        const val DEFAULT_HISTORY_PAGE_SIZE = 40
        const val MAX_HISTORY_PAGE_ITEMS = 101
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "project_relay_message_store_aes_v1"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        val DOMAIN = "ProjectRelay/message-store/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val MESSAGE_PROJECTION = arrayOf(
            COLUMN_MESSAGE_ID,
            COLUMN_PEER_FINGERPRINT,
            COLUMN_DIRECTION,
            COLUMN_NONCE,
            COLUMN_CIPHERTEXT,
            COLUMN_STATUS,
            COLUMN_CREATED_AT,
            COLUMN_ATTEMPT_COUNT,
            COLUMN_LAST_ATTEMPT_AT,
            COLUMN_NEXT_ATTEMPT_AT,
            COLUMN_LAST_ERROR_CODE,
            COLUMN_IS_READ,
            COLUMN_CONTENT_VERSION,
        )

        fun createUnreadIndex(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE INDEX IF NOT EXISTS messages_unread " +
                    "ON messages(peer_fingerprint, direction, is_read)",
            )
        }
    }
}
