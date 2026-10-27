package app.projectrelay.relay_mobile

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * One crash-consistent store for contact secrets, ratchets, local text, and opaque courier data.
 * E2E account/session pickles are already authenticated by Rust; Android Keystore additionally
 * protects the pickle key, contact route secrets, and plaintext history at rest.
 */
internal class RelayMeshStore(
    context: Context,
    private val storageKeyOverride: (() -> SecretKey)? = null,
    private val elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime,
) :
    SQLiteOpenHelper(context.applicationContext, DATABASE_NAME, null, DATABASE_VERSION) {
    private val random = SecureRandom()
    private val profileStore = RelayProfileStore(context)

    init {
        setWriteAheadLoggingEnabled(true)
    }

    data class Contact(
        val deviceFingerprint: String,
        val displayName: String,
        val relayId: String?,
        val localBundle: ByteArray,
        val remoteBundle: ByteArray?,
        val verified: Boolean,
        val sessionIsInitiator: Boolean?,
        val sessionPickle: ByteArray?,
        val nextOutgoingSequence: Long,
        val highestIncomingSequence: Long,
    ) {
        val isComplete: Boolean
            get() = relayId != null && remoteBundle != null

        fun toMap(): Map<String, Any> = buildMap {
            put("fingerprint", deviceFingerprint)
            put("displayName", displayName)
            relayId?.let { put("relayId", it) }
            put("verified", verified)
            put("ready", isComplete)
        }
    }

    data class QueuedMessage(
        val messageId: ByteArray,
        val peerFingerprint: String,
        val envelope: ByteArray?,
        val createdAtMs: Long,
        val message: RelayMessageCodec.TextMessage,
    )

    data class ConversationSummary(
        val lastMessage: Map<String, Any>,
        val messageCount: Int,
        val unreadCount: Int,
    )

    data class ForwardOffer(
        val messageId: ByteArray,
        val wireEnvelope: ByteArray,
        val retainedWireEnvelope: ByteArray,
        val previousCopyBudget: Int,
        val retainedCopies: Int,
        val transferredCopies: Int,
    )

    data class PendingRecipientAttachment(
        val peerFingerprint: String,
        val manifest: RelayRecipientAttachmentManifest,
        val ratchetSequence: Long,
        val lifetimeMs: Long,
        val ageMs: Long,
    )

    data class SenderAttachmentOffer(
        val objectId: ByteArray,
        val recipientFingerprint: String,
        val encodedManifest: ByteArray,
        val encodedPlan: ByteArray,
        val ratchetSequence: Long,
        val lifetimeMs: Long,
        val ageMs: Long,
    )

    data class SenderAttachmentCustody(
        val objectId: ByteArray,
        val courierFingerprint: String,
        val custody: RelayCourierAttachmentCustody,
        val inserted: Boolean,
    )

    data class RecipientAttachmentReceiptQueued(
        val objectId: ByteArray,
        val planSha256: ByteArray,
        val envelopeId: ByteArray,
    )

    data class PendingSenderAttachmentReceipt(
        val objectId: ByteArray,
        val planSha256: ByteArray,
        val recipientFingerprint: String,
        val receiptEnvelopeId: ByteArray,
        val localApplied: Boolean,
    )

    data class RouteProbeOffer(
        val messageId: ByteArray,
        val probeEnvelope: ByteArray,
        val fullEnvelope: ByteArray,
    )

    sealed interface IngestResult {
        val messageId: ByteArray

        data class CourierStored(
            override val messageId: ByteArray,
            val inserted: Boolean,
        ) : IngestResult

        data class Delivered(
            override val messageId: ByteArray,
            val peerFingerprint: String,
            val text: String,
            val replyToMessageId: ByteArray?,
            val replyPreview: String?,
            val inserted: Boolean,
        ) : IngestResult

        data class ReceiptApplied(
            override val messageId: ByteArray,
            val deliveredMessageId: ByteArray,
            val peerFingerprint: String,
            val changed: Boolean,
        ) : IngestResult

        data class AttachmentManifestStored(
            override val messageId: ByteArray,
            val peerFingerprint: String,
            val courierPlanSha256: ByteArray,
            val inserted: Boolean,
        ) : IngestResult

        data class AttachmentReceiptApplied(
            override val messageId: ByteArray,
            val objectId: ByteArray,
            val courierPlanSha256: ByteArray,
            val peerFingerprint: String,
            val inserted: Boolean,
        ) : IngestResult

        data class ProbeDeclined(
            override val messageId: ByteArray,
        ) : IngestResult

        data class StoreFull(
            override val messageId: ByteArray,
        ) : IngestResult

        data class Expired(
            override val messageId: ByteArray,
        ) : IngestResult
    }

    override fun onConfigure(database: SQLiteDatabase) {
        super.onConfigure(database)
        database.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE mesh_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                key_nonce BLOB NOT NULL CHECK(length(key_nonce) = 12),
                key_ciphertext BLOB NOT NULL,
                account_pickle BLOB NOT NULL
            )
            """.trimIndent(),
        )
        database.execSQL(
            """
            CREATE TABLE contacts (
                device_fingerprint TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                relay_id TEXT UNIQUE,
                local_nonce BLOB NOT NULL CHECK(length(local_nonce) = 12),
                local_ciphertext BLOB NOT NULL,
                remote_nonce BLOB CHECK(remote_nonce IS NULL OR length(remote_nonce) = 12),
                remote_ciphertext BLOB,
                verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0, 1)),
                session_role INTEGER CHECK(session_role IS NULL OR session_role IN (0, 1)),
                session_pickle BLOB,
                next_outgoing_sequence INTEGER NOT NULL DEFAULT 1 CHECK(next_outgoing_sequence > 0),
                highest_incoming_sequence INTEGER NOT NULL DEFAULT 0 CHECK(highest_incoming_sequence >= 0),
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                CHECK((remote_nonce IS NULL) = (remote_ciphertext IS NULL)),
                CHECK((session_role IS NULL) = (session_pickle IS NULL))
            )
            """.trimIndent(),
        )
        database.execSQL(
            """
            CREATE TABLE mesh_messages (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL UNIQUE CHECK(length(message_id) = 16),
                peer_fingerprint TEXT NOT NULL REFERENCES contacts(device_fingerprint),
                direction INTEGER NOT NULL CHECK(direction IN (0, 1)),
                text_nonce BLOB NOT NULL CHECK(length(text_nonce) = 12),
                text_ciphertext BLOB NOT NULL,
                status INTEGER NOT NULL CHECK(status IN (0, 1, 2)),
                ratchet_sequence INTEGER NOT NULL CHECK(ratchet_sequence > 0),
                receipt_generated INTEGER NOT NULL DEFAULT 0 CHECK(receipt_generated IN (0, 1)),
                is_read INTEGER NOT NULL DEFAULT 1 CHECK(is_read IN (0, 1)),
                created_at_ms INTEGER NOT NULL,
                content_version INTEGER NOT NULL DEFAULT 1 CHECK(content_version IN (1, 2))
            )
            """.trimIndent(),
        )
        database.execSQL(
            "CREATE INDEX mesh_messages_contact_sequence " +
                "ON mesh_messages(peer_fingerprint, sequence)",
        )
        createUnreadIndex(database)
        database.execSQL(
            """
            CREATE TABLE envelopes (
                message_id BLOB PRIMARY KEY CHECK(length(message_id) = 16),
                wire_envelope BLOB NOT NULL,
                origin_fingerprint TEXT REFERENCES contacts(device_fingerprint),
                age_ms INTEGER NOT NULL DEFAULT 0 CHECK(age_ms >= 0),
                age_anchor_elapsed_ms INTEGER NOT NULL DEFAULT 0 CHECK(age_anchor_elapsed_ms >= 0),
                created_at_ms INTEGER NOT NULL
            )
            """.trimIndent(),
        )
        database.execSQL(
            """
            CREATE TABLE forwarded_envelopes (
                message_id BLOB NOT NULL REFERENCES envelopes(message_id) ON DELETE CASCADE,
                peer_fingerprint TEXT NOT NULL,
                forwarded_at_ms INTEGER NOT NULL,
                PRIMARY KEY(message_id, peer_fingerprint)
            )
            """.trimIndent(),
        )
        createReceiptTables(database)
        createPendingMeshTextTable(database)
        createRecipientAttachmentTables(database)
        createSenderAttachmentTables(database)
    }

    override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        var version = oldVersion
        if (version == 1) {
            createReceiptTables(database)
            version = 2
        }
        if (version == 2) {
            createRecipientAttachmentTables(database)
            version = 3
        }
        if (version == 3) {
            createSenderAttachmentTables(database)
            version = 4
        }
        if (version == 4) {
            createSenderAttachmentReceiptTable(database)
            version = 5
        }
        if (version == 5) {
            if (databaseTableExists(database, TABLE_MESH_MESSAGES)) {
                database.execSQL(
                    "ALTER TABLE mesh_messages ADD COLUMN receipt_generated INTEGER " +
                        "NOT NULL DEFAULT 0 CHECK(receipt_generated IN (0, 1))",
                )
                database.execSQL(
                    "UPDATE mesh_messages SET receipt_generated = 1 " +
                        "WHERE direction = 0 AND message_id IN " +
                        "(SELECT delivered_message_id FROM delivery_receipts)",
                )
            }
            if (databaseTableExists(database, TABLE_ENVELOPES)) {
                database.execSQL(
                    "ALTER TABLE envelopes ADD COLUMN age_ms INTEGER " +
                        "NOT NULL DEFAULT 0 CHECK(age_ms >= 0)",
                )
                database.execSQL(
                    "ALTER TABLE envelopes ADD COLUMN age_anchor_elapsed_ms INTEGER " +
                        "NOT NULL DEFAULT 0 CHECK(age_anchor_elapsed_ms >= 0)",
                )
                database.update(
                    TABLE_ENVELOPES,
                    ContentValues().apply {
                        put(COLUMN_AGE_ANCHOR_ELAPSED_MS, elapsedRealtimeMs().coerceAtLeast(0L))
                    },
                    null,
                    null,
                )
            }
            createPendingMeshTextTable(database)
            version = 6
        }
        if (version == 6) {
            if (
                databaseTableExists(database, TABLE_MESH_MESSAGES) &&
                !databaseColumnExists(database, TABLE_MESH_MESSAGES, COLUMN_IS_READ)
            ) {
                database.execSQL(
                    "ALTER TABLE mesh_messages ADD COLUMN is_read INTEGER " +
                        "NOT NULL DEFAULT 1 CHECK(is_read IN (0, 1))",
                )
                createUnreadIndex(database)
            }
            version = 7
        }
        if (version == 7) {
            if (
                databaseTableExists(database, TABLE_MESH_MESSAGES) &&
                !databaseColumnExists(database, TABLE_MESH_MESSAGES, COLUMN_CONTENT_VERSION)
            ) {
                database.execSQL(
                    "ALTER TABLE mesh_messages ADD COLUMN content_version INTEGER " +
                        "NOT NULL DEFAULT 1 CHECK(content_version IN (1, 2))",
                )
            }
            if (
                databaseTableExists(database, TABLE_PENDING_MESH_TEXTS) &&
                !databaseColumnExists(database, TABLE_PENDING_MESH_TEXTS, COLUMN_CONTENT_VERSION)
            ) {
                database.execSQL(
                    "ALTER TABLE pending_mesh_texts ADD COLUMN content_version INTEGER " +
                        "NOT NULL DEFAULT 1 CHECK(content_version IN (1, 2))",
                )
            }
            version = 8
        }
        check(version == newVersion) {
            "Unsupported Relay mesh database migration $oldVersion to $newVersion"
        }
    }

    private fun databaseTableExists(database: SQLiteDatabase, table: String): Boolean =
        database.rawQuery(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            arrayOf(table),
        ).use(Cursor::moveToFirst)

    private fun databaseColumnExists(
        database: SQLiteDatabase,
        table: String,
        column: String,
    ): Boolean = database.rawQuery("PRAGMA table_info($table)", null).use { cursor ->
        val nameIndex = cursor.getColumnIndexOrThrow("name")
        while (cursor.moveToNext()) {
            if (cursor.getString(nameIndex) == column) return@use true
        }
        false
    }

    private fun createPendingMeshTextTable(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS pending_mesh_texts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL UNIQUE CHECK(length(message_id) = 16),
                peer_fingerprint TEXT NOT NULL REFERENCES contacts(device_fingerprint),
                text_nonce BLOB NOT NULL CHECK(length(text_nonce) = 12),
                text_ciphertext BLOB NOT NULL,
                initial_copy_budget INTEGER CHECK(
                    initial_copy_budget IS NULL OR initial_copy_budget BETWEEN 1 AND 64
                ),
                created_at_ms INTEGER NOT NULL,
                content_version INTEGER NOT NULL DEFAULT 1 CHECK(content_version IN (1, 2))
            )
            """.trimIndent(),
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS pending_mesh_texts_contact_sequence " +
                "ON pending_mesh_texts(peer_fingerprint, sequence)",
        )
    }

    private fun createReceiptTables(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS consumed_envelopes (
                message_id BLOB PRIMARY KEY CHECK(length(message_id) = 16),
                consumed_at_ms INTEGER NOT NULL
            )
            """.trimIndent(),
        )
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS delivery_receipts (
                delivered_message_id BLOB PRIMARY KEY CHECK(length(delivered_message_id) = 16),
                receipt_envelope_id BLOB NOT NULL UNIQUE CHECK(length(receipt_envelope_id) = 16),
                generated_at_ms INTEGER NOT NULL
            )
            """.trimIndent(),
        )
    }

    private fun createRecipientAttachmentTables(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS recipient_attachment_manifests (
                object_id BLOB PRIMARY KEY CHECK(length(object_id) = 16),
                peer_fingerprint TEXT NOT NULL REFERENCES contacts(device_fingerprint),
                courier_plan_sha256 BLOB NOT NULL CHECK(length(courier_plan_sha256) = 32),
                manifest_nonce BLOB NOT NULL CHECK(length(manifest_nonce) = 12),
                manifest_ciphertext BLOB NOT NULL,
                ratchet_sequence INTEGER NOT NULL CHECK(ratchet_sequence > 0),
                lifetime_ms INTEGER NOT NULL CHECK(lifetime_ms > 0),
                age_ms INTEGER NOT NULL CHECK(age_ms >= 0 AND age_ms <= lifetime_ms),
                age_anchor_elapsed_ms INTEGER NOT NULL CHECK(age_anchor_elapsed_ms >= 0),
                created_at_ms INTEGER NOT NULL
            )
            """.trimIndent(),
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS recipient_attachment_age " +
                "ON recipient_attachment_manifests(age_anchor_elapsed_ms)",
        )
    }

    private fun createSenderAttachmentTables(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS sender_attachment_offers (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id BLOB NOT NULL UNIQUE CHECK(length(object_id) = 16),
                recipient_fingerprint TEXT NOT NULL REFERENCES contacts(device_fingerprint),
                wire_manifest BLOB NOT NULL,
                wire_plan BLOB NOT NULL,
                cancel_nonce BLOB NOT NULL CHECK(length(cancel_nonce) = 12),
                cancel_ciphertext BLOB NOT NULL,
                radio_eligible INTEGER NOT NULL DEFAULT 1 CHECK(radio_eligible IN (0, 1)),
                ratchet_sequence INTEGER NOT NULL CHECK(ratchet_sequence > 0),
                lifetime_ms INTEGER NOT NULL CHECK(lifetime_ms > 0),
                age_ms INTEGER NOT NULL CHECK(age_ms >= 0 AND age_ms <= lifetime_ms),
                age_anchor_elapsed_ms INTEGER NOT NULL CHECK(age_anchor_elapsed_ms >= 0),
                created_at_ms INTEGER NOT NULL
            )
            """.trimIndent(),
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS sender_attachment_offer_age " +
                "ON sender_attachment_offers(age_anchor_elapsed_ms)",
        )
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS sender_attachment_custody (
                object_id BLOB NOT NULL REFERENCES sender_attachment_offers(object_id)
                    ON DELETE CASCADE,
                courier_fingerprint TEXT NOT NULL,
                custody_nonce BLOB NOT NULL CHECK(length(custody_nonce) = 12),
                custody_ciphertext BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY(object_id, courier_fingerprint)
            )
            """.trimIndent(),
        )
        createSenderAttachmentReceiptTable(database)
    }

    private fun createSenderAttachmentReceiptTable(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS sender_attachment_receipts (
                object_id BLOB PRIMARY KEY CHECK(length(object_id) = 16),
                courier_plan_sha256 BLOB NOT NULL CHECK(length(courier_plan_sha256) = 32),
                recipient_fingerprint TEXT NOT NULL,
                receipt_envelope_id BLOB NOT NULL UNIQUE CHECK(length(receipt_envelope_id) = 16),
                local_applied INTEGER NOT NULL DEFAULT 0 CHECK(local_applied IN (0, 1)),
                created_at_ms INTEGER NOT NULL
            )
            """.trimIndent(),
        )
    }

    fun displayName(): String = profileStore.displayName()

    fun profileSetupComplete(): Boolean = profileStore.setupComplete()

    fun updateDisplayName(raw: String): String = profileStore.updateDisplayName(raw)

    fun localContactCard(deviceFingerprint: String): RelayContactCard {
        requireFingerprint(deviceFingerprint)
        val database = writableDatabase
        database.beginTransaction()
        try {
            val existing = findContact(database, deviceFingerprint)
            val bundle = if (existing != null) {
                existing.localBundle
            } else {
                val state = ensureState(database)
                try {
                    val issued = RelayNative.issueE2eContactBundle(
                        state.accountPickle,
                        state.protectionKey,
                    )
                    updateAccountPickle(database, issued.accountPickle)
                    val encrypted = encryptContactBundle(
                        deviceFingerprint,
                        LOCAL_BUNDLE_LABEL,
                        issued.contactBundle,
                    )
                    val now = System.currentTimeMillis()
                    val values = ContentValues().apply {
                        put(COLUMN_DEVICE_FINGERPRINT, deviceFingerprint)
                        put(COLUMN_DISPLAY_NAME, UNKNOWN_DISPLAY_NAME)
                        put(COLUMN_LOCAL_NONCE, encrypted.nonce)
                        put(COLUMN_LOCAL_CIPHERTEXT, encrypted.ciphertext)
                        put(COLUMN_CREATED_AT, now)
                        put(COLUMN_UPDATED_AT, now)
                    }
                    check(database.insertOrThrow(TABLE_CONTACTS, null, values) > 0L) {
                        "Local Relay contact material was not stored."
                    }
                    issued.contactBundle
                } finally {
                    state.protectionKey.fill(0)
                }
            }
            database.setTransactionSuccessful()
            return RelayContactCard(profileStore.displayName(), bundle)
        } finally {
            database.endTransaction()
        }
    }

    fun acceptRemoteContactCard(
        deviceFingerprint: String,
        card: RelayContactCard,
    ): Contact {
        requireFingerprint(deviceFingerprint)
        val relayId = RelayNative.e2eRelayId(card.bundle).toHex()
        val database = writableDatabase
        database.beginTransaction()
        try {
            val existing = findContact(database, deviceFingerprint)
                ?: throw IllegalStateException("Create local contact material before accepting a peer card.")
            database.query(
                TABLE_CONTACTS,
                arrayOf(COLUMN_DEVICE_FINGERPRINT),
                "$COLUMN_RELAY_ID = ? AND $COLUMN_DEVICE_FINGERPRINT != ?",
                arrayOf(relayId, deviceFingerprint),
                null,
                null,
                null,
                "1",
            ).use { cursor ->
                check(!cursor.moveToFirst()) {
                    "This Relay identity is already bound to another verified device."
                }
            }
            if (existing.remoteBundle != null) {
                check(existing.remoteBundle.contentEquals(card.bundle)) {
                    "The contact attempted to replace its established E2E identity."
                }
            }
            val encrypted = encryptContactBundle(
                deviceFingerprint,
                REMOTE_BUNDLE_LABEL,
                card.bundle,
            )
            val values = ContentValues().apply {
                put(COLUMN_DISPLAY_NAME, card.displayName)
                put(COLUMN_RELAY_ID, relayId)
                put(COLUMN_REMOTE_NONCE, encrypted.nonce)
                put(COLUMN_REMOTE_CIPHERTEXT, encrypted.ciphertext)
                put(COLUMN_UPDATED_AT, System.currentTimeMillis())
            }
            check(
                database.update(
                    TABLE_CONTACTS,
                    values,
                    "$COLUMN_DEVICE_FINGERPRINT = ?",
                    arrayOf(deviceFingerprint),
                ) == 1,
            ) { "Relay contact was not updated." }
            database.setTransactionSuccessful()
            return requireNotNull(findContact(database, deviceFingerprint))
        } finally {
            database.endTransaction()
        }
    }

    fun markVerified(deviceFingerprint: String) {
        requireFingerprint(deviceFingerprint)
        // Verification belongs to the authenticated device fingerprint, so it
        // must survive a contact-card transfer that is still finishing. Ensure
        // the local half of the contact exists, then persist the user's decision;
        // acceptRemoteContactCard() fills in the remote half without clearing it.
        localContactCard(deviceFingerprint)
        val values = ContentValues().apply {
            put(COLUMN_VERIFIED, 1)
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            writableDatabase.update(
                TABLE_CONTACTS,
                values,
                "$COLUMN_DEVICE_FINGERPRINT = ?",
                arrayOf(deviceFingerprint),
            ) == 1,
        ) { "Relay contact verification could not be stored." }
    }

    fun contact(deviceFingerprint: String): Contact? =
        findContact(readableDatabase, deviceFingerprint)

    fun contacts(): List<Map<String, Any>> {
        val result = mutableListOf<Map<String, Any>>()
        readableDatabase.query(
            TABLE_CONTACTS,
            CONTACT_PROJECTION,
            "$COLUMN_REMOTE_CIPHERTEXT IS NOT NULL",
            null,
            null,
            null,
            "$COLUMN_DISPLAY_NAME COLLATE NOCASE, $COLUMN_DEVICE_FINGERPRINT",
        ).use { cursor ->
            while (cursor.moveToNext()) result += readContact(cursor).toMap()
        }
        return result
    }

    fun hasVerifiedContacts(): Boolean = readableDatabase.query(
        TABLE_CONTACTS,
        arrayOf(COLUMN_DEVICE_FINGERPRINT),
        "$COLUMN_VERIFIED = 1 AND $COLUMN_REMOTE_CIPHERTEXT IS NOT NULL",
        null,
        null,
        null,
        null,
        "1",
    ).use(Cursor::moveToFirst)

    fun queueOutgoingText(
        deviceFingerprint: String,
        text: String,
        replyToMessageIdHex: String? = null,
        replyPreview: String? = null,
        initialCopyBudget: Int? = null,
    ): QueuedMessage {
        requireFingerprint(deviceFingerprint)
        require(initialCopyBudget == null || initialCopyBudget in 1..MAX_DIAGNOSTIC_COPY_BUDGET) {
            "Invalid initial mesh copy budget."
        }
        val cleanText = text.trim()
        require(cleanText.isNotEmpty()) { "Message is empty." }
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainEnvelopeStore(database)
            maintainRecipientAttachmentManifests(database)
            findContact(database, deviceFingerprint)
                ?.takeIf { it.isComplete && it.verified }
                ?: throw IllegalStateException("The selected Relay contact is not ready and verified.")
            val pendingForContact = countPendingTexts(database, deviceFingerprint)
            check(pendingForContact < MAX_PENDING_TEXTS_PER_CONTACT) {
                "This conversation's durable mesh outbox is full."
            }
            check(countPendingTexts(database, null) < MAX_PENDING_TEXTS_TOTAL) {
                "Relay's durable mesh outbox is full."
            }
            val messageId = uniqueEnvelopeId(database)
            val message = RelayMessageCodec.restore(
                messageId,
                cleanText,
                replyToMessageIdHex?.let(RelayMessageCodec::idBytes),
                replyPreview,
            )
            val protectedText = encryptMessage(
                messageId,
                deviceFingerprint,
                Direction.OUTGOING,
                message.encoded,
                LOCAL_CONTENT_VERSION,
            )
            val createdAtMs = System.currentTimeMillis()
            val values = ContentValues().apply {
                put(COLUMN_MESSAGE_ID, messageId)
                put(COLUMN_PEER_FINGERPRINT, deviceFingerprint)
                put(COLUMN_TEXT_NONCE, protectedText.nonce)
                put(COLUMN_TEXT_CIPHERTEXT, protectedText.ciphertext)
                put(COLUMN_CONTENT_VERSION, LOCAL_CONTENT_VERSION)
                initialCopyBudget?.let { put(COLUMN_INITIAL_COPY_BUDGET, it) }
                put(COLUMN_CREATED_AT, createdAtMs)
            }
            check(database.insertOrThrow(TABLE_PENDING_MESH_TEXTS, null, values) > 0L) {
                "Mesh text was not durably queued."
            }
            preparePendingOutgoingTexts(database, onlyFingerprint = deviceFingerprint)
            val wireEnvelope = findEnvelope(database, messageId)
            database.setTransactionSuccessful()
            return QueuedMessage(messageId, deviceFingerprint, wireEnvelope, createdAtMs, message)
        } finally {
            database.endTransaction()
        }
    }

    /**
     * Atomically advances the recipient ratchet and stores only RLY1/HAP1 plus a protected
     * cancellation secret. The direct manifest's name, MIME type, and content key never enter
     * the courier-visible columns.
     */
    fun queueOutgoingAttachment(
        deviceFingerprint: String,
        attachment: RelayAttachmentManifest,
    ): SenderAttachmentOffer {
        requireFingerprint(deviceFingerprint)
        attachment.validate()
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainSenderAttachmentOffers(database)
            findSenderAttachmentOffer(database, attachment.attachmentId)?.let { existing ->
                require(existing.recipientFingerprint == deviceFingerprint) {
                    "An outgoing attachment object is bound to another recipient."
                }
                require(senderOfferMatchesAttachment(database, existing, attachment)) {
                    "An outgoing attachment object was reused with different chunks."
                }
                database.setTransactionSuccessful()
                return existing
            }
            val contact = findContact(database, deviceFingerprint)
                ?.takeIf { it.isComplete && it.verified }
                ?: throw IllegalStateException("The selected Relay contact is not ready and verified.")
            val existingCount = database.rawQuery(
                "SELECT COUNT(*) FROM $TABLE_SENDER_ATTACHMENT_OFFERS",
                null,
            ).use { cursor ->
                check(cursor.moveToFirst()) { "Sender attachment count query returned no row." }
                cursor.getInt(0)
            }
            check(existingCount < MAX_PENDING_SENDER_ATTACHMENTS) {
                "Sender attachment offer quota is full."
            }
            val state = ensureState(database)
            val cancellationSecret = ByteArray(RelayCourierAttachmentPlan.SHA256_BYTES)
                .also(random::nextBytes)
            try {
                val prepared = RelaySenderAttachmentPreparation.prepare(
                    attachment,
                    cancellationSecret,
                )
                val remoteBundle = requireNotNull(contact.remoteBundle)
                val sessionRole: Boolean
                val session = if (contact.sessionPickle == null) {
                    sessionRole = true
                    RelayNative.startE2eConversation(
                        state.accountPickle,
                        state.protectionKey,
                        contact.localBundle,
                        remoteBundle,
                    )
                } else {
                    sessionRole = requireNotNull(contact.sessionIsInitiator)
                    contact.sessionPickle
                }
                val encrypted = RelayNative.encryptE2eAttachmentManifest(
                    accountPickle = state.accountPickle,
                    stateKey = state.protectionKey,
                    localBundle = contact.localBundle,
                    remoteBundle = remoteBundle,
                    sessionPickle = session,
                    isInitiator = sessionRole,
                    sequence = contact.nextOutgoingSequence,
                    manifest = prepared.recipientManifest,
                )
                val stored = commitOutgoingAttachmentOffer(
                    database = database,
                    contact = contact,
                    sessionRole = sessionRole,
                    encrypted = encrypted,
                    plan = prepared.plan,
                    cancellationSecret = cancellationSecret,
                    ratchetSequence = contact.nextOutgoingSequence,
                )
                database.setTransactionSuccessful()
                return stored
            } finally {
                cancellationSecret.fill(0)
                state.protectionKey.fill(0)
            }
        } finally {
            database.endTransaction()
        }
    }

    /** Transaction-scoped seam used by production and crash-consistency tests. */
    internal fun commitOutgoingAttachmentOffer(
        database: SQLiteDatabase,
        contact: Contact,
        sessionRole: Boolean,
        encrypted: E2eEncryptResult,
        plan: RelayCourierAttachmentPlan,
        cancellationSecret: ByteArray,
        ratchetSequence: Long,
    ): SenderAttachmentOffer {
        require(database.inTransaction()) { "Sender attachment commit requires a transaction." }
        require(ratchetSequence == contact.nextOutgoingSequence && ratchetSequence > 0L) {
            "Sender attachment ratchet sequence is invalid."
        }
        require(cancellationSecret.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Sender attachment cancellation secret is invalid."
        }
        plan.validate()
        val envelope = RelayMeshEnvelope.decode(encrypted.envelope)
        require(envelope.encode().contentEquals(encrypted.envelope)) {
            "Sender attachment manifest envelope is not canonical."
        }
        require(envelope.messageId.contentEquals(plan.objectId)) {
            "Sender attachment manifest and plan IDs differ."
        }
        require(envelope.priority == MANIFEST_PRIORITY) {
            "Sender attachment envelope has the wrong priority."
        }
        RelayAttachmentPlanOffer(encrypted.envelope, plan.encode()).validate()
        check(findSenderAttachmentOffer(database, plan.objectId) == null) {
            "Sender attachment object already exists."
        }
        val existingCount = database.rawQuery(
            "SELECT COUNT(*) FROM $TABLE_SENDER_ATTACHMENT_OFFERS",
            null,
        ).use { cursor ->
            check(cursor.moveToFirst()) { "Sender attachment count query returned no row." }
            cursor.getInt(0)
        }
        check(existingCount < MAX_PENDING_SENDER_ATTACHMENTS) {
            "Sender attachment offer quota is full."
        }
        val protectedCancellation = encryptSecret(
            senderAttachmentCancellationAad(plan.objectId, plan.sha256()),
            cancellationSecret,
        )
        val contactValues = ContentValues().apply {
            put(COLUMN_SESSION_ROLE, if (sessionRole) 1 else 0)
            put(COLUMN_SESSION_PICKLE, encrypted.sessionPickle)
            put(COLUMN_NEXT_OUTGOING_SEQUENCE, ratchetSequence + 1L)
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            database.update(
                TABLE_CONTACTS,
                contactValues,
                "$COLUMN_DEVICE_FINGERPRINT = ? AND $COLUMN_NEXT_OUTGOING_SEQUENCE = ?",
                arrayOf(contact.deviceFingerprint, ratchetSequence.toString()),
            ) == 1,
        ) { "Contact ratchet changed while creating the attachment offer." }
        val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
        val values = ContentValues().apply {
            put(COLUMN_OBJECT_ID, plan.objectId)
            put(COLUMN_RECIPIENT_FINGERPRINT, contact.deviceFingerprint)
            put(COLUMN_WIRE_MANIFEST, encrypted.envelope)
            put(COLUMN_WIRE_PLAN, plan.encode())
            put(COLUMN_CANCEL_NONCE, protectedCancellation.nonce)
            put(COLUMN_CANCEL_CIPHERTEXT, protectedCancellation.ciphertext)
            put(COLUMN_RATCHET_SEQUENCE, ratchetSequence)
            put(COLUMN_LIFETIME_MS, envelope.lifetimeMs)
            put(COLUMN_AGE_MS, envelope.ageMs)
            put(COLUMN_AGE_ANCHOR_ELAPSED_MS, nowElapsedMs)
            put(COLUMN_CREATED_AT, System.currentTimeMillis())
        }
        check(database.insertOrThrow(TABLE_SENDER_ATTACHMENT_OFFERS, null, values) > 0L) {
            "Sender attachment offer was not stored."
        }
        return requireNotNull(findSenderAttachmentOffer(database, plan.objectId))
    }

    /** Oldest durable plan that has not already been accepted by this authenticated courier. */
    fun nextSenderAttachmentOffer(courierFingerprint: String? = null): SenderAttachmentOffer? {
        courierFingerprint?.let(::requireFingerprint)
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainSenderAttachmentOffers(database)
            database.query(
                TABLE_SENDER_ATTACHMENT_OFFERS,
                SENDER_ATTACHMENT_OFFER_PROJECTION,
                "$COLUMN_RADIO_ELIGIBLE = 1",
                null,
                null,
                null,
                "$COLUMN_SEQUENCE ASC",
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    val offer = readSenderAttachmentOffer(cursor)
                    if (
                        courierFingerprint == null ||
                        !hasSenderAttachmentCustody(database, offer.objectId, courierFingerprint)
                    ) {
                        database.setTransactionSuccessful()
                        return offer
                    }
                }
            }
            database.setTransactionSuccessful()
            return null
        } finally {
            database.endTransaction()
        }
    }

    /**
     * Persists only a hop-authenticated HCU1. Custody is local resume knowledge; this path
     * cannot create a recipient HAR1 or mark an attachment Delivered.
     */
    fun recordSenderAttachmentCustody(
        courierFingerprint: String,
        encodedCustody: ByteArray,
    ): SenderAttachmentCustody {
        requireFingerprint(courierFingerprint)
        val custody = RelayCourierAttachmentCustody.decode(encodedCustody)
        require(custody.encode().contentEquals(encodedCustody)) {
            "Sender attachment custody is not canonical."
        }
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainSenderAttachmentOffers(database)
            val offer = findSenderAttachmentOffer(database, custody.objectId)
                ?: throw IllegalStateException("The sender attachment offer is no longer available.")
            val plan = RelayCourierAttachmentPlan.decode(offer.encodedPlan)
            require(
                custody.planCommitted &&
                    custody.objectId.contentEquals(plan.objectId) &&
                    MessageDigest.isEqual(custody.planSha256, plan.sha256()) &&
                    custody.chunkCount == plan.chunks.size,
            ) { "Courier custody does not match the durable sender plan." }

            val existing = readSenderAttachmentCustody(
                database,
                custody.objectId,
                courierFingerprint,
                plan.sha256(),
            )
            if (existing != null) {
                require(custodyContainsAll(custody, existing)) {
                    "Courier custody cannot forget durably committed chunks."
                }
                if (custody.encode().contentEquals(existing.encode())) {
                    database.setTransactionSuccessful()
                    return SenderAttachmentCustody(
                        custody.objectId.copyOf(),
                        courierFingerprint,
                        existing,
                        inserted = false,
                    )
                }
            }

            val protected = encryptSecret(
                senderAttachmentCustodyAad(custody.objectId, courierFingerprint, custody.planSha256),
                encodedCustody,
            )
            val values = ContentValues().apply {
                put(COLUMN_OBJECT_ID, custody.objectId)
                put(COLUMN_COURIER_FINGERPRINT, courierFingerprint)
                put(COLUMN_CUSTODY_NONCE, protected.nonce)
                put(COLUMN_CUSTODY_CIPHERTEXT, protected.ciphertext)
                put(COLUMN_UPDATED_AT, System.currentTimeMillis())
            }
            if (existing == null) {
                check(database.insertOrThrow(TABLE_SENDER_ATTACHMENT_CUSTODY, null, values) > 0L) {
                    "Sender attachment custody was not stored."
                }
            } else {
                check(
                    database.update(
                        TABLE_SENDER_ATTACHMENT_CUSTODY,
                        values,
                        "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_COURIER_FINGERPRINT = ?",
                        arrayOf(custody.objectId.toSqlHex(), courierFingerprint),
                    ) == 1,
                ) { "Sender attachment custody disappeared while updating it." }
            }
            database.setTransactionSuccessful()
            return SenderAttachmentCustody(
                custody.objectId.copyOf(),
                courierFingerprint,
                custody,
                inserted = existing == null,
            )
        } finally {
            database.endTransaction()
        }
    }

    internal fun senderAttachmentCustody(
        objectId: ByteArray,
        courierFingerprint: String,
    ): RelayCourierAttachmentCustody? {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES)
        requireFingerprint(courierFingerprint)
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainSenderAttachmentOffers(database)
            val offer = findSenderAttachmentOffer(database, objectId) ?: run {
                database.setTransactionSuccessful()
                return null
            }
            val plan = RelayCourierAttachmentPlan.decode(offer.encodedPlan)
            val custody = readSenderAttachmentCustody(
                database,
                objectId,
                courierFingerprint,
                plan.sha256(),
            )
            database.setTransactionSuccessful()
            return custody
        } finally {
            database.endTransaction()
        }
    }

    fun removeSenderAttachmentOffer(objectId: ByteArray): Boolean {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Sender attachment object ID is invalid."
        }
        return writableDatabase.delete(
            TABLE_SENDER_ATTACHMENT_OFFERS,
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.toSqlHex()),
        ) == 1
    }

    fun setSenderAttachmentOfferEligible(objectId: ByteArray, eligible: Boolean): Boolean {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Sender attachment object ID is invalid."
        }
        return writableDatabase.update(
            TABLE_SENDER_ATTACHMENT_OFFERS,
            ContentValues().apply { put(COLUMN_RADIO_ELIGIBLE, if (eligible) 1 else 0) },
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.toSqlHex()),
        ) == 1
    }

    fun ingestEnvelope(encoded: ByteArray, destinationOnly: Boolean = false): IngestResult {
        val offeredEnvelope = RelayMeshEnvelope.decode(encoded)
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainEnvelopeStore(database)
            if (
                hasMessage(database, offeredEnvelope.messageId) ||
                hasConsumedEnvelope(database, offeredEnvelope.messageId) ||
                hasReceiptEnvelope(database, offeredEnvelope.messageId)
            ) {
                database.setTransactionSuccessful()
                return IngestResult.CourierStored(offeredEnvelope.messageId, inserted = false)
            }
            if (offeredEnvelope.ageMs >= offeredEnvelope.lifetimeMs) {
                database.setTransactionSuccessful()
                return IngestResult.Expired(offeredEnvelope.messageId)
            }
            val storedWire = findEnvelope(database, offeredEnvelope.messageId)
            val candidateWire = storedWire ?: encoded
            val envelope = RelayMeshEnvelope.decode(candidateWire)
            if (storedWire != null) requireSameOpaquePayload(envelope, offeredEnvelope)
            val destination = verifiedContacts(database).firstOrNull { contact ->
                RelayNative.e2eRecognizes(contact.localBundle, candidateWire)
            }
            if (destination == null) {
                if (destinationOnly) {
                    database.setTransactionSuccessful()
                    return IngestResult.ProbeDeclined(envelope.messageId)
                }
                if (storedWire == null) {
                    val allowEviction = offeredEnvelope.priority == CONTROL_PRIORITY
                    if (
                        !ensureEnvelopeCapacity(
                            database,
                            encoded.size,
                            allowCourierEviction = allowEviction,
                            useCourierReserve = !allowEviction,
                            minimumEvictionPriority = CONTROL_PRIORITY + 1,
                        )
                    ) {
                        database.setTransactionSuccessful()
                        return IngestResult.StoreFull(envelope.messageId)
                    }
                    insertEnvelope(database, envelope, encoded, originFingerprint = null)
                }
                database.setTransactionSuccessful()
                return IngestResult.CourierStored(envelope.messageId, inserted = storedWire == null)
            }
            val remoteBundle = requireNotNull(destination.remoteBundle)
            val state = ensureState(database)
            try {
                val result = if (destination.sessionPickle == null) {
                    if (envelope.priority == MANIFEST_PRIORITY) {
                        val accepted = RelayNative.acceptE2ePayloadConversation(
                            accountPickle = state.accountPickle,
                            stateKey = state.protectionKey,
                            localBundle = destination.localBundle,
                            remoteBundle = remoteBundle,
                            envelope = candidateWire,
                        )
                        val received = accepted.payload
                        check(received is E2ePayloadResult.AttachmentManifest) {
                            "A manifest-priority first payload was not an attachment manifest."
                        }
                        commitReceivedAttachmentManifest(
                            database = database,
                            destination = destination,
                            updatedAccountPickle = accepted.accountPickle,
                            sessionRole = false,
                            received = received,
                            envelope = envelope,
                        )
                    } else {
                        val received = RelayNative.acceptE2eConversation(
                            accountPickle = state.accountPickle,
                            stateKey = state.protectionKey,
                            localBundle = destination.localBundle,
                            remoteBundle = remoteBundle,
                            envelope = candidateWire,
                        )
                        commitReceivedTextAndReceipt(
                            database = database,
                            destination = destination,
                            state = state,
                            updatedAccountPickle = requireNotNull(received.accountPickle),
                            decryptedSessionPickle = received.sessionPickle,
                            sessionRole = false,
                            receivedSequence = received.sequence,
                            message = received.message,
                        )
                    }
                } else {
                    when (
                        val received = RelayNative.decryptE2ePayload(
                            stateKey = state.protectionKey,
                            localBundle = destination.localBundle,
                            remoteBundle = remoteBundle,
                            sessionPickle = destination.sessionPickle,
                            isInitiator = requireNotNull(destination.sessionIsInitiator),
                            envelope = candidateWire,
                        )
                    ) {
                        is E2ePayloadResult.Text -> commitReceivedTextAndReceipt(
                            database = database,
                            destination = destination,
                            state = state,
                            updatedAccountPickle = null,
                            decryptedSessionPickle = received.sessionPickle,
                            sessionRole = requireNotNull(destination.sessionIsInitiator),
                            receivedSequence = received.sequence,
                            message = received.message,
                        )
                        is E2ePayloadResult.Receipt -> applyDeliveryReceipt(
                            database = database,
                            destination = destination,
                            received = received,
                        )
                        is E2ePayloadResult.AttachmentManifest ->
                            commitReceivedAttachmentManifest(
                                database = database,
                                destination = destination,
                                updatedAccountPickle = null,
                                sessionRole = requireNotNull(destination.sessionIsInitiator),
                                received = received,
                                envelope = envelope,
                            )
                        is E2ePayloadResult.AttachmentReceipt -> applyAttachmentReceipt(
                            database = database,
                            destination = destination,
                            received = received,
                            envelope = envelope,
                        )
                    }
                }
                database.delete(
                    TABLE_ENVELOPES,
                    "hex($COLUMN_MESSAGE_ID) = ?",
                    arrayOf(envelope.messageId.toSqlHex()),
                )
                database.setTransactionSuccessful()
                return result
            } finally {
                state.protectionKey.fill(0)
            }
        } finally {
            database.endTransaction()
        }
    }

    fun inventory(limit: Int = MAX_INVENTORY_IDS): List<ByteArray> {
        maintainEnvelopeStore()
        preparePendingDeliveryReceipts()
        preparePendingOutgoingTexts()
        val bounded = limit.coerceIn(1, MAX_INVENTORY_IDS)
        val result = linkedMapOf<String, ByteArray>()
        fun appendIds(sql: String) {
            if (result.size >= bounded) return
            readableDatabase.rawQuery(sql, arrayOf(bounded.toString())).use { cursor ->
                while (cursor.moveToNext() && result.size < bounded) {
                    val id = cursor.getBlob(0)
                    result.putIfAbsent(id.toHex(), id)
                }
            }
        }
        // Active custody must never be hidden behind an arbitrarily ordered lifetime history.
        appendIds(
            "SELECT $COLUMN_MESSAGE_ID FROM $TABLE_ENVELOPES " +
                "ORDER BY $COLUMN_CREATED_AT ASC LIMIT ?",
        )
        appendIds(
            "SELECT $COLUMN_MESSAGE_ID FROM $TABLE_CONSUMED_ENVELOPES " +
                "ORDER BY $COLUMN_CONSUMED_AT DESC LIMIT ?",
        )
        appendIds(
            "SELECT $COLUMN_RECEIPT_ENVELOPE_ID FROM $TABLE_DELIVERY_RECEIPTS " +
                "ORDER BY $COLUMN_GENERATED_AT DESC LIMIT ?",
        )
        appendIds(
            "SELECT $COLUMN_MESSAGE_ID FROM $TABLE_MESH_MESSAGES " +
                "ORDER BY $COLUMN_SEQUENCE DESC LIMIT ?",
        )
        return result.values.toList()
    }

    /** True when this phone currently has an encrypted envelope or receipt worth exchanging. */
    fun hasPendingEnvelopes(): Boolean {
        maintainEnvelopeStore()
        preparePendingDeliveryReceipts()
        preparePendingOutgoingTexts()
        readableDatabase.rawQuery(
            "SELECT 1 FROM $TABLE_ENVELOPES LIMIT 1",
            null,
        ).use { cursor ->
            return cursor.moveToFirst()
        }
    }

    /** True only for recipient-unacknowledged text in this conversation's RMS2 FIFO. */
    fun hasPendingOutgoingText(peerFingerprint: String): Boolean {
        requireFingerprint(peerFingerprint)
        maintainEnvelopeStore()
        val database = readableDatabase
        return countPendingTexts(database, peerFingerprint) > 0 ||
            countActiveOutgoingTexts(database, peerFingerprint) > 0
    }

    /**
     * Removes only the opaque HAP1 envelope after the courier store has independently verified
     * the sender's HAR1-authorized cleanup secret and exact object/plan binding.
     */
    fun removeReceiptConfirmedCourierManifest(objectId: ByteArray): Boolean {
        require(objectId.size == RelayMeshEnvelope.MESSAGE_ID_BYTES) {
            "Courier manifest object ID is invalid."
        }
        val database = writableDatabase
        database.beginTransaction()
        try {
            val wireEnvelope = findEnvelope(database, objectId)
            if (wireEnvelope == null) {
                database.setTransactionSuccessful()
                return false
            }
            val envelope = RelayMeshEnvelope.decode(wireEnvelope)
            require(envelope.encode().contentEquals(wireEnvelope)) {
                "Stored courier manifest is not canonical."
            }
            require(
                envelope.messageId.contentEquals(objectId) && envelope.priority == MANIFEST_PRIORITY,
            ) { "Receipt-confirmed cleanup targeted a non-manifest envelope." }
            check(
                database.delete(
                    TABLE_ENVELOPES,
                    "hex($COLUMN_MESSAGE_ID) = ?",
                    arrayOf(objectId.toSqlHex()),
                ) == 1,
            ) { "Receipt-confirmed courier manifest was not removed." }
            database.setTransactionSuccessful()
            return true
        } finally {
            database.endTransaction()
        }
    }

    fun planForPeer(
        peerFingerprint: String,
        peerInventory: Collection<ByteArray>,
        maximumBytes: Int,
    ): List<ForwardOffer> {
        maintainEnvelopeStore()
        preparePendingDeliveryReceipts()
        preparePendingOutgoingTexts()
        requireFingerprint(peerFingerprint)
        val known = peerInventory.mapTo(hashSetOf()) { it.toHex() }
        val offers = mutableListOf<ForwardOffer>()
        var usedBytes = 0
        val database = readableDatabase
        val nowElapsedMs = elapsedRealtimeMs()
        for (stored in transferCandidates(database)) {
                val id = stored.messageId
                if (id.toHex() in known || wasForwarded(readableDatabase, id, peerFingerprint)) continue
                val envelope = effectiveEnvelope(stored, nowElapsedMs) ?: continue
                if (envelope.copyBudget <= 1 || envelope.hopsTaken >= envelope.hopLimit) continue
                val transferred = envelope.copyBudget / 2
                val retained = envelope.copyBudget - transferred
                val wire = envelope.forForward(transferred).encode()
                val retainedWire = envelope.withRetainedCopies(retained).encode()
                val encodedBytes = Int.SIZE_BYTES + wire.size
                if (encodedBytes > maximumBytes - usedBytes) continue
                offers += ForwardOffer(
                    messageId = id,
                    wireEnvelope = wire,
                    retainedWireEnvelope = retainedWire,
                    previousCopyBudget = envelope.copyBudget,
                    retainedCopies = retained,
                    transferredCopies = transferred,
                )
                usedBytes += encodedBytes
        }
        return offers
    }

    fun routeProbesForPeer(
        peerFingerprint: String,
        maximumProbeBytes: Int,
        maximumDeliveryBytes: Int,
    ): List<RouteProbeOffer> {
        maintainEnvelopeStore()
        preparePendingDeliveryReceipts()
        preparePendingOutgoingTexts()
        requireFingerprint(peerFingerprint)
        val offers = mutableListOf<RouteProbeOffer>()
        var usedProbeBytes = 0
        var usedDeliveryBytes = 0
        val database = readableDatabase
        val nowElapsedMs = elapsedRealtimeMs()
        for (stored in transferCandidates(database)) {
                val id = stored.messageId
                if (wasForwarded(readableDatabase, id, peerFingerprint)) continue
                val envelope = effectiveEnvelope(stored, nowElapsedMs) ?: continue
                if (envelope.copyBudget != 1 || envelope.hopsTaken >= envelope.hopLimit) continue
                val full = envelope.forRecognizedDestination().encode()
                val probe = RelayMeshEnvelope.decode(full).asRouteProbe().encode()
                val probeBytes = Int.SIZE_BYTES + probe.size
                val deliveryBytes = Int.SIZE_BYTES + full.size
                if (
                    probeBytes > maximumProbeBytes - usedProbeBytes ||
                    deliveryBytes > maximumDeliveryBytes - usedDeliveryBytes
                ) {
                    continue
                }
                offers += RouteProbeOffer(id, probe, full)
                usedProbeBytes += probeBytes
                usedDeliveryBytes += deliveryBytes
        }
        return offers
    }

    fun recognizedRouteProbeIds(probes: Collection<ByteArray>): List<ByteArray> {
        if (probes.isEmpty()) return emptyList()
        val contacts = verifiedContacts(readableDatabase)
        if (contacts.isEmpty()) return emptyList()
        return probes.mapNotNull { encoded ->
            val envelope = RelayMeshEnvelope.decode(encoded)
            check(
                envelope.copyBudget == 1 &&
                    envelope.ciphertext.contentEquals(RelayMeshSyncCodec.ROUTE_PROBE_CIPHERTEXT),
            ) { "Invalid private destination probe." }
            envelope.messageId.takeIf {
                contacts.any { contact -> RelayNative.e2eRecognizes(contact.localBundle, encoded) }
            }
        }
    }

    fun requestedProbeEnvelopes(
        offers: Collection<RouteProbeOffer>,
        requestedIds: Collection<ByteArray>,
    ): List<ByteArray> {
        val requested = requestedIds.mapTo(hashSetOf()) { it.toHex() }
        check(requested.size == requestedIds.size) { "Duplicate private probe request." }
        val available = offers.associateBy { it.messageId.toHex() }
        check(requested.all(available::containsKey)) { "Peer requested an unknown private probe." }
        return requested.map { requireNotNull(available[it]).fullEnvelope }
    }

    fun commitProbed(
        peerFingerprint: String,
        offers: Collection<RouteProbeOffer>,
        acceptedIds: Collection<ByteArray>,
    ) {
        requireFingerprint(peerFingerprint)
        val accepted = acceptedIds.mapTo(hashSetOf()) { it.toHex() }
        if (accepted.isEmpty()) return
        val offered = offers.mapTo(hashSetOf()) { it.messageId.toHex() }
        check(accepted.all(offered::contains)) { "Peer accepted an unknown private probe." }
        val database = writableDatabase
        database.beginTransaction()
        try {
            for (idHex in accepted) {
                val offer = offers.first { it.messageId.toHex() == idHex }
                val currentWire = findEnvelope(database, offer.messageId) ?: continue
                val isControl = RelayMeshEnvelope.decode(currentWire).priority == CONTROL_PRIORITY
                val isLocallyOriginatedText = hasOutgoingMessage(
                    database,
                    offer.messageId,
                    fingerprint = peerFingerprint,
                )
                if (isControl || !isLocallyOriginatedText) {
                    // A route-probe delivery is accepted only by a recognized destination.
                    // Couriers can therefore discard their delivered copy. The sender keeps
                    // its own copy until the recipient-authenticated receipt is applied so a
                    // lost return receipt cannot silently strand the visible Waiting state.
                    database.delete(
                        TABLE_ENVELOPES,
                        "hex($COLUMN_MESSAGE_ID) = ?",
                        arrayOf(offer.messageId.toSqlHex()),
                    )
                    continue
                }
                val forwarded = ContentValues().apply {
                    put(COLUMN_MESSAGE_ID, offer.messageId)
                    put(COLUMN_PEER_FINGERPRINT, peerFingerprint)
                    put(COLUMN_FORWARDED_AT, System.currentTimeMillis())
                }
                database.insertWithOnConflict(
                    TABLE_FORWARDED,
                    null,
                    forwarded,
                    SQLiteDatabase.CONFLICT_IGNORE,
                )
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    fun commitForwarded(
        peerFingerprint: String,
        offers: Collection<ForwardOffer>,
        acceptedIds: Collection<ByteArray>,
    ) {
        requireFingerprint(peerFingerprint)
        val accepted = acceptedIds.mapTo(hashSetOf()) { it.toHex() }
        if (accepted.isEmpty()) return
        val database = writableDatabase
        database.beginTransaction()
        try {
            for (offer in offers) {
                if (offer.messageId.toHex() !in accepted) continue
                val stored = findStoredEnvelope(database, offer.messageId) ?: continue
                val current = stored.envelope
                val retained = RelayMeshEnvelope.decode(offer.retainedWireEnvelope)
                requireSameOpaquePayload(current, retained)
                check(retained.hopsTaken == current.hopsTaken) {
                    "Mesh retained-copy plan changed the local hop count."
                }
                if (wasForwarded(database, offer.messageId, peerFingerprint)) continue
                check(current.copyBudget == offer.previousCopyBudget) {
                    "Mesh copy budget changed before forwarding committed."
                }
                check(offer.retainedCopies + offer.transferredCopies == current.copyBudget) {
                    "Mesh forwarding plan did not conserve copies."
                }
                check(retained.copyBudget == offer.retainedCopies) {
                    "Mesh retained-copy plan changed before forwarding committed."
                }
                val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
                val effective = effectiveEnvelope(stored, nowElapsedMs)
                if (effective == null || current.hopsTaken >= current.hopLimit) {
                    database.delete(
                        TABLE_ENVELOPES,
                        "hex($COLUMN_MESSAGE_ID) = ?",
                        arrayOf(offer.messageId.toSqlHex()),
                    )
                    continue
                }
                // The offer is a snapshot. Account for time awaiting its ACK instead
                // of installing its stale portable age with a fresh residence anchor.
                val committed = effective.withRetainedCopies(offer.retainedCopies).copy(
                    ageMs = maxOf(effective.ageMs, retained.ageMs),
                )
                if (committed.ageMs >= committed.lifetimeMs) {
                    database.delete(
                        TABLE_ENVELOPES,
                        "hex($COLUMN_MESSAGE_ID) = ?",
                        arrayOf(offer.messageId.toSqlHex()),
                    )
                    continue
                }
                val values = ContentValues().apply {
                    put(COLUMN_WIRE_ENVELOPE, committed.encode())
                    put(COLUMN_AGE_MS, 0)
                    put(COLUMN_AGE_ANCHOR_ELAPSED_MS, nowElapsedMs)
                }
                check(
                    database.update(
                        TABLE_ENVELOPES,
                        values,
                        "hex($COLUMN_MESSAGE_ID) = ?",
                        arrayOf(offer.messageId.toSqlHex()),
                    ) == 1,
                ) { "Forwarded mesh envelope disappeared before commit." }
                val forwarded = ContentValues().apply {
                    put(COLUMN_MESSAGE_ID, offer.messageId)
                    put(COLUMN_PEER_FINGERPRINT, peerFingerprint)
                    put(COLUMN_FORWARDED_AT, System.currentTimeMillis())
                }
                database.insertWithOnConflict(
                    TABLE_FORWARDED,
                    null,
                    forwarded,
                    SQLiteDatabase.CONFLICT_IGNORE,
                )
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    fun storedMessages(limit: Int = 500): List<Map<String, Any>> {
        // UI history reads must be side-effect free. Queueing already prepares
        // new text transactionally, while inventory/admission paths perform
        // expiry maintenance before radio use. Repeating both jobs for every UI
        // refresh made history cost grow sharply as chats became longer.
        val boundedLimit = limit.coerceIn(1, 500)
        val result = mutableListOf<Map<String, Any>>()
        val activeEnvelopeIds = envelopeIdSet(TABLE_ENVELOPES)
        val forwardedEnvelopeIds = envelopeIdSet(TABLE_FORWARDED)
        readableDatabase.query(
            TABLE_MESH_MESSAGES,
            MESSAGE_PROJECTION,
            null,
            null,
            null,
            null,
            "$COLUMN_SEQUENCE DESC",
            boundedLimit.toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getBlob(0)
                val fingerprint = cursor.getString(1)
                val direction = Direction.fromDatabase(cursor.getInt(2))
                val storedStatus = MessageStatus.fromDatabase(cursor.getInt(5))
                val idHex = id.toHex()
                val visibleStatus = RelayMeshMessagePresentation.visibleStatus(
                    outgoing = direction == Direction.OUTGOING,
                    storedStatus = storedStatus.wireValue,
                    hasActiveEnvelope = idHex in activeEnvelopeIds,
                    wasAcceptedByRelay = idHex in forwardedEnvelopeIds,
                )
                val message = decryptMessage(
                    id,
                    fingerprint,
                    direction,
                    cursor.getBlob(3),
                    cursor.getBlob(4),
                    cursor.getInt(9),
                )
                result += buildMap {
                    put("messageId", id.toHex())
                    put("peerFingerprint", fingerprint)
                    put("direction", direction.wireValue)
                    putAll(messageFields(message))
                    put("status", visibleStatus)
                    put("createdAtMs", cursor.getLong(6))
                    put("conversationSequence", cursor.getLong(7))
                    put("attemptCount", 0)
                    put("transport", "mesh")
                    put("isRead", cursor.getInt(8) == 1)
                }
            }
        }
        readableDatabase.query(
            TABLE_PENDING_MESH_TEXTS,
            arrayOf(
                COLUMN_MESSAGE_ID,
                COLUMN_PEER_FINGERPRINT,
                COLUMN_TEXT_NONCE,
                COLUMN_TEXT_CIPHERTEXT,
                COLUMN_CREATED_AT,
                COLUMN_CONTENT_VERSION,
            ),
            null,
            null,
            null,
            null,
            "$COLUMN_SEQUENCE DESC",
            boundedLimit.toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getBlob(0)
                val fingerprint = cursor.getString(1)
                val message = decryptMessage(
                        id,
                        fingerprint,
                        Direction.OUTGOING,
                        cursor.getBlob(2),
                        cursor.getBlob(3),
                        cursor.getInt(5),
                    )
                result += buildMap {
                    put("messageId", id.toHex())
                    put("peerFingerprint", fingerprint)
                    put("direction", Direction.OUTGOING.wireValue)
                    putAll(messageFields(message))
                    put("status", MessageStatus.QUEUED.wireValue)
                    put("createdAtMs", cursor.getLong(4))
                    put("attemptCount", 0)
                    put("transport", "mesh")
                    put("isRead", true)
                }
            }
        }
        return result.sortedBy { (it["createdAtMs"] as Number).toLong() }.takeLast(boundedLimit)
    }

    /** Returns a stable newest-first keyset page while decrypting only bounded rows. */
    fun storedMessagePage(
        peerFingerprint: String,
        beforeCreatedAtMs: Long? = null,
        beforeMessageIdHex: String? = null,
        limit: Int = DEFAULT_HISTORY_PAGE_SIZE,
    ): List<Map<String, Any>> {
        require(peerFingerprint.isNotBlank()) { "Peer fingerprint is required." }
        require((beforeCreatedAtMs == null) == (beforeMessageIdHex == null)) {
            "Both history cursor values are required together."
        }
        val normalizedBeforeId = beforeMessageIdHex?.uppercase()?.also { id ->
            require(
                id.length == RelayMeshEnvelope.MESSAGE_ID_BYTES * 2 &&
                    id.all { it in '0'..'9' || it in 'A'..'F' },
            ) { "History cursor message ID is invalid." }
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
        val result = mutableListOf<Map<String, Any>>()
        val activeEnvelopeIds = envelopeIdSet(TABLE_ENVELOPES)
        val forwardedEnvelopeIds = envelopeIdSet(TABLE_FORWARDED)
        readableDatabase.query(
            TABLE_MESH_MESSAGES,
            MESSAGE_PROJECTION,
            selection,
            selectionArgs,
            null,
            null,
            "$COLUMN_CREATED_AT DESC, hex($COLUMN_MESSAGE_ID) DESC",
            boundedLimit.toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getBlob(0)
                val fingerprint = cursor.getString(1)
                val direction = Direction.fromDatabase(cursor.getInt(2))
                val idHex = id.toHex()
                val message = decryptMessage(
                    id,
                    fingerprint,
                    direction,
                    cursor.getBlob(3),
                    cursor.getBlob(4),
                    cursor.getInt(9),
                )
                result += buildMap {
                    put("messageId", idHex)
                    put("peerFingerprint", fingerprint)
                    put("direction", direction.wireValue)
                    putAll(messageFields(message))
                    put(
                        "status",
                        RelayMeshMessagePresentation.visibleStatus(
                            outgoing = direction == Direction.OUTGOING,
                            storedStatus = MessageStatus.fromDatabase(cursor.getInt(5)).wireValue,
                            hasActiveEnvelope = idHex in activeEnvelopeIds,
                            wasAcceptedByRelay = idHex in forwardedEnvelopeIds,
                        ),
                    )
                    put("createdAtMs", cursor.getLong(6))
                    put("conversationSequence", cursor.getLong(7))
                    put("attemptCount", 0)
                    put("transport", "mesh")
                    put("isRead", cursor.getInt(8) == 1)
                }
            }
        }
        readableDatabase.query(
            TABLE_PENDING_MESH_TEXTS,
            arrayOf(
                COLUMN_MESSAGE_ID,
                COLUMN_PEER_FINGERPRINT,
                COLUMN_TEXT_NONCE,
                COLUMN_TEXT_CIPHERTEXT,
                COLUMN_CREATED_AT,
                COLUMN_CONTENT_VERSION,
            ),
            selection,
            selectionArgs,
            null,
            null,
            "$COLUMN_CREATED_AT DESC, hex($COLUMN_MESSAGE_ID) DESC",
            boundedLimit.toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getBlob(0)
                val fingerprint = cursor.getString(1)
                val message = decryptMessage(
                        id,
                        fingerprint,
                        Direction.OUTGOING,
                        cursor.getBlob(2),
                        cursor.getBlob(3),
                        cursor.getInt(5),
                    )
                result += buildMap {
                    put("messageId", id.toHex())
                    put("peerFingerprint", fingerprint)
                    put("direction", Direction.OUTGOING.wireValue)
                    putAll(messageFields(message))
                    put("status", MessageStatus.QUEUED.wireValue)
                    put("createdAtMs", cursor.getLong(4))
                    put("attemptCount", 0)
                    put("transport", "mesh")
                    put("isRead", true)
                }
            }
        }
        return result.sortedWith(
            compareByDescending<Map<String, Any>> {
                (it["createdAtMs"] as Number).toLong()
            }.thenByDescending { it["messageId"] as String },
        ).take(boundedLimit)
    }

    /** Decrypts only the latest preview for each durable mesh conversation. */
    fun conversationSummaries(): List<ConversationSummary> {
        val fingerprints = linkedSetOf<String>()
        for (table in listOf(TABLE_MESH_MESSAGES, TABLE_PENDING_MESH_TEXTS)) {
            readableDatabase.query(
                true,
                table,
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
        }
        return fingerprints.mapNotNull { fingerprint ->
            val latest = storedMessagePage(fingerprint, limit = 1).singleOrNull()
                ?: return@mapNotNull null
            val count = listOf(TABLE_MESH_MESSAGES, TABLE_PENDING_MESH_TEXTS).sumOf { table ->
                readableDatabase.rawQuery(
                    "SELECT COUNT(*) FROM $table WHERE $COLUMN_PEER_FINGERPRINT = ?",
                    arrayOf(fingerprint),
                ).use { cursor ->
                    check(cursor.moveToFirst()) { "Conversation count query returned no row." }
                    cursor.getInt(0)
                }
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
            TABLE_MESH_MESSAGES,
            ContentValues().apply { put(COLUMN_IS_READ, 1) },
            "$COLUMN_PEER_FINGERPRINT = ? AND $COLUMN_DIRECTION = ? AND $COLUMN_IS_READ = 0",
            arrayOf(peerFingerprint, Direction.INCOMING.databaseValue.toString()),
        )
    }

    fun unreadCount(peerFingerprint: String): Int = readableDatabase.rawQuery(
        "SELECT COUNT(*) FROM $TABLE_MESH_MESSAGES " +
            "WHERE $COLUMN_PEER_FINGERPRINT = ? AND $COLUMN_DIRECTION = ? " +
            "AND $COLUMN_IS_READ = 0",
        arrayOf(peerFingerprint, Direction.INCOMING.databaseValue.toString()),
    ).use { cursor ->
        check(cursor.moveToFirst()) { "Unread count query returned no row." }
        cursor.getInt(0)
    }

    private fun envelopeIdSet(table: String): Set<String> {
        check(table == TABLE_ENVELOPES || table == TABLE_FORWARDED)
        val ids = hashSetOf<String>()
        readableDatabase.query(
            table,
            arrayOf(COLUMN_MESSAGE_ID),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) ids += cursor.getBlob(0).toHex()
        }
        return ids
    }

    /** Endpoint-only manifests waiting for their authenticated courier plan/chunks. */
    fun pendingRecipientAttachments(
        limit: Int = MAX_PENDING_RECIPIENT_ATTACHMENTS,
    ): List<PendingRecipientAttachment> {
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainRecipientAttachmentManifests(database)
            val pending = mutableListOf<PendingRecipientAttachment>()
            database.query(
                TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
                RECIPIENT_ATTACHMENT_PROJECTION,
                null,
                null,
                null,
                null,
                "$COLUMN_CREATED_AT ASC",
                limit.coerceIn(1, MAX_PENDING_RECIPIENT_ATTACHMENTS).toString(),
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    val objectId = cursor.getBlob(0)
                    val fingerprint = cursor.getString(1)
                    val planDigest = cursor.getBlob(2)
                    val encoded = decryptSecret(
                        recipientAttachmentAad(objectId, fingerprint, planDigest),
                        cursor.getBlob(3),
                        cursor.getBlob(4),
                    )
                    val manifest = try {
                        RelayRecipientAttachmentManifest.decode(encoded)
                    } finally {
                        encoded.fill(0)
                    }
                    check(
                        manifest.objectId.contentEquals(objectId) &&
                            manifest.courierPlanSha256.contentEquals(planDigest),
                    ) { "Stored recipient attachment binding is invalid." }
                    pending += PendingRecipientAttachment(
                        peerFingerprint = fingerprint,
                        manifest = manifest,
                        ratchetSequence = cursor.getLong(5),
                        lifetimeMs = cursor.getLong(6),
                        ageMs = cursor.getLong(7),
                    )
                }
            }
            database.setTransactionSuccessful()
            return pending
        } finally {
            database.endTransaction()
        }
    }

    /**
     * Creates HAR1 only after the exact recipient attachment is durably READY. The ratchet
     * advance, control-priority RMS2 envelope, generated-receipt marker, and pending-manifest
     * removal commit together.
     */
    fun queueReadyRecipientAttachmentReceipt(
        ready: RelayAttachmentStore.StoredAttachment,
    ): RecipientAttachmentReceiptQueued? {
        check(
            ready.direction == RelayAttachmentStore.Direction.INCOMING &&
                ready.status == RelayAttachmentStore.Status.READY,
        ) { "Only a durably ready incoming attachment can create HAR1." }
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainRecipientAttachmentManifests(database)
            val pending = findPendingRecipientAttachment(database, ready.manifest.attachmentId)
                ?: run {
                    database.setTransactionSuccessful()
                    return null
                }
            require(readyRecipientAttachmentMatches(pending, ready)) {
                "Ready attachment does not match its recipient-private manifest."
            }
            findGeneratedReceiptEnvelopeId(database, pending.manifest.objectId)?.let { existing ->
                database.delete(
                    TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(pending.manifest.objectId.toSqlHex()),
                )
                database.setTransactionSuccessful()
                return RecipientAttachmentReceiptQueued(
                    objectId = pending.manifest.objectId.copyOf(),
                    planSha256 = pending.manifest.courierPlanSha256.copyOf(),
                    envelopeId = existing,
                )
            }
            val contact = findContact(database, pending.peerFingerprint)
                ?.takeIf { it.isComplete && it.verified && it.sessionPickle != null }
                ?: throw IllegalStateException("The attachment sender is not ready and verified.")
            check(contact.nextOutgoingSequence < Long.MAX_VALUE) {
                "Conversation sequence is exhausted."
            }
            val state = ensureState(database)
            try {
                val receiptEnvelopeId = uniqueEnvelopeId(database)
                val receipt = RelayRecipientAttachmentReceipt(
                    objectId = pending.manifest.objectId.copyOf(),
                    courierPlanSha256 = pending.manifest.courierPlanSha256.copyOf(),
                )
                val encrypted = RelayNative.encryptE2eAttachmentReceipt(
                    accountPickle = state.accountPickle,
                    stateKey = state.protectionKey,
                    localBundle = contact.localBundle,
                    remoteBundle = requireNotNull(contact.remoteBundle),
                    sessionPickle = requireNotNull(contact.sessionPickle),
                    isInitiator = requireNotNull(contact.sessionIsInitiator),
                    envelopeId = receiptEnvelopeId,
                    sequence = contact.nextOutgoingSequence,
                    receipt = receipt,
                )
                val queued = commitReadyRecipientAttachmentReceipt(
                    database = database,
                    contact = contact,
                    receipt = receipt,
                    receiptEnvelopeId = receiptEnvelopeId,
                    encrypted = encrypted,
                )
                database.setTransactionSuccessful()
                return queued
            } finally {
                state.protectionKey.fill(0)
            }
        } finally {
            database.endTransaction()
        }
    }

    /** Transaction seam shared by production and HAR1 crash-consistency tests. */
    internal fun commitReadyRecipientAttachmentReceipt(
        database: SQLiteDatabase,
        contact: Contact,
        receipt: RelayRecipientAttachmentReceipt,
        receiptEnvelopeId: ByteArray,
        encrypted: E2eEncryptResult,
    ): RecipientAttachmentReceiptQueued {
        require(database.inTransaction()) { "HAR1 creation requires a transaction." }
        receipt.validate()
        require(receiptEnvelopeId.size == RelayMeshEnvelope.MESSAGE_ID_BYTES)
        val pending = findPendingRecipientAttachment(database, receipt.objectId)
            ?: throw IllegalStateException("Recipient attachment manifest is unavailable for HAR1.")
        require(
            pending.peerFingerprint == contact.deviceFingerprint &&
                MessageDigest.isEqual(
                    pending.manifest.courierPlanSha256,
                    receipt.courierPlanSha256,
                ),
        ) { "HAR1 does not match the pending recipient manifest." }
        val envelope = RelayMeshEnvelope.decode(encrypted.envelope)
        check(
            envelope.messageId.contentEquals(receiptEnvelopeId) &&
                envelope.priority == CONTROL_PRIORITY,
        ) { "Native HAR1 returned an invalid courier envelope." }
        check(
            ensureEnvelopeCapacity(
                database,
                encrypted.envelope.size,
                allowCourierEviction = true,
                minimumEvictionPriority = CONTROL_PRIORITY + 1,
            ),
        ) { "Relay's protected receipt reserve is full." }
        val contactValues = ContentValues().apply {
            put(COLUMN_SESSION_PICKLE, encrypted.sessionPickle)
            put(COLUMN_NEXT_OUTGOING_SEQUENCE, contact.nextOutgoingSequence + 1L)
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            database.update(
                TABLE_CONTACTS,
                contactValues,
                "$COLUMN_DEVICE_FINGERPRINT = ? AND $COLUMN_NEXT_OUTGOING_SEQUENCE = ?",
                arrayOf(contact.deviceFingerprint, contact.nextOutgoingSequence.toString()),
            ) == 1,
        ) { "Recipient ratchet changed while creating HAR1." }
        insertEnvelope(database, envelope, encrypted.envelope, originFingerprint = null)
        insertGeneratedReceipt(database, receipt.objectId, receiptEnvelopeId)
        check(
            database.delete(
                TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
                "hex($COLUMN_OBJECT_ID) = ?",
                arrayOf(receipt.objectId.toSqlHex()),
            ) == 1,
        ) { "Recipient attachment manifest disappeared while creating HAR1." }
        return RecipientAttachmentReceiptQueued(
            objectId = receipt.objectId.copyOf(),
            planSha256 = receipt.courierPlanSha256.copyOf(),
            envelopeId = receiptEnvelopeId.copyOf(),
        )
    }

    /** Reboot/process-death bridge for READY attachments whose HAR1 was not yet committed. */
    fun queueReadyRecipientAttachmentReceipts(
        attachmentStore: RelayAttachmentStore,
        limit: Int = MAX_PENDING_RECIPIENT_ATTACHMENTS,
    ): Int {
        var queued = 0
        pendingRecipientAttachments(limit).forEach { pending ->
            val ready = attachmentStore.findByHexId(pending.manifest.objectId.toHex())
                ?.takeIf {
                    it.direction == RelayAttachmentStore.Direction.INCOMING &&
                        it.status == RelayAttachmentStore.Status.READY
                }
                ?: return@forEach
            if (queueReadyRecipientAttachmentReceipt(ready) != null) queued += 1
        }
        return queued
    }

    /** Caller must hold the mesh database transaction that performed E2E decryption. */
    internal fun commitReceivedAttachmentManifest(
        database: SQLiteDatabase,
        destination: Contact,
        updatedAccountPickle: ByteArray?,
        sessionRole: Boolean,
        received: E2ePayloadResult.AttachmentManifest,
        envelope: RelayMeshEnvelope,
    ): IngestResult.AttachmentManifestStored {
        val manifest = received.manifest
        manifest.validate()
        check(
            envelope.priority == MANIFEST_PRIORITY &&
                envelope.messageId.contentEquals(received.envelopeId) &&
                manifest.objectId.contentEquals(received.envelopeId),
        ) { "Recipient attachment manifest does not match its courier envelope." }
        maintainRecipientAttachmentManifests(database)
        val inserted = storeRecipientAttachmentManifest(
            database = database,
            destination = destination,
            received = received,
            envelope = envelope,
        )
        updatedAccountPickle?.let { updateAccountPickle(database, it) }
        val contactValues = ContentValues().apply {
            put(COLUMN_SESSION_ROLE, if (sessionRole) 1 else 0)
            put(COLUMN_SESSION_PICKLE, received.sessionPickle)
            put(
                COLUMN_HIGHEST_INCOMING_SEQUENCE,
                maxOf(destination.highestIncomingSequence, received.sequence),
            )
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            database.update(
                TABLE_CONTACTS,
                contactValues,
                "$COLUMN_DEVICE_FINGERPRINT = ?",
                arrayOf(destination.deviceFingerprint),
            ) == 1,
        ) { "Attachment-manifest ratchet could not be committed." }
        insertConsumedEnvelope(database, received.envelopeId)
        return IngestResult.AttachmentManifestStored(
            messageId = received.envelopeId,
            peerFingerprint = destination.deviceFingerprint,
            courierPlanSha256 = manifest.courierPlanSha256.copyOf(),
            inserted = inserted,
        )
    }

    private fun storeRecipientAttachmentManifest(
        database: SQLiteDatabase,
        destination: Contact,
        received: E2ePayloadResult.AttachmentManifest,
        envelope: RelayMeshEnvelope,
    ): Boolean {
        val manifest = received.manifest
        val encoded = manifest.encode()
        try {
            database.query(
                TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
                arrayOf(
                    COLUMN_PEER_FINGERPRINT,
                    COLUMN_COURIER_PLAN_SHA256,
                    COLUMN_MANIFEST_NONCE,
                    COLUMN_MANIFEST_CIPHERTEXT,
                    COLUMN_RATCHET_SEQUENCE,
                    COLUMN_LIFETIME_MS,
                ),
                "hex($COLUMN_OBJECT_ID) = ?",
                arrayOf(manifest.objectId.toSqlHex()),
                null,
                null,
                null,
                "1",
            ).use { cursor ->
                if (cursor.moveToFirst()) {
                    val storedPeer = cursor.getString(0)
                    val storedPlan = cursor.getBlob(1)
                    val storedManifest = decryptSecret(
                        recipientAttachmentAad(manifest.objectId, storedPeer, storedPlan),
                        cursor.getBlob(2),
                        cursor.getBlob(3),
                    )
                    try {
                        check(
                            storedPeer == destination.deviceFingerprint &&
                                storedPlan.contentEquals(manifest.courierPlanSha256) &&
                                storedManifest.contentEquals(encoded) &&
                                cursor.getLong(4) == received.sequence &&
                                cursor.getLong(5) == envelope.lifetimeMs,
                        ) { "A conflicting recipient attachment reused an object ID." }
                        return false
                    } finally {
                        storedManifest.fill(0)
                    }
                }
            }
            val count = database.rawQuery(
                "SELECT COUNT(*) FROM $TABLE_RECIPIENT_ATTACHMENT_MANIFESTS",
                null,
            ).use { cursor ->
                check(cursor.moveToFirst()) { "Recipient attachment count query returned no row." }
                cursor.getInt(0)
            }
            check(count < MAX_PENDING_RECIPIENT_ATTACHMENTS) {
                "Recipient attachment manifest quota is full."
            }
            val protected = encryptSecret(
                recipientAttachmentAad(
                    manifest.objectId,
                    destination.deviceFingerprint,
                    manifest.courierPlanSha256,
                ),
                encoded,
            )
            val values = ContentValues().apply {
                put(COLUMN_OBJECT_ID, manifest.objectId)
                put(COLUMN_PEER_FINGERPRINT, destination.deviceFingerprint)
                put(COLUMN_COURIER_PLAN_SHA256, manifest.courierPlanSha256)
                put(COLUMN_MANIFEST_NONCE, protected.nonce)
                put(COLUMN_MANIFEST_CIPHERTEXT, protected.ciphertext)
                put(COLUMN_RATCHET_SEQUENCE, received.sequence)
                put(COLUMN_LIFETIME_MS, envelope.lifetimeMs)
                put(COLUMN_AGE_MS, envelope.ageMs)
                put(COLUMN_AGE_ANCHOR_ELAPSED_MS, elapsedRealtimeMs())
                put(COLUMN_CREATED_AT, System.currentTimeMillis())
            }
            check(
                database.insertOrThrow(TABLE_RECIPIENT_ATTACHMENT_MANIFESTS, null, values) > 0L,
            ) { "Recipient attachment manifest was not stored." }
            return true
        } finally {
            encoded.fill(0)
        }
    }

    private fun findPendingRecipientAttachment(
        database: SQLiteDatabase,
        objectId: ByteArray,
    ): PendingRecipientAttachment? = database.query(
        TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
        RECIPIENT_ATTACHMENT_PROJECTION,
        "hex($COLUMN_OBJECT_ID) = ?",
        arrayOf(objectId.toSqlHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        val storedObjectId = cursor.getBlob(0)
        val fingerprint = cursor.getString(1)
        val planDigest = cursor.getBlob(2)
        val encoded = decryptSecret(
            recipientAttachmentAad(storedObjectId, fingerprint, planDigest),
            cursor.getBlob(3),
            cursor.getBlob(4),
        )
        val manifest = try {
            RelayRecipientAttachmentManifest.decode(encoded)
        } finally {
            encoded.fill(0)
        }
        require(
            manifest.objectId.contentEquals(storedObjectId) &&
                MessageDigest.isEqual(manifest.courierPlanSha256, planDigest),
        ) { "Stored recipient attachment binding is invalid." }
        PendingRecipientAttachment(
            peerFingerprint = fingerprint,
            manifest = manifest,
            ratchetSequence = cursor.getLong(5),
            lifetimeMs = cursor.getLong(6),
            ageMs = cursor.getLong(7),
        )
    }

    private fun readyRecipientAttachmentMatches(
        pending: PendingRecipientAttachment,
        ready: RelayAttachmentStore.StoredAttachment,
    ): Boolean {
        val privateManifest = pending.manifest
        val stored = ready.manifest
        return ready.peerFingerprint == pending.peerFingerprint &&
            stored.attachmentId.contentEquals(privateManifest.objectId) &&
            stored.kind == privateManifest.kind &&
            stored.fileName == privateManifest.fileName &&
            stored.mimeType == privateManifest.mimeType &&
            stored.plaintextBytes == privateManifest.plaintextBytes &&
            MessageDigest.isEqual(stored.contentKey, privateManifest.contentKey) &&
            MessageDigest.isEqual(stored.plaintextSha256, privateManifest.plaintextSha256)
    }

    private fun findGeneratedReceiptEnvelopeId(
        database: SQLiteDatabase,
        deliveredObjectId: ByteArray,
    ): ByteArray? = database.query(
        TABLE_DELIVERY_RECEIPTS,
        arrayOf(COLUMN_RECEIPT_ENVELOPE_ID),
        "hex($COLUMN_DELIVERED_MESSAGE_ID) = ?",
        arrayOf(deliveredObjectId.toSqlHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor -> if (cursor.moveToFirst()) cursor.getBlob(0) else null }

    private fun commitReceivedTextAndReceipt(
        database: SQLiteDatabase,
        destination: Contact,
        state: AccountState,
        updatedAccountPickle: ByteArray?,
        decryptedSessionPickle: ByteArray,
        sessionRole: Boolean,
        receivedSequence: Long,
        message: RelayMessageCodec.TextMessage,
    ): IngestResult.Delivered {
        val messageId = message.id
        val accountPickle = updatedAccountPickle ?: state.accountPickle
        val receipt = generateDeliveryReceipt(
            database = database,
            destination = destination,
            state = state,
            accountPickle = accountPickle,
            sessionPickle = decryptedSessionPickle,
            sessionRole = sessionRole,
            deliveredMessageId = messageId,
        )
        check(
            ensureEnvelopeCapacity(
                database,
                receipt.encrypted.envelope.size,
                allowCourierEviction = true,
                minimumEvictionPriority = CONTROL_PRIORITY + 1,
            ),
        ) { "Relay's protected receipt reserve is full." }
        val protectedText = encryptMessage(
            messageId,
            destination.deviceFingerprint,
            Direction.INCOMING,
            message.encoded,
            LOCAL_CONTENT_VERSION,
        )
        updatedAccountPickle?.let { updateAccountPickle(database, it) }
        check(destination.nextOutgoingSequence < Long.MAX_VALUE) {
            "Conversation sequence is exhausted."
        }
        val contactValues = ContentValues().apply {
            put(COLUMN_SESSION_ROLE, if (sessionRole) 1 else 0)
            put(COLUMN_SESSION_PICKLE, receipt.encrypted.sessionPickle)
            put(COLUMN_NEXT_OUTGOING_SEQUENCE, destination.nextOutgoingSequence + 1L)
            put(
                COLUMN_HIGHEST_INCOMING_SEQUENCE,
                maxOf(destination.highestIncomingSequence, receivedSequence),
            )
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            database.update(
                TABLE_CONTACTS,
                contactValues,
                "$COLUMN_DEVICE_FINGERPRINT = ? AND $COLUMN_NEXT_OUTGOING_SEQUENCE = ?",
                arrayOf(
                    destination.deviceFingerprint,
                    destination.nextOutgoingSequence.toString(),
                ),
            ) == 1,
        ) { "Recipient ratchet changed while creating its delivery receipt." }
        insertMeshMessage(
            database = database,
            messageId = messageId,
            peerFingerprint = destination.deviceFingerprint,
            direction = Direction.INCOMING,
            protectedText = protectedText,
            contentVersion = LOCAL_CONTENT_VERSION,
            status = MessageStatus.RECEIVED,
            ratchetSequence = receivedSequence,
        )
        insertEnvelope(
            database = database,
            envelope = receipt.envelope,
            encoded = receipt.encrypted.envelope,
            originFingerprint = null,
        )
        insertGeneratedReceipt(database, messageId, receipt.envelope.messageId)
        return IngestResult.Delivered(
            messageId = messageId,
            peerFingerprint = destination.deviceFingerprint,
            text = message.text,
            replyToMessageId = message.replyToMessageId,
            replyPreview = message.replyPreview,
            inserted = true,
        )
    }

    private fun applyDeliveryReceipt(
        database: SQLiteDatabase,
        destination: Contact,
        received: E2ePayloadResult.Receipt,
    ): IngestResult.ReceiptApplied {
        val contactValues = ContentValues().apply {
            put(COLUMN_SESSION_PICKLE, received.sessionPickle)
            put(
                COLUMN_HIGHEST_INCOMING_SEQUENCE,
                maxOf(destination.highestIncomingSequence, received.sequence),
            )
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            database.update(
                TABLE_CONTACTS,
                contactValues,
                "$COLUMN_DEVICE_FINGERPRINT = ?",
                arrayOf(destination.deviceFingerprint),
            ) == 1,
        ) { "Receipt ratchet could not be committed." }
        insertConsumedEnvelope(database, received.envelopeId)
        val statusValues = ContentValues().apply {
            put(COLUMN_STATUS, MessageStatus.DELIVERED.databaseValue)
        }
        val changed = database.update(
            TABLE_MESH_MESSAGES,
            statusValues,
            "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_PEER_FINGERPRINT = ? " +
                "AND $COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ?",
            arrayOf(
                received.deliveredMessageId.toSqlHex(),
                destination.deviceFingerprint,
                Direction.OUTGOING.databaseValue.toString(),
                MessageStatus.QUEUED.databaseValue.toString(),
            ),
        ) == 1
        if (changed || hasOutgoingMessage(database, received.deliveredMessageId, destination.deviceFingerprint)) {
            database.delete(
                TABLE_ENVELOPES,
                "hex($COLUMN_MESSAGE_ID) = ?",
                arrayOf(received.deliveredMessageId.toSqlHex()),
            )
        }
        return IngestResult.ReceiptApplied(
            messageId = received.envelopeId,
            deliveredMessageId = received.deliveredMessageId,
            peerFingerprint = destination.deviceFingerprint,
            changed = changed,
        )
    }

    /** Caller holds the E2E-decryption transaction; HAR1 binding becomes durable here. */
    internal fun applyAttachmentReceipt(
        database: SQLiteDatabase,
        destination: Contact,
        received: E2ePayloadResult.AttachmentReceipt,
        envelope: RelayMeshEnvelope,
    ): IngestResult.AttachmentReceiptApplied {
        require(database.inTransaction()) { "HAR1 application requires a transaction." }
        received.receipt.validate()
        require(
            envelope.priority == CONTROL_PRIORITY &&
                envelope.messageId.contentEquals(received.envelopeId),
        ) { "HAR1 courier envelope binding is invalid." }
        maintainSenderAttachmentOffers(database)
        val existing = readSenderAttachmentReceipt(database, received.receipt.objectId)
        val offer = findSenderAttachmentOffer(database, received.receipt.objectId)
        val expectedPlanSha256: ByteArray
        val expectedRecipient: String
        if (existing != null) {
            expectedPlanSha256 = existing.planSha256
            expectedRecipient = existing.recipientFingerprint
        } else {
            val activeOffer = offer
                ?: throw IllegalStateException("HAR1 does not match an active sender object.")
            expectedPlanSha256 = RelayCourierAttachmentPlan.decode(activeOffer.encodedPlan).sha256()
            expectedRecipient = activeOffer.recipientFingerprint
        }
        require(
            expectedRecipient == destination.deviceFingerprint &&
                received.receipt.confirms(received.receipt.objectId, expectedPlanSha256),
        ) { "HAR1 does not match the sender object, plan, and recipient." }

        val contactValues = ContentValues().apply {
            put(COLUMN_SESSION_PICKLE, received.sessionPickle)
            put(
                COLUMN_HIGHEST_INCOMING_SEQUENCE,
                maxOf(destination.highestIncomingSequence, received.sequence),
            )
            put(COLUMN_UPDATED_AT, System.currentTimeMillis())
        }
        check(
            database.update(
                TABLE_CONTACTS,
                contactValues,
                "$COLUMN_DEVICE_FINGERPRINT = ?",
                arrayOf(destination.deviceFingerprint),
            ) == 1,
        ) { "HAR1 ratchet could not be committed." }
        insertConsumedEnvelope(database, received.envelopeId)
        val inserted = existing == null
        if (inserted) {
            val values = ContentValues().apply {
                put(COLUMN_OBJECT_ID, received.receipt.objectId)
                put(COLUMN_COURIER_PLAN_SHA256, expectedPlanSha256)
                put(COLUMN_RECIPIENT_FINGERPRINT, expectedRecipient)
                put(COLUMN_RECEIPT_ENVELOPE_ID, received.envelopeId)
                put(COLUMN_LOCAL_APPLIED, 0)
                put(COLUMN_CREATED_AT, System.currentTimeMillis())
            }
            check(
                database.insertOrThrow(TABLE_SENDER_ATTACHMENT_RECEIPTS, null, values) > 0L,
            ) { "Authenticated HAR1 was not stored." }
        }
        offer?.let {
            check(
                database.update(
                    TABLE_SENDER_ATTACHMENT_OFFERS,
                    ContentValues().apply { put(COLUMN_RADIO_ELIGIBLE, 0) },
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(received.receipt.objectId.toSqlHex()),
                ) == 1,
            ) { "Sender object disappeared while applying HAR1." }
        }
        return IngestResult.AttachmentReceiptApplied(
            messageId = received.envelopeId.copyOf(),
            objectId = received.receipt.objectId.copyOf(),
            courierPlanSha256 = expectedPlanSha256.copyOf(),
            peerFingerprint = expectedRecipient,
            inserted = inserted,
        )
    }

    /** Durable HAR1 facts waiting for the separate attachment database to reach Delivered. */
    fun pendingSenderAttachmentReceipts(): List<PendingSenderAttachmentReceipt> {
        val database = writableDatabase
        database.beginTransaction()
        try {
            val pending = mutableListOf<PendingSenderAttachmentReceipt>()
            database.query(
                TABLE_SENDER_ATTACHMENT_RECEIPTS,
                arrayOf(
                    COLUMN_OBJECT_ID,
                    COLUMN_COURIER_PLAN_SHA256,
                    COLUMN_RECIPIENT_FINGERPRINT,
                    COLUMN_RECEIPT_ENVELOPE_ID,
                    COLUMN_LOCAL_APPLIED,
                ),
                "$COLUMN_LOCAL_APPLIED = 0",
                null,
                null,
                null,
                "$COLUMN_CREATED_AT ASC",
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    pending += PendingSenderAttachmentReceipt(
                        objectId = cursor.getBlob(0),
                        planSha256 = cursor.getBlob(1),
                        recipientFingerprint = cursor.getString(2),
                        receiptEnvelopeId = cursor.getBlob(3),
                        localApplied = cursor.getInt(4) == 1,
                    )
                }
            }
            database.setTransactionSuccessful()
            return pending
        } finally {
            database.endTransaction()
        }
    }

    /** Called only after RelayAttachmentStore durably records Delivered and releases payload. */
    fun markSenderAttachmentReceiptLocallyApplied(objectId: ByteArray): Boolean {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES)
        val database = writableDatabase
        database.beginTransaction()
        try {
            val receipt = readSenderAttachmentReceipt(database, objectId)
                ?: throw IllegalStateException("Authenticated HAR1 is unavailable.")
            val changed = database.update(
                TABLE_SENDER_ATTACHMENT_RECEIPTS,
                ContentValues().apply { put(COLUMN_LOCAL_APPLIED, 1) },
                "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_LOCAL_APPLIED = 0",
                arrayOf(objectId.toSqlHex()),
            ) == 1
            finalizeSenderAttachmentCleanupIfComplete(database, receipt.objectId)
            database.setTransactionSuccessful()
            return changed
        } finally {
            database.endTransaction()
        }
    }

    /** Oldest receipt-authorized deletion proof for this authenticated courier. */
    fun nextSenderAttachmentCleanup(
        courierFingerprint: String,
    ): RelayCourierAttachmentCleanup? {
        requireFingerprint(courierFingerprint)
        val database = writableDatabase
        database.beginTransaction()
        try {
            database.rawQuery(
                "SELECT r.$COLUMN_OBJECT_ID, r.$COLUMN_COURIER_PLAN_SHA256, " +
                    "o.$COLUMN_WIRE_PLAN, o.$COLUMN_CANCEL_NONCE, o.$COLUMN_CANCEL_CIPHERTEXT " +
                    "FROM $TABLE_SENDER_ATTACHMENT_RECEIPTS r " +
                    "JOIN $TABLE_SENDER_ATTACHMENT_OFFERS o " +
                    "ON hex(o.$COLUMN_OBJECT_ID) = hex(r.$COLUMN_OBJECT_ID) " +
                    "JOIN $TABLE_SENDER_ATTACHMENT_CUSTODY c " +
                    "ON hex(c.$COLUMN_OBJECT_ID) = hex(r.$COLUMN_OBJECT_ID) " +
                    "WHERE r.$COLUMN_LOCAL_APPLIED = 1 " +
                    "AND c.$COLUMN_COURIER_FINGERPRINT = ? " +
                    "ORDER BY r.$COLUMN_CREATED_AT ASC LIMIT 1",
                arrayOf(courierFingerprint),
            ).use { cursor ->
                if (!cursor.moveToFirst()) {
                    database.setTransactionSuccessful()
                    return null
                }
                val objectId = cursor.getBlob(0)
                val planSha256 = cursor.getBlob(1)
                val plan = RelayCourierAttachmentPlan.decode(cursor.getBlob(2))
                require(
                    plan.objectId.contentEquals(objectId) &&
                        MessageDigest.isEqual(plan.sha256(), planSha256),
                ) { "Stored cleanup plan binding is invalid." }
                val secret = decryptSecret(
                    senderAttachmentCancellationAad(objectId, planSha256),
                    cursor.getBlob(3),
                    cursor.getBlob(4),
                )
                require(
                    MessageDigest.isEqual(
                        RelayCourierAttachmentPlan.digest(secret),
                        plan.cancellationCommitment,
                    ),
                ) { "Stored cleanup secret binding is invalid." }
                database.setTransactionSuccessful()
                return RelayCourierAttachmentCleanup(
                    objectId = objectId,
                    planSha256 = planSha256,
                    cancellationSecret = secret,
                )
            }
        } finally {
            database.endTransaction()
        }
    }

    /** Removes one pending courier target only after its authenticated exact HCA1. */
    fun completeSenderAttachmentCleanup(
        courierFingerprint: String,
        acknowledgement: RelayCourierAttachmentCleanupAck,
    ): Boolean {
        requireFingerprint(courierFingerprint)
        acknowledgement.validate()
        val database = writableDatabase
        database.beginTransaction()
        try {
            val receipt = readSenderAttachmentReceipt(database, acknowledgement.objectId)
                ?: throw IllegalStateException("Authenticated HAR1 cleanup state is unavailable.")
            require(MessageDigest.isEqual(receipt.planSha256, acknowledgement.planSha256)) {
                "Courier cleanup acknowledgement does not match HAR1."
            }
            val changed = database.delete(
                TABLE_SENDER_ATTACHMENT_CUSTODY,
                "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_COURIER_FINGERPRINT = ?",
                arrayOf(acknowledgement.objectId.toSqlHex(), courierFingerprint),
            ) == 1
            finalizeSenderAttachmentCleanupIfComplete(database, acknowledgement.objectId)
            database.setTransactionSuccessful()
            return changed
        } finally {
            database.endTransaction()
        }
    }

    private fun preparePendingOutgoingTexts() {
        val database = writableDatabase
        database.beginTransaction()
        try {
            preparePendingOutgoingTexts(database)
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    /**
     * Emits durable plaintext-at-rest text only while the conversation has fewer than 32
     * recipient-unacknowledged RLY1 envelopes. This is the ratchet reordering safety window.
     */
    private fun preparePendingOutgoingTexts(
        database: SQLiteDatabase,
        onlyFingerprint: String? = null,
    ) {
        val fingerprints = mutableListOf<String>()
        val selection = onlyFingerprint?.let { "WHERE $COLUMN_PEER_FINGERPRINT = ?" }.orEmpty()
        database.rawQuery(
            "SELECT $COLUMN_PEER_FINGERPRINT FROM $TABLE_PENDING_MESH_TEXTS $selection " +
                "GROUP BY $COLUMN_PEER_FINGERPRINT ORDER BY MIN($COLUMN_SEQUENCE) ASC LIMIT ?",
            buildList {
                onlyFingerprint?.let(::add)
                add(PENDING_TEXT_CONTACT_BATCH.toString())
            }.toTypedArray(),
        ).use { cursor ->
            while (cursor.moveToNext()) fingerprints += cursor.getString(0)
        }
        val eligible = fingerprints.filter {
            RelayMeshTextWindow.availableSlots(countActiveOutgoingTexts(database, it)) > 0
        }
        if (eligible.isEmpty()) return

        val state = ensureState(database)
        var emitted = 0
        try {
            for (fingerprint in eligible) {
                var active = countActiveOutgoingTexts(database, fingerprint)
                while (
                    RelayMeshTextWindow.availableSlots(active) > 0 &&
                    emitted < PENDING_TEXT_EMIT_BATCH
                ) {
                    val pending = oldestPendingText(database, fingerprint) ?: break
                    val contact = findContact(database, fingerprint)
                        ?.takeIf { it.isComplete && it.verified }
                        ?: break
                    val remoteBundle = requireNotNull(contact.remoteBundle)
                    val sessionRole: Boolean
                    val session = if (contact.sessionPickle == null) {
                        sessionRole = true
                        RelayNative.startE2eConversation(
                            state.accountPickle,
                            state.protectionKey,
                            contact.localBundle,
                            remoteBundle,
                        )
                    } else {
                        sessionRole = requireNotNull(contact.sessionIsInitiator)
                        contact.sessionPickle
                    }
                    check(contact.nextOutgoingSequence < Long.MAX_VALUE) {
                        "Conversation sequence is exhausted."
                    }
                    val message = decryptMessage(
                        pending.messageId,
                        fingerprint,
                        Direction.OUTGOING,
                        pending.protectedText.nonce,
                        pending.protectedText.ciphertext,
                        pending.contentVersion,
                    )
                    val encrypted = RelayNative.encryptE2eMessage(
                        accountPickle = state.accountPickle,
                        stateKey = state.protectionKey,
                        localBundle = contact.localBundle,
                        remoteBundle = remoteBundle,
                        sessionPickle = session,
                        isInitiator = sessionRole,
                        sequence = contact.nextOutgoingSequence,
                        message = message,
                    )
                    val encryptedEnvelope = RelayMeshEnvelope.decode(encrypted.envelope)
                    val envelope = pending.initialCopyBudget?.let {
                        encryptedEnvelope.copy(copyBudget = it)
                    } ?: encryptedEnvelope
                    check(envelope.messageId.contentEquals(pending.messageId)) {
                        "Native E2E envelope returned a different message ID."
                    }
                    val wireEnvelope = envelope.encode()
                    if (
                        !ensureEnvelopeCapacity(
                            database,
                            wireEnvelope.size,
                            allowCourierEviction = true,
                        )
                    ) {
                        break
                    }
                    val contactValues = ContentValues().apply {
                        put(COLUMN_SESSION_ROLE, if (sessionRole) 1 else 0)
                        put(COLUMN_SESSION_PICKLE, encrypted.sessionPickle)
                        put(COLUMN_NEXT_OUTGOING_SEQUENCE, contact.nextOutgoingSequence + 1L)
                        put(COLUMN_UPDATED_AT, System.currentTimeMillis())
                    }
                    check(
                        database.update(
                            TABLE_CONTACTS,
                            contactValues,
                            "$COLUMN_DEVICE_FINGERPRINT = ? AND $COLUMN_NEXT_OUTGOING_SEQUENCE = ?",
                            arrayOf(fingerprint, contact.nextOutgoingSequence.toString()),
                        ) == 1,
                    ) { "Contact ratchet changed while emitting queued text." }
                    insertMeshMessage(
                        database = database,
                        messageId = pending.messageId,
                        peerFingerprint = fingerprint,
                        direction = Direction.OUTGOING,
                        protectedText = pending.protectedText,
                        contentVersion = pending.contentVersion,
                        status = MessageStatus.QUEUED,
                        ratchetSequence = contact.nextOutgoingSequence,
                        createdAtMs = pending.createdAtMs,
                    )
                    insertEnvelope(database, envelope, wireEnvelope, originFingerprint = null)
                    check(
                        database.delete(
                            TABLE_PENDING_MESH_TEXTS,
                            "hex($COLUMN_MESSAGE_ID) = ?",
                            arrayOf(pending.messageId.toSqlHex()),
                        ) == 1,
                    ) { "Emitted mesh text disappeared from the durable pending queue." }
                    active += 1
                    emitted += 1
                }
                if (emitted >= PENDING_TEXT_EMIT_BATCH) break
            }
        } finally {
            state.protectionKey.fill(0)
        }
    }

    private fun countPendingTexts(database: SQLiteDatabase, fingerprint: String?): Int {
        val selection = fingerprint?.let { "$COLUMN_PEER_FINGERPRINT = ?" }
        val arguments = fingerprint?.let { arrayOf(it) }
        return database.query(
            TABLE_PENDING_MESH_TEXTS,
            arrayOf("COUNT(*)"),
            selection,
            arguments,
            null,
            null,
            null,
        ).use { cursor ->
            check(cursor.moveToFirst()) { "Pending mesh text count returned no row." }
            cursor.getInt(0)
        }
    }

    private fun countActiveOutgoingTexts(database: SQLiteDatabase, fingerprint: String): Int =
        database.rawQuery(
            "SELECT COUNT(*) FROM $TABLE_MESH_MESSAGES m " +
                "JOIN $TABLE_ENVELOPES e ON e.$COLUMN_MESSAGE_ID = m.$COLUMN_MESSAGE_ID " +
                "WHERE m.$COLUMN_PEER_FINGERPRINT = ? AND m.$COLUMN_DIRECTION = ? " +
                "AND m.$COLUMN_STATUS = ?",
            arrayOf(
                fingerprint,
                Direction.OUTGOING.databaseValue.toString(),
                MessageStatus.QUEUED.databaseValue.toString(),
            ),
        ).use { cursor ->
            check(cursor.moveToFirst()) { "Active mesh text count returned no row." }
            cursor.getInt(0)
        }

    private fun oldestPendingText(
        database: SQLiteDatabase,
        fingerprint: String,
    ): PendingOutgoingText? = database.query(
        TABLE_PENDING_MESH_TEXTS,
        arrayOf(
            COLUMN_MESSAGE_ID,
            COLUMN_TEXT_NONCE,
            COLUMN_TEXT_CIPHERTEXT,
            COLUMN_INITIAL_COPY_BUDGET,
            COLUMN_CREATED_AT,
            COLUMN_CONTENT_VERSION,
        ),
        "$COLUMN_PEER_FINGERPRINT = ?",
        arrayOf(fingerprint),
        null,
        null,
        "$COLUMN_SEQUENCE ASC",
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        PendingOutgoingText(
            messageId = cursor.getBlob(0),
            protectedText = EncryptedValue(cursor.getBlob(1), cursor.getBlob(2)),
            initialCopyBudget = if (cursor.isNull(3)) null else cursor.getInt(3),
            createdAtMs = cursor.getLong(4),
            contentVersion = cursor.getInt(5),
        )
    }

    /** Repairs the pre-receipt prototype by creating receipts for already stored incoming text. */
    private fun preparePendingDeliveryReceipts() {
        val database = writableDatabase
        database.beginTransaction()
        try {
            val pending = mutableListOf<Pair<ByteArray, String>>()
            database.rawQuery(
                "SELECT m.$COLUMN_MESSAGE_ID, m.$COLUMN_PEER_FINGERPRINT " +
                    "FROM $TABLE_MESH_MESSAGES m " +
                    "LEFT JOIN $TABLE_DELIVERY_RECEIPTS r " +
                    "ON hex(r.$COLUMN_DELIVERED_MESSAGE_ID) = hex(m.$COLUMN_MESSAGE_ID) " +
                    "WHERE m.$COLUMN_DIRECTION = ? AND m.$COLUMN_RECEIPT_GENERATED = 0 " +
                    "AND r.$COLUMN_DELIVERED_MESSAGE_ID IS NULL " +
                    "ORDER BY m.$COLUMN_SEQUENCE ASC LIMIT ?",
                arrayOf(Direction.INCOMING.databaseValue.toString(), RECEIPT_BACKFILL_LIMIT.toString()),
            ).use { cursor ->
                while (cursor.moveToNext()) pending += cursor.getBlob(0) to cursor.getString(1)
            }
            if (pending.isEmpty()) {
                database.setTransactionSuccessful()
                return
            }
            val state = ensureState(database)
            try {
                for ((messageId, fingerprint) in pending) {
                    val contact = findContact(database, fingerprint)
                        ?.takeIf { it.isComplete && it.verified && it.sessionPickle != null }
                        ?: continue
                    val receipt = generateDeliveryReceipt(
                        database = database,
                        destination = contact,
                        state = state,
                        accountPickle = state.accountPickle,
                        sessionPickle = requireNotNull(contact.sessionPickle),
                        sessionRole = requireNotNull(contact.sessionIsInitiator),
                        deliveredMessageId = messageId,
                    )
                    if (
                        !ensureEnvelopeCapacity(
                            database,
                            receipt.encrypted.envelope.size,
                            allowCourierEviction = true,
                            minimumEvictionPriority = CONTROL_PRIORITY + 1,
                        )
                    ) {
                        continue
                    }
                    check(contact.nextOutgoingSequence < Long.MAX_VALUE) {
                        "Conversation sequence is exhausted."
                    }
                    val values = ContentValues().apply {
                        put(COLUMN_SESSION_PICKLE, receipt.encrypted.sessionPickle)
                        put(COLUMN_NEXT_OUTGOING_SEQUENCE, contact.nextOutgoingSequence + 1L)
                        put(COLUMN_UPDATED_AT, System.currentTimeMillis())
                    }
                    check(
                        database.update(
                            TABLE_CONTACTS,
                            values,
                            "$COLUMN_DEVICE_FINGERPRINT = ? AND $COLUMN_NEXT_OUTGOING_SEQUENCE = ?",
                            arrayOf(fingerprint, contact.nextOutgoingSequence.toString()),
                        ) == 1,
                    ) { "Contact ratchet changed while repairing a delivery receipt." }
                    insertEnvelope(database, receipt.envelope, receipt.encrypted.envelope, null)
                    insertGeneratedReceipt(database, messageId, receipt.envelope.messageId)
                }
            } finally {
                state.protectionKey.fill(0)
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    private fun generateDeliveryReceipt(
        database: SQLiteDatabase,
        destination: Contact,
        state: AccountState,
        accountPickle: ByteArray,
        sessionPickle: ByteArray,
        sessionRole: Boolean,
        deliveredMessageId: ByteArray,
    ): GeneratedReceipt {
        val receiptEnvelopeId = uniqueEnvelopeId(database)
        val encrypted = RelayNative.encryptE2eReceipt(
            accountPickle = accountPickle,
            stateKey = state.protectionKey,
            localBundle = destination.localBundle,
            remoteBundle = requireNotNull(destination.remoteBundle),
            sessionPickle = sessionPickle,
            isInitiator = sessionRole,
            envelopeId = receiptEnvelopeId,
            sequence = destination.nextOutgoingSequence,
            deliveredMessageId = deliveredMessageId,
        )
        val envelope = RelayMeshEnvelope.decode(encrypted.envelope)
        check(envelope.messageId.contentEquals(receiptEnvelopeId) && envelope.priority == CONTROL_PRIORITY) {
            "Native E2E receipt returned an invalid courier envelope."
        }
        return GeneratedReceipt(encrypted, envelope)
    }

    private fun uniqueEnvelopeId(database: SQLiteDatabase): ByteArray {
        repeat(UNIQUE_ID_ATTEMPTS) {
            val candidate = ByteArray(RelayMeshEnvelope.MESSAGE_ID_BYTES).also(random::nextBytes)
            if (
                !hasMessage(database, candidate) &&
                !hasPendingText(database, candidate) &&
                !hasConsumedEnvelope(database, candidate) &&
                findEnvelope(database, candidate) == null &&
                !hasReceiptEnvelope(database, candidate)
            ) {
                return candidate
            }
        }
        error("Secure randomness repeatedly produced a duplicate envelope ID.")
    }

    private fun ensureState(database: SQLiteDatabase): AccountState {
        database.query(
            TABLE_STATE,
            arrayOf(COLUMN_KEY_NONCE, COLUMN_KEY_CIPHERTEXT, COLUMN_ACCOUNT_PICKLE),
            "$COLUMN_SINGLETON = 1",
            null,
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            if (cursor.moveToFirst()) {
                val key = decryptSecret(
                    STATE_KEY_AAD,
                    cursor.getBlob(0),
                    cursor.getBlob(1),
                )
                check(key.size == STATE_KEY_BYTES) { "Stored E2E protection key is invalid." }
                return AccountState(key, cursor.getBlob(2))
            }
        }
        val protectionKey = ByteArray(STATE_KEY_BYTES).also(random::nextBytes)
        try {
            val account = RelayNative.createE2eAccount(protectionKey)
            val encryptedKey = encryptSecret(STATE_KEY_AAD, protectionKey)
            val values = ContentValues().apply {
                put(COLUMN_SINGLETON, 1)
                put(COLUMN_KEY_NONCE, encryptedKey.nonce)
                put(COLUMN_KEY_CIPHERTEXT, encryptedKey.ciphertext)
                put(COLUMN_ACCOUNT_PICKLE, account)
            }
            check(database.insertOrThrow(TABLE_STATE, null, values) > 0L) {
                "Relay E2E account was not stored."
            }
            return AccountState(protectionKey.copyOf(), account)
        } finally {
            protectionKey.fill(0)
        }
    }

    private fun updateAccountPickle(database: SQLiteDatabase, pickle: ByteArray) {
        val values = ContentValues().apply { put(COLUMN_ACCOUNT_PICKLE, pickle) }
        check(
            database.update(
                TABLE_STATE,
                values,
                "$COLUMN_SINGLETON = 1",
                null,
            ) == 1,
        ) { "Relay E2E account state was not updated." }
    }

    private fun verifiedContacts(database: SQLiteDatabase): List<Contact> {
        val contacts = mutableListOf<Contact>()
        database.query(
            TABLE_CONTACTS,
            CONTACT_PROJECTION,
            "$COLUMN_VERIFIED = 1 AND $COLUMN_REMOTE_CIPHERTEXT IS NOT NULL",
            null,
            null,
            null,
            null,
        ).use { cursor -> while (cursor.moveToNext()) contacts += readContact(cursor) }
        return contacts
    }

    private fun findContact(database: SQLiteDatabase, fingerprint: String): Contact? =
        database.query(
            TABLE_CONTACTS,
            CONTACT_PROJECTION,
            "$COLUMN_DEVICE_FINGERPRINT = ?",
            arrayOf(fingerprint),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) readContact(cursor) else null }

    private fun readContact(cursor: Cursor): Contact {
        val fingerprint = cursor.getString(0)
        val localBundle = decryptContactBundle(
            fingerprint,
            LOCAL_BUNDLE_LABEL,
            cursor.getBlob(3),
            cursor.getBlob(4),
        )
        val remoteBundle = if (cursor.isNull(5)) {
            null
        } else {
            decryptContactBundle(
                fingerprint,
                REMOTE_BUNDLE_LABEL,
                cursor.getBlob(5),
                cursor.getBlob(6),
            )
        }
        return Contact(
            deviceFingerprint = fingerprint,
            displayName = cursor.getString(1),
            relayId = if (cursor.isNull(2)) null else cursor.getString(2),
            localBundle = localBundle,
            remoteBundle = remoteBundle,
            verified = cursor.getInt(7) == 1,
            sessionIsInitiator = if (cursor.isNull(8)) null else cursor.getInt(8) == 1,
            sessionPickle = if (cursor.isNull(9)) null else cursor.getBlob(9),
            nextOutgoingSequence = cursor.getLong(10),
            highestIncomingSequence = cursor.getLong(11),
        )
    }

    private fun insertMeshMessage(
        database: SQLiteDatabase,
        messageId: ByteArray,
        peerFingerprint: String,
        direction: Direction,
        protectedText: EncryptedValue,
        contentVersion: Int,
        status: MessageStatus,
        ratchetSequence: Long,
        createdAtMs: Long = System.currentTimeMillis(),
    ) {
        val values = ContentValues().apply {
            put(COLUMN_MESSAGE_ID, messageId)
            put(COLUMN_PEER_FINGERPRINT, peerFingerprint)
            put(COLUMN_DIRECTION, direction.databaseValue)
            put(COLUMN_TEXT_NONCE, protectedText.nonce)
            put(COLUMN_TEXT_CIPHERTEXT, protectedText.ciphertext)
            put(COLUMN_CONTENT_VERSION, contentVersion)
            put(COLUMN_STATUS, status.databaseValue)
            put(COLUMN_RATCHET_SEQUENCE, ratchetSequence)
            put(COLUMN_RECEIPT_GENERATED, 0)
            put(COLUMN_IS_READ, if (direction == Direction.INCOMING) 0 else 1)
            put(COLUMN_CREATED_AT, createdAtMs)
        }
        check(database.insertOrThrow(TABLE_MESH_MESSAGES, null, values) > 0L) {
            "Mesh message was not stored."
        }
    }

    private fun hasMessage(database: SQLiteDatabase, id: ByteArray): Boolean =
        database.query(
            TABLE_MESH_MESSAGES,
            arrayOf(COLUMN_MESSAGE_ID),
            "hex($COLUMN_MESSAGE_ID) = ?",
            arrayOf(id.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use(Cursor::moveToFirst)

    private fun hasPendingText(database: SQLiteDatabase, id: ByteArray): Boolean =
        database.query(
            TABLE_PENDING_MESH_TEXTS,
            arrayOf(COLUMN_MESSAGE_ID),
            "hex($COLUMN_MESSAGE_ID) = ?",
            arrayOf(id.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use(Cursor::moveToFirst)

    private fun hasOutgoingMessage(
        database: SQLiteDatabase,
        id: ByteArray,
        fingerprint: String,
    ): Boolean = database.query(
        TABLE_MESH_MESSAGES,
        arrayOf(COLUMN_MESSAGE_ID),
        "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_PEER_FINGERPRINT = ? " +
            "AND $COLUMN_DIRECTION = ?",
        arrayOf(id.toSqlHex(), fingerprint, Direction.OUTGOING.databaseValue.toString()),
        null,
        null,
        null,
        "1",
    ).use(Cursor::moveToFirst)

    private fun hasConsumedEnvelope(database: SQLiteDatabase, id: ByteArray): Boolean =
        database.query(
            TABLE_CONSUMED_ENVELOPES,
            arrayOf(COLUMN_MESSAGE_ID),
            "hex($COLUMN_MESSAGE_ID) = ?",
            arrayOf(id.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use(Cursor::moveToFirst)

    private fun hasReceiptEnvelope(database: SQLiteDatabase, id: ByteArray): Boolean =
        database.query(
            TABLE_DELIVERY_RECEIPTS,
            arrayOf(COLUMN_RECEIPT_ENVELOPE_ID),
            "hex($COLUMN_RECEIPT_ENVELOPE_ID) = ?",
            arrayOf(id.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use(Cursor::moveToFirst)

    private fun insertConsumedEnvelope(database: SQLiteDatabase, id: ByteArray) {
        val values = ContentValues().apply {
            put(COLUMN_MESSAGE_ID, id)
            put(COLUMN_CONSUMED_AT, System.currentTimeMillis())
        }
        check(database.insertOrThrow(TABLE_CONSUMED_ENVELOPES, null, values) > 0L) {
            "Consumed mesh envelope was not recorded."
        }
    }

    private fun insertGeneratedReceipt(
        database: SQLiteDatabase,
        deliveredMessageId: ByteArray,
        receiptEnvelopeId: ByteArray,
    ) {
        val values = ContentValues().apply {
            put(COLUMN_DELIVERED_MESSAGE_ID, deliveredMessageId)
            put(COLUMN_RECEIPT_ENVELOPE_ID, receiptEnvelopeId)
            put(COLUMN_GENERATED_AT, System.currentTimeMillis())
        }
        check(database.insertOrThrow(TABLE_DELIVERY_RECEIPTS, null, values) > 0L) {
            "Delivery receipt was not recorded."
        }
        database.update(
            TABLE_MESH_MESSAGES,
            ContentValues().apply { put(COLUMN_RECEIPT_GENERATED, 1) },
            "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_DIRECTION = ?",
            arrayOf(
                deliveredMessageId.toSqlHex(),
                Direction.INCOMING.databaseValue.toString(),
            ),
        )
    }

    private fun requireSameOpaquePayload(
        stored: RelayMeshEnvelope,
        offered: RelayMeshEnvelope,
    ) {
        check(
            stored.messageId.contentEquals(offered.messageId) &&
                stored.destinationHint.contentEquals(offered.destinationHint) &&
                stored.lifetimeMs == offered.lifetimeMs &&
                stored.hopLimit == offered.hopLimit &&
                stored.priority == offered.priority &&
                stored.ciphertext.contentEquals(offered.ciphertext),
        ) { "A conflicting mesh envelope reused an existing message ID." }
    }

    private fun insertEnvelope(
        database: SQLiteDatabase,
        envelope: RelayMeshEnvelope,
        encoded: ByteArray,
        originFingerprint: String?,
    ) {
        check(envelope.encode().contentEquals(encoded)) { "Mesh envelope is not canonical." }
        val values = ContentValues().apply {
            put(COLUMN_MESSAGE_ID, envelope.messageId)
            put(COLUMN_WIRE_ENVELOPE, encoded)
            originFingerprint?.let { put(COLUMN_ORIGIN_FINGERPRINT, it) }
            put(COLUMN_AGE_MS, 0)
            put(COLUMN_AGE_ANCHOR_ELAPSED_MS, elapsedRealtimeMs().coerceAtLeast(0L))
            put(COLUMN_CREATED_AT, System.currentTimeMillis())
        }
        check(database.insertOrThrow(TABLE_ENVELOPES, null, values) > 0L) {
            "Mesh envelope was not stored."
        }
    }

    private fun maintainEnvelopeStore() {
        val database = writableDatabase
        database.beginTransaction()
        try {
            maintainEnvelopeStore(database)
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    private fun maintainEnvelopeStore(
        database: SQLiteDatabase,
        nowMs: Long = System.currentTimeMillis(),
    ) {
        val expired = mutableListOf<ByteArray>()
        val advanced = mutableListOf<Triple<ByteArray, Long, Long>>()
        val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
        database.query(
            TABLE_ENVELOPES,
            arrayOf(
                COLUMN_MESSAGE_ID,
                COLUMN_WIRE_ENVELOPE,
                COLUMN_AGE_MS,
                COLUMN_AGE_ANCHOR_ELAPSED_MS,
            ),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getBlob(0)
                val stored = StoredEnvelope(
                    messageId = id,
                    envelope = RelayMeshEnvelope.decode(cursor.getBlob(1)),
                    ageMs = cursor.getLong(2),
                    ageAnchorElapsedMs = cursor.getLong(3),
                    createdAtMs = 0L,
                    localRatchetSequence = null,
                )
                val envelope = effectiveEnvelope(stored, nowElapsedMs)
                if (
                    envelope == null ||
                    stored.envelope.hopsTaken >= stored.envelope.hopLimit
                ) {
                    expired += id
                } else {
                    val rebooted = nowElapsedMs < stored.ageAnchorElapsedMs
                    val deltaMs = elapsedSinceAnchor(stored, nowElapsedMs)
                    if (rebooted || deltaMs >= ENVELOPE_AGE_PERSIST_INTERVAL_MS) {
                        advanced += Triple(
                            id,
                            saturatedAdd(stored.ageMs, deltaMs),
                            nowElapsedMs,
                        )
                    }
                }
            }
        }
        for ((id, ageMs, anchorMs) in advanced) {
            database.update(
                TABLE_ENVELOPES,
                ContentValues().apply {
                    put(COLUMN_AGE_MS, ageMs)
                    put(COLUMN_AGE_ANCHOR_ELAPSED_MS, anchorMs)
                },
                "hex($COLUMN_MESSAGE_ID) = ?",
                arrayOf(id.toSqlHex()),
            )
        }
        for (id in expired) {
            database.delete(
                TABLE_ENVELOPES,
                "hex($COLUMN_MESSAGE_ID) = ?",
                arrayOf(id.toSqlHex()),
            )
        }
        database.delete(
            TABLE_CONSUMED_ENVELOPES,
            "$COLUMN_CONSUMED_AT < ?",
            arrayOf((nowMs - CONSUMED_RETENTION_MS).toString()),
        )
        pruneDeliveryReceiptHistory(database, nowMs)
    }

    private fun pruneDeliveryReceiptHistory(database: SQLiteDatabase, nowMs: Long) {
        val inactiveReceipt =
            "$COLUMN_RECEIPT_ENVELOPE_ID NOT IN " +
                "(SELECT $COLUMN_MESSAGE_ID FROM $TABLE_ENVELOPES)"
        database.delete(
            TABLE_DELIVERY_RECEIPTS,
            "$COLUMN_GENERATED_AT < ? AND $inactiveReceipt",
            arrayOf((nowMs - DELIVERY_RECEIPT_RETENTION_MS).toString()),
        )
        database.execSQL(
            "DELETE FROM $TABLE_DELIVERY_RECEIPTS WHERE $COLUMN_DELIVERED_MESSAGE_ID IN (" +
                "SELECT $COLUMN_DELIVERED_MESSAGE_ID FROM $TABLE_DELIVERY_RECEIPTS " +
                "WHERE $inactiveReceipt ORDER BY $COLUMN_GENERATED_AT DESC " +
                "LIMIT -1 OFFSET $MAX_INACTIVE_DELIVERY_RECEIPTS)",
        )
    }

    private fun maintainRecipientAttachmentManifests(database: SQLiteDatabase) {
        val nowElapsedMs = elapsedRealtimeMs()
        val expired = mutableListOf<ByteArray>()
        val advanced = mutableListOf<Triple<ByteArray, Long, Long>>()
        database.query(
            TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
            arrayOf(
                COLUMN_OBJECT_ID,
                COLUMN_LIFETIME_MS,
                COLUMN_AGE_MS,
                COLUMN_AGE_ANCHOR_ELAPSED_MS,
            ),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val objectId = cursor.getBlob(0)
                val confirmedReceipt = readSenderAttachmentReceipt(database, objectId)
                if (confirmedReceipt != null) continue
                val age = RelayCourierAttachmentPolicy.advanceAge(
                    ageMs = cursor.getLong(2),
                    lifetimeMs = cursor.getLong(1),
                    anchorElapsedMs = cursor.getLong(3),
                    nowElapsedMs = nowElapsedMs,
                )
                if (age.expired) {
                    expired += objectId
                } else {
                    advanced += Triple(objectId, age.ageMs, age.anchorElapsedMs)
                }
            }
        }
        for ((objectId, ageMs, anchorElapsedMs) in advanced) {
            val values = ContentValues().apply {
                put(COLUMN_AGE_MS, ageMs)
                put(COLUMN_AGE_ANCHOR_ELAPSED_MS, anchorElapsedMs)
            }
            check(
                database.update(
                    TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
                    values,
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(objectId.toSqlHex()),
                ) == 1,
            ) { "Recipient attachment age state disappeared." }
        }
        for (objectId in expired) {
            database.delete(
                TABLE_RECIPIENT_ATTACHMENT_MANIFESTS,
                "hex($COLUMN_OBJECT_ID) = ?",
                arrayOf(objectId.toSqlHex()),
            )
        }
    }

    private fun maintainSenderAttachmentOffers(database: SQLiteDatabase) {
        val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
        val expired = mutableListOf<ByteArray>()
        val advanced = mutableListOf<Triple<ByteArray, Long, Long>>()
        database.query(
            TABLE_SENDER_ATTACHMENT_OFFERS,
            arrayOf(
                COLUMN_OBJECT_ID,
                COLUMN_LIFETIME_MS,
                COLUMN_AGE_MS,
                COLUMN_AGE_ANCHOR_ELAPSED_MS,
            ),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val objectId = cursor.getBlob(0)
                val age = RelayCourierAttachmentPolicy.advanceAge(
                    ageMs = cursor.getLong(2),
                    lifetimeMs = cursor.getLong(1),
                    anchorElapsedMs = cursor.getLong(3),
                    nowElapsedMs = nowElapsedMs,
                )
                if (age.expired) {
                    expired += objectId
                } else {
                    advanced += Triple(objectId, age.ageMs, age.anchorElapsedMs)
                }
            }
        }
        for ((objectId, ageMs, anchorElapsedMs) in advanced) {
            val values = ContentValues().apply {
                put(COLUMN_AGE_MS, ageMs)
                put(COLUMN_AGE_ANCHOR_ELAPSED_MS, anchorElapsedMs)
            }
            check(
                database.update(
                    TABLE_SENDER_ATTACHMENT_OFFERS,
                    values,
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(objectId.toSqlHex()),
                ) == 1,
            ) { "Sender attachment age state disappeared." }
        }
        for (objectId in expired) {
            database.delete(
                TABLE_SENDER_ATTACHMENT_OFFERS,
                "hex($COLUMN_OBJECT_ID) = ?",
                arrayOf(objectId.toSqlHex()),
            )
        }
    }

    private fun readSenderAttachmentReceipt(
        database: SQLiteDatabase,
        objectId: ByteArray,
    ): StoredSenderAttachmentReceipt? = database.query(
        TABLE_SENDER_ATTACHMENT_RECEIPTS,
        arrayOf(
            COLUMN_OBJECT_ID,
            COLUMN_COURIER_PLAN_SHA256,
            COLUMN_RECIPIENT_FINGERPRINT,
            COLUMN_RECEIPT_ENVELOPE_ID,
            COLUMN_LOCAL_APPLIED,
            COLUMN_CREATED_AT,
        ),
        "hex($COLUMN_OBJECT_ID) = ?",
        arrayOf(objectId.toSqlHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        StoredSenderAttachmentReceipt(
            objectId = cursor.getBlob(0),
            planSha256 = cursor.getBlob(1),
            recipientFingerprint = cursor.getString(2),
            receiptEnvelopeId = cursor.getBlob(3),
            localApplied = cursor.getInt(4) == 1,
            createdAtMs = cursor.getLong(5),
        )
    }

    private fun finalizeSenderAttachmentCleanupIfComplete(
        database: SQLiteDatabase,
        objectId: ByteArray,
    ) {
        val receipt = readSenderAttachmentReceipt(database, objectId) ?: return
        if (!receipt.localApplied) return
        val pendingCouriers = database.rawQuery(
            "SELECT COUNT(*) FROM $TABLE_SENDER_ATTACHMENT_CUSTODY " +
                "WHERE hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.toSqlHex()),
        ).use { cursor ->
            check(cursor.moveToFirst()) { "Sender cleanup count returned no row." }
            cursor.getInt(0)
        }
        if (pendingCouriers != 0) return
        database.delete(
            TABLE_SENDER_ATTACHMENT_OFFERS,
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.toSqlHex()),
        )
        check(
            database.delete(
                TABLE_SENDER_ATTACHMENT_RECEIPTS,
                "hex($COLUMN_OBJECT_ID) = ?",
                arrayOf(objectId.toSqlHex()),
            ) == 1,
        ) { "Sender HAR1 cleanup state disappeared." }
    }

    private fun findSenderAttachmentOffer(
        database: SQLiteDatabase,
        objectId: ByteArray,
    ): SenderAttachmentOffer? = database.query(
        TABLE_SENDER_ATTACHMENT_OFFERS,
        SENDER_ATTACHMENT_OFFER_PROJECTION,
        "hex($COLUMN_OBJECT_ID) = ?",
        arrayOf(objectId.toSqlHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor -> if (cursor.moveToFirst()) readSenderAttachmentOffer(cursor) else null }

    private fun readSenderAttachmentOffer(cursor: Cursor): SenderAttachmentOffer {
        val objectId = cursor.getBlob(0)
        val recipientFingerprint = cursor.getString(1)
        val storedManifest = cursor.getBlob(2)
        val storedPlan = cursor.getBlob(3)
        val ratchetSequence = cursor.getLong(4)
        val lifetimeMs = cursor.getLong(5)
        val ageMs = cursor.getLong(6)
        val plan = RelayCourierAttachmentPlan.decode(storedPlan)
        val envelope = RelayMeshEnvelope.decode(storedManifest)
        require(
            objectId.contentEquals(plan.objectId) &&
                objectId.contentEquals(envelope.messageId) &&
                envelope.priority == MANIFEST_PRIORITY &&
                envelope.lifetimeMs == lifetimeMs &&
                ageMs in envelope.ageMs until lifetimeMs,
        ) { "Stored sender attachment offer is invalid." }
        val agedManifest = envelope.copy(ageMs = ageMs).encode()
        RelayAttachmentPlanOffer(agedManifest, storedPlan).validate()
        return SenderAttachmentOffer(
            objectId = objectId,
            recipientFingerprint = recipientFingerprint,
            encodedManifest = agedManifest,
            encodedPlan = storedPlan,
            ratchetSequence = ratchetSequence,
            lifetimeMs = lifetimeMs,
            ageMs = ageMs,
        )
    }

    private fun senderOfferMatchesAttachment(
        database: SQLiteDatabase,
        offer: SenderAttachmentOffer,
        attachment: RelayAttachmentManifest,
    ): Boolean {
        val plan = RelayCourierAttachmentPlan.decode(offer.encodedPlan)
        val cancellationSecret = database.query(
            TABLE_SENDER_ATTACHMENT_OFFERS,
            arrayOf(COLUMN_CANCEL_NONCE, COLUMN_CANCEL_CIPHERTEXT),
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(offer.objectId.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            check(cursor.moveToFirst()) { "Sender attachment cancellation secret is missing." }
            decryptSecret(
                senderAttachmentCancellationAad(offer.objectId, plan.sha256()),
                cursor.getBlob(0),
                cursor.getBlob(1),
            )
        }
        return try {
            val prepared = RelaySenderAttachmentPreparation.prepare(attachment, cancellationSecret)
            prepared.plan.encode().contentEquals(offer.encodedPlan)
        } finally {
            cancellationSecret.fill(0)
        }
    }

    private fun hasSenderAttachmentCustody(
        database: SQLiteDatabase,
        objectId: ByteArray,
        courierFingerprint: String,
    ): Boolean = database.query(
        TABLE_SENDER_ATTACHMENT_CUSTODY,
        arrayOf(COLUMN_OBJECT_ID),
        "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_COURIER_FINGERPRINT = ?",
        arrayOf(objectId.toSqlHex(), courierFingerprint),
        null,
        null,
        null,
        "1",
    ).use(Cursor::moveToFirst)

    private fun readSenderAttachmentCustody(
        database: SQLiteDatabase,
        objectId: ByteArray,
        courierFingerprint: String,
        planSha256: ByteArray,
    ): RelayCourierAttachmentCustody? = database.query(
        TABLE_SENDER_ATTACHMENT_CUSTODY,
        arrayOf(COLUMN_CUSTODY_NONCE, COLUMN_CUSTODY_CIPHERTEXT),
        "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_COURIER_FINGERPRINT = ?",
        arrayOf(objectId.toSqlHex(), courierFingerprint),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        val encoded = decryptSecret(
            senderAttachmentCustodyAad(objectId, courierFingerprint, planSha256),
            cursor.getBlob(0),
            cursor.getBlob(1),
        )
        RelayCourierAttachmentCustody.decode(encoded).also { custody ->
            require(
                custody.objectId.contentEquals(objectId) &&
                    MessageDigest.isEqual(custody.planSha256, planSha256),
            ) { "Stored sender attachment custody binding is invalid." }
        }
    }

    private fun custodyContainsAll(
        candidate: RelayCourierAttachmentCustody,
        previous: RelayCourierAttachmentCustody,
    ): Boolean {
        if (
            !candidate.objectId.contentEquals(previous.objectId) ||
            !MessageDigest.isEqual(candidate.planSha256, previous.planSha256) ||
            candidate.chunkCount != previous.chunkCount
        ) {
            return false
        }
        return previous.chunkBitmap.indices.all { index ->
            (candidate.chunkBitmap[index].toInt() and previous.chunkBitmap[index].toInt()) ==
                previous.chunkBitmap[index].toInt()
        }
    }

    private fun transferCandidates(database: SQLiteDatabase): List<StoredEnvelope> {
        val result = mutableListOf<StoredEnvelope>()
        database.rawQuery(
            "SELECT e.$COLUMN_MESSAGE_ID, e.$COLUMN_WIRE_ENVELOPE, e.$COLUMN_AGE_MS, " +
                "e.$COLUMN_AGE_ANCHOR_ELAPSED_MS, e.$COLUMN_CREATED_AT, " +
                "m.$COLUMN_RATCHET_SEQUENCE FROM $TABLE_ENVELOPES e " +
                "LEFT JOIN $TABLE_MESH_MESSAGES m " +
                "ON m.$COLUMN_MESSAGE_ID = e.$COLUMN_MESSAGE_ID " +
                "AND m.$COLUMN_DIRECTION = ?",
            arrayOf(Direction.OUTGOING.databaseValue.toString()),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result += StoredEnvelope(
                    messageId = cursor.getBlob(0),
                    envelope = RelayMeshEnvelope.decode(cursor.getBlob(1)),
                    ageMs = cursor.getLong(2),
                    ageAnchorElapsedMs = cursor.getLong(3),
                    createdAtMs = cursor.getLong(4),
                    localRatchetSequence = if (cursor.isNull(5)) null else cursor.getLong(5),
                )
            }
        }
        return result.sortedWith(
            compareBy<StoredEnvelope> { it.envelope.priority }
                .thenBy { it.localRatchetSequence ?: Long.MAX_VALUE }
                .thenBy { it.createdAtMs },
        )
    }

    private fun effectiveEnvelope(
        stored: StoredEnvelope,
        nowElapsedMs: Long,
    ): RelayMeshEnvelope? = stored.envelope.agedBy(
        saturatedAdd(stored.ageMs, elapsedSinceAnchor(stored, nowElapsedMs)),
    )

    private fun elapsedSinceAnchor(stored: StoredEnvelope, nowElapsedMs: Long): Long =
        if (nowElapsedMs >= stored.ageAnchorElapsedMs) {
            nowElapsedMs - stored.ageAnchorElapsedMs
        } else {
            // elapsedRealtime resets at reboot. Persisted age remains valid; a new anchor is
            // installed by maintenance without consulting the editable wall clock.
            0L
        }

    private fun saturatedAdd(left: Long, right: Long): Long =
        if (right > Long.MAX_VALUE - left) Long.MAX_VALUE else left + right

    private fun ensureEnvelopeCapacity(
        database: SQLiteDatabase,
        incomingBytes: Int,
        allowCourierEviction: Boolean,
        useCourierReserve: Boolean = false,
        minimumEvictionPriority: Int = Int.MIN_VALUE,
    ): Boolean {
        require(incomingBytes in 1..RelayMeshEnvelope.MAX_ENCODED_BYTES) {
            "Invalid stored envelope length."
        }
        val countLimit = if (useCourierReserve) COURIER_ENVELOPE_LIMIT else HARD_ENVELOPE_LIMIT
        val byteLimit = if (useCourierReserve) COURIER_WIRE_BYTES_LIMIT else HARD_WIRE_BYTES_LIMIT
        var usage = envelopeUsage(database)
        fun fits(): Boolean =
            usage.count < countLimit && usage.wireBytes <= byteLimit - incomingBytes
        if (fits()) return true
        if (!allowCourierEviction) return false

        for (candidate in courierEvictionCandidates(database)) {
            if (candidate.envelope.priority < minimumEvictionPriority) continue
            database.delete(
                TABLE_ENVELOPES,
                "hex($COLUMN_MESSAGE_ID) = ?",
                arrayOf(candidate.messageId.toSqlHex()),
            )
            usage = EnvelopeUsage(
                count = usage.count - 1,
                wireBytes = usage.wireBytes - candidate.encodedBytes,
            )
            if (fits()) return true
        }
        return false
    }

    private fun envelopeUsage(database: SQLiteDatabase): EnvelopeUsage = database.rawQuery(
        "SELECT COUNT(*), COALESCE(SUM(length($COLUMN_WIRE_ENVELOPE)), 0) " +
            "FROM $TABLE_ENVELOPES",
        null,
    ).use { cursor ->
        check(cursor.moveToFirst()) { "Envelope usage query returned no row." }
        EnvelopeUsage(cursor.getInt(0), cursor.getLong(1))
    }

    private fun courierEvictionCandidates(database: SQLiteDatabase): List<EvictionCandidate> {
        val result = mutableListOf<EvictionCandidate>()
        database.rawQuery(
            "SELECT e.$COLUMN_MESSAGE_ID, e.$COLUMN_WIRE_ENVELOPE, " +
                "e.$COLUMN_CREATED_AT " +
                "FROM $TABLE_ENVELOPES e " +
                "LEFT JOIN $TABLE_MESH_MESSAGES m " +
                "ON m.$COLUMN_MESSAGE_ID = e.$COLUMN_MESSAGE_ID " +
                "AND m.$COLUMN_DIRECTION = ? " +
                "LEFT JOIN $TABLE_DELIVERY_RECEIPTS r " +
                "ON r.$COLUMN_RECEIPT_ENVELOPE_ID = e.$COLUMN_MESSAGE_ID " +
                "WHERE m.$COLUMN_MESSAGE_ID IS NULL " +
                "AND r.$COLUMN_RECEIPT_ENVELOPE_ID IS NULL",
            arrayOf(Direction.OUTGOING.databaseValue.toString()),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val wire = cursor.getBlob(1)
                result += EvictionCandidate(
                    messageId = cursor.getBlob(0),
                    envelope = RelayMeshEnvelope.decode(wire),
                    createdAtMs = cursor.getLong(2),
                    encodedBytes = wire.size.toLong(),
                )
            }
        }
        return result.sortedWith(
            compareByDescending<EvictionCandidate> { it.envelope.priority }
                .thenBy { it.createdAtMs },
        )
    }

    private fun findEnvelope(database: SQLiteDatabase, id: ByteArray): ByteArray? =
        database.query(
            TABLE_ENVELOPES,
            arrayOf(COLUMN_WIRE_ENVELOPE),
            "hex($COLUMN_MESSAGE_ID) = ?",
            arrayOf(id.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) cursor.getBlob(0) else null }

    private fun findStoredEnvelope(database: SQLiteDatabase, id: ByteArray): StoredEnvelope? =
        database.query(
            TABLE_ENVELOPES,
            arrayOf(COLUMN_WIRE_ENVELOPE, COLUMN_AGE_MS, COLUMN_AGE_ANCHOR_ELAPSED_MS, COLUMN_CREATED_AT),
            "hex($COLUMN_MESSAGE_ID) = ?",
            arrayOf(id.toSqlHex()),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            if (!cursor.moveToFirst()) null else StoredEnvelope(
                messageId = id,
                envelope = RelayMeshEnvelope.decode(cursor.getBlob(0)),
                ageMs = cursor.getLong(1),
                ageAnchorElapsedMs = cursor.getLong(2),
                createdAtMs = cursor.getLong(3),
                localRatchetSequence = null,
            )
        }

    private fun wasForwarded(
        database: SQLiteDatabase,
        id: ByteArray,
        peerFingerprint: String,
    ): Boolean = database.query(
        TABLE_FORWARDED,
        arrayOf(COLUMN_MESSAGE_ID),
        "hex($COLUMN_MESSAGE_ID) = ? AND $COLUMN_PEER_FINGERPRINT = ?",
        arrayOf(id.toSqlHex(), peerFingerprint),
        null,
        null,
        null,
        "1",
    ).use(Cursor::moveToFirst)

    private fun encryptContactBundle(
        fingerprint: String,
        label: ByteArray,
        bundle: ByteArray,
    ): EncryptedValue = encryptSecret(contactAad(fingerprint, label), bundle)

    private fun decryptContactBundle(
        fingerprint: String,
        label: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray = decryptSecret(contactAad(fingerprint, label), nonce, ciphertext).also {
        check(it.size == RelayContactCard.CONTACT_BUNDLE_BYTES) { "Stored contact bundle is invalid." }
        RelayNative.e2eRelayId(it)
    }

    private fun encryptMessage(
        id: ByteArray,
        fingerprint: String,
        direction: Direction,
        encodedMessage: ByteArray,
        contentVersion: Int,
    ): EncryptedValue = encryptSecret(
        messageAad(id, fingerprint, direction, contentVersion),
        encodedMessage,
    )

    private fun decryptMessage(
        id: ByteArray,
        fingerprint: String,
        direction: Direction,
        nonce: ByteArray,
        ciphertext: ByteArray,
        contentVersion: Int,
    ): RelayMessageCodec.TextMessage {
        val plaintext = decryptSecret(
            messageAad(id, fingerprint, direction, contentVersion),
            nonce,
            ciphertext,
        )
        return when (contentVersion) {
            1 -> RelayMessageCodec.restore(id, String(plaintext, StandardCharsets.UTF_8))
            LOCAL_CONTENT_VERSION -> RelayMessageCodec.decodeTrusted(plaintext).also { message ->
                check(message.id.contentEquals(id)) { "Stored mesh message ID is inconsistent." }
            }
            else -> error("Unsupported local mesh-message content version.")
        }
    }

    private fun messageFields(message: RelayMessageCodec.TextMessage): Map<String, Any> =
        buildMap {
            put("text", message.text)
            message.replyToMessageId?.let { replyId ->
                put("replyToMessageId", RelayMessageCodec.idHex(replyId))
                put("replyPreview", requireNotNull(message.replyPreview))
            }
        }

    private fun encryptSecret(aad: ByteArray, plaintext: ByteArray): EncryptedValue {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, storageKey())
        cipher.updateAAD(aad)
        return EncryptedValue(cipher.iv, cipher.doFinal(plaintext))
    }

    private fun decryptSecret(
        aad: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
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

    private fun contactAad(fingerprint: String, label: ByteArray): ByteArray =
        STORE_DOMAIN + label + fingerprint.toByteArray(StandardCharsets.UTF_8)

    private fun messageAad(
        id: ByteArray,
        fingerprint: String,
        direction: Direction,
        contentVersion: Int,
    ): ByteArray = STORE_DOMAIN + MESSAGE_LABEL + id +
        fingerprint.toByteArray(StandardCharsets.UTF_8) + direction.databaseValue.toByte() +
        if (contentVersion == 1) byteArrayOf() else byteArrayOf(contentVersion.toByte())

    private fun recipientAttachmentAad(
        objectId: ByteArray,
        fingerprint: String,
        courierPlanSha256: ByteArray,
    ): ByteArray = STORE_DOMAIN + RECIPIENT_ATTACHMENT_LABEL + objectId + courierPlanSha256 +
        fingerprint.toByteArray(StandardCharsets.UTF_8)

    private fun senderAttachmentCancellationAad(
        objectId: ByteArray,
        courierPlanSha256: ByteArray,
    ): ByteArray = STORE_DOMAIN + SENDER_ATTACHMENT_CANCELLATION_LABEL + objectId +
        courierPlanSha256

    private fun senderAttachmentCustodyAad(
        objectId: ByteArray,
        courierFingerprint: String,
        courierPlanSha256: ByteArray,
    ): ByteArray = STORE_DOMAIN + SENDER_ATTACHMENT_CUSTODY_LABEL + objectId +
        courierPlanSha256 + courierFingerprint.toByteArray(StandardCharsets.UTF_8)

    private fun requireFingerprint(fingerprint: String) {
        require(fingerprint.length in 16..256 && fingerprint.none(Char::isISOControl)) {
            "Invalid Hypha device fingerprint."
        }
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    private fun ByteArray.toSqlHex(): String = joinToString(separator = "") { byte ->
        "%02X".format(byte.toInt() and 0xFF)
    }

    private data class AccountState(
        val protectionKey: ByteArray,
        val accountPickle: ByteArray,
    )

    private data class EncryptedValue(
        val nonce: ByteArray,
        val ciphertext: ByteArray,
    )

    private data class GeneratedReceipt(
        val encrypted: E2eEncryptResult,
        val envelope: RelayMeshEnvelope,
    )

    private data class PendingOutgoingText(
        val messageId: ByteArray,
        val protectedText: EncryptedValue,
        val initialCopyBudget: Int?,
        val createdAtMs: Long,
        val contentVersion: Int,
    )

    private data class StoredEnvelope(
        val messageId: ByteArray,
        val envelope: RelayMeshEnvelope,
        val ageMs: Long,
        val ageAnchorElapsedMs: Long,
        val createdAtMs: Long,
        val localRatchetSequence: Long?,
    )

    private data class StoredSenderAttachmentReceipt(
        val objectId: ByteArray,
        val planSha256: ByteArray,
        val recipientFingerprint: String,
        val receiptEnvelopeId: ByteArray,
        val localApplied: Boolean,
        val createdAtMs: Long,
    )

    private data class EnvelopeUsage(val count: Int, val wireBytes: Long)

    private data class EvictionCandidate(
        val messageId: ByteArray,
        val envelope: RelayMeshEnvelope,
        val createdAtMs: Long,
        val encodedBytes: Long,
    )

    private enum class Direction(val databaseValue: Int, val wireValue: String) {
        INCOMING(0, "incoming"),
        OUTGOING(1, "outgoing");

        companion object {
            fun fromDatabase(value: Int): Direction = entries.first { it.databaseValue == value }
        }
    }

    private enum class MessageStatus(val databaseValue: Int, val wireValue: String) {
        QUEUED(0, "queued"),
        DELIVERED(1, "delivered"),
        RECEIVED(2, "received");

        companion object {
            fun fromDatabase(value: Int): MessageStatus =
                entries.first { it.databaseValue == value }
        }
    }

    private companion object {
        const val DATABASE_NAME = "relay_mesh.db"
        const val DATABASE_VERSION = 8
        const val LOCAL_CONTENT_VERSION = 2
        const val MAX_DIAGNOSTIC_COPY_BUDGET = 64
        const val MAX_PENDING_TEXTS_PER_CONTACT = 512
        const val MAX_PENDING_TEXTS_TOTAL = 10_000
        const val DEFAULT_HISTORY_PAGE_SIZE = 40
        const val MAX_HISTORY_PAGE_ITEMS = 101
        const val PENDING_TEXT_CONTACT_BATCH = 64
        const val PENDING_TEXT_EMIT_BATCH = 64
        const val HARD_ENVELOPE_LIMIT = 10_000
        const val HARD_WIRE_BYTES_LIMIT = 64L * 1024L * 1024L
        const val COURIER_ENVELOPE_LIMIT = 9_500
        const val COURIER_WIRE_BYTES_LIMIT = 60L * 1024L * 1024L
        const val CONSUMED_RETENTION_MS = 30L * 24L * 60L * 60L * 1_000L
        const val DELIVERY_RECEIPT_RETENTION_MS = 30L * 24L * 60L * 60L * 1_000L
        const val MAX_INACTIVE_DELIVERY_RECEIPTS = 10_000
        const val ENVELOPE_AGE_PERSIST_INTERVAL_MS = 60_000L
        const val STATE_KEY_BYTES = 32
        const val MAX_INVENTORY_IDS = 512
        const val RECEIPT_BACKFILL_LIMIT = 32
        const val UNIQUE_ID_ATTEMPTS = 8
        const val MAX_PENDING_RECIPIENT_ATTACHMENTS = 64
        const val MAX_PENDING_SENDER_ATTACHMENTS = 64
        const val CONTROL_PRIORITY = 0
        const val MANIFEST_PRIORITY = 4
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "project_relay_mesh_store_aes_v1"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val UNKNOWN_DISPLAY_NAME = "Nearby Hypha user"

        const val TABLE_STATE = "mesh_state"
        const val TABLE_CONTACTS = "contacts"
        const val TABLE_MESH_MESSAGES = "mesh_messages"
        const val TABLE_PENDING_MESH_TEXTS = "pending_mesh_texts"
        const val TABLE_ENVELOPES = "envelopes"
        const val TABLE_FORWARDED = "forwarded_envelopes"
        const val TABLE_CONSUMED_ENVELOPES = "consumed_envelopes"
        const val TABLE_DELIVERY_RECEIPTS = "delivery_receipts"
        const val TABLE_RECIPIENT_ATTACHMENT_MANIFESTS = "recipient_attachment_manifests"
        const val TABLE_SENDER_ATTACHMENT_OFFERS = "sender_attachment_offers"
        const val TABLE_SENDER_ATTACHMENT_CUSTODY = "sender_attachment_custody"
        const val TABLE_SENDER_ATTACHMENT_RECEIPTS = "sender_attachment_receipts"

        const val COLUMN_SINGLETON = "singleton"
        const val COLUMN_KEY_NONCE = "key_nonce"
        const val COLUMN_KEY_CIPHERTEXT = "key_ciphertext"
        const val COLUMN_ACCOUNT_PICKLE = "account_pickle"
        const val COLUMN_DEVICE_FINGERPRINT = "device_fingerprint"
        const val COLUMN_DISPLAY_NAME = "display_name"
        const val COLUMN_RELAY_ID = "relay_id"
        const val COLUMN_LOCAL_NONCE = "local_nonce"
        const val COLUMN_LOCAL_CIPHERTEXT = "local_ciphertext"
        const val COLUMN_REMOTE_NONCE = "remote_nonce"
        const val COLUMN_REMOTE_CIPHERTEXT = "remote_ciphertext"
        const val COLUMN_VERIFIED = "verified"
        const val COLUMN_SESSION_ROLE = "session_role"
        const val COLUMN_SESSION_PICKLE = "session_pickle"
        const val COLUMN_NEXT_OUTGOING_SEQUENCE = "next_outgoing_sequence"
        const val COLUMN_HIGHEST_INCOMING_SEQUENCE = "highest_incoming_sequence"
        const val COLUMN_SEQUENCE = "sequence"
        const val COLUMN_MESSAGE_ID = "message_id"
        const val COLUMN_PEER_FINGERPRINT = "peer_fingerprint"
        const val COLUMN_DIRECTION = "direction"
        const val COLUMN_TEXT_NONCE = "text_nonce"
        const val COLUMN_TEXT_CIPHERTEXT = "text_ciphertext"
        const val COLUMN_STATUS = "status"
        const val COLUMN_RATCHET_SEQUENCE = "ratchet_sequence"
        const val COLUMN_RECEIPT_GENERATED = "receipt_generated"
        const val COLUMN_IS_READ = "is_read"
        const val COLUMN_INITIAL_COPY_BUDGET = "initial_copy_budget"
        const val COLUMN_CONTENT_VERSION = "content_version"
        const val COLUMN_WIRE_ENVELOPE = "wire_envelope"
        const val COLUMN_ORIGIN_FINGERPRINT = "origin_fingerprint"
        const val COLUMN_CREATED_AT = "created_at_ms"
        const val COLUMN_UPDATED_AT = "updated_at_ms"
        const val COLUMN_FORWARDED_AT = "forwarded_at_ms"
        const val COLUMN_DELIVERED_MESSAGE_ID = "delivered_message_id"
        const val COLUMN_RECEIPT_ENVELOPE_ID = "receipt_envelope_id"
        const val COLUMN_CONSUMED_AT = "consumed_at_ms"
        const val COLUMN_GENERATED_AT = "generated_at_ms"
        const val COLUMN_OBJECT_ID = "object_id"
        const val COLUMN_COURIER_PLAN_SHA256 = "courier_plan_sha256"
        const val COLUMN_MANIFEST_NONCE = "manifest_nonce"
        const val COLUMN_MANIFEST_CIPHERTEXT = "manifest_ciphertext"
        const val COLUMN_RECIPIENT_FINGERPRINT = "recipient_fingerprint"
        const val COLUMN_COURIER_FINGERPRINT = "courier_fingerprint"
        const val COLUMN_WIRE_MANIFEST = "wire_manifest"
        const val COLUMN_WIRE_PLAN = "wire_plan"
        const val COLUMN_CANCEL_NONCE = "cancel_nonce"
        const val COLUMN_CANCEL_CIPHERTEXT = "cancel_ciphertext"
        const val COLUMN_RADIO_ELIGIBLE = "radio_eligible"
        const val COLUMN_CUSTODY_NONCE = "custody_nonce"
        const val COLUMN_CUSTODY_CIPHERTEXT = "custody_ciphertext"
        const val COLUMN_LOCAL_APPLIED = "local_applied"
        const val COLUMN_LIFETIME_MS = "lifetime_ms"
        const val COLUMN_AGE_MS = "age_ms"
        const val COLUMN_AGE_ANCHOR_ELAPSED_MS = "age_anchor_elapsed_ms"

        val STORE_DOMAIN = "ProjectRelay/mesh-store/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val STATE_KEY_AAD = STORE_DOMAIN + "state-key".toByteArray(StandardCharsets.UTF_8)
        val LOCAL_BUNDLE_LABEL = "local-bundle\u0000".toByteArray(StandardCharsets.UTF_8)
        val REMOTE_BUNDLE_LABEL = "remote-bundle\u0000".toByteArray(StandardCharsets.UTF_8)
        val MESSAGE_LABEL = "message\u0000".toByteArray(StandardCharsets.UTF_8)
        val RECIPIENT_ATTACHMENT_LABEL =
            "recipient-attachment-manifest\u0000".toByteArray(StandardCharsets.UTF_8)
        val SENDER_ATTACHMENT_CANCELLATION_LABEL =
            "sender-attachment-cancellation\u0000".toByteArray(StandardCharsets.UTF_8)
        val SENDER_ATTACHMENT_CUSTODY_LABEL =
            "sender-attachment-custody\u0000".toByteArray(StandardCharsets.UTF_8)

        val CONTACT_PROJECTION = arrayOf(
            COLUMN_DEVICE_FINGERPRINT,
            COLUMN_DISPLAY_NAME,
            COLUMN_RELAY_ID,
            COLUMN_LOCAL_NONCE,
            COLUMN_LOCAL_CIPHERTEXT,
            COLUMN_REMOTE_NONCE,
            COLUMN_REMOTE_CIPHERTEXT,
            COLUMN_VERIFIED,
            COLUMN_SESSION_ROLE,
            COLUMN_SESSION_PICKLE,
            COLUMN_NEXT_OUTGOING_SEQUENCE,
            COLUMN_HIGHEST_INCOMING_SEQUENCE,
        )
        val MESSAGE_PROJECTION = arrayOf(
            COLUMN_MESSAGE_ID,
            COLUMN_PEER_FINGERPRINT,
            COLUMN_DIRECTION,
            COLUMN_TEXT_NONCE,
            COLUMN_TEXT_CIPHERTEXT,
            COLUMN_STATUS,
            COLUMN_CREATED_AT,
            COLUMN_RATCHET_SEQUENCE,
            COLUMN_IS_READ,
            COLUMN_CONTENT_VERSION,
        )

        fun createUnreadIndex(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE INDEX IF NOT EXISTS mesh_messages_unread " +
                    "ON mesh_messages(peer_fingerprint, direction, is_read)",
            )
        }
        val RECIPIENT_ATTACHMENT_PROJECTION = arrayOf(
            COLUMN_OBJECT_ID,
            COLUMN_PEER_FINGERPRINT,
            COLUMN_COURIER_PLAN_SHA256,
            COLUMN_MANIFEST_NONCE,
            COLUMN_MANIFEST_CIPHERTEXT,
            COLUMN_RATCHET_SEQUENCE,
            COLUMN_LIFETIME_MS,
            COLUMN_AGE_MS,
        )
        val SENDER_ATTACHMENT_OFFER_PROJECTION = arrayOf(
            COLUMN_OBJECT_ID,
            COLUMN_RECIPIENT_FINGERPRINT,
            COLUMN_WIRE_MANIFEST,
            COLUMN_WIRE_PLAN,
            COLUMN_RATCHET_SEQUENCE,
            COLUMN_LIFETIME_MS,
            COLUMN_AGE_MS,
        )
    }
}
