package app.projectrelay.relay_mobile

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.SystemClock
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Courier-only durable storage for recipient-encrypted manifests and opaque chunks.
 *
 * This database intentionally has no contact, conversation, filename, MIME, content-key,
 * preview, sender, or recipient column. A hop custody bitmap is returned only after the
 * corresponding file and SQLite row are committed.
 */
internal class RelayCourierAttachmentStore(
    context: Context,
    private val quotaBytes: Long = RelayCourierAttachmentPolicy.ENGINEERING_QUOTA_BYTES,
    private val elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime,
    private val usableSpaceOverride: (() -> Long)? = null,
) : SQLiteOpenHelper(context.applicationContext, DATABASE_NAME, null, DATABASE_VERSION) {
    private val appContext = context.applicationContext
    private val random = SecureRandom()
    private val chunksRoot = File(appContext.filesDir, CHUNKS_DIRECTORY)
    private var lastRecoveryElapsedMs = Long.MIN_VALUE

    init {
        require(quotaBytes > 0L) { "Courier attachment quota must be positive." }
        setWriteAheadLoggingEnabled(true)
    }

    sealed interface PlanAcceptance {
        data class Accepted(
            val custody: ByteArray,
            val inserted: Boolean,
        ) : PlanAcceptance

        data object StoreFull : PlanAcceptance
        data object Expired : PlanAcceptance
        data object Terminal : PlanAcceptance
    }

    sealed interface ChunkAcceptance {
        data class Accepted(
            val custody: ByteArray,
            val inserted: Boolean,
        ) : ChunkAcceptance

        data object PlanMissing : ChunkAcceptance
        data object StoreFull : ChunkAcceptance
        data object Expired : ChunkAcceptance
        data object Terminal : ChunkAcceptance
    }

    data class Usage(
        val activePlans: Int,
        val storedChunks: Int,
        val reservedBytes: Long,
        val actualBytes: Long,
    )

    data class CleanupResult(
        val expiredPlans: Int,
        val invalidPlans: Int,
        val expiredTombstones: Int,
        val invalidChunks: Int,
        val orphanFiles: Int,
    )

    enum class CompletionResult {
        REMOVED,
        ALREADY_REMOVED,
        NOT_FOUND,
    }

    override fun onConfigure(database: SQLiteDatabase) {
        super.onConfigure(database)
        database.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE courier_attachment_plans (
                object_id BLOB PRIMARY KEY CHECK(length(object_id) = 16),
                plan_sha256 BLOB NOT NULL CHECK(length(plan_sha256) = 32),
                wire_manifest BLOB NOT NULL,
                wire_plan BLOB NOT NULL,
                lifetime_ms INTEGER NOT NULL CHECK(lifetime_ms > 0),
                age_ms INTEGER NOT NULL CHECK(age_ms >= 0 AND age_ms <= lifetime_ms),
                hop_limit INTEGER NOT NULL CHECK(hop_limit BETWEEN 1 AND 255),
                hops_taken INTEGER NOT NULL CHECK(hops_taken >= 0 AND hops_taken <= hop_limit),
                copy_budget INTEGER NOT NULL CHECK(copy_budget BETWEEN 1 AND 64),
                priority INTEGER NOT NULL CHECK(priority = 4),
                chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 512),
                total_ciphertext_bytes INTEGER NOT NULL CHECK(total_ciphertext_bytes > 0),
                reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes > 0),
                age_anchor_elapsed_ms INTEGER NOT NULL CHECK(age_anchor_elapsed_ms >= 0),
                accepted_elapsed_ms INTEGER NOT NULL CHECK(accepted_elapsed_ms >= 0)
            )
            """.trimIndent(),
        )
        database.execSQL(
            """
            CREATE TABLE courier_attachment_chunks (
                object_id BLOB NOT NULL REFERENCES courier_attachment_plans(object_id)
                    ON DELETE CASCADE,
                chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 511),
                ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes > 0),
                ciphertext_sha256 BLOB NOT NULL CHECK(length(ciphertext_sha256) = 32),
                record_bytes INTEGER NOT NULL CHECK(record_bytes > 72),
                committed_elapsed_ms INTEGER NOT NULL CHECK(committed_elapsed_ms >= 0),
                PRIMARY KEY(object_id, chunk_index)
            )
            """.trimIndent(),
        )
        database.execSQL(
            """
            CREATE TABLE courier_attachment_tombstones (
                object_id BLOB PRIMARY KEY CHECK(length(object_id) = 16),
                plan_sha256 BLOB NOT NULL CHECK(length(plan_sha256) = 32),
                reason INTEGER NOT NULL CHECK(reason IN (1, 2, 3)),
                age_ms INTEGER NOT NULL CHECK(age_ms >= 0),
                lifetime_ms INTEGER NOT NULL CHECK(lifetime_ms > 0 AND age_ms <= lifetime_ms),
                age_anchor_elapsed_ms INTEGER NOT NULL CHECK(age_anchor_elapsed_ms >= 0)
            )
            """.trimIndent(),
        )
        database.execSQL(
            "CREATE INDEX courier_attachment_age ON courier_attachment_plans(age_anchor_elapsed_ms)",
        )
    }

    override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        error("Unsupported courier attachment database migration $oldVersion to $newVersion")
    }

    /** Stores a canonical plan and recipient-encrypted RLY1 manifest before custody. */
    @Synchronized
    fun acceptPlan(
        encodedManifest: ByteArray,
        encodedPlan: ByteArray,
    ): PlanAcceptance {
        recoverIfDue()
        val envelope = RelayMeshEnvelope.decode(encodedManifest)
        val plan = RelayCourierAttachmentPlan.decode(encodedPlan)
        require(envelope.encode().contentEquals(encodedManifest)) {
            "Courier attachment manifest is not canonical."
        }
        require(envelope.messageId.contentEquals(plan.objectId)) {
            "Courier attachment manifest and plan IDs differ."
        }
        require(envelope.priority == MANIFEST_PRIORITY) {
            "Courier attachment manifest has the wrong priority."
        }
        if (envelope.ageMs >= envelope.lifetimeMs || envelope.hopsTaken >= envelope.hopLimit) {
            return PlanAcceptance.Expired
        }
        val planSha256 = plan.sha256()
        val database = writableDatabase
        if (findTombstone(database, plan.objectId) != null) return PlanAcceptance.Terminal
        findPlan(database, plan.objectId)?.let { existing ->
            requireSamePlan(existing, envelope, plan, planSha256)
            val age = advanceStoredAge(database, existing)
            if (age.expired || existing.envelope.hopsTaken >= existing.envelope.hopLimit) {
                terminalDelete(database, existing, TerminalReason.EXPIRED)
                deleteObjectDirectory(existing.plan.objectId)
                return PlanAcceptance.Terminal
            }
            return PlanAcceptance.Accepted(custodyFor(database, existing).encode(), inserted = false)
        }

        val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
        val requiredBytes = Math.addExact(plan.requiredStoredBytes(), encodedManifest.size.toLong())
        val usage = usage(database)
        if (usage.activePlans >= RelayCourierAttachmentPolicy.MAX_ACTIVE_PLANS ||
            !RelayCourierAttachmentPolicy.canAdmit(
                usedBytes = usage.reservedBytes,
                incomingBytes = requiredBytes,
                quotaBytes = quotaBytes,
                usableSpaceBytes = usableSpaceBytes(),
            )
        ) {
            return PlanAcceptance.StoreFull
        }
        val values = ContentValues().apply {
            put(COLUMN_OBJECT_ID, plan.objectId)
            put(COLUMN_PLAN_SHA256, planSha256)
            put(COLUMN_WIRE_MANIFEST, encodedManifest)
            put(COLUMN_WIRE_PLAN, encodedPlan)
            put(COLUMN_LIFETIME_MS, envelope.lifetimeMs)
            put(COLUMN_AGE_MS, envelope.ageMs)
            put(COLUMN_HOP_LIMIT, envelope.hopLimit)
            put(COLUMN_HOPS_TAKEN, envelope.hopsTaken)
            put(COLUMN_COPY_BUDGET, envelope.copyBudget)
            put(COLUMN_PRIORITY, envelope.priority)
            put(COLUMN_CHUNK_COUNT, plan.chunks.size)
            put(COLUMN_TOTAL_CIPHERTEXT_BYTES, plan.totalCiphertextBytes)
            put(COLUMN_RESERVED_BYTES, requiredBytes)
            put(COLUMN_AGE_ANCHOR_ELAPSED_MS, nowElapsedMs)
            put(COLUMN_ACCEPTED_ELAPSED_MS, nowElapsedMs)
        }
        check(database.insertOrThrow(TABLE_PLANS, null, values) > 0L) {
            "Courier attachment plan was not stored."
        }
        val stored = requireNotNull(findPlan(database, plan.objectId))
        return PlanAcceptance.Accepted(custodyFor(database, stored).encode(), inserted = true)
    }

    /**
     * Commits an opaque chunk file first, then its database row. The returned custody bit
     * therefore cannot get ahead of crash-consistent local bytes.
     */
    @Synchronized
    fun acceptChunk(encodedChunk: ByteArray): ChunkAcceptance {
        recoverIfDue()
        val chunk = RelayCourierAttachmentChunk.decode(encodedChunk)
        val database = writableDatabase
        if (findTombstone(database, chunk.objectId) != null) return ChunkAcceptance.Terminal
        val stored = findPlan(database, chunk.objectId) ?: return ChunkAcceptance.PlanMissing
        val age = advanceStoredAge(database, stored)
        if (age.expired || stored.envelope.hopsTaken >= stored.envelope.hopLimit) {
            terminalDelete(database, stored, TerminalReason.EXPIRED)
            deleteObjectDirectory(stored.plan.objectId)
            return ChunkAcceptance.Expired
        }
        chunk.verifyAgainst(stored.plan)

        findChunk(database, chunk.objectId, chunk.chunkIndex)?.let { existing ->
            requireSameChunk(existing, chunk, encodedChunk)
            return ChunkAcceptance.Accepted(custodyFor(database, stored).encode(), inserted = false)
        }
        if (!RelayCourierAttachmentPolicy.canAdmit(
                usedBytes = 0L,
                incomingBytes = encodedChunk.size.toLong(),
                quotaBytes = Long.MAX_VALUE,
                usableSpaceBytes = usableSpaceBytes(),
            )
        ) {
            return ChunkAcceptance.StoreFull
        }

        val file = chunkFile(chunk.objectId, chunk.chunkIndex)
        val created = writeExactRecord(file, encodedChunk)
        try {
            val values = ContentValues().apply {
                put(COLUMN_OBJECT_ID, chunk.objectId)
                put(COLUMN_CHUNK_INDEX, chunk.chunkIndex)
                put(COLUMN_CIPHERTEXT_BYTES, chunk.ciphertext.size)
                put(COLUMN_CIPHERTEXT_SHA256, chunk.ciphertextSha256)
                put(COLUMN_RECORD_BYTES, encodedChunk.size)
                put(COLUMN_COMMITTED_ELAPSED_MS, elapsedRealtimeMs().coerceAtLeast(0L))
            }
            check(database.insertOrThrow(TABLE_CHUNKS, null, values) > 0L) {
                "Courier attachment chunk was not stored."
            }
        } catch (error: Throwable) {
            if (created) runCatching { file.delete() }
            throw error
        }
        return ChunkAcceptance.Accepted(custodyFor(database, stored).encode(), inserted = true)
    }

    @Synchronized
    fun custody(objectId: ByteArray): ByteArray? {
        recoverIfDue()
        val database = writableDatabase
        val stored = findPlan(database, objectId) ?: return null
        val age = advanceStoredAge(database, stored)
        if (age.expired || stored.envelope.hopsTaken >= stored.envelope.hopLimit) {
            terminalDelete(database, stored, TerminalReason.EXPIRED)
            deleteObjectDirectory(stored.plan.objectId)
            return null
        }
        return custodyFor(database, stored).encode()
    }

    @Synchronized
    fun missingChunks(objectId: ByteArray): List<Int> = custody(objectId)
        ?.let(RelayCourierAttachmentCustody::decode)
        ?.missingChunks()
        .orEmpty()

    /** Returns only the canonical courier-visible HAP1 for an active durable object. */
    @Synchronized
    fun plan(objectId: ByteArray): ByteArray? {
        recoverIfDue()
        val database = writableDatabase
        val stored = findPlan(database, objectId) ?: return null
        val age = advanceStoredAge(database, stored)
        if (age.expired || stored.envelope.hopsTaken >= stored.envelope.hopLimit) {
            terminalDelete(database, stored, TerminalReason.EXPIRED)
            deleteObjectDirectory(stored.plan.objectId)
            return null
        }
        return stored.plan.encode()
    }

    /** Restart-safe opaque RLY1 bridge into the ordinary RMS2 forwarding store. */
    @Synchronized
    fun manifestsForMesh(limit: Int = RelayCourierAttachmentPolicy.MAX_ACTIVE_PLANS): List<ByteArray> {
        recoverIfDue()
        val database = writableDatabase
        return listPlans(database)
            .asSequence()
            .filter { stored -> custody(stored.plan.objectId) != null }
            .take(limit.coerceIn(1, RelayCourierAttachmentPolicy.MAX_ACTIVE_PLANS))
            .map { stored -> stored.encodedManifest.copyOf() }
            .toList()
    }

    @Synchronized
    fun readChunk(objectId: ByteArray, chunkIndex: Int): ByteArray {
        recoverIfDue()
        val database = writableDatabase
        val stored = requireNotNull(findPlan(database, objectId)) { "Courier plan was not found." }
        val age = advanceStoredAge(database, stored)
        if (age.expired || stored.envelope.hopsTaken >= stored.envelope.hopLimit) {
            terminalDelete(database, stored, TerminalReason.EXPIRED)
            deleteObjectDirectory(stored.plan.objectId)
            throw IllegalStateException("Courier plan expired before forwarding.")
        }
        val row = requireNotNull(findChunk(database, objectId, chunkIndex)) {
            "Courier chunk was not found."
        }
        val encoded = readAndValidateChunk(row, stored.plan)
            ?: throw IllegalStateException("Courier chunk file is missing or corrupt.")
        return encoded
    }

    /** A valid cancellation preimage removes only the matching opaque object. */
    @Synchronized
    fun applyCancellation(objectId: ByteArray, cancelSecret: ByteArray): Boolean {
        require(cancelSecret.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier cancellation secret is invalid."
        }
        recoverIfDue()
        val database = writableDatabase
        findTombstone(database, objectId)?.let { return it.reason == TerminalReason.CANCELLED }
        val stored = findPlan(database, objectId) ?: return false
        require(
            MessageDigest.isEqual(
                RelayCourierAttachmentPlan.digest(cancelSecret),
                stored.plan.cancellationCommitment,
            ),
        ) { "Courier cancellation secret does not match." }
        terminalDelete(database, stored, TerminalReason.CANCELLED)
        deleteObjectDirectory(objectId)
        return true
    }

    /** Applies only a recipient-authenticated receipt already verified by the E2E layer. */
    @Synchronized
    fun applyRecipientReceipt(objectId: ByteArray, planSha256: ByteArray): Boolean {
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier receipt plan digest is invalid."
        }
        recoverIfDue()
        val database = writableDatabase
        findTombstone(database, objectId)?.let { tombstone ->
            require(MessageDigest.isEqual(tombstone.planSha256, planSha256)) {
                "Courier receipt conflicts with a terminal object."
            }
            return tombstone.reason == TerminalReason.RECIPIENT_RECEIPT
        }
        val stored = findPlan(database, objectId) ?: return false
        require(MessageDigest.isEqual(stored.planSha256, planSha256)) {
            "Courier receipt does not match the stored plan."
        }
        terminalDelete(database, stored, TerminalReason.RECIPIENT_RECEIPT)
        deleteObjectDirectory(objectId)
        return true
    }

    /**
     * Deletes an active courier copy only when HAP1's existing cancellation commitment proves
     * sender authorization. The sender releases this proof only after authenticating HAR1.
     */
    @Synchronized
    fun applyRecipientCompletion(cleanup: RelayCourierAttachmentCleanup): CompletionResult {
        cleanup.validate()
        recoverIfDue()
        val database = writableDatabase
        findTombstone(database, cleanup.objectId)?.let { tombstone ->
            require(MessageDigest.isEqual(tombstone.planSha256, cleanup.planSha256)) {
                "Courier completion conflicts with a terminal object."
            }
            return if (tombstone.reason == TerminalReason.RECIPIENT_RECEIPT) {
                CompletionResult.ALREADY_REMOVED
            } else {
                CompletionResult.NOT_FOUND
            }
        }
        val stored = findPlan(database, cleanup.objectId) ?: return CompletionResult.NOT_FOUND
        require(MessageDigest.isEqual(stored.planSha256, cleanup.planSha256)) {
            "Courier completion does not match the stored plan."
        }
        require(
            MessageDigest.isEqual(
                RelayCourierAttachmentPlan.digest(cleanup.cancellationSecret),
                stored.plan.cancellationCommitment,
            ),
        ) { "Courier completion secret does not match." }
        terminalDelete(database, stored, TerminalReason.RECIPIENT_RECEIPT)
        deleteObjectDirectory(cleanup.objectId)
        return CompletionResult.REMOVED
    }

    @Synchronized
    fun usage(): Usage {
        recoverIfDue()
        return usage(readableDatabase)
    }

    /** Repairs restart uncertainty, advances monotonic age, and removes only safe garbage. */
    @Synchronized
    fun recover(): CleanupResult {
        val database = writableDatabase
        val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
        val objectDirectoriesToDelete = mutableListOf<ByteArray>()
        var expiredPlans = 0
        var invalidPlans = 0
        var expiredTombstones = 0
        var invalidChunks = 0

        database.beginTransaction()
        try {
            val rawPlanIds = listPlanIds(database)
            val plans = listPlans(database)
            val decodedIds = plans.map { it.plan.objectId.toHex() }.toHashSet()
            rawPlanIds.filter { it.toHex() !in decodedIds }.forEach { invalidId ->
                database.delete(
                    TABLE_PLANS,
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(invalidId.sqlHex()),
                )
                objectDirectoriesToDelete += invalidId
                invalidPlans += 1
            }
            plans.forEach { stored ->
                val age = runCatching { advanceStoredAge(database, stored, nowElapsedMs) }.getOrNull()
                val valid = age != null && runCatching { validateStoredPlan(stored) }.isSuccess
                if (!valid || age.expired || stored.envelope.hopsTaken >= stored.envelope.hopLimit) {
                    expirePlan(database, stored, nowElapsedMs)
                    objectDirectoriesToDelete += stored.plan.objectId
                    expiredPlans += 1
                } else {
                    listChunks(database, stored.plan.objectId).forEach { row ->
                        if (readAndValidateChunk(row, stored.plan) == null) {
                            database.delete(
                                TABLE_CHUNKS,
                                "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_CHUNK_INDEX = ?",
                                arrayOf(stored.plan.objectId.sqlHex(), row.chunkIndex.toString()),
                            )
                            runCatching { chunkFile(stored.plan.objectId, row.chunkIndex).delete() }
                            invalidChunks += 1
                        }
                    }
                }
            }
            listTombstones(database).forEach { tombstone ->
                val age = RelayCourierAttachmentPolicy.advanceAge(
                    tombstone.ageMs,
                    tombstone.lifetimeMs,
                    tombstone.ageAnchorElapsedMs,
                    nowElapsedMs,
                )
                if (age.expired) {
                    database.delete(
                        TABLE_TOMBSTONES,
                        "hex($COLUMN_OBJECT_ID) = ?",
                        arrayOf(tombstone.objectId.sqlHex()),
                    )
                    expiredTombstones += 1
                } else {
                    database.update(
                        TABLE_TOMBSTONES,
                        ContentValues().apply {
                            put(COLUMN_AGE_MS, age.ageMs)
                            put(COLUMN_AGE_ANCHOR_ELAPSED_MS, age.anchorElapsedMs)
                        },
                        "hex($COLUMN_OBJECT_ID) = ?",
                        arrayOf(tombstone.objectId.sqlHex()),
                    )
                }
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
        objectDirectoriesToDelete.forEach(::deleteObjectDirectory)
        val orphanFiles = pruneOrphanFiles(database)
        lastRecoveryElapsedMs = nowElapsedMs
        return CleanupResult(
            expiredPlans,
            invalidPlans,
            expiredTombstones,
            invalidChunks,
            orphanFiles,
        )
    }

    private fun recoverIfDue() {
        val nowElapsedMs = elapsedRealtimeMs().coerceAtLeast(0L)
        if (lastRecoveryElapsedMs == Long.MIN_VALUE ||
            nowElapsedMs < lastRecoveryElapsedMs ||
            nowElapsedMs - lastRecoveryElapsedMs >= RECOVERY_INTERVAL_MS
        ) {
            recover()
        }
    }

    private fun validateStoredPlan(stored: StoredPlan) {
        stored.plan.validate()
        require(stored.envelope.encode().contentEquals(stored.encodedManifest))
        require(stored.plan.encode().contentEquals(stored.encodedPlan))
        require(stored.envelope.messageId.contentEquals(stored.plan.objectId))
        require(MessageDigest.isEqual(stored.plan.sha256(), stored.planSha256))
        require(stored.envelope.lifetimeMs == stored.lifetimeMs)
        require(stored.envelope.hopLimit == stored.hopLimit)
        require(stored.envelope.hopsTaken == stored.hopsTaken)
        require(stored.envelope.copyBudget == stored.copyBudget)
        require(stored.envelope.priority == stored.priority)
        require(stored.envelope.priority == MANIFEST_PRIORITY)
        require(stored.plan.chunks.size == stored.chunkCount)
        require(stored.plan.totalCiphertextBytes == stored.totalCiphertextBytes)
        require(
            stored.reservedBytes == Math.addExact(
                stored.plan.requiredStoredBytes(),
                stored.encodedManifest.size.toLong(),
            ),
        )
    }

    private fun requireSamePlan(
        stored: StoredPlan,
        envelope: RelayMeshEnvelope,
        plan: RelayCourierAttachmentPlan,
        planSha256: ByteArray,
    ) {
        validateStoredPlan(stored)
        require(MessageDigest.isEqual(stored.planSha256, planSha256)) {
            "A conflicting courier plan reused an object ID."
        }
        require(stored.plan.encode().contentEquals(plan.encode())) {
            "A conflicting courier plan reused an object ID."
        }
        require(
            stored.envelope.destinationHint.contentEquals(envelope.destinationHint) &&
                stored.envelope.lifetimeMs == envelope.lifetimeMs &&
                stored.envelope.hopLimit == envelope.hopLimit &&
                stored.envelope.priority == envelope.priority &&
                stored.envelope.ciphertext.contentEquals(envelope.ciphertext),
        ) { "A conflicting recipient manifest reused a courier object ID." }
    }

    private fun requireSameChunk(
        row: StoredChunk,
        chunk: RelayCourierAttachmentChunk,
        encodedChunk: ByteArray,
    ) {
        require(
            row.ciphertextBytes == chunk.ciphertext.size &&
                MessageDigest.isEqual(row.ciphertextSha256, chunk.ciphertextSha256) &&
                row.recordBytes == encodedChunk.size &&
                readRecordFile(chunkFile(chunk.objectId, chunk.chunkIndex))?.contentEquals(encodedChunk) == true,
        ) { "A conflicting courier chunk reused an object ID and index." }
    }

    private fun advanceStoredAge(
        database: SQLiteDatabase,
        stored: StoredPlan,
        nowElapsedMs: Long = elapsedRealtimeMs().coerceAtLeast(0L),
    ): RelayCourierAttachmentPolicy.AgeResult {
        val age = RelayCourierAttachmentPolicy.advanceAge(
            stored.ageMs,
            stored.lifetimeMs,
            stored.ageAnchorElapsedMs,
            nowElapsedMs,
        )
        database.update(
            TABLE_PLANS,
            ContentValues().apply {
                put(COLUMN_AGE_MS, age.ageMs)
                put(COLUMN_AGE_ANCHOR_ELAPSED_MS, age.anchorElapsedMs)
            },
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(stored.plan.objectId.sqlHex()),
        )
        return age
    }

    private fun expirePlan(database: SQLiteDatabase, stored: StoredPlan, nowElapsedMs: Long) {
        insertTombstone(database, stored, TerminalReason.EXPIRED, nowElapsedMs)
        database.delete(
            TABLE_PLANS,
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(stored.plan.objectId.sqlHex()),
        )
    }

    private fun terminalDelete(
        database: SQLiteDatabase,
        stored: StoredPlan,
        reason: TerminalReason,
    ) {
        database.beginTransaction()
        try {
            insertTombstone(database, stored, reason, elapsedRealtimeMs().coerceAtLeast(0L))
            check(
                database.delete(
                    TABLE_PLANS,
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(stored.plan.objectId.sqlHex()),
                ) == 1,
            ) { "Courier terminal cleanup changed unexpectedly." }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    private fun insertTombstone(
        database: SQLiteDatabase,
        stored: StoredPlan,
        reason: TerminalReason,
        nowElapsedMs: Long,
    ) {
        val tombstoneCount = database.rawQuery(
            "SELECT COUNT(*) FROM $TABLE_TOMBSTONES",
            null,
        ).use { cursor ->
            check(cursor.moveToFirst())
            cursor.getInt(0)
        }
        if (tombstoneCount >= MAX_TOMBSTONES) {
            val oldest = database.query(
                TABLE_TOMBSTONES,
                arrayOf(COLUMN_OBJECT_ID),
                null,
                null,
                null,
                null,
                "$COLUMN_AGE_MS DESC, $COLUMN_AGE_ANCHOR_ELAPSED_MS ASC",
                "1",
            ).use { cursor -> if (cursor.moveToFirst()) cursor.getBlob(0) else null }
            oldest?.let { objectId ->
                database.delete(
                    TABLE_TOMBSTONES,
                    "hex($COLUMN_OBJECT_ID) = ?",
                    arrayOf(objectId.sqlHex()),
                )
            }
        }
        val values = ContentValues().apply {
            put(COLUMN_OBJECT_ID, stored.plan.objectId)
            put(COLUMN_PLAN_SHA256, stored.planSha256)
            put(COLUMN_REASON, reason.databaseValue)
            put(COLUMN_AGE_MS, 0L)
            put(COLUMN_LIFETIME_MS, TOMBSTONE_RETENTION_MS)
            put(COLUMN_AGE_ANCHOR_ELAPSED_MS, nowElapsedMs)
        }
        database.insertWithOnConflict(
            TABLE_TOMBSTONES,
            null,
            values,
            SQLiteDatabase.CONFLICT_IGNORE,
        )
    }

    private fun custodyFor(
        database: SQLiteDatabase,
        stored: StoredPlan,
    ): RelayCourierAttachmentCustody = RelayCourierAttachmentCustody.fromCommitted(
        stored.plan,
        listChunks(database, stored.plan.objectId).map(StoredChunk::chunkIndex),
    )

    private fun usage(database: SQLiteDatabase): Usage {
        val planUsage = database.rawQuery(
            "SELECT COUNT(*), COALESCE(SUM($COLUMN_RESERVED_BYTES), 0), " +
                "COALESCE(SUM(length($COLUMN_WIRE_MANIFEST) + length($COLUMN_WIRE_PLAN)), 0) " +
                "FROM $TABLE_PLANS",
            null,
        ).use { cursor ->
            check(cursor.moveToFirst())
            Triple(cursor.getInt(0), cursor.getLong(1), cursor.getLong(2))
        }
        val chunkUsage = database.rawQuery(
            "SELECT COUNT(*), COALESCE(SUM($COLUMN_RECORD_BYTES), 0) FROM $TABLE_CHUNKS",
            null,
        ).use { cursor ->
            check(cursor.moveToFirst())
            cursor.getInt(0) to cursor.getLong(1)
        }
        return Usage(
            activePlans = planUsage.first,
            storedChunks = chunkUsage.first,
            reservedBytes = planUsage.second,
            actualBytes = Math.addExact(planUsage.third, chunkUsage.second),
        )
    }

    private fun findPlan(database: SQLiteDatabase, objectId: ByteArray): StoredPlan? {
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier object ID is invalid."
        }
        return database.query(
            TABLE_PLANS,
            PLAN_PROJECTION,
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.sqlHex()),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) readPlan(cursor) else null }
    }

    private fun listPlans(database: SQLiteDatabase): List<StoredPlan> {
        val plans = mutableListOf<StoredPlan>()
        database.query(TABLE_PLANS, PLAN_PROJECTION, null, null, null, null, null).use { cursor ->
            while (cursor.moveToNext()) {
                runCatching { readPlan(cursor) }.getOrNull()?.let(plans::add)
            }
        }
        return plans
    }

    private fun listPlanIds(database: SQLiteDatabase): List<ByteArray> {
        val ids = mutableListOf<ByteArray>()
        database.query(
            TABLE_PLANS,
            arrayOf(COLUMN_OBJECT_ID),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor -> while (cursor.moveToNext()) ids += cursor.getBlob(0) }
        return ids
    }

    private fun readPlan(cursor: Cursor): StoredPlan {
        val encodedManifest = cursor.getBlob(2)
        val encodedPlan = cursor.getBlob(3)
        return StoredPlan(
            plan = RelayCourierAttachmentPlan.decode(encodedPlan),
            envelope = RelayMeshEnvelope.decode(encodedManifest),
            planSha256 = cursor.getBlob(1),
            encodedManifest = encodedManifest,
            encodedPlan = encodedPlan,
            lifetimeMs = cursor.getLong(4),
            ageMs = cursor.getLong(5),
            ageAnchorElapsedMs = cursor.getLong(6),
            hopLimit = cursor.getInt(7),
            hopsTaken = cursor.getInt(8),
            copyBudget = cursor.getInt(9),
            priority = cursor.getInt(10),
            chunkCount = cursor.getInt(11),
            totalCiphertextBytes = cursor.getLong(12),
            reservedBytes = cursor.getLong(13),
        )
    }

    private fun findChunk(
        database: SQLiteDatabase,
        objectId: ByteArray,
        chunkIndex: Int,
    ): StoredChunk? = database.query(
        TABLE_CHUNKS,
        CHUNK_PROJECTION,
        "hex($COLUMN_OBJECT_ID) = ? AND $COLUMN_CHUNK_INDEX = ?",
        arrayOf(objectId.sqlHex(), chunkIndex.toString()),
        null,
        null,
        null,
        "1",
    ).use { cursor -> if (cursor.moveToFirst()) readChunk(cursor) else null }

    private fun listChunks(database: SQLiteDatabase, objectId: ByteArray): List<StoredChunk> {
        val chunks = mutableListOf<StoredChunk>()
        database.query(
            TABLE_CHUNKS,
            CHUNK_PROJECTION,
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.sqlHex()),
            null,
            null,
            "$COLUMN_CHUNK_INDEX ASC",
        ).use { cursor -> while (cursor.moveToNext()) chunks += readChunk(cursor) }
        return chunks
    }

    private fun readChunk(cursor: Cursor): StoredChunk = StoredChunk(
        objectId = cursor.getBlob(0),
        chunkIndex = cursor.getInt(1),
        ciphertextBytes = cursor.getInt(2),
        ciphertextSha256 = cursor.getBlob(3),
        recordBytes = cursor.getInt(4),
    )

    private fun readAndValidateChunk(
        row: StoredChunk,
        plan: RelayCourierAttachmentPlan,
    ): ByteArray? = runCatching {
        val encoded = requireNotNull(readRecordFile(chunkFile(row.objectId, row.chunkIndex)))
        require(encoded.size == row.recordBytes)
        val chunk = RelayCourierAttachmentChunk.decode(encoded)
        chunk.verifyAgainst(plan)
        require(chunk.objectId.contentEquals(row.objectId))
        require(chunk.chunkIndex == row.chunkIndex)
        require(chunk.ciphertext.size == row.ciphertextBytes)
        require(MessageDigest.isEqual(chunk.ciphertextSha256, row.ciphertextSha256))
        encoded
    }.getOrNull()

    private fun findTombstone(database: SQLiteDatabase, objectId: ByteArray): Tombstone? =
        database.query(
            TABLE_TOMBSTONES,
            TOMBSTONE_PROJECTION,
            "hex($COLUMN_OBJECT_ID) = ?",
            arrayOf(objectId.sqlHex()),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) readTombstone(cursor) else null }

    private fun listTombstones(database: SQLiteDatabase): List<Tombstone> {
        val tombstones = mutableListOf<Tombstone>()
        database.query(
            TABLE_TOMBSTONES,
            TOMBSTONE_PROJECTION,
            null,
            null,
            null,
            null,
            null,
        ).use { cursor -> while (cursor.moveToNext()) tombstones += readTombstone(cursor) }
        return tombstones
    }

    private fun readTombstone(cursor: Cursor): Tombstone = Tombstone(
        objectId = cursor.getBlob(0),
        planSha256 = cursor.getBlob(1),
        reason = TerminalReason.fromDatabase(cursor.getInt(2)),
        ageMs = cursor.getLong(3),
        lifetimeMs = cursor.getLong(4),
        ageAnchorElapsedMs = cursor.getLong(5),
    )

    private fun writeExactRecord(target: File, encoded: ByteArray): Boolean {
        target.parentFile?.mkdirs()
        check(target.parentFile?.isDirectory == true) { "Courier chunk directory is unavailable." }
        if (target.exists()) {
            if (readRecordFile(target)?.contentEquals(encoded) == true) return false
            check(target.delete()) { "Conflicting orphan courier chunk could not be removed." }
        }
        val temporary = File(target.parentFile, ".${target.name}.${random.nextLong()}.tmp")
        try {
            FileOutputStream(temporary).use { output ->
                output.write(encoded)
                output.fd.sync()
            }
            check(temporary.renameTo(target)) { "Courier chunk could not be committed." }
            return true
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun readRecordFile(file: File): ByteArray? = runCatching {
        if (!file.isFile || file.length() !in MIN_RECORD_FILE_BYTES..MAX_RECORD_FILE_BYTES) return null
        file.readBytes()
    }.getOrNull()

    private fun pruneOrphanFiles(database: SQLiteDatabase): Int {
        if (!chunksRoot.exists()) return 0
        val referenced = mutableSetOf<String>()
        database.query(
            TABLE_CHUNKS,
            arrayOf(COLUMN_OBJECT_ID, COLUMN_CHUNK_INDEX),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) {
                referenced += chunkFile(cursor.getBlob(0), cursor.getInt(1)).absolutePath
            }
        }
        var deleted = 0
        chunksRoot.walkBottomUp().forEach { file ->
            when {
                file == chunksRoot -> Unit
                file.isFile && (file.name.endsWith(".tmp") || file.absolutePath !in referenced) -> {
                    if (file.delete()) deleted += 1
                }
                file.isDirectory && file.list().isNullOrEmpty() -> runCatching { file.delete() }
            }
        }
        return deleted
    }

    private fun chunkFile(objectId: ByteArray, chunkIndex: Int): File = File(
        File(chunksRoot, objectId.toHex()),
        "$chunkIndex.record",
    )

    private fun deleteObjectDirectory(objectId: ByteArray) {
        val directory = File(chunksRoot, objectId.toHex())
        if (!directory.isDirectory) return
        directory.listFiles().orEmpty().forEach { file -> runCatching { file.delete() } }
        runCatching { directory.delete() }
    }

    private fun usableSpaceBytes(): Long =
        usableSpaceOverride?.invoke()?.coerceAtLeast(0L) ?: appContext.filesDir.usableSpace

    private data class StoredPlan(
        val plan: RelayCourierAttachmentPlan,
        val envelope: RelayMeshEnvelope,
        val planSha256: ByteArray,
        val encodedManifest: ByteArray,
        val encodedPlan: ByteArray,
        val lifetimeMs: Long,
        val ageMs: Long,
        val ageAnchorElapsedMs: Long,
        val hopLimit: Int,
        val hopsTaken: Int,
        val copyBudget: Int,
        val priority: Int,
        val chunkCount: Int,
        val totalCiphertextBytes: Long,
        val reservedBytes: Long,
    )

    private data class StoredChunk(
        val objectId: ByteArray,
        val chunkIndex: Int,
        val ciphertextBytes: Int,
        val ciphertextSha256: ByteArray,
        val recordBytes: Int,
    )

    private data class Tombstone(
        val objectId: ByteArray,
        val planSha256: ByteArray,
        val reason: TerminalReason,
        val ageMs: Long,
        val lifetimeMs: Long,
        val ageAnchorElapsedMs: Long,
    )

    private enum class TerminalReason(val databaseValue: Int) {
        CANCELLED(1),
        RECIPIENT_RECEIPT(2),
        EXPIRED(3);

        companion object {
            fun fromDatabase(value: Int): TerminalReason = entries.first { it.databaseValue == value }
        }
    }

    private companion object {
        const val DATABASE_NAME = "relay_courier_attachments.db"
        const val DATABASE_VERSION = 1
        const val CHUNKS_DIRECTORY = "relay_courier_attachment_chunks_v1"
        const val TABLE_PLANS = "courier_attachment_plans"
        const val TABLE_CHUNKS = "courier_attachment_chunks"
        const val TABLE_TOMBSTONES = "courier_attachment_tombstones"
        const val MANIFEST_PRIORITY = 4
        const val TOMBSTONE_RETENTION_MS = 30L * 24L * 60L * 60L * 1_000L
        const val RECOVERY_INTERVAL_MS = 15L * 60L * 1_000L
        const val MAX_TOMBSTONES = 1_024
        const val MIN_RECORD_FILE_BYTES =
            (RelayCourierAttachmentChunk.HEADER_BYTES +
                RelayCourierAttachmentPlan.MIN_CHUNK_CIPHERTEXT_BYTES).toLong()
        const val MAX_RECORD_FILE_BYTES =
            (RelayCourierAttachmentChunk.HEADER_BYTES +
                RelayCourierAttachmentPlan.MAX_CHUNK_CIPHERTEXT_BYTES).toLong()

        const val COLUMN_OBJECT_ID = "object_id"
        const val COLUMN_PLAN_SHA256 = "plan_sha256"
        const val COLUMN_WIRE_MANIFEST = "wire_manifest"
        const val COLUMN_WIRE_PLAN = "wire_plan"
        const val COLUMN_LIFETIME_MS = "lifetime_ms"
        const val COLUMN_AGE_MS = "age_ms"
        const val COLUMN_HOP_LIMIT = "hop_limit"
        const val COLUMN_HOPS_TAKEN = "hops_taken"
        const val COLUMN_COPY_BUDGET = "copy_budget"
        const val COLUMN_PRIORITY = "priority"
        const val COLUMN_CHUNK_COUNT = "chunk_count"
        const val COLUMN_TOTAL_CIPHERTEXT_BYTES = "total_ciphertext_bytes"
        const val COLUMN_RESERVED_BYTES = "reserved_bytes"
        const val COLUMN_AGE_ANCHOR_ELAPSED_MS = "age_anchor_elapsed_ms"
        const val COLUMN_ACCEPTED_ELAPSED_MS = "accepted_elapsed_ms"
        const val COLUMN_CHUNK_INDEX = "chunk_index"
        const val COLUMN_CIPHERTEXT_BYTES = "ciphertext_bytes"
        const val COLUMN_CIPHERTEXT_SHA256 = "ciphertext_sha256"
        const val COLUMN_RECORD_BYTES = "record_bytes"
        const val COLUMN_COMMITTED_ELAPSED_MS = "committed_elapsed_ms"
        const val COLUMN_REASON = "reason"

        val PLAN_PROJECTION = arrayOf(
            COLUMN_OBJECT_ID,
            COLUMN_PLAN_SHA256,
            COLUMN_WIRE_MANIFEST,
            COLUMN_WIRE_PLAN,
            COLUMN_LIFETIME_MS,
            COLUMN_AGE_MS,
            COLUMN_AGE_ANCHOR_ELAPSED_MS,
            COLUMN_HOP_LIMIT,
            COLUMN_HOPS_TAKEN,
            COLUMN_COPY_BUDGET,
            COLUMN_PRIORITY,
            COLUMN_CHUNK_COUNT,
            COLUMN_TOTAL_CIPHERTEXT_BYTES,
            COLUMN_RESERVED_BYTES,
        )
        val CHUNK_PROJECTION = arrayOf(
            COLUMN_OBJECT_ID,
            COLUMN_CHUNK_INDEX,
            COLUMN_CIPHERTEXT_BYTES,
            COLUMN_CIPHERTEXT_SHA256,
            COLUMN_RECORD_BYTES,
        )
        val TOMBSTONE_PROJECTION = arrayOf(
            COLUMN_OBJECT_ID,
            COLUMN_PLAN_SHA256,
            COLUMN_REASON,
            COLUMN_AGE_MS,
            COLUMN_LIFETIME_MS,
            COLUMN_AGE_ANCHOR_ELAPSED_MS,
        )
    }
}

private fun ByteArray.sqlHex(): String = joinToString(separator = "") { byte ->
    "%02X".format(byte.toInt() and 0xFF)
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
    "%02x".format(byte.toInt() and 0xFF)
}
