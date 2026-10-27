package app.projectrelay.relay_mobile

import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.net.Uri
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Durable encrypted attachment queue and content-addressed chunk store. */
internal class RelayAttachmentStore(context: Context) :
    SQLiteOpenHelper(context.applicationContext, DATABASE_NAME, null, DATABASE_VERSION) {
    private val appContext = context.applicationContext
    private val random = SecureRandom()
    private val chunksRoot = File(appContext.filesDir, CHUNKS_DIRECTORY)
    private val exportsRoot = File(appContext.cacheDir, EXPORTS_DIRECTORY)
    private val previewSourcesRoot = File(appContext.cacheDir, PREVIEW_SOURCES_DIRECTORY)

    init {
        setWriteAheadLoggingEnabled(true)
    }

    enum class Direction(val databaseValue: Int, val wireValue: String) {
        INCOMING(0, "incoming"),
        OUTGOING(1, "outgoing");

        companion object {
            fun fromDatabase(value: Int): Direction = entries.first { it.databaseValue == value }
        }
    }

    enum class Status(val databaseValue: Int, val wireValue: String) {
        QUEUED(0, "queued"),
        TRANSFERRING(1, "transferring"),
        DELIVERED(2, "delivered"),
        READY(3, "ready");

        companion object {
            fun fromDatabase(value: Int): Status = entries.first { it.databaseValue == value }
        }
    }

    data class StoredAttachment(
        val manifest: RelayAttachmentManifest,
        val peerFingerprint: String,
        val direction: Direction,
        val status: Status,
        val createdAtMs: Long,
        val attemptCount: Int,
        val nextAttemptAtMs: Long?,
        val lastErrorCode: String?,
    ) {
        fun toMap(): Map<String, Any> = buildMap {
            put("attachmentId", manifest.attachmentId.toHex())
            put("peerFingerprint", peerFingerprint)
            put("direction", direction.wireValue)
            put("status", status.wireValue)
            put("kind", manifest.kind.name.lowercase())
            put("fileName", manifest.fileName)
            put("mimeType", manifest.mimeType)
            put("bytes", manifest.plaintextBytes)
            put("chunkCount", manifest.chunks.size)
            put("createdAtMs", createdAtMs)
            put("attemptCount", attemptCount)
            nextAttemptAtMs?.let { put("nextAttemptAtMs", it) }
            lastErrorCode?.let { put("lastErrorCode", it) }
        }
    }

    override fun onConfigure(database: SQLiteDatabase) {
        super.onConfigure(database)
        database.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE attachments (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                attachment_id BLOB NOT NULL UNIQUE CHECK(length(attachment_id) = 16),
                peer_fingerprint TEXT NOT NULL,
                direction INTEGER NOT NULL CHECK(direction IN (0, 1)),
                manifest_nonce BLOB NOT NULL CHECK(length(manifest_nonce) = 12),
                manifest_ciphertext BLOB NOT NULL,
                status INTEGER NOT NULL CHECK(status IN (0, 1, 2, 3)),
                created_at_ms INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                next_attempt_at_ms INTEGER,
                last_error_code TEXT
            )
            """.trimIndent(),
        )
        database.execSQL(
            "CREATE INDEX attachment_peer_sequence " +
                "ON attachments(peer_fingerprint, sequence)",
        )
        database.execSQL(
            "CREATE INDEX attachment_outbox_due " +
                "ON attachments(direction, status, next_attempt_at_ms, sequence)",
        )
    }

    override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        error("Unsupported attachment database migration $oldVersion to $newVersion")
    }

    fun importOutgoing(
        resolver: ContentResolver,
        uri: Uri,
        peerFingerprint: String,
        kind: RelayAttachmentManifest.Kind,
    ): StoredAttachment {
        require(peerFingerprint.isNotBlank()) { "A verified recipient is required." }
        val metadata = queryMetadata(resolver, uri)
        metadata.declaredBytes?.let { declared ->
            require(declared in 1..kind.maximumBytes) { "Selected attachment is too large." }
        }
        val fileName = RelayAttachmentManifest.normalizedFileName(
            metadata.displayName ?: uri.lastPathSegment.orEmpty(),
        )
        val mimeType = RelayAttachmentManifest.normalizedMimeType(
            resolver.getType(uri),
            kind,
        )
        val attachmentId = ByteArray(RelayAttachmentManifest.ATTACHMENT_ID_BYTES).also(random::nextBytes)
        val contentKey = ByteArray(RelayAttachmentManifest.CONTENT_KEY_BYTES).also(random::nextBytes)
        val plaintextDigest = MessageDigest.getInstance(DIGEST_ALGORITHM)
        val descriptors = mutableListOf<RelayAttachmentManifest.Chunk>()
        val newlyCreatedFiles = mutableListOf<File>()
        var totalBytes = 0L

        try {
            val input = requireNotNull(resolver.openInputStream(uri)) {
                "The selected attachment could not be opened."
            }
            input.use { stream ->
                val buffer = ByteArray(RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES)
                while (true) {
                    val plaintextBytes = stream.readUpTo(buffer)
                    if (plaintextBytes == 0) break
                    totalBytes += plaintextBytes
                    require(totalBytes <= kind.maximumBytes) { "Selected attachment is too large." }
                    plaintextDigest.update(buffer, 0, plaintextBytes)
                    val index = descriptors.size
                    require(index < RelayAttachmentManifest.MAX_CHUNKS) {
                        "Selected attachment has too many chunks."
                    }
                    val nonce = ByteArray(RelayAttachmentManifest.NONCE_BYTES).also(random::nextBytes)
                    val ciphertext = encryptContentChunk(
                        attachmentId,
                        index,
                        plaintextBytes,
                        contentKey,
                        nonce,
                        buffer,
                    )
                    val ciphertextDigest = MessageDigest.getInstance(DIGEST_ALGORITHM).digest(ciphertext)
                    writeContentAddressed(ciphertextDigest, ciphertext)?.let(newlyCreatedFiles::add)
                    descriptors += RelayAttachmentManifest.Chunk(
                        index = index,
                        plaintextBytes = plaintextBytes,
                        nonce = nonce,
                        ciphertextBytes = ciphertext.size,
                        ciphertextSha256 = ciphertextDigest,
                    )
                }
            }
            require(totalBytes > 0) { "Empty attachments cannot be sent." }
            metadata.declaredBytes?.let { declared ->
                require(declared == totalBytes) { "The selected attachment changed while reading." }
            }
            val manifest = RelayAttachmentManifest(
                attachmentId = attachmentId,
                kind = kind,
                fileName = fileName,
                mimeType = mimeType,
                plaintextBytes = totalBytes,
                chunkSize = RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES,
                contentKey = contentKey,
                plaintextSha256 = plaintextDigest.digest(),
                chunks = descriptors,
            ).also(RelayAttachmentManifest::validate)
            insertManifest(manifest, peerFingerprint, Direction.OUTGOING, Status.QUEUED)
            return requireNotNull(findById(manifest.attachmentId))
        } catch (error: Throwable) {
            newlyCreatedFiles.forEach { file -> runCatching { file.delete() } }
            contentKey.fill(0)
            throw error
        }
    }

    fun acceptIncoming(peerFingerprint: String, encodedManifest: ByteArray): StoredAttachment {
        require(peerFingerprint.isNotBlank()) { "A verified sender is required." }
        val manifest = RelayAttachmentManifest.decode(encodedManifest)
        findById(manifest.attachmentId)?.let { existing ->
            check(
                existing.peerFingerprint == peerFingerprint &&
                    existing.direction == Direction.INCOMING &&
                    existing.manifest.encode().contentEquals(encodedManifest),
            ) { "Attachment ID collision or manifest mismatch." }
            return existing
        }
        insertManifest(manifest, peerFingerprint, Direction.INCOMING, Status.TRANSFERRING)
        return requireNotNull(findById(manifest.attachmentId))
    }

    fun findByHexId(idHex: String): StoredAttachment? {
        if (idHex.length != RelayAttachmentManifest.ATTACHMENT_ID_BYTES * 2 ||
            !idHex.all { character -> character.isHexDigit() }
        ) {
            return null
        }
        return findByHex(readableDatabase, idHex.uppercase())
    }

    fun listRecent(limit: Int = 200): List<StoredAttachment> {
        val attachments = mutableListOf<StoredAttachment>()
        readableDatabase.query(
            TABLE_ATTACHMENTS,
            PROJECTION,
            null,
            null,
            null,
            null,
            "$COLUMN_SEQUENCE DESC",
            limit.coerceIn(1, 500).toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) attachments += readStored(cursor)
        }
        attachments.reverse()
        return attachments
    }

    fun oldestQueuedForPeer(peerFingerprint: String, nowMs: Long = System.currentTimeMillis()):
        StoredAttachment? = readableDatabase.query(
        TABLE_ATTACHMENTS,
        PROJECTION,
        "$COLUMN_PEER_FINGERPRINT = ? AND $COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ? AND " +
            "($COLUMN_NEXT_ATTEMPT_AT IS NULL OR $COLUMN_NEXT_ATTEMPT_AT <= ?)",
        arrayOf(
            peerFingerprint,
            Direction.OUTGOING.databaseValue.toString(),
            Status.QUEUED.databaseValue.toString(),
            nowMs.toString(),
        ),
        null,
        null,
        "$COLUMN_SEQUENCE ASC",
        "1",
    ).use { cursor -> if (cursor.moveToFirst()) readStored(cursor) else null }

    fun queuedBacklogBytes(peerFingerprint: String): Long = listRecent(500)
        .asSequence()
        .filter {
            it.peerFingerprint == peerFingerprint &&
                it.direction == Direction.OUTGOING && it.status == Status.QUEUED
        }
        .fold(0L) { total, attachment ->
            val bytes = attachment.manifest.plaintextBytes
            if (Long.MAX_VALUE - total < bytes) Long.MAX_VALUE else total + bytes
        }

    /** Requeues only sender work that could not survive a prior process death. */
    fun recoverInterruptedOutgoing(): Int = writableDatabase.update(
        TABLE_ATTACHMENTS,
        ContentValues().apply {
            put(COLUMN_STATUS, Status.QUEUED.databaseValue)
            putNull(COLUMN_NEXT_ATTEMPT_AT)
            put(COLUMN_LAST_ERROR_CODE, "process_interrupted")
        },
        "$COLUMN_DIRECTION = ? AND $COLUMN_STATUS = ?",
        arrayOf(
            Direction.OUTGOING.databaseValue.toString(),
            Status.TRANSFERRING.databaseValue.toString(),
        ),
    )

    fun beginAttempt(attachmentId: ByteArray): StoredAttachment {
        val existing = requireNotNull(findById(attachmentId)) { "Queued attachment was not found." }
        check(existing.direction == Direction.OUTGOING && existing.status == Status.QUEUED) {
            "Only queued outgoing attachments can be attempted."
        }
        val values = ContentValues().apply {
            put(COLUMN_STATUS, Status.TRANSFERRING.databaseValue)
            put(COLUMN_ATTEMPT_COUNT, existing.attemptCount + 1)
            putNull(COLUMN_NEXT_ATTEMPT_AT)
            putNull(COLUMN_LAST_ERROR_CODE)
        }
        updateById(attachmentId, values)
        return requireNotNull(findById(attachmentId))
    }

    fun markRetryable(
        attachmentId: ByteArray,
        code: String,
        retryDelayOverrideMs: Long? = null,
    ) {
        val existing = findById(attachmentId) ?: return
        if (existing.direction != Direction.OUTGOING ||
            existing.status == Status.DELIVERED ||
            isCancelled(existing)
        ) {
            return
        }
        val exponent = (existing.attemptCount - 1).coerceIn(0, MAX_BACKOFF_EXPONENT)
        val retryDelay = retryDelayOverrideMs?.coerceIn(RETRY_BASE_MS, RETRY_MAX_MS)
            ?: (RETRY_BASE_MS shl exponent).coerceAtMost(RETRY_MAX_MS)
        val retryAt = System.currentTimeMillis() + retryDelay
        updateById(
            attachmentId,
            ContentValues().apply {
                put(COLUMN_STATUS, Status.QUEUED.databaseValue)
                put(COLUMN_NEXT_ATTEMPT_AT, retryAt)
                put(COLUMN_LAST_ERROR_CODE, code.take(MAX_ERROR_CODE_CHARS))
            },
        )
    }

    /** Removes encrypted sender copies after delivery/cancellation. */
    fun pruneReleasedPayloads(): Pair<Int, Long> = synchronized(PAYLOAD_CLEANUP_LOCK) {
        val stored = listAll()
        val retainedDigests = stored.asSequence()
            .filter(::retainsPayload)
            .flatMap { it.manifest.chunks.asSequence() }
            .map { it.ciphertextSha256.toHex() }
            .toHashSet()
        var deletedFiles = 0
        var deletedBytes = 0L
        stored.asSequence()
            .filterNot(::retainsPayload)
            .flatMap { it.manifest.chunks.asSequence() }
            .forEach { chunk ->
                if (chunk.ciphertextSha256.toHex() in retainedDigests) return@forEach
                val file = chunkFile(chunk.ciphertextSha256)
                val bytes = file.length()
                if (file.isFile && file.delete()) {
                    deletedFiles += 1
                    deletedBytes += bytes
                }
            }
        deletedFiles to deletedBytes
    }

    fun markPaused(attachmentId: ByteArray): StoredAttachment {
        val existing = requireNotNull(findById(attachmentId)) { "Attachment was not found." }
        check(existing.direction == Direction.OUTGOING && existing.status != Status.DELIVERED) {
            "Only an unfinished outgoing attachment can be paused."
        }
        updateById(
            attachmentId,
            ContentValues().apply {
                put(COLUMN_STATUS, Status.QUEUED.databaseValue)
                put(COLUMN_NEXT_ATTEMPT_AT, Long.MAX_VALUE)
                put(COLUMN_LAST_ERROR_CODE, USER_PAUSED_CODE)
            },
        )
        return requireNotNull(findById(attachmentId))
    }

    fun markResumed(attachmentId: ByteArray): StoredAttachment {
        val existing = requireNotNull(findById(attachmentId)) { "Attachment was not found." }
        check(
            existing.direction == Direction.OUTGOING &&
                existing.status == Status.QUEUED &&
                isPaused(existing)
        ) {
            "Only a paused outgoing attachment can be resumed."
        }
        updateById(
            attachmentId,
            ContentValues().apply {
                putNull(COLUMN_NEXT_ATTEMPT_AT)
                putNull(COLUMN_LAST_ERROR_CODE)
            },
        )
        return requireNotNull(findById(attachmentId))
    }

    fun markCancelled(attachmentId: ByteArray): StoredAttachment {
        val existing = requireNotNull(findById(attachmentId)) { "Attachment was not found." }
        check(existing.direction == Direction.OUTGOING && existing.status != Status.DELIVERED) {
            "Only an unfinished outgoing attachment can be cancelled."
        }
        updateById(
            attachmentId,
            ContentValues().apply {
                put(COLUMN_STATUS, Status.QUEUED.databaseValue)
                put(COLUMN_NEXT_ATTEMPT_AT, Long.MAX_VALUE)
                put(COLUMN_LAST_ERROR_CODE, USER_CANCELLED_CODE)
            },
        )
        return requireNotNull(findById(attachmentId)).also {
            releasePayloadIfUnused(it)
        }
    }

    fun isCancelled(attachment: StoredAttachment): Boolean =
        attachment.lastErrorCode == USER_CANCELLED_CODE

    fun isPaused(attachment: StoredAttachment): Boolean =
        attachment.lastErrorCode == USER_PAUSED_CODE

    fun markDelivered(attachmentId: ByteArray) {
        val existing = requireNotNull(findById(attachmentId)) { "Outgoing attachment was not found." }
        check(existing.direction == Direction.OUTGOING) { "Only outgoing attachments are delivered." }
        updateById(
            attachmentId,
            ContentValues().apply {
                put(COLUMN_STATUS, Status.DELIVERED.databaseValue)
                putNull(COLUMN_NEXT_ATTEMPT_AT)
                putNull(COLUMN_LAST_ERROR_CODE)
            },
        )
        releasePayloadIfUnused(
            requireNotNull(findById(attachmentId)) { "Delivered attachment was not found." },
        )
    }

    fun missingChunkIndices(attachmentId: ByteArray): List<Int> {
        val manifest = requireNotNull(findById(attachmentId)) { "Attachment was not found." }.manifest
        return manifest.chunks.filterNot(::validChunkFile).map(RelayAttachmentManifest.Chunk::index)
    }

    fun readChunk(attachmentId: ByteArray, index: Int): ByteArray {
        val manifest = requireNotNull(findById(attachmentId)) { "Attachment was not found." }.manifest
        val chunk = manifest.chunks.getOrNull(index)
            ?: throw IllegalArgumentException("Attachment chunk index is invalid.")
        val file = chunkFile(chunk.ciphertextSha256)
        require(file.isFile && file.length() == chunk.ciphertextBytes.toLong()) {
            "Attachment chunk is missing."
        }
        val ciphertext = file.readBytes()
        require(sha256(ciphertext).contentEquals(chunk.ciphertextSha256)) {
            "Attachment chunk digest mismatch."
        }
        return ciphertext
    }

    fun storeIncomingChunk(attachmentId: ByteArray, index: Int, ciphertext: ByteArray): Boolean {
        val stored = requireNotNull(findById(attachmentId)) { "Incoming attachment was not found." }
        check(stored.direction == Direction.INCOMING && stored.status != Status.READY) {
            "Attachment is not accepting chunks."
        }
        val chunk = stored.manifest.chunks.getOrNull(index)
            ?: throw IllegalArgumentException("Attachment chunk index is invalid.")
        require(ciphertext.size == chunk.ciphertextBytes) { "Attachment chunk length mismatch." }
        require(sha256(ciphertext).contentEquals(chunk.ciphertextSha256)) {
            "Attachment chunk digest mismatch."
        }
        return writeContentAddressed(chunk.ciphertextSha256, ciphertext) != null
    }

    fun verifyAndMarkReady(attachmentId: ByteArray): StoredAttachment {
        val stored = requireNotNull(findById(attachmentId)) { "Incoming attachment was not found." }
        check(stored.direction == Direction.INCOMING) { "Only incoming attachments become ready." }
        verifyPlaintext(stored.manifest, output = null)
        updateById(
            attachmentId,
            ContentValues().apply { put(COLUMN_STATUS, Status.READY.databaseValue) },
        )
        return requireNotNull(findById(attachmentId))
    }

    /** Decrypts only after full verification, into the one cache directory exposed by FileProvider. */
    fun exportVerified(attachmentId: ByteArray): File {
        val stored = requireNotNull(findById(attachmentId)) { "Attachment was not found." }
        check(stored.direction == Direction.INCOMING && stored.status == Status.READY) {
            "Attachment is not ready to open."
        }
        val directory = File(exportsRoot, attachmentId.toHex()).apply { mkdirs() }
        check(directory.isDirectory) { "Attachment export directory is unavailable." }
        val target = File(directory, stored.manifest.fileName)
        val temporary = File(directory, ".${stored.manifest.fileName}.${random.nextLong()}.tmp")
        try {
            FileOutputStream(temporary).use { output ->
                verifyPlaintext(stored.manifest, output)
                output.fd.sync()
            }
            if (target.exists()) check(target.delete()) { "Old attachment export could not be replaced." }
            check(temporary.renameTo(target)) { "Verified attachment could not be published." }
            return target
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    /**
     * Decrypts a verified local payload into a short-lived private cache file for thumbnailing.
     *
     * Incoming payloads are available only after full verification. Outgoing payloads are
     * available only while their encrypted chunks are still retained; a separately encrypted,
     * bounded thumbnail survives the normal post-delivery payload cleanup.
     */
    fun exportPreviewSource(attachmentId: ByteArray): File {
        val stored = requireNotNull(findById(attachmentId)) { "Attachment was not found." }
        val readable = when (stored.direction) {
            Direction.INCOMING -> stored.status == Status.READY
            Direction.OUTGOING -> stored.status != Status.DELIVERED && !isCancelled(stored)
        }
        check(readable) { "Attachment payload is not available for preview." }
        val directory = File(previewSourcesRoot, attachmentId.toHex()).apply { mkdirs() }
        check(directory.isDirectory) { "Attachment preview directory is unavailable." }
        val temporary = File(
            directory,
            ".${stored.manifest.fileName}.${random.nextLong()}.preview-source",
        )
        try {
            FileOutputStream(temporary).use { output ->
                verifyPlaintext(stored.manifest, output)
                output.fd.sync()
            }
            return temporary
        } catch (error: Throwable) {
            if (temporary.exists()) temporary.delete()
            throw error
        }
    }

    private fun insertManifest(
        manifest: RelayAttachmentManifest,
        peerFingerprint: String,
        direction: Direction,
        status: Status,
    ) {
        val encoded = manifest.encode()
        val encrypted = encryptManifest(manifest.attachmentId, peerFingerprint, direction, encoded)
        val values = ContentValues().apply {
            put(COLUMN_ATTACHMENT_ID, manifest.attachmentId)
            put(COLUMN_PEER_FINGERPRINT, peerFingerprint)
            put(COLUMN_DIRECTION, direction.databaseValue)
            put(COLUMN_MANIFEST_NONCE, encrypted.nonce)
            put(COLUMN_MANIFEST_CIPHERTEXT, encrypted.ciphertext)
            put(COLUMN_STATUS, status.databaseValue)
            put(COLUMN_CREATED_AT, System.currentTimeMillis())
        }
        check(writableDatabase.insertOrThrow(TABLE_ATTACHMENTS, null, values) > 0) {
            "Attachment manifest was not stored."
        }
    }

    private fun findById(id: ByteArray): StoredAttachment? = findByHex(readableDatabase, id.sqlHex())

    private fun findByHex(database: SQLiteDatabase, idHex: String): StoredAttachment? =
        database.query(
            TABLE_ATTACHMENTS,
            PROJECTION,
            "hex($COLUMN_ATTACHMENT_ID) = ?",
            arrayOf(idHex),
            null,
            null,
            null,
            "1",
        ).use { cursor -> if (cursor.moveToFirst()) readStored(cursor) else null }

    private fun readStored(cursor: Cursor): StoredAttachment {
        val id = cursor.getBlob(0)
        val peer = cursor.getString(1)
        val direction = Direction.fromDatabase(cursor.getInt(2))
        val manifest = RelayAttachmentManifest.decode(
            decryptManifest(id, peer, direction, cursor.getBlob(3), cursor.getBlob(4)),
        )
        check(manifest.attachmentId.contentEquals(id)) { "Stored attachment ID mismatch." }
        return StoredAttachment(
            manifest = manifest,
            peerFingerprint = peer,
            direction = direction,
            status = Status.fromDatabase(cursor.getInt(5)),
            createdAtMs = cursor.getLong(6),
            attemptCount = cursor.getInt(7),
            nextAttemptAtMs = cursor.nullableLong(8),
            lastErrorCode = if (cursor.isNull(9)) null else cursor.getString(9),
        )
    }

    private fun updateById(id: ByteArray, values: ContentValues) {
        check(
            writableDatabase.update(
                TABLE_ATTACHMENTS,
                values,
                "hex($COLUMN_ATTACHMENT_ID) = ?",
                arrayOf(id.sqlHex()),
            ) == 1,
        ) { "Attachment state changed unexpectedly." }
    }

    private fun listAll(): List<StoredAttachment> {
        val attachments = mutableListOf<StoredAttachment>()
        readableDatabase.query(
            TABLE_ATTACHMENTS,
            PROJECTION,
            null,
            null,
            null,
            null,
            "$COLUMN_SEQUENCE ASC",
        ).use { cursor ->
            while (cursor.moveToNext()) attachments += readStored(cursor)
        }
        return attachments
    }

    private fun retainsPayload(attachment: StoredAttachment): Boolean =
        attachment.direction == Direction.INCOMING ||
            (attachment.status != Status.DELIVERED && !isCancelled(attachment))

    private fun releasePayloadIfUnused(attachment: StoredAttachment) {
        if (retainsPayload(attachment)) return
        synchronized(PAYLOAD_CLEANUP_LOCK) {
            val retainedDigests = listAll().asSequence()
                .filter(::retainsPayload)
                .flatMap { it.manifest.chunks.asSequence() }
                .map { it.ciphertextSha256.toHex() }
                .toHashSet()
            attachment.manifest.chunks.forEach { chunk ->
                if (chunk.ciphertextSha256.toHex() !in retainedDigests) {
                    runCatching { chunkFile(chunk.ciphertextSha256).delete() }
                }
            }
        }
    }

    private fun validChunkFile(chunk: RelayAttachmentManifest.Chunk): Boolean {
        val file = chunkFile(chunk.ciphertextSha256)
        if (!file.isFile || file.length() != chunk.ciphertextBytes.toLong()) return false
        return runCatching { sha256(file.readBytes()).contentEquals(chunk.ciphertextSha256) }
            .getOrDefault(false)
    }

    private fun writeContentAddressed(digest: ByteArray, ciphertext: ByteArray): File? {
        require(digest.size == RelayAttachmentManifest.SHA256_BYTES) { "Chunk digest is invalid." }
        require(sha256(ciphertext).contentEquals(digest)) { "Chunk content address mismatch." }
        val target = chunkFile(digest)
        target.parentFile?.mkdirs()
        check(target.parentFile?.isDirectory == true) { "Attachment chunk directory is unavailable." }
        if (target.exists()) {
            require(target.length() == ciphertext.size.toLong() && validChunkBytes(target, digest)) {
                "Content-addressed chunk collision."
            }
            return null
        }
        val temporary = File(target.parentFile, ".${target.name}.${random.nextLong()}.tmp")
        try {
            FileOutputStream(temporary).use { output ->
                output.write(ciphertext)
                output.fd.sync()
            }
            if (target.exists()) return null
            check(temporary.renameTo(target)) { "Encrypted attachment chunk could not be committed." }
            return target
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun validChunkBytes(file: File, digest: ByteArray): Boolean =
        runCatching { sha256(file.readBytes()).contentEquals(digest) }.getOrDefault(false)

    private fun verifyPlaintext(manifest: RelayAttachmentManifest, output: FileOutputStream?) {
        require(missingChunkIndices(manifest.attachmentId).isEmpty()) { "Attachment is incomplete." }
        val digest = MessageDigest.getInstance(DIGEST_ALGORITHM)
        var total = 0L
        manifest.chunks.forEach { chunk ->
            val plaintext = decryptContentChunk(manifest, chunk, readChunk(manifest.attachmentId, chunk.index))
            check(plaintext.size == chunk.plaintextBytes) { "Attachment plaintext length mismatch." }
            digest.update(plaintext)
            output?.write(plaintext)
            total += plaintext.size
            plaintext.fill(0)
        }
        check(total == manifest.plaintextBytes) { "Attachment total length mismatch." }
        check(digest.digest().contentEquals(manifest.plaintextSha256)) {
            "Attachment full-file digest mismatch."
        }
    }

    private fun encryptContentChunk(
        attachmentId: ByteArray,
        index: Int,
        plaintextBytes: Int,
        contentKey: ByteArray,
        nonce: ByteArray,
        buffer: ByteArray,
    ): ByteArray = Cipher.getInstance(CIPHER_TRANSFORMATION).run {
        init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(contentKey, KeyProperties.KEY_ALGORITHM_AES),
            GCMParameterSpec(GCM_TAG_BITS, nonce),
        )
        updateAAD(chunkAad(attachmentId, index, plaintextBytes))
        doFinal(buffer, 0, plaintextBytes)
    }

    private fun decryptContentChunk(
        manifest: RelayAttachmentManifest,
        chunk: RelayAttachmentManifest.Chunk,
        ciphertext: ByteArray,
    ): ByteArray = Cipher.getInstance(CIPHER_TRANSFORMATION).run {
        init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(manifest.contentKey, KeyProperties.KEY_ALGORITHM_AES),
            GCMParameterSpec(GCM_TAG_BITS, chunk.nonce),
        )
        updateAAD(chunkAad(manifest.attachmentId, chunk.index, chunk.plaintextBytes))
        doFinal(ciphertext)
    }

    private fun encryptManifest(
        id: ByteArray,
        peer: String,
        direction: Direction,
        plaintext: ByteArray,
    ): EncryptedValue = Cipher.getInstance(CIPHER_TRANSFORMATION).run {
        init(Cipher.ENCRYPT_MODE, storageKey())
        updateAAD(manifestAad(id, peer, direction))
        EncryptedValue(iv, doFinal(plaintext))
    }

    private fun decryptManifest(
        id: ByteArray,
        peer: String,
        direction: Direction,
        nonce: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray = Cipher.getInstance(CIPHER_TRANSFORMATION).run {
        init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
        updateAAD(manifestAad(id, peer, direction))
        doFinal(ciphertext)
    }

    private fun storageKey(): SecretKey {
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

    private fun queryMetadata(resolver: ContentResolver, uri: Uri): SelectedMetadata {
        var name: String? = null
        var size: Long? = null
        resolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
            null,
            null,
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (nameIndex >= 0 && !cursor.isNull(nameIndex)) name = cursor.getString(nameIndex)
                if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) size = cursor.getLong(sizeIndex)
            }
        }
        return SelectedMetadata(name, size?.takeIf { it >= 0 })
    }

    private fun chunkFile(digest: ByteArray): File {
        val hex = digest.toHex()
        return File(File(chunksRoot, hex.take(2)), "$hex.chunk")
    }

    private fun manifestAad(id: ByteArray, peer: String, direction: Direction): ByteArray =
        MANIFEST_DOMAIN + id + peer.toByteArray(StandardCharsets.UTF_8) + direction.databaseValue.toByte()

    private fun chunkAad(id: ByteArray, index: Int, plaintextBytes: Int): ByteArray =
        ByteBuffer.allocate(CHUNK_DOMAIN.size + id.size + 8).order(ByteOrder.BIG_ENDIAN)
            .put(CHUNK_DOMAIN)
            .put(id)
            .putInt(index)
            .putInt(plaintextBytes)
            .array()

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance(DIGEST_ALGORITHM).digest(bytes)

    private fun InputStream.readUpTo(buffer: ByteArray): Int {
        var offset = 0
        while (offset < buffer.size) {
            val read = read(buffer, offset, buffer.size - offset)
            if (read < 0) break
            if (read == 0) {
                val single = read()
                if (single < 0) break
                buffer[offset++] = single.toByte()
            } else {
                offset += read
            }
        }
        return offset
    }

    private fun Cursor.nullableLong(index: Int): Long? = if (isNull(index)) null else getLong(index)

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private fun ByteArray.sqlHex(): String = joinToString(separator = "") { byte ->
        "%02X".format(byte.toInt() and 0xFF)
    }

    private data class SelectedMetadata(val displayName: String?, val declaredBytes: Long?)
    private data class EncryptedValue(val nonce: ByteArray, val ciphertext: ByteArray)

    private companion object {
        const val DATABASE_NAME = "relay_attachments.db"
        const val DATABASE_VERSION = 1
        const val TABLE_ATTACHMENTS = "attachments"
        const val COLUMN_SEQUENCE = "sequence"
        const val COLUMN_ATTACHMENT_ID = "attachment_id"
        const val COLUMN_PEER_FINGERPRINT = "peer_fingerprint"
        const val COLUMN_DIRECTION = "direction"
        const val COLUMN_MANIFEST_NONCE = "manifest_nonce"
        const val COLUMN_MANIFEST_CIPHERTEXT = "manifest_ciphertext"
        const val COLUMN_STATUS = "status"
        const val COLUMN_CREATED_AT = "created_at_ms"
        const val COLUMN_ATTEMPT_COUNT = "attempt_count"
        const val COLUMN_NEXT_ATTEMPT_AT = "next_attempt_at_ms"
        const val COLUMN_LAST_ERROR_CODE = "last_error_code"
        const val CHUNKS_DIRECTORY = "relay_attachment_chunks_v1"
        const val EXPORTS_DIRECTORY = "hypha_verified_attachments"
        const val PREVIEW_SOURCES_DIRECTORY = "hypha_attachment_preview_sources"
        const val DIGEST_ALGORITHM = "SHA-256"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "project_relay_attachment_manifest_aes_v1"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val MAX_ERROR_CODE_CHARS = 80
        const val MAX_BACKOFF_EXPONENT = 5
        const val RETRY_BASE_MS = 2_000L
        const val RETRY_MAX_MS = 60_000L
        const val USER_PAUSED_CODE = "user_paused"
        const val USER_CANCELLED_CODE = "user_cancelled"
        val PAYLOAD_CLEANUP_LOCK = Any()
        val MANIFEST_DOMAIN =
            "ProjectRelay/attachment-store/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val CHUNK_DOMAIN =
            "ProjectRelay/attachment-chunk/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val PROJECTION = arrayOf(
            COLUMN_ATTACHMENT_ID,
            COLUMN_PEER_FINGERPRINT,
            COLUMN_DIRECTION,
            COLUMN_MANIFEST_NONCE,
            COLUMN_MANIFEST_CIPHERTEXT,
            COLUMN_STATUS,
            COLUMN_CREATED_AT,
            COLUMN_ATTEMPT_COUNT,
            COLUMN_NEXT_ATTEMPT_AT,
            COLUMN_LAST_ERROR_CODE,
        )
    }
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
    "%02x".format(byte.toInt() and 0xFF)
}
