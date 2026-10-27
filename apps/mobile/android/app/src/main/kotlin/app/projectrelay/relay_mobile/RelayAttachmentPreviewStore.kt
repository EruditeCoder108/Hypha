package app.projectrelay.relay_mobile

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.media.MediaMetadataRetriever
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.math.max
import kotlin.math.roundToInt

/** Endpoint-only encrypted thumbnails. Preview bytes never enter attachment or courier envelopes. */
internal class RelayAttachmentPreviewStore(
    context: android.content.Context,
    private val attachmentStore: RelayAttachmentStore,
) {
    private val appContext = context.applicationContext
    private val previewsRoot = File(appContext.filesDir, PREVIEWS_DIRECTORY)

    init {
        synchronized(CACHE_LOCK) { pruneCache() }
    }

    fun loadOrCreate(attachmentIdHex: String): ByteArray? {
        val stored = attachmentStore.findByHexId(attachmentIdHex) ?: return null
        val mediaKind = previewKind(stored.manifest.mimeType) ?: return null
        val attachmentId = stored.manifest.attachmentId
        readCached(attachmentId)?.let { return it }

        val source = runCatching {
            attachmentStore.exportPreviewSource(attachmentId)
        }.getOrNull() ?: return null
        return try {
            val bitmap = when (mediaKind) {
                PreviewKind.IMAGE -> decodeImage(source)
                PreviewKind.VIDEO -> decodeVideoFrame(source)
            } ?: return null
            try {
                val encoded = encodeBounded(bitmap) ?: return null
                writeCached(attachmentId, encoded)
                encoded
            } finally {
                bitmap.recycle()
            }
        } finally {
            source.delete()
            source.parentFile?.takeIf { it.listFiles().isNullOrEmpty() }?.delete()
        }
    }

    private fun decodeImage(source: File): Bitmap? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(source)) { decoder, info, _ ->
                val width = info.size.width.coerceAtLeast(1)
                val height = info.size.height.coerceAtLeast(1)
                val largest = max(width, height)
                if (largest > MAX_DECODE_DIMENSION) {
                    val scale = MAX_DECODE_DIMENSION.toDouble() / largest
                    decoder.setTargetSize(
                        (width * scale).roundToInt().coerceAtLeast(1),
                        (height * scale).roundToInt().coerceAtLeast(1),
                    )
                }
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            }
        } else {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(source.absolutePath, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return@runCatching null
            var sample = 1
            while (max(bounds.outWidth, bounds.outHeight) / sample > MAX_DECODE_DIMENSION) {
                sample *= 2
            }
            BitmapFactory.decodeFile(
                source.absolutePath,
                BitmapFactory.Options().apply { inSampleSize = sample },
            )
        }
    }.getOrNull()

    @Suppress("DEPRECATION")
    private fun decodeVideoFrame(source: File): Bitmap? = runCatching {
        val retriever = MediaMetadataRetriever()
        try {
            retriever.setDataSource(source.absolutePath)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
                val width = retriever.extractMetadata(
                    MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH,
                )?.toIntOrNull()?.coerceAtLeast(1) ?: MAX_PREVIEW_DIMENSION
                val height = retriever.extractMetadata(
                    MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT,
                )?.toIntOrNull()?.coerceAtLeast(1) ?: MAX_PREVIEW_DIMENSION
                val largest = max(width, height)
                val scale = minOf(1.0, MAX_PREVIEW_DIMENSION.toDouble() / largest)
                retriever.getScaledFrameAtTime(
                    0,
                    MediaMetadataRetriever.OPTION_CLOSEST_SYNC,
                    (width * scale).roundToInt().coerceAtLeast(1),
                    (height * scale).roundToInt().coerceAtLeast(1),
                )
            } else {
                retriever.getFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            }
        } finally {
            retriever.release()
        }
    }.getOrNull()

    private fun encodeBounded(decoded: Bitmap): ByteArray? {
        var current = scaleToMaximum(decoded, MAX_PREVIEW_DIMENSION)
        var ownsCurrent = current !== decoded
        try {
            while (true) {
                for (quality in intArrayOf(82, 68, 54)) {
                    val output = ByteArrayOutputStream()
                    if (current.compress(Bitmap.CompressFormat.JPEG, quality, output)) {
                        val bytes = output.toByteArray()
                        if (bytes.size <= MAX_PREVIEW_BYTES) return bytes
                    }
                }
                val largest = max(current.width, current.height)
                if (largest <= MIN_PREVIEW_DIMENSION) return null
                val smaller = scaleToMaximum(current, (largest * 0.75).roundToInt())
                if (ownsCurrent) current.recycle()
                current = smaller
                ownsCurrent = true
            }
        } finally {
            if (ownsCurrent) current.recycle()
        }
    }

    private fun scaleToMaximum(bitmap: Bitmap, maximum: Int): Bitmap {
        val largest = max(bitmap.width, bitmap.height)
        if (largest <= maximum) return bitmap
        val scale = maximum.toDouble() / largest
        return Bitmap.createScaledBitmap(
            bitmap,
            (bitmap.width * scale).roundToInt().coerceAtLeast(1),
            (bitmap.height * scale).roundToInt().coerceAtLeast(1),
            true,
        )
    }

    private fun readCached(attachmentId: ByteArray): ByteArray? = synchronized(CACHE_LOCK) {
        val file = previewFile(attachmentId)
        if (!file.isFile || file.length() !in MIN_STORED_BYTES..MAX_STORED_BYTES) return null
        runCatching {
            val encoded = file.readBytes()
            val buffer = ByteBuffer.wrap(encoded)
            val magic = ByteArray(PREVIEW_MAGIC.size).also(buffer::get)
            require(magic.contentEquals(PREVIEW_MAGIC)) { "Attachment preview header is invalid." }
            val nonce = ByteArray(NONCE_BYTES).also(buffer::get)
            val ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
            Cipher.getInstance(CIPHER_TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(PREVIEW_DOMAIN + attachmentId)
                doFinal(ciphertext).also { plaintext ->
                    require(plaintext.size in 1..MAX_PREVIEW_BYTES) {
                        "Attachment preview size is invalid."
                    }
                }
            }
                .also { file.setLastModified(System.currentTimeMillis()) }
        }.getOrElse {
            file.delete()
            null
        }
    }

    private fun writeCached(attachmentId: ByteArray, plaintext: ByteArray) = synchronized(CACHE_LOCK) {
        require(plaintext.size in 1..MAX_PREVIEW_BYTES) { "Attachment preview is too large." }
        previewsRoot.mkdirs()
        check(previewsRoot.isDirectory) { "Attachment preview storage is unavailable." }
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, storageKey())
            updateAAD(PREVIEW_DOMAIN + attachmentId)
        }
        val nonce = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        val encoded = ByteBuffer.allocate(PREVIEW_MAGIC.size + nonce.size + ciphertext.size)
            .put(PREVIEW_MAGIC)
            .put(nonce)
            .put(ciphertext)
            .array()
        val target = previewFile(attachmentId)
        val temporary = File(previewsRoot, ".${target.name}.${System.nanoTime()}.tmp")
        try {
            FileOutputStream(temporary).use { output ->
                output.write(encoded)
                output.fd.sync()
            }
            if (target.exists()) check(target.delete()) { "Old attachment preview could not be replaced." }
            check(temporary.renameTo(target)) { "Attachment preview could not be stored." }
            pruneCache()
        } finally {
            if (temporary.exists()) temporary.delete()
        }
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

    private fun previewFile(attachmentId: ByteArray): File =
        File(previewsRoot, "${attachmentId.toHex()}.preview")

    private fun pruneCache() {
        val files = previewsRoot.listFiles()
            ?.filter { file -> file.isFile && file.extension == "preview" }
            ?.sortedBy(File::lastModified)
            ?.toMutableList()
            ?: return
        var totalBytes = files.sumOf(File::length)
        while (files.size > MAX_PREVIEW_FILES || totalBytes > MAX_CACHE_BYTES) {
            val oldest = files.removeAt(0)
            val bytes = oldest.length()
            if (oldest.delete()) totalBytes -= bytes
        }
    }

    private fun previewKind(mimeType: String): PreviewKind? = when {
        mimeType.startsWith("image/", ignoreCase = true) -> PreviewKind.IMAGE
        mimeType.startsWith("video/", ignoreCase = true) -> PreviewKind.VIDEO
        else -> null
    }

    private enum class PreviewKind { IMAGE, VIDEO }

    private companion object {
        const val PREVIEWS_DIRECTORY = "relay_attachment_previews_v1"
        const val MAX_DECODE_DIMENSION = 1024
        const val MAX_PREVIEW_DIMENSION = 512
        const val MIN_PREVIEW_DIMENSION = 160
        const val MAX_PREVIEW_BYTES = 128 * 1024
        const val MAX_PREVIEW_FILES = 256
        const val MAX_CACHE_BYTES = 16L * 1024L * 1024L
        const val NONCE_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "project_relay_attachment_preview_aes_v1"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val MIN_STORED_BYTES = 4L + NONCE_BYTES + 16L + 1L
        const val MAX_STORED_BYTES = 4L + NONCE_BYTES + 16L + MAX_PREVIEW_BYTES
        val CACHE_LOCK = Any()
        val PREVIEW_MAGIC = byteArrayOf('H'.code.toByte(), 'T'.code.toByte(), 'P'.code.toByte(), 1)
        val PREVIEW_DOMAIN = "Hypha/attachment-preview/v1\u0000".toByteArray(Charsets.UTF_8)
    }
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
    "%02x".format(byte.toInt() and 0xFF)
}
