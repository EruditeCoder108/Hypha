package app.projectrelay.relay_mobile

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32

/** Strict, bounded assembler for sequenced HNR1 GATT read responses. */
internal class HyphaFixedNodeResponseAssembler(
    private val maximumTransferBytes: Int,
) {
    init {
        require(maximumTransferBytes in 1..U16_MAX) {
            "Fixed-node maximum response length is invalid."
        }
    }

    private var accumulator: Accumulator? = null

    fun reset() {
        accumulator = null
    }

    fun accept(frame: ByteArray): CompletedResponse? {
        require(
            frame.size > RESPONSE_HEADER_BYTES &&
                frame.copyOfRange(0, RESPONSE_MAGIC.size).contentEquals(RESPONSE_MAGIC),
        ) { "Fixed-node response frame has an invalid prefix." }
        val kind = frame[4].toInt() and 0xff
        require(kind == RESPONSE_HELLO || kind == RESPONSE_SECURE) {
            "Fixed node returned an error response."
        }
        val flags = frame[5].toInt() and 0xff
        require((flags and FINAL_FLAG.inv()) == 0) {
            "Fixed-node response flags are invalid."
        }
        val final = (flags and FINAL_FLAG) != 0
        val sequence = readU16(frame, 6)
        val totalBytes = readU16(frame, 8)
        val expectedCrc = readU32(frame, 10)
        require(totalBytes in 1..maximumTransferBytes) {
            "Fixed-node response length is invalid."
        }
        val current = accumulator ?: Accumulator(
            kind = kind,
            totalBytes = totalBytes,
            crc32 = expectedCrc,
        ).also { accumulator = it }
        require(
            current.kind == kind && current.totalBytes == totalBytes &&
                current.crc32 == expectedCrc && current.nextSequence == sequence,
        ) { "Fixed-node response chunks are inconsistent." }

        val chunk = frame.copyOfRange(RESPONSE_HEADER_BYTES, frame.size)
        require(current.output.size() + chunk.size <= totalBytes) {
            "Fixed-node response exceeds its declared length."
        }
        current.output.write(chunk)
        current.nextSequence += 1
        if (!final) {
            require(current.output.size() < totalBytes) {
                "Fixed-node response omitted its final marker."
            }
            return null
        }

        val payload = current.output.toByteArray()
        require(payload.size == totalBytes && crc32(payload) == expectedCrc) {
            "Fixed-node response checksum is invalid."
        }
        accumulator = null
        return CompletedResponse(kind, payload)
    }

    internal data class CompletedResponse(
        val kind: Int,
        val payload: ByteArray,
    )

    private data class Accumulator(
        val kind: Int,
        val totalBytes: Int,
        val crc32: Long,
        val output: ByteArrayOutputStream = ByteArrayOutputStream(totalBytes),
        var nextSequence: Int = 0,
    )

    private fun readU16(source: ByteArray, offset: Int): Int =
        ((source[offset].toInt() and 0xff) shl 8) or (source[offset + 1].toInt() and 0xff)

    private fun readU32(source: ByteArray, offset: Int): Long =
        ((source[offset].toLong() and 0xff) shl 24) or
            ((source[offset + 1].toLong() and 0xff) shl 16) or
            ((source[offset + 2].toLong() and 0xff) shl 8) or
            (source[offset + 3].toLong() and 0xff)

    private fun crc32(bytes: ByteArray): Long = CRC32().apply { update(bytes) }.value

    internal companion object {
        const val RESPONSE_HEADER_BYTES = 14
        const val RESPONSE_HELLO = 1
        const val RESPONSE_SECURE = 2
        private const val FINAL_FLAG = 1
        private const val U16_MAX = 65_535
        val RESPONSE_MAGIC: ByteArray = "HNR1".encodeToByteArray()
    }
}
