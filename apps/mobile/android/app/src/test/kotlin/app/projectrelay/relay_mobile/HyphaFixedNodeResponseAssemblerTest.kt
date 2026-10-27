package app.projectrelay.relay_mobile

import java.util.zip.CRC32
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class HyphaFixedNodeResponseAssemblerTest {
    @Test
    fun `assembles a multi-record response across 247-byte MTU reads`() {
        val payload = ByteArray(1_021) { index -> (index * 37).toByte() }
        val frames = encodeFrames(payload, mtu = 247)
        val assembler = HyphaFixedNodeResponseAssembler(MAX_TRANSFER_BYTES)

        frames.dropLast(1).forEach { frame -> assertNull(assembler.accept(frame)) }
        val completed = requireNotNull(assembler.accept(frames.last()))

        assertEquals(HyphaFixedNodeResponseAssembler.RESPONSE_SECURE, completed.kind)
        assertArrayEquals(payload, completed.payload)
    }

    @Test
    fun `assembles at the mandatory 23-byte ATT MTU`() {
        val payload = ByteArray(39) { index -> (0xa0 + index).toByte() }
        val frames = encodeFrames(payload, mtu = 23)
        val assembler = HyphaFixedNodeResponseAssembler(MAX_TRANSFER_BYTES)

        var completed: HyphaFixedNodeResponseAssembler.CompletedResponse? = null
        frames.forEach { frame -> completed = assembler.accept(frame) }

        assertArrayEquals(payload, requireNotNull(completed).payload)
    }

    @Test
    fun `rejects reordering and accepts a clean response after reset`() {
        val payload = ByteArray(600) { index -> index.toByte() }
        val frames = encodeFrames(payload, mtu = 247)
        val assembler = HyphaFixedNodeResponseAssembler(MAX_TRANSFER_BYTES)
        assertNull(assembler.accept(frames.first()))

        assertThrows(IllegalArgumentException::class.java) {
            assembler.accept(frames.last())
        }

        assembler.reset()
        var completed: HyphaFixedNodeResponseAssembler.CompletedResponse? = null
        frames.forEach { frame -> completed = assembler.accept(frame) }
        assertArrayEquals(payload, requireNotNull(completed).payload)
    }

    @Test
    fun `rejects corrupt final payload and oversized declarations`() {
        val payload = ByteArray(500) { index -> (index * 11).toByte() }
        val frames = encodeFrames(payload, mtu = 247).toMutableList()
        frames[frames.lastIndex] = frames.last().copyOf().also { frame ->
            frame[frame.lastIndex] = (frame.last().toInt() xor 1).toByte()
        }
        val assembler = HyphaFixedNodeResponseAssembler(MAX_TRANSFER_BYTES)
        assertThrows(IllegalArgumentException::class.java) {
            frames.forEach { frame -> assembler.accept(frame) }
        }

        val oversized = encodeFrames(byteArrayOf(1), mtu = 247).single().copyOf().also { frame ->
            putU16(frame, 8, MAX_TRANSFER_BYTES + 1)
        }
        assembler.reset()
        assertThrows(IllegalArgumentException::class.java) { assembler.accept(oversized) }
    }

    private fun encodeFrames(payload: ByteArray, mtu: Int): List<ByteArray> {
        require(mtu >= 23)
        val chunkBytes = mtu - 1 - HyphaFixedNodeResponseAssembler.RESPONSE_HEADER_BYTES
        val crc = CRC32().apply { update(payload) }.value
        val frames = mutableListOf<ByteArray>()
        var offset = 0
        var sequence = 0
        while (offset < payload.size) {
            val count = minOf(chunkBytes, payload.size - offset)
            val frame = ByteArray(HyphaFixedNodeResponseAssembler.RESPONSE_HEADER_BYTES + count)
            HyphaFixedNodeResponseAssembler.RESPONSE_MAGIC.copyInto(frame)
            frame[4] = HyphaFixedNodeResponseAssembler.RESPONSE_SECURE.toByte()
            frame[5] = if (offset + count == payload.size) 1 else 0
            putU16(frame, 6, sequence)
            putU16(frame, 8, payload.size)
            putU32(frame, 10, crc)
            payload.copyInto(
                frame,
                HyphaFixedNodeResponseAssembler.RESPONSE_HEADER_BYTES,
                offset,
                offset + count,
            )
            frames += frame
            offset += count
            sequence += 1
        }
        return frames
    }

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private fun putU32(target: ByteArray, offset: Int, value: Long) {
        target[offset] = (value ushr 24).toByte()
        target[offset + 1] = (value ushr 16).toByte()
        target[offset + 2] = (value ushr 8).toByte()
        target[offset + 3] = value.toByte()
    }

    private companion object {
        const val MAX_TRANSFER_BYTES = 16 * 1024
    }
}
