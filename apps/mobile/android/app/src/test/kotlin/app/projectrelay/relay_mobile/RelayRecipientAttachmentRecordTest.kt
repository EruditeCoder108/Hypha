package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayRecipientAttachmentRecordTest {
    @Test
    fun manifestMatchesRustGoldenVectorExactly() {
        val manifest = manifest()
        val encoded = manifest.encode()

        assertEquals(
            "48414d3101020000" +
                "11111111111111111111111111111111" +
                "2222222222222222222222222222222222222222222222222222222222222222" +
                "3333333333333333333333333333333333333333333333333333333333333333" +
                "000000000000002a" +
                "4444444444444444444444444444444444444444444444444444444444444444" +
                "00180008" +
                "6170706c69636174696f6e2f6f637465742d73747265616d" +
                "6e6f74652e747874",
            encoded.toHex(),
        )
        assertTrue(RelayRecipientAttachmentManifest.decode(encoded).encode().contentEquals(encoded))
    }

    @Test
    fun manifestRejectsPrivateMetadataOutsideStrictBounds() {
        assertThrows(IllegalArgumentException::class.java) {
            manifest().copy(fileName = "../note.txt").encode()
        }
        assertThrows(IllegalArgumentException::class.java) {
            manifest().copy(mimeType = "Application/octet-stream").encode()
        }
        assertThrows(IllegalArgumentException::class.java) {
            manifest().copy(
                kind = RelayAttachmentManifest.Kind.IMAGE,
                plaintextBytes = RelayAttachmentManifest.MAX_IMAGE_BYTES + 1,
            ).encode()
        }

        val trailing = manifest().encode() + 0
        assertThrows(IllegalArgumentException::class.java) {
            RelayRecipientAttachmentManifest.decode(trailing)
        }
    }

    @Test
    fun receiptBindsBothObjectAndCourierPlan() {
        val receipt = RelayRecipientAttachmentReceipt(
            objectId = ByteArray(16) { 7 },
            courierPlanSha256 = ByteArray(32) { 8 },
        )
        val encoded = receipt.encode()
        assertEquals(RelayRecipientAttachmentReceipt.ENCODED_BYTES, encoded.size)
        val decoded = RelayRecipientAttachmentReceipt.decode(encoded)
        assertTrue(decoded.confirms(ByteArray(16) { 7 }, ByteArray(32) { 8 }))
        assertFalse(decoded.confirms(ByteArray(16) { 7 }, ByteArray(32) { 9 }))
        assertFalse(decoded.confirms(ByteArray(16) { 6 }, ByteArray(32) { 8 }))

        val wrongStatus = encoded.copyOf().also { it[5] = 2 }
        assertThrows(IllegalArgumentException::class.java) {
            RelayRecipientAttachmentReceipt.decode(wrongStatus)
        }
    }

    private fun manifest(): RelayRecipientAttachmentManifest = RelayRecipientAttachmentManifest(
        objectId = ByteArray(16) { 0x11 },
        kind = RelayAttachmentManifest.Kind.FILE,
        courierPlanSha256 = ByteArray(32) { 0x22 },
        contentKey = ByteArray(32) { 0x33 },
        plaintextBytes = 42,
        plaintextSha256 = ByteArray(32) { 0x44 },
        mimeType = "application/octet-stream",
        fileName = "note.txt",
    )

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }
}
