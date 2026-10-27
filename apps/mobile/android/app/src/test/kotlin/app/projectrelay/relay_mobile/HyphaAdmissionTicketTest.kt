package app.projectrelay.relay_mobile

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HyphaAdmissionTicketTest {
    private val rly1 = hex(
        "524c59310102000000112233445566778899aabbccddeeffffeeddccbbaa9988" +
            "77665544332211000000000005265c0000000000000000000800000400000008" +
            "0123456789abcdef",
    )
    private val header = hex(
        "4841543101020200102132435465768798a9bacbdcedfe0f0000000000000007" +
            "000400000346cf7e11224ae9e67a224d4c1dc538ae0f6978aa340711f94c6734" +
            "df32f65c",
    )
    private val challenge = hex(
        "0002001761646d697373696f6e2e68797068612e696e76616c6964200d2a59e6" +
            "0b7ef9600f1a78fcaade927a4c5cab19f689b74d9f05208c2d6433d50000",
    )
    private val spki = hex(
        "30820152303d06092a864886f70d01010a3030a00d300b060960864801650304" +
            "0202a11a301806092a864886f70d010108300b0609608648016503040202a203" +
            "0201300382010f003082010a0282010100b471c19585cf737d7e96cb561fe716" +
            "953f522bab983f8846c927d24f1de1e25eb38bc49004af040fa67df6d237248" +
            "afa7c9b15f7281dbc3a5e6dc293506eacec6093160ff666f4686f4fce63d0e4" +
            "d0dacd45088b333c12af97bba536f02a4edda17d6dd1063a58a8d9ca909680" +
            "48effc28ba5f259d9dec956d708c1da3ee83380226076d8f8873ecaf66ada8e" +
            "638f12eff58efc1ff9126d2d8be5bb9520b9567f4ac1fa8349ced97e936f996" +
            "90850cda4a7396a792d506245db53ed10ec3999d21810aa6df6eceb4bb713ab" +
            "ca26f9a4907cae729421311d64ac374151fc161d2fe49bd3529b43fbb2120fa0" +
            "020073dcbf22b33dae1ac6c8597b34a03519103b70203010001",
    )
    private val token = hex(
        "000252329f18b48ca852e85d9b4df8cfdc6ad69cc775d555bc9e779a14897436" +
            "93fe057218c2484503726b139fcb01e20e54a15c0d413c21d9c472c31ecf995" +
            "6637100287007da1d096321d094d8610e1e1dfa5b722b47ce755a94b171aac63" +
            "d9fbaabbfb6ee56cd88fabf72809759a2ec2bec97fbd96cb1a3f55b628119e3" +
            "db51568867f830dac5f410f4e4c9912065f7c26b7c4fe69ae36d1c0be71933a" +
            "421784256943a5ac6c7a22a1f0a3e586e6abf57c8d0c921b30fe6f427109da3" +
            "771c092c8eab44846593b9e34e42aaf1da3f12b346c96f537b4df6de4565496" +
            "ce22cf51b2bcd874efdc6d2003376243dcfedad556a5566bc6eb869022318034c" +
            "cfaf77cca48fefd90fc3ed080ccf2e2b16a6d2062bbf5dcc52864d1484ab685" +
            "6eed2c360bb10907268ef618638ba5b9f9034bf4462aabb479ccd08663378dac" +
            "bf84f60096db0c9722ebcd0e904dfa363225ee57ff5749645c4d36d911c54b3" +
            "f59f9eaa85",
    )
    private val venueId = hex("102132435465768798a9bacbdcedfe0f")

    @Test
    fun blindIssuedGoldenVectorVerifiesOnAndroidJvm() {
        assertArrayEquals(challenge, HyphaAdmissionTicket.tokenChallenge(header))
        assertEquals(
            HyphaAdmissionTicket.Verification(true, "accepted"),
            verify(),
        )
    }

    @Test
    fun portableMutationsVerifyButAreNotANewPhoneDeposit() {
        val forwarded = rly1.copyOf()
        putLong(forwarded, 48, 10_000)
        forwarded[57] = 2
        putShort(forwarded, 58, 2)
        assertTrue(verify(encodedRly1 = forwarded, initialDeposit = false).accepted)
        assertEquals("non_initial_deposit", verify(encodedRly1 = forwarded).reason)
    }

    @Test
    fun immutableMutationAndCopyRollbackFailClosed() {
        assertEquals("envelope_mismatch", verify(encodedRly1 = changed(rly1, 8)).reason)
        val rollback = rly1.copyOf()
        putShort(rollback, 58, 5)
        assertEquals("copy_budget_rollback", verify(encodedRly1 = rollback, initialDeposit = false).reason)
    }

    @Test
    fun wrongVenueEpochAndClassKeyFailClosed() {
        assertEquals("wrong_venue", verify(expectedVenueId = ByteArray(16) { 9 }).reason)
        assertEquals("wrong_epoch", verify(expectedOperatorEpoch = 8).reason)
        assertEquals(
            "wrong_class_key",
            verify(expectedObjectClass = HyphaAdmissionTicket.CLASS_RECIPIENT_RECEIPT).reason,
        )
    }

    @Test
    fun corruptedAuthenticatorNeverVerifies() {
        val corrupted = (header + token).copyOf()
        corrupted[corrupted.lastIndex] = (corrupted.last().toInt() xor 1).toByte()
        val result = verify(encodedHat1 = corrupted)
        assertFalse(result.accepted)
        assertEquals("invalid_signature", result.reason)
    }

    private fun verify(
        encodedHat1: ByteArray = header + token,
        encodedRly1: ByteArray = rly1,
        expectedVenueId: ByteArray = venueId,
        expectedOperatorEpoch: Long = 7,
        expectedObjectClass: Int = HyphaAdmissionTicket.CLASS_TEXT,
        initialDeposit: Boolean = true,
    ) = HyphaAdmissionTicket.verify(
        encodedHat1,
        encodedRly1,
        spki,
        expectedVenueId,
        expectedOperatorEpoch,
        expectedObjectClass,
        initialDeposit,
    )

    private fun changed(source: ByteArray, offset: Int) = source.copyOf().also {
        it[offset] = (it[offset].toInt() xor 1).toByte()
    }

    private fun putLong(target: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 8) target[offset + index] = (value ushr (56 - index * 8)).toByte()
    }

    private fun putShort(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
