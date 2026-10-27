package app.projectrelay.relay_mobile

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayMeshWorkGateTest {
    @Test
    fun unchangedEmptyExchangeIsSuppressed() {
        val gate = RelayMeshWorkGate()

        assertTrue(gate.canAttempt("identity", "token-a", 4L, 7))
        gate.markEmpty("identity", "token-a", 4L, 7)

        assertFalse(gate.canAttempt("identity", "token-a", 4L, 7))
    }

    @Test
    fun eitherSidesWorkChangeAllowsFreshExchange() {
        val gate = RelayMeshWorkGate()
        gate.markEmpty("identity", "token-a", 4L, 7)

        assertTrue(gate.canAttempt("identity", "token-a", 5L, 7))
        assertTrue(gate.canAttempt("identity", "token-a", 4L, 8))
    }

    @Test
    fun restartedPeerGetsOneFreshExchange() {
        val gate = RelayMeshWorkGate()
        gate.markEmpty("identity", "token-a", 4L, 7)

        assertTrue(gate.canAttempt("identity", "token-b", 4L, 7))
    }

    @Test
    fun productiveActivityClearsTheEmptySnapshot() {
        val gate = RelayMeshWorkGate()
        gate.markEmpty("identity", "token-a", 4L, 7)

        gate.clearPeer("identity")

        assertTrue(gate.canAttempt("identity", "token-a", 4L, 7))
    }

    @Test
    fun workQueuedDuringAnEmptyExchangeForcesAPromptRetry() {
        val gate = RelayMeshWorkGate()
        gate.markAttemptStarted("token-a", localRevision = 4L, remoteHint = 7)

        val unchanged = gate.markEmptyIfAttemptUnchanged(
            peerKey = "identity",
            peerToken = "token-a",
            localRevision = 5L,
            remoteHint = 7,
        )

        assertFalse(unchanged)
        assertTrue(gate.canAttempt("identity", "token-a", 5L, 7))
    }

    @Test
    fun unchangedAttemptIsSuppressedAfterItsEmptyCompletion() {
        val gate = RelayMeshWorkGate()
        gate.markAttemptStarted("token-a", localRevision = 4L, remoteHint = 7)

        val unchanged = gate.markEmptyIfAttemptUnchanged(
            peerKey = "identity",
            peerToken = "token-a",
            localRevision = 4L,
            remoteHint = 7,
        )

        assertTrue(unchanged)
        assertFalse(gate.canAttempt("identity", "token-a", 4L, 7))
    }
}
