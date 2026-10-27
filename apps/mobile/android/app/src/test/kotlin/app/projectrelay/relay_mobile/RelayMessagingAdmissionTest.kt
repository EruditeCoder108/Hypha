package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayMessagingAdmissionTest {
    @Test
    fun ratchetWindowStopsEmissionAtThirtyTwo() {
        assertEquals(1, RelayMeshTextWindow.availableSlots(31))
        assertEquals(0, RelayMeshTextWindow.availableSlots(32))
        assertEquals(0, RelayMeshTextWindow.availableSlots(40))
    }

    @Test
    fun impossibleFutureRetryDeadlineRecoversAfterClockRollback() {
        assertFalse(
            RelayRetryClockPolicy.isEligible(
                nextAttemptAtMs = 50_000L,
                nowMs = 10_000L,
                maximumLegitimateDelayMs = 60_000L,
            ),
        )
        assertTrue(
            RelayRetryClockPolicy.isEligible(
                nextAttemptAtMs = 5_000_000L,
                nowMs = 10_000L,
                maximumLegitimateDelayMs = 60_000L,
            ),
        )
    }

    @Test
    fun conversationStaysOnDirectWhileAnOlderDirectMessageWaits() {
        assertEquals(
            RelayTextTransport.DIRECT,
            RelayConversationTransportPolicy.select(
                requested = RelayTextTransport.MESH,
                hasDirectBacklog = true,
                hasMeshBacklog = false,
            ),
        )
    }

    @Test
    fun conversationStaysOnMeshWhileAnOlderMeshMessageWaits() {
        assertEquals(
            RelayTextTransport.MESH,
            RelayConversationTransportPolicy.select(
                requested = RelayTextTransport.DIRECT,
                hasDirectBacklog = false,
                hasMeshBacklog = true,
            ),
        )
    }

    @Test
    fun conversationUsesRequestedTransportWithoutAQueuedPredecessor() {
        assertEquals(
            RelayTextTransport.DIRECT,
            RelayConversationTransportPolicy.select(
                requested = RelayTextTransport.DIRECT,
                hasDirectBacklog = false,
                hasMeshBacklog = false,
            ),
        )
        assertEquals(
            RelayTextTransport.MESH,
            RelayConversationTransportPolicy.select(
                requested = RelayTextTransport.MESH,
                hasDirectBacklog = false,
                hasMeshBacklog = false,
            ),
        )
    }

    @Test
    fun directBacklogRepairsADeviceWithLegacyMixedQueues() {
        assertEquals(
            RelayTextTransport.DIRECT,
            RelayConversationTransportPolicy.select(
                requested = RelayTextTransport.MESH,
                hasDirectBacklog = true,
                hasMeshBacklog = true,
            ),
        )
    }

    @Test
    fun meshStatusChangesOnlyAfterAuthenticatedRelayAcceptance() {
        assertEquals(
            "queued",
            RelayMeshMessagePresentation.visibleStatus(
                outgoing = true,
                storedStatus = "queued",
                hasActiveEnvelope = true,
                wasAcceptedByRelay = false,
            ),
        )
        assertEquals(
            "relayed",
            RelayMeshMessagePresentation.visibleStatus(
                outgoing = true,
                storedStatus = "queued",
                hasActiveEnvelope = true,
                wasAcceptedByRelay = true,
            ),
        )
        assertEquals(
            "delivered",
            RelayMeshMessagePresentation.visibleStatus(
                outgoing = true,
                storedStatus = "delivered",
                hasActiveEnvelope = false,
                wasAcceptedByRelay = false,
            ),
        )
    }

    @Test
    fun peerOrderingRotatesAfterASelection() {
        val fairness = RelayPeerFairness()

        assertEquals(listOf("a", "b", "c"), fairness.ordered(listOf("c", "a", "b")))
        fairness.markServiced("a")
        assertEquals(listOf("b", "c", "a"), fairness.ordered(listOf("c", "a", "b")))
        fairness.markServiced("c")
        assertEquals(listOf("a", "b", "c"), fairness.ordered(listOf("c", "a", "b")))
    }

    @Test
    fun urgentMeshGetsAnOpportunityAfterOneDirectAdmission() {
        val policy = RelayRadioAdmissionPolicy(maximumDirectAdmissionsBeforeMesh = 1)

        assertFalse(policy.shouldOfferMeshFirst(hasUrgentMeshWork = true))
        policy.recordDirectAdmission()
        assertTrue(policy.shouldOfferMeshFirst(hasUrgentMeshWork = true))
        assertFalse(policy.shouldOfferMeshFirst(hasUrgentMeshWork = false))
        policy.recordMeshAdmission()
        assertFalse(policy.shouldOfferMeshFirst(hasUrgentMeshWork = true))
    }

    @Test
    fun warmConnectionYieldsAfterItsBoundedBurst() {
        val budget = RelayWarmTextBudget(maximumMessages = 4)

        assertTrue(budget.recordDeliveredAndMayContinue())
        assertTrue(budget.recordDeliveredAndMayContinue())
        assertTrue(budget.recordDeliveredAndMayContinue())
        assertFalse(budget.recordDeliveredAndMayContinue())
        budget.reset()
        assertTrue(budget.recordDeliveredAndMayContinue())
    }
}
