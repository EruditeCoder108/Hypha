package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayEncounterSchedulerTest {
    @Test
    fun firstEncounterStartsImmediatelyAndBusyDoesNotConsumeIdleBackoff() {
        val scheduler = RelayEncounterScheduler()

        assertTrue(scheduler.canStart("peer", 1_000L))
        scheduler.markStarted("peer", 1_000L)
        assertFalse(scheduler.canStart("peer", 1_100L))

        scheduler.markBusy("peer", 1_100L)
        assertEquals(1_450L, scheduler.nextEligibleAt("peer"))
        assertTrue(scheduler.canStart("peer", 1_450L))
    }

    @Test
    fun emptyEncountersBackOffButUrgentWorkBypassesTheDelay() {
        val scheduler = RelayEncounterScheduler()

        scheduler.markStarted("peer", 0L)
        scheduler.markSucceeded("peer", 1_000L, movedPayload = false)
        assertEquals(16_000L, scheduler.nextEligibleAt("peer"))
        assertFalse(scheduler.canStart("peer", 2_000L))

        scheduler.nudge("peer", 2_000L)
        assertTrue(scheduler.canStart("peer", 2_000L))
    }

    @Test
    fun productiveEncounterGetsPromptReceiptFollowUp() {
        val scheduler = RelayEncounterScheduler()

        scheduler.markStarted("peer", 5_000L)
        scheduler.markSucceeded("peer", 6_000L, movedPayload = true)

        assertFalse(scheduler.canStart("peer", 6_749L))
        assertTrue(scheduler.canStart("peer", 6_750L))
    }

    @Test
    fun settledMeshBackoffCanYieldToLowerPriorityWork() {
        val scheduler = RelayEncounterScheduler()

        scheduler.markStarted("peer", 0L)
        scheduler.markSucceeded("peer", 1_000L, movedPayload = false)
        assertFalse(scheduler.canStart("peer", 2_000L))

        scheduler.releaseSuccessfulBackoff("peer", 2_000L)

        assertTrue(scheduler.canStart("peer", 2_000L))
    }

    @Test
    fun lowerPriorityWorkDoesNotBypassFailureOrInflightBackoff() {
        val scheduler = RelayEncounterScheduler()

        scheduler.markStarted("failed", 0L)
        scheduler.markFailed("failed", 100L)
        scheduler.releaseSuccessfulBackoff("failed", 200L)
        assertFalse(scheduler.canStart("failed", 200L))

        scheduler.markStarted("inflight", 0L)
        scheduler.releaseSuccessfulBackoff("inflight", 1_000L)
        assertFalse(scheduler.canStart("inflight", 1_000L))
    }

    @Test
    fun failuresRetryExponentiallyAndThenCap() {
        val scheduler = RelayEncounterScheduler()
        var now = 0L
        val expectedDelays = listOf(750L, 1_500L, 3_000L, 6_000L, 12_000L, 12_000L)

        for (delay in expectedDelays) {
            scheduler.markStarted("peer", now)
            scheduler.markFailed("peer", now)
            assertEquals(now + delay, scheduler.nextEligibleAt("peer"))
            now += delay
        }
    }
}
