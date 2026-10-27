package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayIdentityRefreshSchedulerTest {
    @Test
    fun encounterRefreshWaitsThenRunsOnlyOnceAfterSuccess() {
        val scheduler = RelayIdentityRefreshScheduler()

        scheduler.observe("peer", 1_000L)
        assertNull(scheduler.nextEligibleToken(2_499L))
        assertEquals("peer", scheduler.nextEligibleToken(2_500L))

        scheduler.markStarted("peer")
        assertTrue(scheduler.isInFlight("peer"))
        assertNull(scheduler.nextEligibleToken(9_000L))

        scheduler.markSucceeded("peer")
        scheduler.observe("peer", 10_000L)
        assertFalse(scheduler.isInFlight("peer"))
        assertNull(scheduler.nextEligibleToken(30_000L))
    }

    @Test
    fun profileChangeForcesACompletedPeerToRefreshImmediately() {
        val scheduler = RelayIdentityRefreshScheduler()

        scheduler.observe("peer", 0L)
        scheduler.markStarted("peer")
        scheduler.markSucceeded("peer")
        scheduler.force("peer", 8_000L)

        assertTrue(scheduler.isForced("peer"))
        assertEquals("peer", scheduler.nextEligibleToken(8_000L))
    }

    @Test
    fun failuresBackOffAndEventuallyStopForThisEncounter() {
        val scheduler = RelayIdentityRefreshScheduler()

        scheduler.observe("peer", 0L)
        scheduler.markStarted("peer")
        scheduler.markFailed("peer", 1_500L)
        assertNull(scheduler.nextEligibleToken(2_999L))
        assertEquals("peer", scheduler.nextEligibleToken(3_000L))

        scheduler.markStarted("peer")
        scheduler.markFailed("peer", 3_000L)
        assertEquals("peer", scheduler.nextEligibleToken(7_000L))

        scheduler.markStarted("peer")
        scheduler.markFailed("peer", 7_000L)
        assertNull(scheduler.nextEligibleToken(60_000L))
    }

    @Test
    fun preemptedRefreshYieldsToForegroundWork() {
        val scheduler = RelayIdentityRefreshScheduler()

        scheduler.force("peer", 5_000L)
        scheduler.markStarted("peer")
        scheduler.markPreempted("peer", 5_100L)

        assertFalse(scheduler.isInFlight("peer"))
        assertNull(scheduler.nextEligibleToken(6_599L))
        assertEquals("peer", scheduler.nextEligibleToken(6_600L))
    }
}
