package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HyphaFixedNodeSchedulingPolicyTest {
    @Test
    fun `phone advertisement does not abort an active fixed-node exchange`() {
        assertTrue(HyphaFixedNodeSchedulingPolicy.deferPhoneWork(activeFixedNodeSync = true))
    }

    @Test
    fun `phone work runs immediately while the fixed node is idle`() {
        assertFalse(HyphaFixedNodeSchedulingPolicy.deferPhoneWork(activeFixedNodeSync = false))
    }

    @Test
    fun `idle fixed node polling keeps the conservative cooldown`() {
        val started = HyphaFixedNodeSchedulingPolicy.started(nowElapsedMs = 2_000L)

        assertEquals(17_000L, started.nextAttemptAtMs)
        assertFalse(HyphaFixedNodeSchedulingPolicy.canAttempt(started, 16_999L))
        assertTrue(HyphaFixedNodeSchedulingPolicy.canAttempt(started, 17_000L))
    }

    @Test
    fun `durable work releases a bounded one second follow up`() {
        val started = HyphaFixedNodeSchedulingPolicy.started(nowElapsedMs = 2_000L)
        val nudged = HyphaFixedNodeSchedulingPolicy.localWorkChanged(
            current = started,
            nowElapsedMs = 4_000L,
        )

        assertEquals(5_000L, nudged.nextAttemptAtMs)
        assertFalse(HyphaFixedNodeSchedulingPolicy.canAttempt(nudged, 4_999L))
        assertTrue(HyphaFixedNodeSchedulingPolicy.canAttempt(nudged, 5_000L))
    }

    @Test
    fun `recipient delivery gets a fast receipt upload follow up`() {
        val started = HyphaFixedNodeSchedulingPolicy.started(nowElapsedMs = 2_000L)
        val completed = HyphaFixedNodeSchedulingPolicy.completed(
            current = started,
            nowElapsedMs = 4_500L,
            followUpRequired = true,
        )

        assertEquals(5_500L, completed.nextAttemptAtMs)
    }

    @Test
    fun `unchanged completion does not create a polling loop`() {
        val started = HyphaFixedNodeSchedulingPolicy.started(nowElapsedMs = 2_000L)
        val completed = HyphaFixedNodeSchedulingPolicy.completed(
            current = started,
            nowElapsedMs = 4_500L,
            followUpRequired = false,
        )

        assertEquals(17_000L, completed.nextAttemptAtMs)
    }

    @Test
    fun `failure backoff cannot be shortened by newly queued work`() {
        val failed = HyphaFixedNodeSchedulingPolicy.failed(nowElapsedMs = 10_000L)
        val nudged = HyphaFixedNodeSchedulingPolicy.localWorkChanged(
            current = failed,
            nowElapsedMs = 11_000L,
        )

        assertEquals(12_000L, nudged.nextAttemptAtMs)
        assertFalse(HyphaFixedNodeSchedulingPolicy.canAttempt(nudged, 24_999L))
        assertTrue(HyphaFixedNodeSchedulingPolicy.canAttempt(nudged, 25_000L))
    }
}
