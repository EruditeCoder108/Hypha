package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RelayTextRetryPolicyTest {
    @Test
    fun `multiple visible phones retain every authenticated identity candidate`() {
        val plan = RelayTextRetryPolicy.plan(
            visiblePeerTokens = listOf("courier", "recipient", "recipient"),
            hasAuthenticatedIdentity = { it == "courier" || it == "recipient" },
        )

        assertEquals(listOf("courier", "recipient"), plan.identityDirectedTokens)
        assertNull(plan.singleUnobservedFallback)
    }

    @Test
    fun `unknown radios are excluded when several phones are visible`() {
        val plan = RelayTextRetryPolicy.plan(
            visiblePeerTokens = listOf("unknown", "recipient"),
            hasAuthenticatedIdentity = { it == "recipient" },
        )

        assertEquals(listOf("recipient"), plan.identityDirectedTokens)
        assertNull(plan.singleUnobservedFallback)
    }

    @Test
    fun `one unknown phone retains the authenticated-handshake fallback`() {
        val plan = RelayTextRetryPolicy.plan(
            visiblePeerTokens = listOf("only-phone"),
            hasAuthenticatedIdentity = { false },
        )

        assertEquals(emptyList<String>(), plan.identityDirectedTokens)
        assertEquals("only-phone", plan.singleUnobservedFallback)
    }

    @Test
    fun `no visible phone produces no retry candidate`() {
        val plan = RelayTextRetryPolicy.plan(
            visiblePeerTokens = emptyList(),
            hasAuthenticatedIdentity = { true },
        )

        assertEquals(emptyList<String>(), plan.identityDirectedTokens)
        assertNull(plan.singleUnobservedFallback)
    }
}
