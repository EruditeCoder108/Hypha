package app.projectrelay.relay_mobile

internal data class RelayTextRetryPlan(
    val identityDirectedTokens: List<String>,
    val singleUnobservedFallback: String?,
)

/** Pure admission policy for safely draining the durable direct-text outbox. */
internal object RelayTextRetryPolicy {
    fun plan(
        visiblePeerTokens: Collection<String>,
        hasAuthenticatedIdentity: (String) -> Boolean,
    ): RelayTextRetryPlan {
        val visible = visiblePeerTokens.distinct()
        val directed = visible.filter(hasAuthenticatedIdentity)
        return RelayTextRetryPlan(
            identityDirectedTokens = directed,
            // Before identity is known, trying an arbitrary radio is safe only when it is
            // the sole visible phone. The authenticated GATT proof still checks the recipient.
            singleUnobservedFallback = visible.singleOrNull()
                ?.takeIf { it !in directed },
        )
    }
}
