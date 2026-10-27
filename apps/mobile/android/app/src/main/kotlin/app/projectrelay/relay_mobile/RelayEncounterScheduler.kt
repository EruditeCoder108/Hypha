package app.projectrelay.relay_mobile

/**
 * Per-peer mesh retry policy.
 *
 * Productive encounters receive one prompt follow-up so newly generated receipts can leave.
 * Failed/busy links retry quickly, while genuinely empty encounters progressively back off.
 */
internal class RelayEncounterScheduler(
    private val busyRetryMs: Long = 350L,
    private val activeFollowUpMs: Long = 750L,
    private val failureDelaysMs: LongArray = longArrayOf(750L, 1_500L, 3_000L, 6_000L, 12_000L),
    private val idleDelaysMs: LongArray = longArrayOf(15_000L, 30_000L, 60_000L, 120_000L),
) {
    private val states = mutableMapOf<String, PeerState>()

    fun canStart(peerToken: String, nowElapsedMs: Long): Boolean {
        val state = states.getOrPut(peerToken, ::PeerState)
        return !state.inFlight && nowElapsedMs >= state.nextEligibleAtMs
    }

    fun markStarted(peerToken: String, nowElapsedMs: Long) {
        val state = states.getOrPut(peerToken, ::PeerState)
        state.inFlight = true
        // A guard against duplicate scan callbacks before the GATT client becomes visible.
        state.nextEligibleAtMs = nowElapsedMs + busyRetryMs
    }

    fun markBusy(peerToken: String, nowElapsedMs: Long) {
        val state = states.getOrPut(peerToken, ::PeerState)
        state.inFlight = false
        state.nextEligibleAtMs = nowElapsedMs + busyRetryMs
    }

    fun markFailed(peerToken: String, nowElapsedMs: Long) {
        val state = states.getOrPut(peerToken, ::PeerState)
        val delay = failureDelaysMs[state.failureStreak.coerceAtMost(failureDelaysMs.lastIndex)]
        state.inFlight = false
        state.failureStreak = (state.failureStreak + 1).coerceAtMost(failureDelaysMs.size)
        state.nextEligibleAtMs = nowElapsedMs + delay
    }

    fun markSucceeded(peerToken: String, nowElapsedMs: Long, movedPayload: Boolean) {
        val state = states.getOrPut(peerToken, ::PeerState)
        state.inFlight = false
        state.failureStreak = 0
        if (movedPayload) {
            state.idleStreak = 0
            state.nextEligibleAtMs = nowElapsedMs + activeFollowUpMs
        } else {
            val delay = idleDelaysMs[state.idleStreak.coerceAtMost(idleDelaysMs.lastIndex)]
            state.idleStreak = (state.idleStreak + 1).coerceAtMost(idleDelaysMs.size)
            state.nextEligibleAtMs = nowElapsedMs + delay
        }
    }

    /** A local queue change or a remote urgency transition bypasses idle backoff. */
    fun nudge(peerToken: String, nowElapsedMs: Long) {
        val state = states.getOrPut(peerToken, ::PeerState)
        state.idleStreak = 0
        if (!state.inFlight) state.nextEligibleAtMs = nowElapsedMs
    }

    /**
     * Releases only backoff produced by a completed/busy encounter before lower-priority work.
     * A real failed link keeps its retry delay, and an in-flight exchange is never disturbed.
     */
    fun releaseSuccessfulBackoff(peerToken: String, nowElapsedMs: Long) {
        val state = states.getOrPut(peerToken, ::PeerState)
        if (state.inFlight || state.failureStreak != 0) return
        state.idleStreak = 0
        state.nextEligibleAtMs = minOf(state.nextEligibleAtMs, nowElapsedMs)
    }

    fun remove(peerToken: String) {
        states.remove(peerToken)
    }

    fun clear() {
        states.clear()
    }

    internal fun nextEligibleAt(peerToken: String): Long? = states[peerToken]?.nextEligibleAtMs

    private data class PeerState(
        var nextEligibleAtMs: Long = 0L,
        var idleStreak: Int = 0,
        var failureStreak: Int = 0,
        var inFlight: Boolean = false,
    )
}
