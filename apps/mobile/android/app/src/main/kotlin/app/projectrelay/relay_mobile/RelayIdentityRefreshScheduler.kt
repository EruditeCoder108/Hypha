package app.projectrelay.relay_mobile

/**
 * Low-priority, encounter-scoped scheduling for authenticated contact refreshes.
 *
 * A temporary BLE token is attempted only a few times. Successful and exhausted
 * tokens stay terminal until the encounter disappears, preventing a scan loop
 * from repeatedly opening GATT connections.
 */
internal class RelayIdentityRefreshScheduler(
    private val initialDelayMs: Long = 1_500L,
    private val retryDelaysMs: LongArray = longArrayOf(1_500L, 4_000L),
) {
    private val entries = linkedMapOf<String, Entry>()

    fun observe(token: String, nowElapsedMs: Long) {
        entries.putIfAbsent(
            token,
            Entry(nextEligibleAtMs = nowElapsedMs + initialDelayMs),
        )
    }

    fun force(token: String, nowElapsedMs: Long) {
        entries[token] = Entry(nextEligibleAtMs = nowElapsedMs, forced = true)
    }

    fun nextEligibleToken(nowElapsedMs: Long): String? =
        entries.entries.firstOrNull { (_, entry) ->
            !entry.inFlight && !entry.terminal && nowElapsedMs >= entry.nextEligibleAtMs
        }?.key

    fun markStarted(token: String) {
        entries[token]?.inFlight = true
    }

    fun markSucceeded(token: String) {
        entries[token]?.apply {
            inFlight = false
            terminal = true
        }
    }

    fun markFailed(token: String, nowElapsedMs: Long) {
        val entry = entries[token] ?: return
        entry.inFlight = false
        if (entry.attempts >= retryDelaysMs.size) {
            entry.terminal = true
            return
        }
        entry.nextEligibleAtMs = nowElapsedMs + retryDelaysMs[entry.attempts]
        entry.attempts += 1
    }

    fun markPreempted(token: String, nowElapsedMs: Long) {
        entries[token]?.apply {
            inFlight = false
            nextEligibleAtMs = nowElapsedMs + initialDelayMs
        }
    }

    fun isInFlight(token: String): Boolean = entries[token]?.inFlight == true

    fun isForced(token: String): Boolean = entries[token]?.forced == true

    fun remove(token: String) {
        entries.remove(token)
    }

    fun clear() {
        entries.clear()
    }

    private data class Entry(
        var nextEligibleAtMs: Long,
        var attempts: Int = 0,
        var inFlight: Boolean = false,
        var terminal: Boolean = false,
        val forced: Boolean = false,
    )
}
