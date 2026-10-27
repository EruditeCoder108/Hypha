package app.projectrelay.relay_mobile

/** Radio admission rule for the bounded experimental fixed-node exchange. */
internal object HyphaFixedNodeSchedulingPolicy {
    const val IDLE_RESYNC_COOLDOWN_MS = 15_000L
    const val WORK_FOLLOW_UP_COOLDOWN_MS = 1_000L
    const val FAILURE_COOLDOWN_MS = 15_000L

    data class RetryWindow(
        val nextAttemptAtMs: Long,
        val failureNotBeforeMs: Long = Long.MIN_VALUE,
    )

    /**
     * Phone work is admitted before a fixed-node sync starts. Once a node sync is active,
     * newly discovered phone work waits for that bounded exchange instead of aborting it.
     */
    fun deferPhoneWork(activeFixedNodeSync: Boolean): Boolean = activeFixedNodeSync

    fun started(nowElapsedMs: Long): RetryWindow = RetryWindow(
        nextAttemptAtMs = nowElapsedMs + IDLE_RESYNC_COOLDOWN_MS,
    )

    fun completed(
        current: RetryWindow,
        nowElapsedMs: Long,
        followUpRequired: Boolean,
    ): RetryWindow = RetryWindow(
        nextAttemptAtMs = if (followUpRequired) {
            minOf(current.nextAttemptAtMs, nowElapsedMs + WORK_FOLLOW_UP_COOLDOWN_MS)
        } else {
            current.nextAttemptAtMs
        },
    )

    fun localWorkChanged(current: RetryWindow, nowElapsedMs: Long): RetryWindow = current.copy(
        nextAttemptAtMs = minOf(
            current.nextAttemptAtMs,
            nowElapsedMs + WORK_FOLLOW_UP_COOLDOWN_MS,
        ),
    )

    fun failed(nowElapsedMs: Long): RetryWindow {
        val retryAt = nowElapsedMs + FAILURE_COOLDOWN_MS
        return RetryWindow(nextAttemptAtMs = retryAt, failureNotBeforeMs = retryAt)
    }

    fun canAttempt(window: RetryWindow, nowElapsedMs: Long): Boolean =
        nowElapsedMs >= maxOf(window.nextAttemptAtMs, window.failureNotBeforeMs)
}
