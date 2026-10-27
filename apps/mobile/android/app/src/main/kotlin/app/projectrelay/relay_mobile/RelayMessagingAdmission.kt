package app.projectrelay.relay_mobile

/** Sender-side safety window required by the recipient ratchet's skipped-key bound. */
internal object RelayMeshTextWindow {
    const val MAX_UNACKNOWLEDGED = 32

    fun availableSlots(activeUnacknowledged: Int): Int {
        require(activeUnacknowledged >= 0)
        return (MAX_UNACKNOWLEDGED - activeUnacknowledged).coerceAtLeast(0)
    }
}

/** Recovers a bounded retry deadline if the user or network moves wall time backwards. */
internal object RelayRetryClockPolicy {
    fun futureCutoff(nowMs: Long, maximumLegitimateDelayMs: Long): Long {
        require(maximumLegitimateDelayMs >= 0)
        return if (nowMs > Long.MAX_VALUE - maximumLegitimateDelayMs) {
            Long.MAX_VALUE
        } else {
            nowMs + maximumLegitimateDelayMs
        }
    }

    fun isEligible(nextAttemptAtMs: Long?, nowMs: Long, maximumLegitimateDelayMs: Long): Boolean =
        nextAttemptAtMs == null ||
            nextAttemptAtMs <= nowMs ||
            nextAttemptAtMs > futureCutoff(nowMs, maximumLegitimateDelayMs)
}

internal enum class RelayTextTransport {
    DIRECT,
    MESH,
}

/** Truthful UI state derived from durable mesh custody, never from radio proximity. */
internal object RelayMeshMessagePresentation {
    fun visibleStatus(
        outgoing: Boolean,
        storedStatus: String,
        hasActiveEnvelope: Boolean,
        wasAcceptedByRelay: Boolean,
    ): String = when {
        !outgoing || storedStatus != "queued" -> storedStatus
        !hasActiveEnvelope -> "expired"
        wasAcceptedByRelay -> "relayed"
        else -> storedStatus
    }
}

/** Keeps one conversation on its existing durable FIFO until that backlog is settled. */
internal object RelayConversationTransportPolicy {
    fun select(
        requested: RelayTextTransport,
        hasDirectBacklog: Boolean,
        hasMeshBacklog: Boolean,
    ): RelayTextTransport = when {
        // Direct wins the impossible legacy mixed state because it is the only queue whose
        // retry lease can explain an older message waiting behind newer RMS2 traffic.
        hasDirectBacklog -> RelayTextTransport.DIRECT
        hasMeshBacklog -> RelayTextTransport.MESH
        else -> requested
    }
}

/**
 * Keeps completion-driven work from selecting the same visible phone forever.
 * Tokens are encounter-scoped and never persisted.
 */
internal class RelayPeerFairness {
    private var lastServicedToken: String? = null

    fun ordered(tokens: Collection<String>): List<String> {
        val sorted = tokens.distinct().sorted()
        if (sorted.size < 2) return sorted
        val previousIndex = sorted.indexOf(lastServicedToken)
        if (previousIndex < 0) return sorted
        val start = (previousIndex + 1) % sorted.size
        return sorted.drop(start) + sorted.take(start)
    }

    fun markServiced(token: String) {
        lastServicedToken = token
    }

    fun forget(token: String) {
        if (lastServicedToken == token) lastServicedToken = null
    }

    fun clear() {
        lastServicedToken = null
    }
}

/** Allows one bounded direct-text connection before urgent RMS2 work gets an opportunity. */
internal class RelayRadioAdmissionPolicy(
    private val maximumDirectAdmissionsBeforeMesh: Int = 1,
) {
    private var consecutiveDirectAdmissions = 0

    init {
        require(maximumDirectAdmissionsBeforeMesh > 0)
    }

    fun shouldOfferMeshFirst(hasUrgentMeshWork: Boolean): Boolean =
        hasUrgentMeshWork && consecutiveDirectAdmissions >= maximumDirectAdmissionsBeforeMesh

    fun recordDirectAdmission() {
        consecutiveDirectAdmissions =
            (consecutiveDirectAdmissions + 1).coerceAtMost(maximumDirectAdmissionsBeforeMesh)
    }

    fun recordMeshAdmission() {
        consecutiveDirectAdmissions = 0
    }

    fun clear() {
        consecutiveDirectAdmissions = 0
    }
}

/** Bounds how many direct messages one authenticated warm GATT connection may monopolize. */
internal class RelayWarmTextBudget(
    private val maximumMessages: Int = 4,
) {
    private var deliveredMessages = 0

    init {
        require(maximumMessages > 0)
    }

    fun reset() {
        deliveredMessages = 0
    }

    /** True when the connection may drain another queued text message. */
    fun recordDeliveredAndMayContinue(): Boolean {
        deliveredMessages += 1
        return deliveredMessages < maximumMessages
    }
}
