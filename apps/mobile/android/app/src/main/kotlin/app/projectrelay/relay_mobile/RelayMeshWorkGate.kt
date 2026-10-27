package app.projectrelay.relay_mobile

/**
 * Suppresses a repeated empty mesh exchange until either side advertises changed work.
 *
 * The authenticated identity is the long-lived key. The rotating discovery token remains in
 * the snapshot so a restarted peer still receives one fresh inventory exchange.
 */
internal class RelayMeshWorkGate {
    private val emptySnapshotByPeer = mutableMapOf<String, WorkSnapshot>()
    private val attemptSnapshotByToken = mutableMapOf<String, WorkSnapshot>()

    fun canAttempt(
        peerKey: String,
        peerToken: String,
        localRevision: Long,
        remoteHint: Int,
    ): Boolean = emptySnapshotByPeer[peerKey] != WorkSnapshot(
        peerToken = peerToken,
        localRevision = localRevision,
        remoteHint = remoteHint,
    )

    fun markEmpty(
        peerKey: String,
        peerToken: String,
        localRevision: Long,
        remoteHint: Int,
    ) {
        emptySnapshotByPeer[peerKey] = WorkSnapshot(
            peerToken = peerToken,
            localRevision = localRevision,
            remoteHint = remoteHint,
        )
    }

    /** Captures exactly the work state represented by an outgoing inventory request. */
    fun markAttemptStarted(
        peerToken: String,
        localRevision: Long,
        remoteHint: Int,
    ) {
        attemptSnapshotByToken[peerToken] = WorkSnapshot(
            peerToken = peerToken,
            localRevision = localRevision,
            remoteHint = remoteHint,
        )
    }

    /**
     * Records an empty result only when no local or advertised peer work changed while the
     * exchange was in flight. Returns false when the caller must promptly try the new work.
     *
     * A missing attempt belongs to an inbound/server exchange, for which the current snapshot
     * remains the best suppression boundary.
     */
    fun markEmptyIfAttemptUnchanged(
        peerKey: String,
        peerToken: String,
        localRevision: Long,
        remoteHint: Int,
    ): Boolean {
        val current = WorkSnapshot(
            peerToken = peerToken,
            localRevision = localRevision,
            remoteHint = remoteHint,
        )
        val attempted = attemptSnapshotByToken.remove(peerToken)
        if (attempted != null && attempted != current) {
            emptySnapshotByPeer.remove(peerKey)
            return false
        }
        emptySnapshotByPeer[peerKey] = current
        return true
    }

    fun markAttemptFinished(peerKey: String, peerToken: String) {
        attemptSnapshotByToken.remove(peerToken)
        emptySnapshotByPeer.remove(peerKey)
    }

    fun markAttemptFailed(peerToken: String) {
        attemptSnapshotByToken.remove(peerToken)
    }

    fun clearPeer(peerKey: String) {
        emptySnapshotByPeer.remove(peerKey)
    }

    fun clear() {
        emptySnapshotByPeer.clear()
        attemptSnapshotByToken.clear()
    }

    private data class WorkSnapshot(
        val peerToken: String,
        val localRevision: Long,
        val remoteHint: Int,
    )
}
