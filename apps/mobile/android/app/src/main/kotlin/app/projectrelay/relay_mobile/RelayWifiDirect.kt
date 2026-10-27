package app.projectrelay.relay_mobile

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.NetworkInfo
import android.location.LocationManager
import android.net.wifi.WpsInfo
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import kotlin.math.max

/** BLE-authorized Wi-Fi Direct data plane for resumable encrypted bulk transfers. */
internal class RelayWifiDirect(
    private val activity: Context,
    private val emit: (Map<String, Any>) -> Unit,
    private val meshStore: RelayMeshStore = RelayMeshStore(activity),
    private val courierAttachmentStore: RelayCourierAttachmentStore =
        RelayCourierAttachmentStore(activity),
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val random = SecureRandom()
    private val ioExecutor = Executors.newCachedThreadPool()
    private val socketLock = Any()
    private val manager = activity.getSystemService(WifiP2pManager::class.java)
    private var channel: WifiP2pManager.Channel? = null
    private var localService: WifiP2pDnsSdServiceInfo? = null
    private var serviceRequest: WifiP2pDnsSdServiceRequest? = null
    private val devicesByToken = mutableMapOf<String, WifiP2pDevice>()
    private val peerKeyByDeviceAddress = mutableMapOf<String, String>()
    private val authorizationTokenByPeerKey = mutableMapOf<String, ByteArray?>()
    private val lastSeenByPeerKey = mutableMapOf<String, Long>()
    private val authorizationsByOffer = mutableMapOf<String, RelayWifiUpgradeAuthorization>()
    private val messageStore = RelayMessageStore(activity)
    private val attachmentStore = RelayAttachmentStore(activity)
    private var localToken: String? = null
    private var activeTest: ActiveTest? = null
    private var pendingTextTransfer: PendingTextTransfer? = null
    private var pendingAttachmentTransfer: PendingAttachmentTransfer? = null
    private var pendingCourierAttachmentTransfer: PendingCourierAttachmentTransfer? = null
    private var pendingRecipientAttachmentTransfer: PendingRecipientAttachmentTransfer? = null
    private var pendingUpgradePeerKey: String? = null
    private var connectedPeerToken: String? = null
    private var receiverRegistered = false
    private var started = false
    private var socketJobStarted = false
    private var serverSocket: ServerSocket? = null
    private var socket: Socket? = null
    private var sessionGeneration = 0L
    private var warmConnectionInfo: WifiP2pInfo? = null
    private var warmRemoteToken: ByteArray? = null
    private var consecutiveRadioBusyFailures = 0

    init {
        attachmentStore.recoverInterruptedOutgoing()
    }

    private val connectionTimeout = Runnable {
        if (activeTest != null && !socketJobStarted) {
            failActiveConnection(
                "wifi_direct_connection_timeout",
                "The other phone did not accept or complete the Wi-Fi connection in time.",
            )
        }
    }

    private val discoveryWatchdog = object : Runnable {
        override fun run() {
            if (!started) return
            if (activeTest == null && !socketJobStarted && warmConnectionInfo == null) {
                pruneStalePeers()
                refreshServiceDiscovery()
                if (devicesByToken.isEmpty()) {
                    emit(
                        mapOf(
                            "type" to "wifi_direct_passive_ready",
                            "message" to "No outgoing peer record yet; this phone can still accept an incoming Relay connection.",
                        ),
                    )
                }
            }
            mainHandler.postDelayed(this, DISCOVERY_WATCHDOG_MS)
        }
    }

    private val warmGroupTeardown = Runnable {
        if (started && activeTest == null && !socketJobStarted) {
            removeGroup()
        }
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val enabled = intent.getIntExtra(
                        WifiP2pManager.EXTRA_WIFI_STATE,
                        WifiP2pManager.WIFI_P2P_STATE_DISABLED,
                    ) == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                    emit(mapOf("type" to "wifi_direct_state", "enabled" to enabled))
                    if (!enabled && started) {
                        emit(errorEvent("wifi_off", "Wi-Fi was turned off; the high-speed path stopped."))
                        mainHandler.post(::stop)
                    }
                }
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION ->
                    handleConnectionBroadcast(intent)
            }
        }
    }

    @SuppressLint("MissingPermission")
    @Synchronized
    fun start(): Map<String, Any> {
        if (started && channel != null) return mapOf("token" to requireNotNull(localToken))
        if (started) stop()
        val p2pManager = manager
            ?: throw WifiDirectException("wifi_direct_unsupported", "Wi-Fi Direct is unavailable.")
        val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.NEARBY_WIFI_DEVICES
        } else {
            Manifest.permission.ACCESS_FINE_LOCATION
        }
        if (activity.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
            throw WifiDirectException(
                "wifi_permission_required",
                "Allow Nearby Wi-Fi before using encrypted attachments.",
            )
        }
        val wifi = activity.applicationContext.getSystemService(android.net.wifi.WifiManager::class.java)
        if (wifi?.isWifiEnabled != true) {
            throw WifiDirectException("wifi_off", "Turn Wi-Fi on before enabling high-speed transfers.")
        }
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
            val location = activity.getSystemService(LocationManager::class.java)
            val locationEnabled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                location?.isLocationEnabled == true
            } else {
                location?.isProviderEnabled(LocationManager.GPS_PROVIDER) == true ||
                    location?.isProviderEnabled(LocationManager.NETWORK_PROVIDER) == true
            }
            if (!locationEnabled) {
                throw WifiDirectException(
                    "location_off",
                    "Turn Location on; Android 12 and older require it for Wi-Fi peer discovery.",
                )
            }
        }
        val generation = ++sessionGeneration
        val p2pChannel = p2pManager.initialize(activity, Looper.getMainLooper()) {
            if (started && sessionGeneration == generation) {
                emit(errorEvent("wifi_direct_channel_lost", "The Android Wi-Fi Direct channel was lost."))
                channel = null
                mainHandler.post(::stop)
            }
        }
        val token = ByteArray(TOKEN_BYTES).also(random::nextBytes).toHex()
        channel = p2pChannel
        localToken = token
        devicesByToken.clear()
        peerKeyByDeviceAddress.clear()
        authorizationTokenByPeerKey.clear()
        lastSeenByPeerKey.clear()
        activeTest = null
        connectedPeerToken = null
        socketJobStarted = false
        clearWarmConnection()
        registerReceiver()
        started = true
        mainHandler.removeCallbacks(discoveryWatchdog)
        mainHandler.postDelayed(discoveryWatchdog, DISCOVERY_WATCHDOG_MS)
        bootstrapP2p(p2pManager, p2pChannel, token, attempt = 0)
        emit(mapOf("type" to "wifi_direct_started", "token" to token))
        return mapOf("token" to token)
    }

    @SuppressLint("MissingPermission")
    fun runSpeedTest(peerToken: String) {
        beginSpeedTest(peerToken, authorization = null)
    }

    fun localTokenBytes(): ByteArray? = localToken?.hexToBytesOrNull()

    fun isBusy(): Boolean =
        activeTest != null || pendingTextTransfer != null ||
            pendingAttachmentTransfer != null || pendingCourierAttachmentTransfer != null ||
            pendingRecipientAttachmentTransfer != null ||
            pendingUpgradePeerKey != null ||
            socketJobStarted

    /** Called only after a verified BLE peer asks for a bulk upgrade. */
    fun ensureStartedToken(): ByteArray? = try {
        start()
        localTokenBytes()
    } catch (error: WifiDirectException) {
        emit(errorEvent(error.code, error.message))
        null
    }

    fun prepareAuthorization(peerKey: String): ByteArray {
        checkStarted()
        if (!devicesByToken.containsKey(peerKey)) {
            throw WifiDirectException("wifi_peer_stale", "That Wi-Fi Direct peer is no longer available.")
        }
        if (pendingUpgradePeerKey != null) {
            throw WifiDirectException("wifi_direct_busy", "Another secure Wi-Fi upgrade is pending.")
        }
        pendingUpgradePeerKey = peerKey
        return authorizationTokenByPeerKey[peerKey]?.copyOf() ?: ByteArray(TOKEN_BYTES)
    }

    fun installAuthorization(authorization: RelayWifiUpgradeAuthorization) {
        if (authorization.isExpired()) {
            authorization.destroySecret()
            throw WifiDirectException("wifi_upgrade_expired", "The Wi-Fi upgrade capability expired.")
        }
        val currentToken = localTokenBytes()
        if (currentToken == null || !authorization.localToken().contentEquals(currentToken)) {
            authorization.destroySecret()
            throw WifiDirectException("wifi_upgrade_stale", "The Wi-Fi discovery session changed.")
        }
        val offerKey = authorization.offerId.toHex()
        synchronized(authorizationsByOffer) {
            authorizationsByOffer.put(offerKey, authorization)?.destroySecret()
        }
        if (authorization.isInitiator) {
            val requestedPeerKey = pendingUpgradePeerKey
            val generation = sessionGeneration
            mainHandler.post {
                startAuthorizedInitiator(
                    authorization,
                    requestedPeerKey,
                    offerKey,
                    SystemClock.elapsedRealtime(),
                    generation,
                )
            }
        } else {
            startWarmResponderIfReady(authorization)
        }
    }

    private fun startAuthorizedInitiator(
        authorization: RelayWifiUpgradeAuthorization,
        requestedPeerKey: String?,
        offerKey: String,
        waitStartedAtMs: Long,
        generation: Long,
    ) {
        var queuedMessage: RelayMessageCodec.TextMessage? = null
        var attemptedAttachment: RelayAttachmentStore.StoredAttachment? = null
        try {
            if (!started || generation != sessionGeneration) {
                synchronized(authorizationsByOffer) {
                    authorizationsByOffer.remove(offerKey)?.destroySecret()
                }
                return
            }
            if (authorization.isExpired()) {
                throw WifiDirectException("wifi_upgrade_expired", "The Wi-Fi upgrade capability expired.")
            }
            val peerKey = if (requestedPeerKey == AUTO_PEER_KEY) {
                authorizationTokenByPeerKey.entries.firstOrNull { (_, token) ->
                    token?.contentEquals(authorization.remoteToken()) == true
                }?.key
            } else {
                requestedPeerKey
            }
            if (peerKey == null && requestedPeerKey == AUTO_PEER_KEY &&
                SystemClock.elapsedRealtime() - waitStartedAtMs < AUTHORIZED_PEER_WAIT_MS
            ) {
                refreshServiceDiscovery()
                mainHandler.postDelayed(
                    {
                        startAuthorizedInitiator(
                            authorization,
                            requestedPeerKey,
                            offerKey,
                            waitStartedAtMs,
                            generation,
                        )
                    },
                    AUTHORIZED_PEER_RETRY_MS,
                )
                return
            }
            val resolvedPeerKey = peerKey ?: throw WifiDirectException(
                "wifi_peer_stale",
                "The verified phone did not appear on Wi-Fi Direct in time.",
            )
            val expectedToken = authorizationTokenByPeerKey[resolvedPeerKey]
            if (expectedToken != null && !expectedToken.contentEquals(authorization.remoteToken())) {
                throw WifiDirectException(
                    "wifi_upgrade_mismatch",
                    "BLE resolved a different Wi-Fi peer than the selected device.",
                )
            }
            pendingUpgradePeerKey = null
            val pendingText = pendingTextTransfer?.takeIf { it.peerToken == resolvedPeerKey }
            val pendingAttachment = pendingAttachmentTransfer
            val pendingCourierAttachment = pendingCourierAttachmentTransfer
            val pendingRecipientAttachment = pendingRecipientAttachmentTransfer
            when {
                pendingText != null -> {
                    pendingTextTransfer = null
                    queuedMessage = pendingText.message
                    messageStore.storeOutgoing(pendingText.message, authorization.peerFingerprint)
                    val attempts = messageStore.beginAttempt(pendingText.message.id)
                    emit(
                        mapOf(
                            "type" to "text_message_queued",
                            "token" to resolvedPeerKey,
                            "messageId" to RelayMessageCodec.idHex(pendingText.message.id),
                            "text" to pendingText.message.text,
                            "fingerprint" to authorization.peerFingerprint,
                            "attemptCount" to attempts,
                            "automatic" to false,
                        ) + pendingText.message.replyMap(),
                    )
                    beginTransfer(
                        peerToken = resolvedPeerKey,
                        authorization = authorization,
                        payload = pendingText.message.encoded,
                        payloadKind = PayloadKind.USER_TEXT,
                        message = pendingText.message,
                    )
                }
                pendingCourierAttachment != null -> {
                    check(pendingCourierAttachment.courierFingerprint == authorization.peerFingerprint) {
                        "BLE authorized a different attachment courier."
                    }
                    pendingCourierAttachmentTransfer = null
                    beginCourierAttachmentTransfer(
                        resolvedPeerKey,
                        authorization,
                        pendingCourierAttachment,
                    )
                }
                pendingRecipientAttachment != null -> {
                    pendingRecipientAttachmentTransfer = null
                    beginRecipientAttachmentTransfer(
                        resolvedPeerKey,
                        authorization,
                        pendingRecipientAttachment,
                    )
                }
                pendingAttachment != null -> {
                    check(pendingAttachment.attachment.peerFingerprint == authorization.peerFingerprint) {
                        "BLE authorized a different attachment recipient."
                    }
                    pendingAttachmentTransfer = null
                    attemptedAttachment = attachmentStore.beginAttempt(
                        pendingAttachment.attachment.manifest.attachmentId,
                    )
                    beginAttachmentTransfer(resolvedPeerKey, authorization, attemptedAttachment)
                }
                requestedPeerKey == AUTO_PEER_KEY -> throw WifiDirectException(
                    "attachment_cancelled",
                    "The attachment transfer was paused.",
                )
                else -> beginSpeedTest(resolvedPeerKey, authorization)
            }
        } catch (error: RuntimeException) {
            val code = (error as? WifiDirectException)?.code ?: "wifi_upgrade_failed"
            queuedMessage?.let { message ->
                val retryAt = messageStore.markRetryableFailure(message.id, code)
                emitQueuedMessage(message, requestedPeerKey, retryAt, code)
            }
            attemptedAttachment?.let { attachment ->
                attachmentStore.markRetryable(attachment.manifest.attachmentId, code)
                emitAttachmentQueued(attachment, code)
            }
            synchronized(authorizationsByOffer) {
                authorizationsByOffer.remove(offerKey)?.destroySecret()
            }
            emit(
                errorEvent(
                    code,
                    error.message ?: "The secure Wi-Fi transfer could not start.",
                    requestedPeerKey?.takeUnless { it == AUTO_PEER_KEY },
                ),
            )
            pendingUpgradePeerKey = null
        }
    }

    fun prepareTextTransfer(peerToken: String, text: String): ByteArray {
        checkStarted()
        if (activeTest != null || pendingTextTransfer != null) {
            throw WifiDirectException("wifi_direct_busy", "A Wi-Fi transfer is already running.")
        }
        if (!devicesByToken.containsKey(peerToken)) {
            throw WifiDirectException("wifi_peer_stale", "That Wi-Fi Direct peer is no longer available.")
        }
        val message = try {
            RelayMessageCodec.create(text)
        } catch (error: RuntimeException) {
            throw WifiDirectException(
                "invalid_message",
                error.message ?: "The message cannot be encoded.",
            )
        }
        pendingTextTransfer = PendingTextTransfer(peerToken, message)
        val authorizationToken = prepareAuthorization(peerToken)
        emit(mapOf("type" to "wifi_text_prepared", "token" to peerToken))
        return authorizationToken
    }

    fun prepareAttachmentTransfer(attachmentIdHex: String): ByteArray {
        var attachment = attachmentStore.findByHexId(attachmentIdHex)
            ?: throw WifiDirectException("attachment_missing", "The queued attachment was not found.")
        if (attachment.direction != RelayAttachmentStore.Direction.OUTGOING ||
            attachment.status != RelayAttachmentStore.Status.QUEUED ||
            attachmentStore.isCancelled(attachment)
        ) {
            throw WifiDirectException("attachment_not_queued", "The attachment is not waiting to send.")
        }
        if (attachmentStore.isPaused(attachment)) {
            attachment = attachmentStore.markResumed(attachment.manifest.attachmentId)
        }
        // There is no BLE attachment data plane.  Every selected attachment is a
        // real Wi-Fi Direct transfer, including small files; otherwise it could
        // remain queued forever while repeatedly competing with text delivery.
        if (!RelayTransportPolicy.canUseWifiForAttachment()) {
            throw WifiDirectException("wifi_promotion_deferred", "Turn Wi-Fi on to send this attachment.")
        }
        start()
        if (activeTest != null || pendingTextTransfer != null || pendingAttachmentTransfer != null) {
            throw WifiDirectException("wifi_direct_busy", "A Wi-Fi transfer is already running.")
        }
        pendingAttachmentTransfer = PendingAttachmentTransfer(attachment)
        pendingUpgradePeerKey = AUTO_PEER_KEY
        emit(
            mapOf(
                "type" to "attachment_wifi_prepared",
                "attachmentId" to attachment.manifest.attachmentId.toHex(),
                "bytes" to attachment.manifest.plaintextBytes,
            ),
        )
        return ByteArray(TOKEN_BYTES)
    }

    /** Stages only HCU1-missing opaque HAC1 records; it cannot mark recipient delivery. */
    fun prepareCourierAttachmentTransfer(
        attachmentIdHex: String,
        courierFingerprint: String,
        encodedCustody: ByteArray,
    ): ByteArray {
        val attachment = attachmentStore.findByHexId(attachmentIdHex)
            ?: throw WifiDirectException("attachment_missing", "The queued attachment was not found.")
        if (
            attachment.direction != RelayAttachmentStore.Direction.OUTGOING ||
            attachment.status != RelayAttachmentStore.Status.QUEUED ||
            attachmentStore.isCancelled(attachment)
        ) {
            throw WifiDirectException("attachment_not_queued", "The attachment is not waiting to send.")
        }
        val custody = try {
            RelayCourierAttachmentCustody.decode(encodedCustody)
        } catch (error: RuntimeException) {
            throw WifiDirectException("attachment_custody_invalid", "Courier custody is invalid.")
        }
        if (
            !custody.planCommitted ||
            !custody.objectId.contentEquals(attachment.manifest.attachmentId) ||
            custody.chunkCount != attachment.manifest.chunks.size ||
            custody.missingChunks().isEmpty()
        ) {
            throw WifiDirectException(
                "attachment_custody_complete",
                "Courier custody has no missing opaque chunks.",
            )
        }
        val durable = meshStore.senderAttachmentCustody(custody.objectId, courierFingerprint)
        if (durable == null || !durable.encode().contentEquals(custody.encode())) {
            throw WifiDirectException(
                "attachment_custody_stale",
                "Courier custody changed before the Wi-Fi hop.",
            )
        }
        if (!RelayTransportPolicy.canUseWifiForAttachment()) {
            throw WifiDirectException("wifi_promotion_deferred", "Turn Wi-Fi on to relay this attachment.")
        }
        start()
        if (
            activeTest != null || pendingTextTransfer != null ||
            pendingAttachmentTransfer != null || pendingCourierAttachmentTransfer != null
        ) {
            throw WifiDirectException("wifi_direct_busy", "A Wi-Fi transfer is already running.")
        }
        pendingCourierAttachmentTransfer = PendingCourierAttachmentTransfer(
            attachment = attachment,
            courierFingerprint = courierFingerprint,
            custody = custody,
        )
        pendingUpgradePeerKey = AUTO_PEER_KEY
        emit(
            mapOf(
                "type" to "courier_attachment_wifi_prepared",
                "attachmentId" to attachment.manifest.attachmentId.toHex(),
                "remainingChunks" to custody.missingChunks().size,
                "bytes" to custody.missingChunks().sumOf { index ->
                    attachment.manifest.chunks[index].ciphertextBytes.toLong()
                },
            ),
        )
        return ByteArray(TOKEN_BYTES)
    }

    /** Stages a private HAM1 recipient pull; the courier must prove a complete matching HAP1. */
    fun prepareRecipientAttachmentTransfer(
        pending: RelayMeshStore.PendingRecipientAttachment,
    ): ByteArray {
        pending.manifest.validate()
        val existing = attachmentStore.findByHexId(pending.manifest.objectId.toHex())
        if (existing?.direction == RelayAttachmentStore.Direction.INCOMING &&
            existing.status == RelayAttachmentStore.Status.READY
        ) {
            throw WifiDirectException("recipient_attachment_complete", "The attachment is already ready.")
        }
        if (!RelayTransportPolicy.canUseWifiForAttachment()) {
            throw WifiDirectException("wifi_promotion_deferred", "Turn Wi-Fi on to receive this attachment.")
        }
        start()
        if (
            activeTest != null || pendingTextTransfer != null || pendingAttachmentTransfer != null ||
            pendingCourierAttachmentTransfer != null || pendingRecipientAttachmentTransfer != null
        ) {
            throw WifiDirectException("wifi_direct_busy", "A Wi-Fi transfer is already running.")
        }
        pendingRecipientAttachmentTransfer = PendingRecipientAttachmentTransfer(
            senderFingerprint = pending.peerFingerprint,
            manifest = pending.manifest,
        )
        pendingUpgradePeerKey = AUTO_PEER_KEY
        emit(
            mapOf(
                "type" to "recipient_attachment_wifi_prepared",
                "attachmentId" to pending.manifest.objectId.toHex(),
                "bytes" to pending.manifest.plaintextBytes,
            ),
        )
        return ByteArray(TOKEN_BYTES)
    }

    fun cancelAuthorization() {
        pendingUpgradePeerKey = null
    }

    fun cancelPreparedTextTransfer() {
        pendingTextTransfer = null
        cancelAuthorization()
    }

    fun cancelPreparedAttachmentTransfer() {
        pendingAttachmentTransfer = null
        pendingCourierAttachmentTransfer = null
        pendingRecipientAttachmentTransfer = null
        cancelAuthorization()
    }

    fun pauseAttachment(attachmentIdHex: String) {
        val attachmentId = stopAttachmentTransfer(attachmentIdHex, "paused")
        val paused = attachmentStore.markPaused(attachmentId)
        emit(paused.toMap() + mapOf("type" to "attachment_paused"))
    }

    fun cancelAttachment(attachmentIdHex: String) {
        val attachmentId = stopAttachmentTransfer(attachmentIdHex, "cancelled")
        val cancelled = attachmentStore.markCancelled(attachmentId)
        emit(cancelled.toMap() + mapOf("type" to "attachment_cancelled"))
    }

    private fun stopAttachmentTransfer(attachmentIdHex: String, action: String): ByteArray {
        val stored = attachmentStore.findByHexId(attachmentIdHex)
            ?: throw WifiDirectException("attachment_missing", "The attachment was not found.")
        if (stored.direction != RelayAttachmentStore.Direction.OUTGOING ||
            stored.status == RelayAttachmentStore.Status.DELIVERED ||
            attachmentStore.isCancelled(stored)
        ) {
            throw WifiDirectException(
                "attachment_not_active",
                "Only an unfinished outgoing attachment can be $action.",
            )
        }
        val attachmentId = stored.manifest.attachmentId
        if (pendingAttachmentTransfer?.attachment?.manifest?.attachmentId?.contentEquals(attachmentId) == true) {
            pendingAttachmentTransfer = null
            pendingUpgradePeerKey = null
        }
        if (
            pendingCourierAttachmentTransfer?.attachment?.manifest?.attachmentId
                ?.contentEquals(attachmentId) == true
        ) {
            pendingCourierAttachmentTransfer = null
            pendingUpgradePeerKey = null
        }
        val active = activeTest
        if (active?.attachment?.manifest?.attachmentId?.contentEquals(attachmentId) == true) {
            mainHandler.removeCallbacks(connectionTimeout)
            active.authorization?.let { authorization ->
                synchronized(authorizationsByOffer) {
                    authorizationsByOffer.remove(authorization.offerId.toHex())?.destroySecret()
                }
                authorization.destroySecret()
            }
            closeSockets()
            activeTest = null
            socketJobStarted = false
            connectedPeerToken = null
            removeGroup()
        }
        return attachmentId
    }

    fun cancelPreparedUpgrade() {
        pendingTextTransfer = null
        pendingAttachmentTransfer = null
        pendingCourierAttachmentTransfer = null
        pendingRecipientAttachmentTransfer = null
        cancelAuthorization()
    }

    @SuppressLint("MissingPermission")
    private fun beginSpeedTest(
        peerToken: String,
        authorization: RelayWifiUpgradeAuthorization?,
    ) {
        val payload = ByteArray(TEST_PAYLOAD_BYTES).also(random::nextBytes)
        beginTransfer(
            peerToken = peerToken,
            authorization = authorization,
            payload = payload,
            payloadKind = PayloadKind.ENGINEERING,
            message = null,
        )
    }

    @SuppressLint("MissingPermission")
    private fun beginAttachmentTransfer(
        peerToken: String,
        authorization: RelayWifiUpgradeAuthorization,
        attachment: RelayAttachmentStore.StoredAttachment,
    ) {
        beginTransfer(
            peerToken = peerToken,
            authorization = authorization,
            payload = ByteArray(0),
            payloadKind = PayloadKind.ATTACHMENT,
            message = null,
            attachment = attachment,
        )
    }

    @SuppressLint("MissingPermission")
    private fun beginCourierAttachmentTransfer(
        peerToken: String,
        authorization: RelayWifiUpgradeAuthorization,
        transfer: PendingCourierAttachmentTransfer,
    ) {
        beginTransfer(
            peerToken = peerToken,
            authorization = authorization,
            payload = ByteArray(0),
            payloadKind = PayloadKind.COURIER_ATTACHMENT,
            message = null,
            attachment = transfer.attachment,
            courierAttachment = transfer,
        )
    }

    @SuppressLint("MissingPermission")
    private fun beginRecipientAttachmentTransfer(
        peerToken: String,
        authorization: RelayWifiUpgradeAuthorization,
        transfer: PendingRecipientAttachmentTransfer,
    ) {
        beginTransfer(
            peerToken = peerToken,
            authorization = authorization,
            payload = ByteArray(0),
            payloadKind = PayloadKind.RECIPIENT_ATTACHMENT,
            message = null,
            recipientAttachment = transfer,
        )
    }

    @SuppressLint("MissingPermission")
    private fun beginTransfer(
        peerToken: String,
        authorization: RelayWifiUpgradeAuthorization?,
        payload: ByteArray,
        payloadKind: PayloadKind,
        message: RelayMessageCodec.TextMessage?,
        attachment: RelayAttachmentStore.StoredAttachment? = null,
        courierAttachment: PendingCourierAttachmentTransfer? = null,
        recipientAttachment: PendingRecipientAttachmentTransfer? = null,
    ) {
        checkStarted()
        if (activeTest != null) {
            throw WifiDirectException("wifi_direct_busy", "A Wi-Fi speed test is already running.")
        }
        val device = devicesByToken[peerToken]
            ?: throw WifiDirectException("wifi_peer_stale", "That Wi-Fi Direct peer is no longer available.")
        val test = ActiveTest(
            peerToken = peerToken,
            sessionId = ByteArray(SESSION_ID_BYTES).also(random::nextBytes),
            payload = payload,
            digest = courierAttachment?.custody?.planSha256?.copyOf()
                ?: recipientAttachment?.manifest?.courierPlanSha256?.copyOf()
                ?: attachment?.manifest?.plaintextSha256?.copyOf()
                ?: MessageDigest.getInstance(DIGEST_ALGORITHM).digest(payload),
            connectionStartedAtMs = SystemClock.elapsedRealtime(),
            authorization = authorization,
            payloadKind = payloadKind,
            message = message,
            attachment = attachment,
            courierAttachment = courierAttachment,
            recipientAttachment = recipientAttachment,
        )
        activeTest = test
        connectedPeerToken = peerToken
        val reusableConnection = authorization?.let(::reusableConnectionFor)
        if (reusableConnection != null) {
            mainHandler.removeCallbacks(warmGroupTeardown)
            emit(
                mapOf(
                    "type" to "wifi_direct_group_reused",
                    "token" to peerToken,
                    "message" to "Reusing the secure Wi-Fi link.",
                ),
            )
            startSocketJob(reusableConnection)
            return
        }
        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            groupOwnerIntent = MIN_GROUP_OWNER_INTENT
            wps.setup = WpsInfo.PBC
        }
        emit(mapOf("type" to "wifi_direct_connecting", "token" to peerToken))
        mainHandler.removeCallbacks(connectionTimeout)
        mainHandler.postDelayed(connectionTimeout, CONNECTION_ESTABLISH_TIMEOUT_MS)
        try {
            requireNotNull(manager).connect(
                requireNotNull(channel),
                config,
                action(
                    operation = "connect",
                    onSuccess = {
                        emit(mapOf("type" to "wifi_direct_connect_started", "token" to peerToken))
                    },
                    onFailure = { reason ->
                        val radioBusy = reason == WifiP2pManager.BUSY
                        failActiveConnection(
                            if (radioBusy) {
                                "wifi_direct_radio_busy"
                            } else {
                                "wifi_direct_connect_failed"
                            },
                            if (radioBusy) {
                                "The Wi-Fi radio is busy. Turn hotspot off; Hypha will retry automatically."
                            } else {
                                "Android could not start the Wi-Fi connection (${failureName(reason)})."
                            },
                        )
                    },
                ),
            )
        } catch (error: SecurityException) {
            mainHandler.removeCallbacks(connectionTimeout)
            activeTest = null
            connectedPeerToken = null
            throw WifiDirectException(
                "wifi_permission_required",
                "Nearby Wi-Fi permission is required for Wi-Fi Direct.",
            )
        }
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        sessionGeneration += 1
        activeTest?.let { queueFailedTest(it, "wifi_direct_stopped") }
        mainHandler.removeCallbacks(connectionTimeout)
        mainHandler.removeCallbacks(discoveryWatchdog)
        mainHandler.removeCallbacks(warmGroupTeardown)
        closeSockets()
        val p2pManager = manager
        val p2pChannel = channel
        if (p2pManager != null && p2pChannel != null) {
            runCatching { p2pManager.removeGroup(p2pChannel, null) }
            serviceRequest?.let { request ->
                runCatching { p2pManager.removeServiceRequest(p2pChannel, request, null) }
            }
            localService?.let { service ->
                runCatching { p2pManager.removeLocalService(p2pChannel, service, null) }
            }
        }
        if (receiverRegistered) {
            runCatching { activity.unregisterReceiver(receiver) }
            receiverRegistered = false
        }
        started = false
        socketJobStarted = false
        clearWarmConnection()
        activeTest = null
        pendingTextTransfer = null
        pendingAttachmentTransfer = null
        pendingCourierAttachmentTransfer = null
        pendingRecipientAttachmentTransfer = null
        pendingUpgradePeerKey = null
        connectedPeerToken = null
        devicesByToken.clear()
        peerKeyByDeviceAddress.clear()
        authorizationTokenByPeerKey.clear()
        lastSeenByPeerKey.clear()
        synchronized(authorizationsByOffer) {
            authorizationsByOffer.values.forEach(RelayWifiUpgradeAuthorization::destroySecret)
            authorizationsByOffer.clear()
        }
        localToken = null
        localService = null
        serviceRequest = null
        channel = null
        emit(mapOf("type" to "wifi_direct_stopped"))
    }

    @SuppressLint("MissingPermission")
    private fun bootstrapP2p(
        p2pManager: WifiP2pManager,
        p2pChannel: WifiP2pManager.Channel,
        token: String,
        attempt: Int,
    ) {
        if (!isCurrentSession(token, p2pChannel)) return
        p2pManager.discoverPeers(
            p2pChannel,
            action(
                operation = "wake Wi-Fi Direct",
                onSuccess = {
                    if (!isCurrentSession(token, p2pChannel)) return@action
                    p2pManager.stopPeerDiscovery(
                        p2pChannel,
                        action(
                            operation = "prepare service discovery",
                            onSuccess = {
                                if (!isCurrentSession(token, p2pChannel)) return@action
                                mainHandler.postDelayed(
                                    {
                                        configureDnsSd(
                                            p2pManager,
                                            p2pChannel,
                                            token,
                                            attempt,
                                        )
                                    },
                                    P2P_SETTLE_DELAY_MS,
                                )
                            },
                            onFailure = { reason ->
                                retryBootstrap(reason, p2pManager, p2pChannel, token, attempt)
                            },
                        ),
                    )
                },
                onFailure = { reason ->
                    retryBootstrap(reason, p2pManager, p2pChannel, token, attempt)
                },
            ),
        )
    }

    @SuppressLint("MissingPermission")
    private fun configureDnsSd(
        p2pManager: WifiP2pManager,
        p2pChannel: WifiP2pManager.Channel,
        token: String,
        attempt: Int,
    ) {
        if (!isCurrentSession(token, p2pChannel)) return
        p2pManager.setDnsSdResponseListeners(
            p2pChannel,
            ::handleServiceResponse,
            { _, record, device -> handleTxtRecord(record, device) },
        )
        val service = WifiP2pDnsSdServiceInfo.newInstance(
            INSTANCE_NAME,
            SERVICE_TYPE,
            mapOf(
                "v" to PROTOCOL_VERSION.toString(),
                "t" to token,
                "p" to SERVER_PORT.toString(),
            ),
        )
        localService = service
        p2pManager.clearLocalServices(
            p2pChannel,
            action(
                operation = "clear local services",
                onSuccess = {
                    if (!isCurrentSession(token, p2pChannel)) return@action
                    p2pManager.addLocalService(
                        p2pChannel,
                        service,
                        action(
                            operation = "advertise service",
                            onSuccess = {
                                if (!isCurrentSession(token, p2pChannel)) return@action
                                configureServiceDiscovery(
                                    p2pManager,
                                    p2pChannel,
                                    token,
                                    attempt,
                                )
                            },
                            onFailure = { reason ->
                                retryBootstrap(reason, p2pManager, p2pChannel, token, attempt)
                            },
                        ),
                    )
                },
                onFailure = { reason ->
                    retryBootstrap(reason, p2pManager, p2pChannel, token, attempt)
                },
            ),
        )
    }

    @SuppressLint("MissingPermission")
    private fun configureServiceDiscovery(
        p2pManager: WifiP2pManager,
        p2pChannel: WifiP2pManager.Channel,
        token: String,
        attempt: Int,
    ) {
        if (!isCurrentSession(token, p2pChannel)) return
        val request = WifiP2pDnsSdServiceRequest.newInstance()
        serviceRequest = request
        p2pManager.clearServiceRequests(
            p2pChannel,
            action(
                operation = "clear service requests",
                onSuccess = {
                    if (!isCurrentSession(token, p2pChannel)) return@action
                    p2pManager.addServiceRequest(
                        p2pChannel,
                        request,
                        action(
                            operation = "add service request",
                            onSuccess = {
                                if (!isCurrentSession(token, p2pChannel)) return@action
                                p2pManager.discoverServices(
                                    p2pChannel,
                                    action(
                                        operation = "discover services",
                                        onSuccess = {
                                            if (!isCurrentSession(token, p2pChannel)) return@action
                                            emit(mapOf("type" to "wifi_direct_discovering"))
                                        },
                                        onFailure = { reason ->
                                            retryBootstrap(
                                                reason,
                                                p2pManager,
                                                p2pChannel,
                                                token,
                                                attempt,
                                            )
                                        },
                                    ),
                                )
                            },
                            onFailure = { reason ->
                                retryBootstrap(reason, p2pManager, p2pChannel, token, attempt)
                            },
                        ),
                    )
                },
                onFailure = { reason ->
                    retryBootstrap(reason, p2pManager, p2pChannel, token, attempt)
                },
            ),
        )
    }

    private fun retryBootstrap(
        reason: Int,
        p2pManager: WifiP2pManager,
        p2pChannel: WifiP2pManager.Channel,
        token: String,
        attempt: Int,
    ) {
        if (!isCurrentSession(token, p2pChannel)) return
        if (reason == WifiP2pManager.BUSY && attempt < MAX_BOOTSTRAP_RETRIES) {
            val nextAttempt = attempt + 1
            emit(
                mapOf(
                    "type" to "wifi_direct_retrying",
                    "attempt" to nextAttempt,
                    "message" to "Android Wi-Fi Direct is waking up; retrying automatically...",
                ),
            )
            mainHandler.postDelayed(
                { bootstrapP2p(p2pManager, p2pChannel, token, nextAttempt) },
                P2P_RETRY_DELAY_MS * nextAttempt,
            )
            return
        }
        val radioBusy = reason == WifiP2pManager.BUSY
        val errorCode = if (radioBusy) "wifi_direct_radio_busy" else "wifi_direct_start_failed"
        val pendingAttachment = pendingAttachmentTransfer?.attachment
        if (radioBusy && pendingAttachment != null) {
            consecutiveRadioBusyFailures =
                (consecutiveRadioBusyFailures + 1).coerceAtMost(MAX_RADIO_BUSY_FAILURES)
            attachmentStore.markRetryable(
                pendingAttachment.manifest.attachmentId,
                errorCode,
                radioBusyBackoffMs(),
            )
        }
        emit(
            errorEvent(
                errorCode,
                if (radioBusy) {
                    "The Wi-Fi radio is busy. Turn hotspot off; Hypha will retry automatically."
                } else {
                    "Wi-Fi Direct could not start (${failureName(reason)})."
                },
            ),
        )
        if (radioBusy) {
            pendingAttachment?.let { attachment ->
                val updated = attachmentStore.findByHexId(attachment.manifest.attachmentId.toHex())
                emitAttachmentQueued(updated ?: attachment, errorCode)
            }
            mainHandler.post {
                if (isCurrentSession(token, p2pChannel)) stop()
            }
        }
    }

    private fun isCurrentSession(
        token: String,
        p2pChannel: WifiP2pManager.Channel,
    ): Boolean = started && localToken == token && channel === p2pChannel

    private fun radioBusyBackoffMs(): Long =
        (RADIO_BUSY_RETRY_BASE_MS shl (consecutiveRadioBusyFailures - 1).coerceAtLeast(0))
            .coerceAtMost(RADIO_BUSY_RETRY_MAX_MS)

    private fun handleTxtRecord(record: Map<String, String>, device: WifiP2pDevice) {
        if (record["v"] != PROTOCOL_VERSION.toString()) return
        val token = record["t"] ?: return
        if (!TOKEN_PATTERN.matches(token) || token == localToken) return
        registerPeer(
            peerKey = token,
            device = device,
            authorizationToken = token.hexToBytesOrNull(),
            discovery = "txt",
        )
    }

    private fun handleServiceResponse(
        instanceName: String,
        registrationType: String,
        device: WifiP2pDevice,
    ) {
        if (instanceName != INSTANCE_NAME || !registrationType.startsWith(SERVICE_TYPE)) return
        Log.i(TAG, "Observed a Relay Wi-Fi Direct service")
        peerKeyByDeviceAddress[device.deviceAddress]?.let { existingKey ->
            lastSeenByPeerKey[existingKey] = SystemClock.elapsedRealtime()
            devicesByToken[existingKey] = device
            return
        }
        registerPeer(
            peerKey = fallbackPeerKey(device),
            device = device,
            authorizationToken = null,
            discovery = "service_only",
        )
    }

    private fun registerPeer(
        peerKey: String,
        device: WifiP2pDevice,
        authorizationToken: ByteArray?,
        discovery: String,
    ) {
        val previousKey = peerKeyByDeviceAddress.put(device.deviceAddress, peerKey)
        if (previousKey != null && previousKey != peerKey) {
            devicesByToken.remove(previousKey)
            authorizationTokenByPeerKey.remove(previousKey)
            lastSeenByPeerKey.remove(previousKey)
            emit(
                mapOf(
                    "type" to "wifi_direct_peer_replaced",
                    "previousToken" to previousKey,
                    "token" to peerKey,
                    "discovery" to discovery,
                ),
            )
        }
        val isNew = devicesByToken.put(peerKey, device) == null
        authorizationTokenByPeerKey[peerKey] = authorizationToken?.copyOf()
        lastSeenByPeerKey[peerKey] = SystemClock.elapsedRealtime()
        if (isNew) {
            emit(
                mapOf(
                    "type" to "wifi_direct_peer_seen",
                    "token" to peerKey,
                    "discovery" to discovery,
                    "limited" to (authorizationToken == null),
                ),
            )
        }
    }

    private fun fallbackPeerKey(device: WifiP2pDevice): String {
        val session = localTokenBytes() ?: ByteArray(TOKEN_BYTES)
        val address = device.deviceAddress.toByteArray(StandardCharsets.UTF_8)
        val digest = MessageDigest.getInstance(DIGEST_ALGORITHM).digest(session + address)
        val first = digest.copyOfRange(0, TOKEN_BYTES)
        return if (first.toHex() != localToken) first.toHex() else {
            digest.copyOfRange(TOKEN_BYTES, TOKEN_BYTES * 2).toHex()
        }
    }

    private fun pruneStalePeers() {
        val cutoff = SystemClock.elapsedRealtime() - PEER_STALE_MS
        val staleKeys = lastSeenByPeerKey
            .filterValues { seenAt -> seenAt < cutoff }
            .keys
            .toList()
        for (peerKey in staleKeys) {
            lastSeenByPeerKey.remove(peerKey)
            devicesByToken.remove(peerKey)
            authorizationTokenByPeerKey.remove(peerKey)
            peerKeyByDeviceAddress.entries.removeAll { it.value == peerKey }
            emit(mapOf("type" to "wifi_direct_peer_lost", "token" to peerKey))
        }
    }

    @Suppress("DEPRECATION")
    private fun handleConnectionBroadcast(intent: Intent) {
        val networkInfo: NetworkInfo? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO, NetworkInfo::class.java)
        } else {
            intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO)
        }
        if (networkInfo?.isConnected == true) {
            val p2pManager = manager ?: return
            val p2pChannel = channel ?: return
            try {
                p2pManager.requestConnectionInfo(p2pChannel, ::handleConnectionInfo)
            } catch (error: SecurityException) {
                emit(errorEvent("wifi_permission_required", "Nearby Wi-Fi permission was revoked."))
            }
        } else if (socketJobStarted || warmConnectionInfo != null) {
            if (socketJobStarted && activeTest != null) {
                failActiveConnection(
                    "wifi_direct_disconnected_early",
                    "The Wi-Fi connection closed before the encrypted transfer finished.",
                )
            } else {
                closeSockets()
                socketJobStarted = false
                clearWarmConnection()
                emit(mapOf("type" to "wifi_direct_disconnected"))
            }
        }
    }

    private fun handleConnectionInfo(info: WifiP2pInfo) {
        if (!info.groupFormed || info.groupOwnerAddress == null || socketJobStarted) return
        val groupWasAlreadyWarm = warmConnectionInfo != null
        warmConnectionInfo = info
        consecutiveRadioBusyFailures = 0
        val hasAuthorizedResponder = synchronized(authorizationsByOffer) {
            authorizationsByOffer.isNotEmpty()
        }
        if (groupWasAlreadyWarm && activeTest == null && !hasAuthorizedResponder) return
        startSocketJob(info)
    }

    private fun startSocketJob(info: WifiP2pInfo) {
        if (!started || !info.groupFormed || info.groupOwnerAddress == null || socketJobStarted) return
        mainHandler.removeCallbacks(connectionTimeout)
        mainHandler.removeCallbacks(warmGroupTeardown)
        socketJobStarted = true
        val token = activeTest?.peerToken ?: devicesByToken.keys.singleOrNull() ?: "unknown"
        connectedPeerToken = token
        emit(
            mapOf(
                "type" to "wifi_direct_group_ready",
                "token" to token,
                "role" to if (info.isGroupOwner) "group_owner" else "group_client",
            ),
        )
        ioExecutor.execute {
            try {
                val connected = if (info.isGroupOwner) {
                    acceptGroupClient()
                } else {
                    connectToGroupOwner(
                        info.groupOwnerAddress.hostAddress
                            ?: throw IOException("Wi-Fi group owner address is unavailable."),
                    )
                }
                synchronized(socketLock) { socket = connected }
                runSocketProtocol(connected)
                mainHandler.post(::finishSuccessfulSocketJob)
            } catch (error: Exception) {
                Log.w(TAG, "Wi-Fi Direct socket test failed", error)
                mainHandler.post {
                    failActiveConnection(
                        "wifi_direct_transfer_failed",
                        error.message ?: "The Wi-Fi Direct transfer failed.",
                    )
                }
            } finally {
                closeSockets()
            }
        }
    }

    private fun startWarmResponderIfReady(authorization: RelayWifiUpgradeAuthorization) {
        val run = Runnable {
            if (authorization.isInitiator || authorization.isExpired()) return@Runnable
            val info = reusableConnectionFor(authorization) ?: return@Runnable
            authorizationTokenByPeerKey.entries.firstOrNull { (_, token) ->
                token?.contentEquals(authorization.remoteToken()) == true
            }?.key?.let { connectedPeerToken = it }
            emit(
                mapOf(
                    "type" to "wifi_direct_group_reused",
                    "token" to (connectedPeerToken ?: "unknown"),
                    "message" to "Reusing the secure Wi-Fi link.",
                ),
            )
            startSocketJob(info)
        }
        if (Looper.myLooper() == Looper.getMainLooper()) run.run() else mainHandler.post(run)
    }

    private fun reusableConnectionFor(
        authorization: RelayWifiUpgradeAuthorization,
    ): WifiP2pInfo? {
        val info = warmConnectionInfo ?: return null
        val expectedRemote = warmRemoteToken ?: return null
        if (!started || socketJobStarted || !info.groupFormed || info.groupOwnerAddress == null) {
            return null
        }
        return info.takeIf { expectedRemote.contentEquals(authorization.remoteToken()) }
    }

    private fun rememberWarmPeer(authorization: RelayWifiUpgradeAuthorization) {
        warmRemoteToken?.fill(0)
        warmRemoteToken = authorization.remoteToken().copyOf()
    }

    private fun finishSuccessfulSocketJob() {
        mainHandler.removeCallbacks(connectionTimeout)
        socketJobStarted = false
        if (started && warmConnectionInfo != null && warmRemoteToken != null) {
            emit(
                mapOf(
                    "type" to "wifi_direct_group_warm",
                    "token" to (connectedPeerToken ?: "unknown"),
                    "idleMs" to WARM_GROUP_IDLE_MS,
                ),
            )
            mainHandler.removeCallbacks(warmGroupTeardown)
            mainHandler.postDelayed(warmGroupTeardown, WARM_GROUP_IDLE_MS)
        } else {
            removeGroup()
        }
    }

    private fun acceptGroupClient(): Socket {
        val listener = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(SERVER_PORT))
            soTimeout = SOCKET_TIMEOUT_MS
        }
        synchronized(socketLock) { serverSocket = listener }
        return listener.accept().apply {
            tcpNoDelay = true
            soTimeout = SOCKET_TIMEOUT_MS
        }
    }

    private fun connectToGroupOwner(host: String): Socket {
        var lastError: IOException? = null
        repeat(CONNECT_ATTEMPTS) {
            val candidate = Socket()
            try {
                candidate.connect(InetSocketAddress(host, SERVER_PORT), CONNECT_TIMEOUT_MS)
                candidate.tcpNoDelay = true
                candidate.soTimeout = SOCKET_TIMEOUT_MS
                return candidate
            } catch (error: IOException) {
                lastError = error
                runCatching { candidate.close() }
                Thread.sleep(CONNECT_RETRY_MS)
            }
        }
        throw lastError ?: IOException("Could not connect to the Wi-Fi Direct group owner.")
    }

    private fun runSocketProtocol(connected: Socket) {
        val input = DataInputStream(BufferedInputStream(connected.getInputStream(), IO_BUFFER_BYTES))
        val output = DataOutputStream(BufferedOutputStream(connected.getOutputStream(), IO_BUFFER_BYTES))
        val localTest = activeTest
        output.write(buildHello(localTest))
        output.flush()
        val remoteHello = parseHello(input.readExact(HELLO_BYTES))
        check((localTest != null) xor remoteHello.initiator) {
            "The speed test must have exactly one initiator."
        }
        if (localTest != null) {
            check(remoteHello.sessionId.all { it == 0.toByte() }) {
                "Responder advertised an unexpected session ID."
            }
            check(remoteHello.offerId.all { it == 0.toByte() }) {
                "Responder advertised an unexpected upgrade offer."
            }
            if (localTest.authorization == null) {
                sendPayload(localTest, input, output)
            } else {
                val authorization = consumeAuthorization(
                    localTest.authorization.offerId,
                    expectedInitiator = true,
                )
                rememberWarmPeer(authorization)
                createFastSession(authorization).use { session ->
                    runFastHandshake(session, input, output, isInitiator = true)
                    sendSecurePayload(localTest, session, input, output)
                }
            }
        } else {
            check(remoteHello.initiator) { "Remote peer did not initiate a speed test." }
            if (remoteHello.offerId.all { it == 0.toByte() }) {
                receivePayload(remoteHello.sessionId, input, output)
            } else {
                val authorization = consumeAuthorization(
                    remoteHello.offerId,
                    expectedInitiator = false,
                )
                val peerFingerprint = authorization.peerFingerprint
                rememberWarmPeer(authorization)
                createFastSession(authorization).use { session ->
                    runFastHandshake(session, input, output, isInitiator = false)
                    receiveSecurePayload(
                        remoteHello.sessionId,
                        peerFingerprint,
                        session,
                        input,
                        output,
                    )
                }
            }
        }
    }

    private fun consumeAuthorization(
        offerId: ByteArray,
        expectedInitiator: Boolean,
    ): RelayWifiUpgradeAuthorization {
        val offerKey = offerId.toHex()
        val authorization = synchronized(authorizationsByOffer) {
            authorizationsByOffer.remove(offerKey)
        } ?: throw SecurityException("This Wi-Fi upgrade was not authorized by verified BLE.")
        val currentToken = localTokenBytes()
        val valid = !authorization.isExpired() &&
            authorization.isInitiator == expectedInitiator &&
            authorization.offerId.contentEquals(offerId) &&
            currentToken != null &&
            authorization.localToken().contentEquals(currentToken)
        if (!valid) {
            authorization.destroySecret()
            throw SecurityException("The Wi-Fi upgrade capability is stale or invalid.")
        }
        if (expectedInitiator) {
            val peerKey = activeTest?.peerToken
            val expectedToken = peerKey?.let(authorizationTokenByPeerKey::get)
            if (expectedToken != null && !expectedToken.contentEquals(authorization.remoteToken())) {
                authorization.destroySecret()
                throw SecurityException("The Wi-Fi upgrade was issued for a different peer.")
            }
        }
        return authorization
    }

    private fun createFastSession(
        authorization: RelayWifiUpgradeAuthorization,
    ): NativeRelaySession = try {
        RelayNative.createFastSession(
            isInitiator = authorization.isInitiator,
            psk = authorization.psk,
            offerId = authorization.offerId,
            initiatorToken = authorization.initiatorToken,
            responderToken = authorization.responderToken,
        )
    } finally {
        authorization.destroySecret()
    }

    private fun runFastHandshake(
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
        isInitiator: Boolean,
    ) {
        if (isInitiator) {
            val first = requireNotNull(session.start()) { "Fast Noise initiator produced no message." }
            output.writePacket(first, MAX_HANDSHAKE_BYTES)
            output.flush()
            check(session.receiveHandshake(input.readPacket(MAX_HANDSHAKE_BYTES)) == null) {
                "Fast Noise handshake produced an unexpected third message."
            }
        } else {
            check(session.start() == null) { "Fast Noise responder produced an early message." }
            val reply = requireNotNull(
                session.receiveHandshake(input.readPacket(MAX_HANDSHAKE_BYTES)),
            ) { "Fast Noise responder produced no reply." }
            output.writePacket(reply, MAX_HANDSHAKE_BYTES)
            output.flush()
        }
        check(session.isEstablished()) { "Fast Noise handshake did not establish a session." }
        emit(
            mapOf(
                "type" to "wifi_upgrade_noise_established",
                "token" to (connectedPeerToken ?: "unknown"),
                "binding" to session.sessionBinding().copyOfRange(0, 6).toHex(),
            ),
        )
    }

    private fun sendSecurePayload(
        test: ActiveTest,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        if (test.payloadKind == PayloadKind.RECIPIENT_ATTACHMENT) {
            pullSecureRecipientAttachment(test, session, input, output)
            return
        }
        if (test.payloadKind == PayloadKind.COURIER_ATTACHMENT) {
            sendSecureCourierAttachment(test, session, input, output)
            return
        }
        if (test.payloadKind == PayloadKind.ATTACHMENT) {
            sendSecureAttachment(test, session, input, output)
            return
        }
        val header = buildTransferHeader(
            DATA_MAGIC,
            test.sessionId,
            test.payload.size,
            test.digest,
            test.payloadKind,
        )
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        emit(
            mapOf(
                "type" to if (test.payloadKind == PayloadKind.USER_TEXT) {
                    "wifi_text_sending"
                } else {
                    "wifi_direct_transfer_sending"
                },
                "token" to test.peerToken,
                "bytes" to test.payload.size,
                "secure" to true,
            ),
        )
        output.writeSecureRecord(session, header)
        var offset = 0
        while (offset < test.payload.size) {
            val end = minOf(offset + SECURE_PLAINTEXT_BYTES, test.payload.size)
            output.writeSecureRecord(session, test.payload.copyOfRange(offset, end))
            offset = end
        }
        output.flush()
        val encryptedReceipt = input.readSecureRecord(session)
        if (test.payloadKind == PayloadKind.USER_TEXT) {
            val message = requireNotNull(test.message) { "Wi-Fi text metadata is unavailable." }
            check(RelayMessageCodec.receiptMatches(encryptedReceipt, message.id)) {
                "Encrypted message receipt mismatch."
            }
            messageStore.markDelivered(message.id)
            emit(
                mapOf(
                    "type" to "wifi_text_delivered",
                    "token" to test.peerToken,
                    "messageId" to RelayMessageCodec.idHex(message.id),
                    "text" to message.text,
                    "setupMs" to max(
                        1L,
                        transferStartedAtMs - test.connectionStartedAtMs,
                    ),
                ) + message.replyMap(),
            )
            activeTest = null
        } else {
            val receipt = parseTransferHeader(encryptedReceipt, ACK_MAGIC)
            check(receipt.sessionId.contentEquals(test.sessionId)) { "Receipt session ID mismatch." }
            check(receipt.payloadBytes == test.payload.size) { "Receipt byte count mismatch." }
            check(receipt.digest.contentEquals(test.digest)) { "Receipt digest mismatch." }
            finishSendingTest(test, transferStartedAtMs, secure = true)
        }
    }

    private fun receiveSecurePayload(
        expectedSessionId: ByteArray,
        peerFingerprint: String,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val header = parseTransferHeader(input.readSecureRecord(session), DATA_MAGIC)
        check(header.sessionId.contentEquals(expectedSessionId)) { "Transfer session ID mismatch." }
        if (header.payloadKind == PayloadKind.RECIPIENT_ATTACHMENT) {
            serveSecureRecipientAttachment(header, session, input, output)
            return
        }
        if (header.payloadKind == PayloadKind.COURIER_ATTACHMENT) {
            receiveSecureCourierAttachment(header, session, input, output)
            return
        }
        if (header.payloadKind == PayloadKind.ATTACHMENT) {
            check(header.payloadBytes in 1..RelayAttachmentManifest.MAX_FILE_BYTES.toInt()) {
                "Attachment size is invalid."
            }
            receiveSecureAttachment(header, peerFingerprint, session, input, output)
            return
        }
        check(header.payloadBytes in 1..MAX_TEST_PAYLOAD_BYTES) { "Transfer size is invalid." }
        if (header.payloadKind == PayloadKind.USER_TEXT) {
            check(header.payloadBytes <= MAX_TEXT_WIRE_BYTES) { "Wi-Fi text message is too large." }
        }
        val digest = MessageDigest.getInstance(DIGEST_ALGORITHM)
        val textPayload = if (header.payloadKind == PayloadKind.USER_TEXT) {
            ByteArray(header.payloadBytes)
        } else {
            null
        }
        var receivedBytes = 0
        var remaining = header.payloadBytes
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        emit(
            mapOf(
                "type" to if (header.payloadKind == PayloadKind.USER_TEXT) {
                    "wifi_text_receiving"
                } else {
                    "wifi_direct_transfer_receiving"
                },
                "token" to (connectedPeerToken ?: "unknown"),
                "bytes" to header.payloadBytes,
                "secure" to true,
            ),
        )
        while (remaining > 0) {
            val plaintext = input.readSecureRecord(session)
            check(plaintext.size in 1..minOf(SECURE_PLAINTEXT_BYTES, remaining)) {
                "Encrypted Wi-Fi record has an invalid size."
            }
            digest.update(plaintext)
            if (textPayload != null) {
                plaintext.copyInto(textPayload, destinationOffset = receivedBytes)
            }
            receivedBytes += plaintext.size
            remaining -= plaintext.size
        }
        val actualDigest = digest.digest()
        check(actualDigest.contentEquals(header.digest)) { "Payload integrity check failed." }
        if (header.payloadKind == PayloadKind.USER_TEXT) {
            val message = RelayMessageCodec.decode(requireNotNull(textPayload))
            val inserted = messageStore.storeIncoming(message, peerFingerprint)
            output.writeSecureRecord(session, RelayMessageCodec.createReceipt(message.id))
            emit(
                mapOf(
                    "type" to if (inserted) "wifi_text_received" else "wifi_text_duplicate",
                    "token" to (connectedPeerToken ?: "unknown"),
                    "messageId" to RelayMessageCodec.idHex(message.id),
                    "text" to message.text,
                    "fingerprint" to peerFingerprint,
                ) + message.replyMap(),
            )
        } else {
            output.writeSecureRecord(
                session,
                buildTransferHeader(ACK_MAGIC, header.sessionId, header.payloadBytes, actualDigest),
            )
        }
        output.flush()
        if (header.payloadKind == PayloadKind.ENGINEERING) {
            finishReceivingTest(header, transferStartedAtMs, secure = true)
        }
    }

    private fun sendSecureAttachment(
        test: ActiveTest,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val attachment = requireNotNull(test.attachment) { "Attachment metadata is unavailable." }
        val manifest = attachment.manifest
        val payloadBytes = manifest.plaintextBytes.toInt()
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        output.writeSecureRecord(
            session,
            buildTransferHeader(
                DATA_MAGIC,
                test.sessionId,
                payloadBytes,
                manifest.plaintextSha256,
                PayloadKind.ATTACHMENT,
            ),
        )
        output.writeSecureRecord(session, manifest.encode())
        output.flush()
        val missing = decodeAttachmentResume(
            input.readSecureRecord(session),
            manifest.attachmentId,
            manifest.chunks.size,
        )
        val resumedBytes = resumedPlaintextBytes(manifest, missing)
        emit(
            mapOf(
                "type" to "attachment_sending",
                "token" to test.peerToken,
                "attachmentId" to manifest.attachmentId.toHex(),
                "bytes" to manifest.plaintextBytes,
                "remainingChunks" to missing.size,
                "totalChunks" to manifest.chunks.size,
                "transferredBytes" to resumedBytes,
                "totalBytes" to manifest.plaintextBytes,
                "resumedBytes" to resumedBytes,
                "throughputBps" to 0L,
                "secure" to true,
            ),
        )
        var transferredBytes = resumedBytes
        var sentThisAttemptBytes = 0L
        var lastProgressAtMs = transferStartedAtMs
        missing.forEach { index ->
            val chunk = manifest.chunks[index]
            val ciphertext = attachmentStore.readChunk(manifest.attachmentId, index)
            output.writeSecureRecord(session, encodeAttachmentChunkHeader(manifest.attachmentId, chunk))
            var offset = 0
            while (offset < ciphertext.size) {
                val end = minOf(offset + SECURE_PLAINTEXT_BYTES, ciphertext.size)
                output.writeSecureRecord(session, ciphertext.copyOfRange(offset, end))
                offset = end
            }
            transferredBytes += chunk.plaintextBytes
            sentThisAttemptBytes += chunk.plaintextBytes
            val nowMs = SystemClock.elapsedRealtime()
            if (nowMs - lastProgressAtMs >= ATTACHMENT_PROGRESS_INTERVAL_MS ||
                transferredBytes == manifest.plaintextBytes
            ) {
                emitAttachmentProgress(
                    type = "attachment_send_progress",
                    token = test.peerToken,
                    manifest = manifest,
                    transferredBytes = transferredBytes,
                    resumedBytes = resumedBytes,
                    attemptBytes = sentThisAttemptBytes,
                    transferStartedAtMs = transferStartedAtMs,
                )
                lastProgressAtMs = nowMs
            }
        }
        output.writeSecureRecord(session, encodeAttachmentDone(manifest.attachmentId))
        output.flush()
        validateAttachmentReceipt(
            input.readSecureRecord(session),
            manifest.attachmentId,
            manifest.plaintextBytes,
            manifest.plaintextSha256,
        )
        attachmentStore.markDelivered(manifest.attachmentId)
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        emit(
            mapOf(
                "type" to "attachment_delivered",
                "token" to test.peerToken,
                "attachmentId" to manifest.attachmentId.toHex(),
                "fileName" to manifest.fileName,
                "mimeType" to manifest.mimeType,
                "bytes" to manifest.plaintextBytes,
                "resumedChunks" to (manifest.chunks.size - missing.size),
                "transferredBytes" to manifest.plaintextBytes,
                "totalBytes" to manifest.plaintextBytes,
                "resumedBytes" to resumedBytes,
                "elapsedMs" to elapsedMs,
                "setupMs" to max(1L, transferStartedAtMs - test.connectionStartedAtMs),
                "throughputBps" to (sentThisAttemptBytes * 1_000L / elapsedMs),
            ),
        )
        activeTest = null
    }

    private fun sendSecureCourierAttachment(
        test: ActiveTest,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val transfer = requireNotNull(test.courierAttachment) {
            "Courier attachment metadata is unavailable."
        }
        val manifest = transfer.attachment.manifest
        val initialCustody = transfer.custody
        val maximumWireBytes = initialCustody.missingChunks().sumOf { index ->
            Math.addExact(
                RelayCourierAttachmentChunk.HEADER_BYTES.toLong(),
                manifest.chunks[index].ciphertextBytes.toLong(),
            )
        }
        check(maximumWireBytes in 1..MAX_COURIER_ATTACHMENT_WIRE_BYTES) {
            "Courier attachment transfer size is invalid."
        }
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        output.writeSecureRecord(
            session,
            buildTransferHeader(
                DATA_MAGIC,
                test.sessionId,
                maximumWireBytes.toInt(),
                initialCustody.planSha256,
                PayloadKind.COURIER_ATTACHMENT,
            ),
        )
        output.writeSecureRecord(session, initialCustody.encode())
        output.flush()

        val currentCustody = RelayCourierAttachmentCustody.decode(input.readSecureRecord(session))
        RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(initialCustody, currentCustody)
        val missing = currentCustody.missingChunks()
        var sentWireBytes = 0L
        missing.forEach { index ->
            val ciphertext = attachmentStore.readChunk(manifest.attachmentId, index)
            val encodedChunk = RelayCourierWifiTransferPolicy
                .buildChunk(manifest, index, ciphertext)
                .encode()
            output.writeSecureRecord(
                session,
                RelayCourierWifiChunkStart(
                    objectId = manifest.attachmentId.copyOf(),
                    chunkIndex = index,
                    recordBytes = encodedChunk.size,
                ).encode(),
            )
            output.writeSecureBlob(session, encodedChunk)
            sentWireBytes = Math.addExact(sentWireBytes, encodedChunk.size.toLong())
            emit(
                mapOf(
                    "type" to "courier_attachment_send_progress",
                    "token" to test.peerToken,
                    "attachmentId" to manifest.attachmentId.toHex(),
                    "transferredChunks" to (missing.indexOf(index) + 1),
                    "totalChunks" to missing.size,
                    "transferredBytes" to sentWireBytes,
                    "totalBytes" to maximumWireBytes,
                    "secure" to true,
                ),
            )
        }
        output.writeSecureRecord(session, RelayCourierWifiDone(manifest.attachmentId.copyOf()).encode())
        output.flush()

        val finalCustody = RelayCourierAttachmentCustody.decode(input.readSecureRecord(session))
        RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(currentCustody, finalCustody)
        check(finalCustody.missingChunks().isEmpty()) {
            "Courier did not durably acknowledge every transferred chunk."
        }
        meshStore.recordSenderAttachmentCustody(
            transfer.courierFingerprint,
            finalCustody.encode(),
        )
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        emit(
            mapOf(
                "type" to "courier_attachment_custodied",
                "token" to test.peerToken,
                "attachmentId" to manifest.attachmentId.toHex(),
                "chunks" to missing.size,
                "wireBytes" to sentWireBytes,
                "remainingChunks" to 0,
                "elapsedMs" to elapsedMs,
                "throughputBps" to (sentWireBytes * 1_000L / elapsedMs),
                "secure" to true,
            ),
        )
        // Hop custody is not recipient delivery; the outgoing attachment remains Waiting.
        activeTest = null
    }

    private fun receiveSecureCourierAttachment(
        header: TransferHeader,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        check(header.payloadBytes in 1..MAX_COURIER_ATTACHMENT_WIRE_BYTES.toInt()) {
            "Courier attachment transfer size is invalid."
        }
        val offeredCustody = RelayCourierAttachmentCustody.decode(input.readSecureRecord(session))
        check(MessageDigest.isEqual(header.digest, offeredCustody.planSha256)) {
            "Courier attachment header belongs to another plan."
        }
        val currentCustody = courierAttachmentStore.custody(offeredCustody.objectId)
            ?.let(RelayCourierAttachmentCustody::decode)
            ?: throw IllegalStateException("Courier attachment plan is unavailable.")
        RelayCourierWifiTransferPolicy.requireResumeDoesNotRegress(offeredCustody, currentCustody)
        output.writeSecureRecord(session, currentCustody.encode())
        output.flush()

        val missing = currentCustody.missingChunks()
        var receivedWireBytes = 0L
        missing.forEach { expectedIndex ->
            val start = RelayCourierWifiChunkStart.decode(input.readSecureRecord(session))
            check(
                start.objectId.contentEquals(currentCustody.objectId) &&
                    start.chunkIndex == expectedIndex,
            ) { "Courier attachment chunk order or object ID is invalid." }
            val encodedChunk = input.readSecureBlob(session, start.recordBytes)
            val accepted = courierAttachmentStore.acceptChunk(encodedChunk)
            check(accepted is RelayCourierAttachmentStore.ChunkAcceptance.Accepted) {
                "Courier attachment chunk was not durably accepted."
            }
            receivedWireBytes = Math.addExact(receivedWireBytes, encodedChunk.size.toLong())
            check(receivedWireBytes <= header.payloadBytes.toLong()) {
                "Courier attachment exceeded its authorized byte bound."
            }
            emit(
                mapOf(
                    "type" to "courier_attachment_receive_progress",
                    "token" to (connectedPeerToken ?: "unknown"),
                    "objectId" to currentCustody.objectId.toHex(),
                    "transferredChunks" to (missing.indexOf(expectedIndex) + 1),
                    "totalChunks" to missing.size,
                    "transferredBytes" to receivedWireBytes,
                    "totalBytes" to header.payloadBytes.toLong(),
                    "secure" to true,
                ),
            )
        }
        val done = RelayCourierWifiDone.decode(input.readSecureRecord(session))
        check(done.objectId.contentEquals(currentCustody.objectId)) {
            "Courier attachment completion belongs to another object."
        }
        val finalCustody = courierAttachmentStore.custody(currentCustody.objectId)
            ?.let(RelayCourierAttachmentCustody::decode)
            ?: throw IllegalStateException("Courier attachment plan disappeared after transfer.")
        check(finalCustody.missingChunks().isEmpty()) {
            "Courier attachment transfer ended before every missing chunk was durable."
        }
        output.writeSecureRecord(session, finalCustody.encode())
        output.flush()
        emit(
            mapOf(
                "type" to "courier_attachment_chunks_stored",
                "token" to (connectedPeerToken ?: "unknown"),
                "objectId" to finalCustody.objectId.toHex(),
                "chunks" to missing.size,
                "wireBytes" to receivedWireBytes,
                "remainingChunks" to 0,
                "secure" to true,
            ),
        )
    }

    /** Recipient pulls only opaque HAC1 and materializes private HYA1 locally. */
    private fun pullSecureRecipientAttachment(
        test: ActiveTest,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val transfer = requireNotNull(test.recipientAttachment) {
            "Recipient attachment metadata is unavailable."
        }
        val recipient = transfer.manifest
        val expectedChunks = ((recipient.plaintextBytes + RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES - 1) /
            RelayAttachmentManifest.CHUNK_PLAINTEXT_BYTES).toInt()
        val maximumWireBytes = Math.addExact(
            recipient.plaintextBytes,
            Math.multiplyExact(
                expectedChunks.toLong(),
                (RelayAttachmentManifest.GCM_TAG_BYTES + RelayCourierAttachmentChunk.HEADER_BYTES).toLong(),
            ),
        )
        check(maximumWireBytes in 1..MAX_COURIER_ATTACHMENT_WIRE_BYTES) {
            "Recipient attachment transfer size is invalid."
        }
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        output.writeSecureRecord(
            session,
            buildTransferHeader(
                DATA_MAGIC,
                test.sessionId,
                maximumWireBytes.toInt(),
                recipient.courierPlanSha256,
                PayloadKind.RECIPIENT_ATTACHMENT,
            ),
        )
        output.writeSecureRecord(
            session,
            RelayRecipientWifiPull(
                objectId = recipient.objectId.copyOf(),
                planSha256 = recipient.courierPlanSha256.copyOf(),
            ).encode(),
        )
        output.flush()

        val descriptor = RelayRecipientCourierDescriptor.decode(input.readSecureRecord(session))
        val manifest = RelayRecipientCourierTransferPolicy.materialize(recipient, descriptor)
        check(maximumWireBytes == Math.addExact(
            descriptor.plan.totalCiphertextBytes,
            descriptor.plan.chunks.size.toLong() * RelayCourierAttachmentChunk.HEADER_BYTES,
        )) { "Recipient attachment byte bound does not match its plan." }
        attachmentStore.acceptIncoming(transfer.senderFingerprint, manifest.encode())
        val missing = attachmentStore.missingChunkIndices(manifest.attachmentId)
        val missingSet = missing.toHashSet()
        val committed = manifest.chunks.indices.filterNot(missingSet::contains)
        output.writeSecureRecord(
            session,
            RelayRecipientChunkResume.fromCommitted(descriptor.plan, committed).encode(),
        )
        output.flush()

        val resumedBytes = resumedPlaintextBytes(manifest, missing)
        var transferredBytes = resumedBytes
        var receivedThisAttemptBytes = 0L
        missing.forEachIndexed { position, expectedIndex ->
            val start = RelayCourierWifiChunkStart.decode(input.readSecureRecord(session))
            check(
                start.objectId.contentEquals(manifest.attachmentId) &&
                    start.chunkIndex == expectedIndex,
            ) { "Recipient courier chunk order or object ID is invalid." }
            val encodedChunk = input.readSecureBlob(session, start.recordBytes)
            val chunk = RelayCourierAttachmentChunk.decode(encodedChunk)
            chunk.verifyAgainst(descriptor.plan)
            check(chunk.chunkIndex == expectedIndex) { "Recipient courier chunk index changed." }
            attachmentStore.storeIncomingChunk(
                manifest.attachmentId,
                expectedIndex,
                chunk.ciphertext,
            )
            transferredBytes += manifest.chunks[expectedIndex].plaintextBytes
            receivedThisAttemptBytes += manifest.chunks[expectedIndex].plaintextBytes
            emit(
                mapOf(
                    "type" to "attachment_receive_progress",
                    "token" to test.peerToken,
                    "attachmentId" to manifest.attachmentId.toHex(),
                    "transferredChunks" to (position + 1),
                    "totalChunks" to missing.size,
                    "transferredBytes" to transferredBytes,
                    "totalBytes" to manifest.plaintextBytes,
                    "resumedBytes" to resumedBytes,
                    "secure" to true,
                    "transport" to "courier",
                ),
            )
        }
        val done = RelayCourierWifiDone.decode(input.readSecureRecord(session))
        check(done.objectId.contentEquals(manifest.attachmentId)) {
            "Recipient courier completion belongs to another object."
        }
        val ready = attachmentStore.verifyAndMarkReady(manifest.attachmentId)
        val queuedReceipt = try {
            meshStore.queueReadyRecipientAttachmentReceipt(ready)
        } catch (error: RuntimeException) {
            // READY is already durable. Keep the pending private manifest so BLE inventory can
            // retry HAR1 creation after process death or temporary receipt-reserve pressure.
            Log.w(TAG, "Could not queue recipient attachment receipt after READY", error)
            null
        }
        output.writeSecureRecord(
            session,
            RelayRecipientChunkResume.fromCommitted(descriptor.plan, manifest.chunks.indices.toList())
                .encode(),
        )
        output.flush()
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        emit(
            ready.toMap() + mapOf(
                "type" to "attachment_received",
                "fingerprint" to transfer.senderFingerprint,
                "resumedChunks" to (manifest.chunks.size - missing.size),
                "transferredBytes" to manifest.plaintextBytes,
                "totalBytes" to manifest.plaintextBytes,
                "resumedBytes" to resumedBytes,
                "elapsedMs" to elapsedMs,
                "throughputBps" to (receivedThisAttemptBytes * 1_000L / elapsedMs),
                "transport" to "courier",
                "receiptQueued" to (queuedReceipt != null),
            ),
        )
        activeTest = null
    }

    /** Courier serves a complete durable HAP1/HAC1 set without seeing HAM1 plaintext. */
    private fun serveSecureRecipientAttachment(
        header: TransferHeader,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        check(header.payloadBytes in 1..MAX_COURIER_ATTACHMENT_WIRE_BYTES.toInt()) {
            "Recipient courier transfer size is invalid."
        }
        val pull = RelayRecipientWifiPull.decode(input.readSecureRecord(session))
        check(MessageDigest.isEqual(header.digest, pull.planSha256)) {
            "Recipient courier header belongs to another plan."
        }
        val encodedPlan = courierAttachmentStore.plan(pull.objectId)
            ?: throw IllegalStateException("Recipient courier plan is unavailable.")
        val plan = RelayCourierAttachmentPlan.decode(encodedPlan)
        val custody = courierAttachmentStore.custody(plan.objectId)
            ?.let(RelayCourierAttachmentCustody::decode)
            ?: throw IllegalStateException("Recipient courier custody is unavailable.")
        check(
            MessageDigest.isEqual(plan.sha256(), pull.planSha256) &&
                custody.missingChunks().isEmpty(),
        ) { "Recipient courier object is incomplete or belongs to another plan." }
        val expectedWireBytes = Math.addExact(
            plan.totalCiphertextBytes,
            plan.chunks.size.toLong() * RelayCourierAttachmentChunk.HEADER_BYTES,
        )
        check(header.payloadBytes.toLong() == expectedWireBytes) {
            "Recipient courier byte bound disagrees with its plan."
        }
        val nonces = plan.chunks.indices.map { index ->
            RelayCourierAttachmentChunk.decode(courierAttachmentStore.readChunk(plan.objectId, index))
                .also { it.verifyAgainst(plan) }
                .nonce
                .copyOf()
        }
        output.writeSecureRecord(
            session,
            RelayRecipientCourierTransferPolicy.descriptor(plan, nonces).encode(),
        )
        output.flush()

        val resume = RelayRecipientChunkResume.decode(input.readSecureRecord(session))
        check(
            resume.objectId.contentEquals(plan.objectId) &&
                MessageDigest.isEqual(resume.planSha256, plan.sha256()) &&
                resume.chunkCount == plan.chunks.size,
        ) { "Recipient resume belongs to another plan." }
        val missing = resume.missingChunks()
        var sentWireBytes = 0L
        missing.forEachIndexed { position, index ->
            val encodedChunk = courierAttachmentStore.readChunk(plan.objectId, index)
            output.writeSecureRecord(
                session,
                RelayCourierWifiChunkStart(plan.objectId.copyOf(), index, encodedChunk.size).encode(),
            )
            output.writeSecureBlob(session, encodedChunk)
            sentWireBytes = Math.addExact(sentWireBytes, encodedChunk.size.toLong())
            emit(
                mapOf(
                    "type" to "courier_attachment_forward_progress",
                    "token" to (connectedPeerToken ?: "unknown"),
                    "objectId" to plan.objectId.toHex(),
                    "transferredChunks" to (position + 1),
                    "totalChunks" to missing.size,
                    "transferredBytes" to sentWireBytes,
                    "secure" to true,
                ),
            )
        }
        output.writeSecureRecord(session, RelayCourierWifiDone(plan.objectId.copyOf()).encode())
        output.flush()
        val finalResume = RelayRecipientChunkResume.decode(input.readSecureRecord(session))
        check(
            finalResume.objectId.contentEquals(plan.objectId) &&
                MessageDigest.isEqual(finalResume.planSha256, plan.sha256()) &&
                finalResume.missingChunks().isEmpty(),
        ) { "Recipient did not verify every courier chunk." }
        emit(
            mapOf(
                "type" to "courier_attachment_forwarded",
                "token" to (connectedPeerToken ?: "unknown"),
                "objectId" to plan.objectId.toHex(),
                "chunks" to missing.size,
                "wireBytes" to sentWireBytes,
                "secure" to true,
            ),
        )
        // Fast-hop completion is not HAR1 and does not delete the courier copy.
    }

    private fun receiveSecureAttachment(
        header: TransferHeader,
        peerFingerprint: String,
        session: NativeRelaySession,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val manifestBytes = input.readSecureRecord(session)
        val manifest = RelayAttachmentManifest.decode(manifestBytes)
        check(manifest.plaintextBytes == header.payloadBytes.toLong()) {
            "Attachment manifest byte count mismatch."
        }
        check(manifest.plaintextSha256.contentEquals(header.digest)) {
            "Attachment manifest digest mismatch."
        }
        attachmentStore.acceptIncoming(peerFingerprint, manifestBytes)
        val missing = attachmentStore.missingChunkIndices(manifest.attachmentId)
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        val resumedBytes = resumedPlaintextBytes(manifest, missing)
        output.writeSecureRecord(session, encodeAttachmentResume(manifest.attachmentId, missing))
        output.flush()
        emit(
            mapOf(
                "type" to "attachment_receiving",
                "token" to (connectedPeerToken ?: "unknown"),
                "attachmentId" to manifest.attachmentId.toHex(),
                "fileName" to manifest.fileName,
                "mimeType" to manifest.mimeType,
                "bytes" to manifest.plaintextBytes,
                "remainingChunks" to missing.size,
                "totalChunks" to manifest.chunks.size,
                "transferredBytes" to resumedBytes,
                "totalBytes" to manifest.plaintextBytes,
                "resumedBytes" to resumedBytes,
                "throughputBps" to 0L,
                "secure" to true,
            ),
        )
        var transferredBytes = resumedBytes
        var receivedThisAttemptBytes = 0L
        var lastProgressAtMs = transferStartedAtMs
        missing.forEach { expectedIndex ->
            val chunk = manifest.chunks[expectedIndex]
            decodeAttachmentChunkHeader(
                input.readSecureRecord(session),
                manifest.attachmentId,
                chunk,
            )
            val ciphertext = ByteArray(chunk.ciphertextBytes)
            var offset = 0
            while (offset < ciphertext.size) {
                val record = input.readSecureRecord(session)
                check(record.size in 1..minOf(SECURE_PLAINTEXT_BYTES, ciphertext.size - offset)) {
                    "Attachment chunk record length is invalid."
                }
                record.copyInto(ciphertext, destinationOffset = offset)
                offset += record.size
            }
            attachmentStore.storeIncomingChunk(manifest.attachmentId, expectedIndex, ciphertext)
            transferredBytes += chunk.plaintextBytes
            receivedThisAttemptBytes += chunk.plaintextBytes
            val nowMs = SystemClock.elapsedRealtime()
            if (nowMs - lastProgressAtMs >= ATTACHMENT_PROGRESS_INTERVAL_MS ||
                transferredBytes == manifest.plaintextBytes
            ) {
                emitAttachmentProgress(
                    type = "attachment_receive_progress",
                    token = connectedPeerToken ?: "unknown",
                    manifest = manifest,
                    transferredBytes = transferredBytes,
                    resumedBytes = resumedBytes,
                    attemptBytes = receivedThisAttemptBytes,
                    transferStartedAtMs = transferStartedAtMs,
                )
                lastProgressAtMs = nowMs
            }
        }
        decodeAttachmentDone(input.readSecureRecord(session), manifest.attachmentId)
        val ready = attachmentStore.verifyAndMarkReady(manifest.attachmentId)
        output.writeSecureRecord(
            session,
            encodeAttachmentReceipt(
                manifest.attachmentId,
                manifest.plaintextBytes,
                manifest.plaintextSha256,
            ),
        )
        output.flush()
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        emit(
            ready.toMap() + mapOf(
                "type" to "attachment_received",
                "fingerprint" to peerFingerprint,
                "resumedChunks" to (manifest.chunks.size - missing.size),
                "transferredBytes" to manifest.plaintextBytes,
                "totalBytes" to manifest.plaintextBytes,
                "resumedBytes" to resumedBytes,
                "elapsedMs" to elapsedMs,
                "throughputBps" to (receivedThisAttemptBytes * 1_000L / elapsedMs),
            ),
        )
    }

    private fun resumedPlaintextBytes(
        manifest: RelayAttachmentManifest,
        missing: List<Int>,
    ): Long {
        val missingIndices = missing.toHashSet()
        return manifest.chunks
            .asSequence()
            .filterNot { it.index in missingIndices }
            .sumOf { it.plaintextBytes.toLong() }
    }

    private fun emitAttachmentProgress(
        type: String,
        token: String,
        manifest: RelayAttachmentManifest,
        transferredBytes: Long,
        resumedBytes: Long,
        attemptBytes: Long,
        transferStartedAtMs: Long,
    ) {
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        emit(
            mapOf(
                "type" to type,
                "token" to token,
                "attachmentId" to manifest.attachmentId.toHex(),
                "transferredBytes" to transferredBytes,
                "totalBytes" to manifest.plaintextBytes,
                "resumedBytes" to resumedBytes,
                "throughputBps" to (attemptBytes * 1_000L / elapsedMs),
                "secure" to true,
            ),
        )
    }

    private fun sendPayload(
        test: ActiveTest,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val header = buildTransferHeader(DATA_MAGIC, test.sessionId, test.payload.size, test.digest)
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        emit(
            mapOf(
                "type" to "wifi_direct_transfer_sending",
                "token" to test.peerToken,
                "bytes" to test.payload.size,
                "secure" to false,
            ),
        )
        output.write(header)
        output.write(test.payload)
        output.flush()
        val receipt = parseTransferHeader(input.readExact(TRANSFER_HEADER_BYTES), ACK_MAGIC)
        check(receipt.sessionId.contentEquals(test.sessionId)) { "Receipt session ID mismatch." }
        check(receipt.payloadBytes == test.payload.size) { "Receipt byte count mismatch." }
        check(receipt.digest.contentEquals(test.digest)) { "Receipt digest mismatch." }
        finishSendingTest(test, transferStartedAtMs, secure = false)
    }

    private fun receivePayload(
        expectedSessionId: ByteArray,
        input: DataInputStream,
        output: DataOutputStream,
    ) {
        val header = parseTransferHeader(input.readExact(TRANSFER_HEADER_BYTES), DATA_MAGIC)
        check(header.sessionId.contentEquals(expectedSessionId)) { "Transfer session ID mismatch." }
        check(header.payloadKind == PayloadKind.ENGINEERING) {
            "Raw Wi-Fi mode cannot carry user content."
        }
        check(header.payloadBytes in 1..MAX_TEST_PAYLOAD_BYTES) { "Transfer size is invalid." }
        val digest = MessageDigest.getInstance(DIGEST_ALGORITHM)
        val buffer = ByteArray(IO_BUFFER_BYTES)
        var remaining = header.payloadBytes
        val transferStartedAtMs = SystemClock.elapsedRealtime()
        emit(
            mapOf(
                "type" to "wifi_direct_transfer_receiving",
                "token" to (connectedPeerToken ?: "unknown"),
                "bytes" to header.payloadBytes,
                "secure" to false,
            ),
        )
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) throw IOException("Wi-Fi Direct payload ended early.")
            digest.update(buffer, 0, read)
            remaining -= read
        }
        val actualDigest = digest.digest()
        check(actualDigest.contentEquals(header.digest)) { "Payload integrity check failed." }
        output.write(buildTransferHeader(ACK_MAGIC, header.sessionId, header.payloadBytes, actualDigest))
        output.flush()
        finishReceivingTest(header, transferStartedAtMs, secure = false)
    }

    private fun finishSendingTest(
        test: ActiveTest,
        transferStartedAtMs: Long,
        secure: Boolean,
    ) {
        mainHandler.removeCallbacks(connectionTimeout)
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        val setupMs = max(1L, transferStartedAtMs - test.connectionStartedAtMs)
        emit(
            mapOf(
                "type" to "wifi_direct_transfer_complete",
                "token" to test.peerToken,
                "bytes" to test.payload.size,
                "elapsedMs" to elapsedMs,
                "setupMs" to setupMs,
                "throughputBps" to (test.payload.size * 1_000L / elapsedMs),
                "secure" to secure,
            ),
        )
        activeTest = null
    }

    private fun finishReceivingTest(
        header: TransferHeader,
        transferStartedAtMs: Long,
        secure: Boolean,
    ) {
        val elapsedMs = max(1L, SystemClock.elapsedRealtime() - transferStartedAtMs)
        emit(
            mapOf(
                "type" to "wifi_direct_transfer_received",
                "token" to (connectedPeerToken ?: "unknown"),
                "bytes" to header.payloadBytes,
                "elapsedMs" to elapsedMs,
                "throughputBps" to (header.payloadBytes * 1_000L / elapsedMs),
                "secure" to secure,
            ),
        )
    }

    private fun encodeAttachmentResume(attachmentId: ByteArray, missing: List<Int>): ByteArray {
        require(missing.size <= RelayAttachmentManifest.MAX_CHUNKS)
        return ByteBuffer.allocate(ATTACHMENT_RESUME_HEADER_BYTES + missing.size * Int.SIZE_BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .put(ATTACHMENT_RESUME_MAGIC)
            .put(attachmentId)
            .putShort(missing.size.toShort())
            .apply { missing.forEach(::putInt) }
            .array()
    }

    private fun decodeAttachmentResume(
        encoded: ByteArray,
        attachmentId: ByteArray,
        chunkCount: Int,
    ): List<Int> {
        require(encoded.size in ATTACHMENT_RESUME_HEADER_BYTES..
            (ATTACHMENT_RESUME_HEADER_BYTES + RelayAttachmentManifest.MAX_CHUNKS * Int.SIZE_BYTES)
        ) { "Attachment resume record length is invalid." }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4).also(buffer::get)
        val id = ByteArray(RelayAttachmentManifest.ATTACHMENT_ID_BYTES).also(buffer::get)
        val count = buffer.short.toInt() and 0xFFFF
        require(magic.contentEquals(ATTACHMENT_RESUME_MAGIC) && id.contentEquals(attachmentId)) {
            "Attachment resume record does not match."
        }
        require(count <= chunkCount && encoded.size == ATTACHMENT_RESUME_HEADER_BYTES + count * 4) {
            "Attachment resume count is invalid."
        }
        val indices = List(count) { buffer.int }
        require(indices.distinct().size == indices.size && indices.all { it in 0 until chunkCount }) {
            "Attachment resume indices are invalid."
        }
        return indices
    }

    private fun encodeAttachmentChunkHeader(
        attachmentId: ByteArray,
        chunk: RelayAttachmentManifest.Chunk,
    ): ByteArray = ByteBuffer.allocate(ATTACHMENT_CHUNK_HEADER_BYTES)
        .order(ByteOrder.BIG_ENDIAN)
        .put(ATTACHMENT_CHUNK_MAGIC)
        .put(attachmentId)
        .putInt(chunk.index)
        .putInt(chunk.ciphertextBytes)
        .put(chunk.ciphertextSha256)
        .array()

    private fun decodeAttachmentChunkHeader(
        encoded: ByteArray,
        attachmentId: ByteArray,
        expected: RelayAttachmentManifest.Chunk,
    ) {
        require(encoded.size == ATTACHMENT_CHUNK_HEADER_BYTES) {
            "Attachment chunk header length is invalid."
        }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4).also(buffer::get)
        val id = ByteArray(RelayAttachmentManifest.ATTACHMENT_ID_BYTES).also(buffer::get)
        val index = buffer.int
        val bytes = buffer.int
        val digest = ByteArray(RelayAttachmentManifest.SHA256_BYTES).also(buffer::get)
        require(
            magic.contentEquals(ATTACHMENT_CHUNK_MAGIC) && id.contentEquals(attachmentId) &&
                index == expected.index && bytes == expected.ciphertextBytes &&
                digest.contentEquals(expected.ciphertextSha256),
        ) { "Attachment chunk header does not match its manifest." }
    }

    private fun encodeAttachmentDone(attachmentId: ByteArray): ByteArray =
        ATTACHMENT_DONE_MAGIC + attachmentId

    private fun decodeAttachmentDone(encoded: ByteArray, attachmentId: ByteArray) {
        require(
            encoded.size == ATTACHMENT_DONE_BYTES &&
                encoded.copyOfRange(0, 4).contentEquals(ATTACHMENT_DONE_MAGIC) &&
                encoded.copyOfRange(4, encoded.size).contentEquals(attachmentId),
        ) { "Attachment completion marker does not match." }
    }

    private fun encodeAttachmentReceipt(
        attachmentId: ByteArray,
        plaintextBytes: Long,
        plaintextDigest: ByteArray,
    ): ByteArray = ByteBuffer.allocate(ATTACHMENT_RECEIPT_BYTES)
        .order(ByteOrder.BIG_ENDIAN)
        .put(ATTACHMENT_RECEIPT_MAGIC)
        .put(attachmentId)
        .putLong(plaintextBytes)
        .put(plaintextDigest)
        .array()

    private fun validateAttachmentReceipt(
        encoded: ByteArray,
        attachmentId: ByteArray,
        plaintextBytes: Long,
        plaintextDigest: ByteArray,
    ) {
        require(encoded.contentEquals(encodeAttachmentReceipt(attachmentId, plaintextBytes, plaintextDigest))) {
            "Encrypted attachment receipt mismatch."
        }
    }

    private fun buildHello(test: ActiveTest?): ByteArray = ByteBuffer
        .allocate(HELLO_BYTES)
        .order(ByteOrder.BIG_ENDIAN)
        .put(HELLO_MAGIC)
        .put(PROTOCOL_VERSION)
        .put(if (test == null) 0.toByte() else INITIATOR_FLAG)
        .putShort(0)
        .put(test?.sessionId ?: ByteArray(SESSION_ID_BYTES))
        .put(test?.authorization?.offerId ?: ByteArray(OFFER_ID_BYTES))
        .array()

    private fun parseHello(encoded: ByteArray): Hello {
        check(encoded.size == HELLO_BYTES && encoded.copyOfRange(0, 4).contentEquals(HELLO_MAGIC)) {
            "Invalid Wi-Fi Direct hello."
        }
        check(encoded[4] == PROTOCOL_VERSION && encoded[6] == 0.toByte() && encoded[7] == 0.toByte()) {
            "Unsupported Wi-Fi Direct hello."
        }
        check(encoded[5] == 0.toByte() || encoded[5] == INITIATOR_FLAG) {
            "Invalid Wi-Fi Direct role flag."
        }
        return Hello(
            initiator = encoded[5] == INITIATOR_FLAG,
            sessionId = encoded.copyOfRange(8, 16),
            offerId = encoded.copyOfRange(16, HELLO_BYTES),
        )
    }

    private fun buildTransferHeader(
        magic: ByteArray,
        sessionId: ByteArray,
        payloadBytes: Int,
        digest: ByteArray,
        payloadKind: PayloadKind = PayloadKind.ENGINEERING,
    ): ByteArray = ByteBuffer
        .allocate(TRANSFER_HEADER_BYTES)
        .order(ByteOrder.BIG_ENDIAN)
        .put(magic)
        .put(PROTOCOL_VERSION)
        .put(payloadKind.wireValue)
        .putShort(0)
        .put(sessionId)
        .putInt(payloadBytes)
        .put(digest)
        .array()

    private fun parseTransferHeader(encoded: ByteArray, expectedMagic: ByteArray): TransferHeader {
        check(
            encoded.size == TRANSFER_HEADER_BYTES &&
                encoded.copyOfRange(0, 4).contentEquals(expectedMagic),
        ) { "Invalid Wi-Fi Direct transfer header." }
        check(encoded[4] == PROTOCOL_VERSION && encoded[6] == 0.toByte() && encoded[7] == 0.toByte()) {
            "Unsupported Wi-Fi Direct transfer header."
        }
        return TransferHeader(
            sessionId = encoded.copyOfRange(8, 16),
            payloadBytes = ByteBuffer.wrap(encoded, 16, 4).order(ByteOrder.BIG_ENDIAN).int,
            digest = encoded.copyOfRange(20, TRANSFER_HEADER_BYTES),
            payloadKind = PayloadKind.fromWire(encoded[5]),
        )
    }

    private fun DataInputStream.readExact(bytes: Int): ByteArray = ByteArray(bytes).also(::readFully)

    private fun DataOutputStream.writePacket(payload: ByteArray, maximumBytes: Int) {
        check(payload.isNotEmpty() && payload.size <= maximumBytes && payload.size <= 0xFFFF) {
            "Wi-Fi packet size is invalid."
        }
        writeShort(payload.size)
        write(payload)
    }

    private fun DataInputStream.readPacket(maximumBytes: Int): ByteArray {
        val bytes = readUnsignedShort()
        check(bytes in 1..maximumBytes) { "Wi-Fi packet size is invalid." }
        return readExact(bytes)
    }

    private fun DataOutputStream.writeSecureRecord(
        session: NativeRelaySession,
        plaintext: ByteArray,
    ) {
        writePacket(session.encrypt(plaintext), MAX_SECURE_CIPHERTEXT_BYTES)
    }

    private fun DataInputStream.readSecureRecord(session: NativeRelaySession): ByteArray =
        session.decrypt(readPacket(MAX_SECURE_CIPHERTEXT_BYTES))

    private fun DataOutputStream.writeSecureBlob(
        session: NativeRelaySession,
        plaintext: ByteArray,
    ) {
        require(plaintext.isNotEmpty()) { "Secure Wi-Fi blob is empty." }
        var offset = 0
        while (offset < plaintext.size) {
            val end = minOf(offset + SECURE_PLAINTEXT_BYTES, plaintext.size)
            writeSecureRecord(session, plaintext.copyOfRange(offset, end))
            offset = end
        }
    }

    private fun DataInputStream.readSecureBlob(
        session: NativeRelaySession,
        plaintextBytes: Int,
    ): ByteArray {
        require(plaintextBytes in 1..RelayCourierWifiChunkStart.MAX_RECORD_BYTES) {
            "Secure Wi-Fi blob length is invalid."
        }
        val plaintext = ByteArray(plaintextBytes)
        var offset = 0
        while (offset < plaintext.size) {
            val record = readSecureRecord(session)
            require(record.size in 1..minOf(SECURE_PLAINTEXT_BYTES, plaintext.size - offset)) {
                "Secure Wi-Fi blob record length is invalid."
            }
            record.copyInto(plaintext, destinationOffset = offset)
            offset += record.size
        }
        return plaintext
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun registerReceiver() {
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            activity.registerReceiver(receiver, filter)
        }
        receiverRegistered = true
    }

    @SuppressLint("MissingPermission")
    private fun removeGroup() {
        mainHandler.removeCallbacks(warmGroupTeardown)
        clearWarmConnection()
        val p2pManager = manager ?: return
        val p2pChannel = channel ?: return
        runCatching { p2pManager.removeGroup(p2pChannel, null) }
    }

    private fun clearWarmConnection() {
        warmConnectionInfo = null
        warmRemoteToken?.fill(0)
        warmRemoteToken = null
    }

    @SuppressLint("MissingPermission")
    private fun refreshServiceDiscovery() {
        val p2pManager = manager ?: return
        val p2pChannel = channel ?: return
        if (serviceRequest == null) return
        if (!started) return
        try {
            p2pManager.discoverServices(
                p2pChannel,
                action(
                    operation = "refresh service discovery",
                    onSuccess = {
                        emit(mapOf("type" to "wifi_direct_discovery_refreshed"))
                    },
                    onFailure = { reason ->
                        if (reason != WifiP2pManager.BUSY) {
                            emit(
                                mapOf(
                                    "type" to "wifi_direct_warning",
                                    "code" to "wifi_direct_refresh_failed",
                                    "message" to
                                        "Wi-Fi peer refresh failed (${failureName(reason)}); retrying automatically.",
                                ),
                            )
                        }
                    },
                ),
            )
        } catch (_: SecurityException) {
            emit(errorEvent("wifi_permission_required", "Nearby Wi-Fi permission was revoked."))
        }
    }

    @SuppressLint("MissingPermission")
    private fun failActiveConnection(code: String, message: String) {
        val token = activeTest?.peerToken ?: connectedPeerToken
        val failedTest = activeTest
        val failureEvent = errorEvent(code, message, token)
        failedTest?.authorization?.let { authorization ->
            synchronized(authorizationsByOffer) {
                authorizationsByOffer.remove(authorization.offerId.toHex())?.destroySecret()
            }
            authorization.destroySecret()
        }
        mainHandler.removeCallbacks(connectionTimeout)
        closeSockets()
        activeTest = null
        socketJobStarted = false
        connectedPeerToken = null
        emit(failureEvent)
        val resetRadio = code == "wifi_direct_radio_busy"
        if (resetRadio) {
            consecutiveRadioBusyFailures =
                (consecutiveRadioBusyFailures + 1).coerceAtMost(MAX_RADIO_BUSY_FAILURES)
        }
        failedTest?.let {
            queueFailedTest(
                it,
                code,
                retryDelayOverrideMs = if (resetRadio) radioBusyBackoffMs() else null,
            )
        }
        if (resetRadio) stop() else removeGroup()
    }

    private fun queueFailedTest(
        test: ActiveTest,
        code: String,
        retryDelayOverrideMs: Long? = null,
    ) {
        if (test.payloadKind == PayloadKind.ATTACHMENT) {
            val attachment = test.attachment ?: return
            try {
                attachmentStore.markRetryable(
                    attachment.manifest.attachmentId,
                    code,
                    retryDelayOverrideMs,
                )
            } catch (error: RuntimeException) {
                Log.w(TAG, "Could not update queued attachment retry metadata", error)
            }
            val updated = attachmentStore.findByHexId(attachment.manifest.attachmentId.toHex())
            emitAttachmentQueued(updated ?: attachment, code)
            return
        }
        if (test.payloadKind == PayloadKind.USER_TEXT) {
            val message = test.message ?: return
            val retryAt = try {
                messageStore.markRetryableFailure(message.id, code)
            } catch (error: RuntimeException) {
                Log.w(TAG, "Could not update queued Wi-Fi message retry metadata", error)
                null
            }
            emitQueuedMessage(message, test.peerToken, retryAt, code)
        }
    }

    private fun emitAttachmentQueued(
        attachment: RelayAttachmentStore.StoredAttachment,
        errorCode: String,
    ) {
        emit(
            attachment.toMap() + mapOf(
                "type" to "attachment_queued",
                "code" to errorCode,
            ),
        )
    }

    private fun emitQueuedMessage(
        message: RelayMessageCodec.TextMessage,
        peerToken: String?,
        retryAtMs: Long?,
        errorCode: String,
    ) {
        emit(
            buildMap {
                put("type", "text_message_queued")
                peerToken?.let { put("token", it) }
                put("messageId", RelayMessageCodec.idHex(message.id))
                put("text", message.text)
                putAll(message.replyMap())
                put("code", errorCode)
                put("automatic", false)
                retryAtMs?.let { put("retryAtMs", it) }
            },
        )
    }

    private fun closeSockets() {
        synchronized(socketLock) {
            runCatching { socket?.close() }
            runCatching { serverSocket?.close() }
            socket = null
            serverSocket = null
        }
    }

    private fun checkStarted() {
        if (!started || manager == null || channel == null) {
            throw WifiDirectException("wifi_direct_stopped", "Start Wi-Fi Direct discovery first.")
        }
    }

    private fun action(
        operation: String,
        onSuccess: () -> Unit,
        onFailure: ((Int) -> Unit)? = null,
    ): WifiP2pManager.ActionListener = object : WifiP2pManager.ActionListener {
        override fun onSuccess() = onSuccess.invoke()

        override fun onFailure(reason: Int) {
            if (onFailure != null) {
                onFailure.invoke(reason)
                return
            }
            emit(
                errorEvent(
                    "wifi_direct_${operation.replace(' ', '_')}_failed",
                    "$operation failed (${failureName(reason)}).",
                ),
            )
        }
    }

    private fun errorEvent(
        code: String,
        message: String,
        token: String? = null,
    ): Map<String, Any> = buildMap {
        put("type", "wifi_direct_error")
        put("code", code)
        put("message", message)
        if (token != null) put("token", token)
        val attachmentId = activeTest?.attachment?.manifest?.attachmentId
            ?: pendingAttachmentTransfer?.attachment?.manifest?.attachmentId
        if (attachmentId != null) put("attachmentId", attachmentId.toHex())
    }

    private fun failureName(reason: Int): String = when (reason) {
        WifiP2pManager.P2P_UNSUPPORTED -> "unsupported"
        WifiP2pManager.BUSY -> "radio busy"
        WifiP2pManager.ERROR -> "system error"
        else -> "code $reason"
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    private fun String.hexToBytesOrNull(): ByteArray? {
        if (length % 2 != 0) return null
        return try {
            ByteArray(length / 2) { index ->
                substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        } catch (_: NumberFormatException) {
            null
        }
    }

    private data class ActiveTest(
        val peerToken: String,
        val sessionId: ByteArray,
        val payload: ByteArray,
        val digest: ByteArray,
        val connectionStartedAtMs: Long,
        val authorization: RelayWifiUpgradeAuthorization?,
        val payloadKind: PayloadKind,
        val message: RelayMessageCodec.TextMessage?,
        val attachment: RelayAttachmentStore.StoredAttachment?,
        val courierAttachment: PendingCourierAttachmentTransfer?,
        val recipientAttachment: PendingRecipientAttachmentTransfer?,
    )

    private data class PendingTextTransfer(
        val peerToken: String,
        val message: RelayMessageCodec.TextMessage,
    )

    private data class PendingAttachmentTransfer(
        val attachment: RelayAttachmentStore.StoredAttachment,
    )

    private data class PendingCourierAttachmentTransfer(
        val attachment: RelayAttachmentStore.StoredAttachment,
        val courierFingerprint: String,
        val custody: RelayCourierAttachmentCustody,
    )

    private data class PendingRecipientAttachmentTransfer(
        val senderFingerprint: String,
        val manifest: RelayRecipientAttachmentManifest,
    )

    private data class Hello(
        val initiator: Boolean,
        val sessionId: ByteArray,
        val offerId: ByteArray,
    )

    private data class TransferHeader(
        val sessionId: ByteArray,
        val payloadBytes: Int,
        val digest: ByteArray,
        val payloadKind: PayloadKind,
    )

    private enum class PayloadKind(val wireValue: Byte) {
        ENGINEERING(0),
        USER_TEXT(1),
        ATTACHMENT(2),
        COURIER_ATTACHMENT(3),
        RECIPIENT_ATTACHMENT(4);

        companion object {
            fun fromWire(value: Byte): PayloadKind = entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalStateException("Unsupported Wi-Fi payload kind.")
        }
    }

    class WifiDirectException(
        val code: String,
        override val message: String,
    ) : IllegalStateException(message)

    private companion object {
        const val TAG = "RelayWifiDirect"
        const val INSTANCE_NAME = "ProjectRelay"
        const val SERVICE_TYPE = "_relay._tcp"
        const val SERVER_PORT = 49_371
        const val PROTOCOL_VERSION: Byte = 1
        const val INITIATOR_FLAG: Byte = 1
        const val TOKEN_BYTES = 8
        const val SESSION_ID_BYTES = 8
        const val OFFER_ID_BYTES = 16
        const val HELLO_BYTES = 32
        const val TRANSFER_HEADER_BYTES = 52
        const val MAX_HANDSHAKE_BYTES = 512
        const val SECURE_PLAINTEXT_BYTES = 32 * 1024
        const val MAX_SECURE_CIPHERTEXT_BYTES = SECURE_PLAINTEXT_BYTES + 16
        const val ATTACHMENT_PROGRESS_INTERVAL_MS = 250L
        const val TEST_PAYLOAD_BYTES = 4 * 1024 * 1024
        const val MAX_TEST_PAYLOAD_BYTES = 16 * 1024 * 1024
        const val MAX_TEXT_WIRE_BYTES = 44 + 256 + 2_048
        const val MAX_COURIER_ATTACHMENT_WIRE_BYTES =
            RelayCourierAttachmentPlan.MAX_ATTACHMENT_CIPHERTEXT_BYTES +
                RelayCourierAttachmentPlan.MAX_CHUNKS.toLong() *
                RelayCourierAttachmentChunk.HEADER_BYTES
        const val IO_BUFFER_BYTES = 64 * 1024
        const val SOCKET_TIMEOUT_MS = 60_000
        const val CONNECT_TIMEOUT_MS = 1_000
        const val CONNECT_ATTEMPTS = 30
        const val CONNECT_RETRY_MS = 250L
        const val WARM_GROUP_IDLE_MS = 30_000L
        const val CONNECTION_ESTABLISH_TIMEOUT_MS = 35_000L
        const val DISCOVERY_WATCHDOG_MS = 12_000L
        const val PEER_STALE_MS = 90_000L
        const val AUTHORIZED_PEER_WAIT_MS = 25_000L
        const val AUTHORIZED_PEER_RETRY_MS = 350L
        const val P2P_SETTLE_DELAY_MS = 350L
        const val P2P_RETRY_DELAY_MS = 700L
        const val MAX_BOOTSTRAP_RETRIES = 5
        const val MAX_RADIO_BUSY_FAILURES = 3
        const val RADIO_BUSY_RETRY_BASE_MS = 5_000L
        const val RADIO_BUSY_RETRY_MAX_MS = 15_000L
        const val MIN_GROUP_OWNER_INTENT = 0
        const val AUTO_PEER_KEY = ""
        const val DIGEST_ALGORITHM = "SHA-256"
        val TOKEN_PATTERN = Regex("[0-9a-f]{16}")
        val HELLO_MAGIC = byteArrayOf(0x52, 0x57, 0x48, 0x31)
        val DATA_MAGIC = byteArrayOf(0x52, 0x57, 0x44, 0x54)
        val ACK_MAGIC = byteArrayOf(0x52, 0x57, 0x41, 0x4B)
        val ATTACHMENT_RESUME_MAGIC = byteArrayOf(0x48, 0x59, 0x52, 0x31)
        val ATTACHMENT_CHUNK_MAGIC = byteArrayOf(0x48, 0x59, 0x43, 0x31)
        val ATTACHMENT_DONE_MAGIC = byteArrayOf(0x48, 0x59, 0x44, 0x31)
        val ATTACHMENT_RECEIPT_MAGIC = byteArrayOf(0x48, 0x59, 0x41, 0x4B)
        const val ATTACHMENT_RESUME_HEADER_BYTES = 22
        const val ATTACHMENT_CHUNK_HEADER_BYTES = 60
        const val ATTACHMENT_DONE_BYTES = 20
        const val ATTACHMENT_RECEIPT_BYTES = 60
    }
}
