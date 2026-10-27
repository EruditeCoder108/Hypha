package app.projectrelay.relay_mobile

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.os.SystemClock
import io.flutter.plugin.common.EventChannel
import android.util.Log
import java.security.SecureRandom

/**
 * Foreground-only Phase 0 discovery transport.
 *
 * The Android Bluetooth address is deliberately discarded. Flutter receives
 * only a random session token, signal strength, and coarse PHY information.
 */
class RelayBleDiscovery(
    private val activity: Context,
) : EventChannel.StreamHandler {
    private val random = SecureRandom()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val lastEmissionByToken = mutableMapOf<String, Long>()
    private val deviceByToken = mutableMapOf<String, android.bluetooth.BluetoothDevice>()
    private val lastSeenByToken = mutableMapOf<String, Long>()
    private val remoteMeshHintByToken = mutableMapOf<String, Int>()
    private val meshActivityByToken = mutableMapOf<String, Boolean>()
    private val encounterScheduler = RelayEncounterScheduler()
    private val meshWorkGate = RelayMeshWorkGate()
    private val identityRefreshScheduler = RelayIdentityRefreshScheduler()
    private val retryPeerFairness = RelayPeerFairness()
    private val priorityPeerFairness = RelayPeerFairness()
    private val radioAdmissionPolicy = RelayRadioAdmissionPolicy()
    private val meshStore = RelayMeshStore(activity)
    private val venueTrustStore = HyphaVenueTrustStore(activity)
    private val attachmentStore = RelayAttachmentStore(activity)
    private val courierAttachmentStore = RelayCourierAttachmentStore(activity)
    private val wifiDirect = RelayWifiDirect(
        activity = activity,
        emit = ::handleWifiEvent,
        meshStore = meshStore,
        courierAttachmentStore = courierAttachmentStore,
    )
    private val gattLink = RelayGattLink(
        activity = activity,
        emit = ::handleGattEvent,
        localToken = { localToken },
        localWifiToken = wifiDirect::ensureStartedToken,
        onWifiUpgradeAuthorized = wifiDirect::installAuthorization,
        onWifiUpgradeFailed = ::handleWifiUpgradeFailure,
        meshStore = meshStore,
        courierAttachmentStore = courierAttachmentStore,
    )
    private val fixedNodeLink = HyphaFixedNodeLink(
        context = activity,
        meshStore = meshStore,
        venueTrustStore = venueTrustStore,
        emit = ::handleFixedNodeEvent,
    )
    private var eventSink: EventChannel.EventSink? = null
    @Volatile
    private var backgroundEventObserver: ((Map<String, Any>) -> Unit)? = null
    private var localToken: ByteArray? = null
    @Volatile
    private var desiredActive = false
    @Volatile
    private var active = false
    @Volatile
    private var destroyed = false
    private var recoveryAttempt = 0
    private var lastAutomaticRetryCheckMs = 0L
    private var advertisedMeshHint: Int? = null
    private var meshWorkEpoch = 1
    private var localMeshRevision = 1L
    private var pendingCourierCleanup: PendingCourierCleanup? = null
    private var pendingCourierPlanOffer: PendingCourierPlanOffer? = null
    private var pendingCourierChunkRequest: PendingCourierChunkRequest? = null
    private var pendingRecipientAttachmentRequest: PendingRecipientAttachmentRequest? = null
    private var pendingAttachmentRequest: PendingAttachmentRequest? = null
    // Scan callbacks arrive on the main thread many times per second per nearby phone. The
    // durable mesh check below runs several SQLite transactions, so it is cached briefly and
    // invalidated by every event that can change it; per-peer servicing is rate limited.
    private val lastServiceByToken = mutableMapOf<String, Long>()
    private var pendingMeshWorkCache: Boolean? = null
    private var pendingMeshWorkCheckedAtMs = 0L
    private var lastPhoneLinkEventAtMs = 0L

    private val advertiseRefreshRunnable = Runnable { refreshAdvertisedMeshWork() }
    private val attachmentDispatchRunnable = Runnable { servicePriorityRadioWork() }

    private val recoveryRunnable = object : Runnable {
        override fun run() {
            if (destroyed || !desiredActive || active) return
            val adapter = bluetoothAdapter
            if (adapter?.isEnabled != true) return
            try {
                startRadio()
            } catch (error: DiscoveryException) {
                if (error.code in NON_RECOVERABLE_START_ERRORS) {
                    desiredActive = false
                    emit(
                        mapOf(
                            "type" to "error",
                            "code" to error.code,
                            "message" to error.message,
                            "automatic" to true,
                        ),
                    )
                    return
                }
                emit(
                    mapOf(
                        "type" to "radio_recovery_deferred",
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
                scheduleRecovery()
            } catch (error: RuntimeException) {
                emit(
                    mapOf(
                        "type" to "radio_recovery_deferred",
                        "code" to "radio_restart_failed",
                        "message" to "Nearby discovery is restarting automatically.",
                        "automatic" to true,
                    ),
                )
                scheduleRecovery()
            }
        }
    }

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED || destroyed) return
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_TURNING_OFF,
                BluetoothAdapter.STATE_OFF,
                -> suspendForBluetoothOff()
                BluetoothAdapter.STATE_ON -> {
                    emit(
                        mapOf(
                            "type" to "radio_state_changed",
                            "enabled" to true,
                            "automatic" to true,
                        ),
                    )
                    recoveryAttempt = 0
                    scheduleRecovery()
                }
            }
        }
    }

    init {
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.registerReceiver(
                bluetoothStateReceiver,
                filter,
                // Bluetooth framework broadcasts can originate from a privileged process
                // outside the system UID. ACTION_STATE_CHANGED is a protected broadcast.
                Context.RECEIVER_EXPORTED,
            )
        } else {
            @Suppress("DEPRECATION")
            activity.registerReceiver(bluetoothStateReceiver, filter)
        }
    }

    private val bluetoothAdapter: BluetoothAdapter?
        get() = activity.getSystemService(BluetoothManager::class.java)?.adapter

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            emit(mapOf("type" to "advertising_started"))
        }

        override fun onStartFailure(errorCode: Int) {
            recoverFromRadioFailure(
                code = "advertise_failed_$errorCode",
                message = "BLE advertising stopped unexpectedly (code $errorCode).",
            )
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val scanRecord = result.scanRecord ?: return
            val payload = scanRecord
                .getManufacturerSpecificData(EXPERIMENTAL_MANUFACTURER_ID)
                ?: return
            if (isFixedNodeFrame(payload)) {
                val token = payload.copyOfRange(FIXED_NODE_PREFIX.size, FIXED_NODE_FRAME_LENGTH)
                    .toHex()
                val nodeSeenAt = SystemClock.elapsedRealtime()
                pruneStalePeers(nodeSeenAt)
                // Phones keep admission priority, but a visible phone must not lock the node
                // out forever: once the phone link has been quiet briefly, the node gets a turn.
                val phoneLinkQuiet = deviceByToken.isEmpty() ||
                    nodeSeenAt - lastPhoneLinkEventAtMs >= FIXED_NODE_SHARE_QUIET_MS
                if (phoneLinkQuiet && !gattLink.isBusy()) {
                    fixedNodeLink.consider(token, result.device)
                }
                return
            }
            if (!isRelayFrame(payload)) return
            val token = payload.copyOfRange(PREFIX.size, FRAME_LENGTH).toHex()
            val now = SystemClock.elapsedRealtime()
            val newEncounter = !deviceByToken.containsKey(token)
            rememberPeer(token, result.device, now)
            if (newEncounter) Log.i(METRICS_TAG, "encounter_seen")
            val remoteMeshHint = scanRecord.getServiceData(MESH_WORK_SERVICE_UUID)
                ?.firstOrNull()
                ?.toInt()
                ?.and(0xFF)
                ?: 0
            val previousMeshHint = remoteMeshHintByToken.put(token, remoteMeshHint)
            val hintChanged = remoteMeshHint != 0 && previousMeshHint != remoteMeshHint
            if (hintChanged) {
                encounterScheduler.nudge(token, now)
            }
            if (newEncounter) observeVerifiedContactRefresh(token, now)
            val lastService = lastServiceByToken[token]
            val serviceDue = newEncounter || hintChanged || lastService == null ||
                now - lastService >= SCAN_SERVICE_INTERVAL_MS
            // Phone work gets admission priority before a node sync starts. If a node sync was
            // already admitted during a phone-free scan window, let that short authenticated
            // exchange finish. Aborting it for every advertisement starves fixed couriers in a
            // real mesh. The remembered phone is serviced by the completion/error callback.
            // A busy link cannot admit new work; its completion event reschedules servicing.
            if (
                serviceDue && !gattLink.isBusy() &&
                !HyphaFixedNodeSchedulingPolicy.deferPhoneWork(fixedNodeLink.isBusy())
            ) {
                lastServiceByToken[token] = now
                serviceRadioWork(token, result.device, now)
            }
            val lastEmission = lastEmissionByToken[token] ?: 0L
            if (now - lastEmission < EMIT_INTERVAL_MS) return
            lastEmissionByToken[token] = now
            emit(
                buildMap {
                    put("type", "peer_seen")
                    put("token", token)
                    put("rssi", result.rssi)
                    put("primaryPhy", primaryPhy(result))
                    put("seenAtMs", now)
                    // Re-attach an already authenticated token when Flutter's
                    // screen/controller state was recreated. The BLE address is
                    // still never exposed or treated as identity.
                    gattLink.observedPeerMetadata(token)?.let(::putAll)
                },
            )
        }

        override fun onScanFailed(errorCode: Int) {
            recoverFromRadioFailure(
                code = "scan_failed_$errorCode",
                message = "BLE scanning stopped unexpectedly (code $errorCode).",
            )
        }
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    fun setBackgroundEventObserver(observer: ((Map<String, Any>) -> Unit)?) {
        backgroundEventObserver = observer
    }

    @SuppressLint("MissingPermission")
    fun start(): Map<String, Any> {
        if (destroyed) {
            throw DiscoveryException("discovery_destroyed", "Nearby discovery is no longer available.")
        }
        desiredActive = true
        recoveryAttempt = 0
        mainHandler.removeCallbacks(recoveryRunnable)
        if (active) {
            return mapOf("token" to requireNotNull(localToken).toHex())
        }
        return try {
            startRadio()
        } catch (error: DiscoveryException) {
            if (error.code in NON_RECOVERABLE_START_ERRORS) desiredActive = false
            throw error
        }
    }

    @SuppressLint("MissingPermission")
    private fun startRadio(): Map<String, Any> {
        val adapter = bluetoothAdapter
            ?: throw DiscoveryException("bluetooth_unavailable", "This phone has no Bluetooth adapter.")
        if (!adapter.isEnabled) {
            throw DiscoveryException(
                "bluetooth_off",
                "Bluetooth is off. Relay will reconnect automatically when it is turned on.",
            )
        }
        val advertiser = adapter.bluetoothLeAdvertiser
            ?: throw DiscoveryException(
                "advertising_unsupported",
                "This phone cannot advertise over Bluetooth LE.",
            )
        val scanner = adapter.bluetoothLeScanner
            ?: throw DiscoveryException("scan_unavailable", "Bluetooth scanning is unavailable.")

        bridgeCourierManifestsToMesh()
        val token = ByteArray(TOKEN_LENGTH).also(random::nextBytes)
        val meshHint = pendingMeshHintOrPrevious(defaultValue = 0)
        val advertiseSettings = buildAdvertiseSettings()
        val advertiseData = buildAdvertiseData(token, meshHint)
        val relayScanFilter = ScanFilter.Builder()
            .setManufacturerData(
                EXPERIMENTAL_MANUFACTURER_ID,
                PREFIX,
                ByteArray(PREFIX.size) { 0xFF.toByte() },
            )
            .build()
        val fixedNodeScanFilter = ScanFilter.Builder()
            .setManufacturerData(
                EXPERIMENTAL_MANUFACTURER_ID,
                FIXED_NODE_PREFIX,
                ByteArray(FIXED_NODE_PREFIX.size) { 0xFF.toByte() },
            )
            .build()
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0)
            .build()

        try {
            localToken = token
            active = true
            advertisedMeshHint = meshHint
            lastEmissionByToken.clear()
            lastServiceByToken.clear()
            invalidatePendingMeshWork()
            deviceByToken.clear()
            lastSeenByToken.clear()
            remoteMeshHintByToken.clear()
            meshActivityByToken.clear()
            encounterScheduler.clear()
            identityRefreshScheduler.clear()
            retryPeerFairness.clear()
            priorityPeerFairness.clear()
            radioAdmissionPolicy.clear()
            lastAutomaticRetryCheckMs = 0L
            gattLink.startServer()
            advertiser.startAdvertising(advertiseSettings, advertiseData, advertiseCallback)
            scanner.startScan(listOf(relayScanFilter, fixedNodeScanFilter), scanSettings, scanCallback)
        } catch (error: SecurityException) {
            stopRadio(emitStopped = false)
            throw DiscoveryException(
                "permission_required",
                "Nearby Devices permission is required for BLE discovery.",
            )
        } catch (error: RelayGattLink.LinkException) {
            stopRadio(emitStopped = false)
            throw DiscoveryException(error.code, error.message)
        } catch (error: RuntimeException) {
            stopRadio(emitStopped = false)
            throw DiscoveryException(
                "radio_start_failed",
                "Nearby discovery could not start yet.",
            )
        }
        recoveryAttempt = 0
        mainHandler.removeCallbacks(recoveryRunnable)
        emit(mapOf("type" to "discovery_started", "token" to token.toHex()))
        return mapOf("token" to token.toHex())
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        desiredActive = false
        recoveryAttempt = 0
        mainHandler.removeCallbacks(recoveryRunnable)
        stopRadio(emitStopped = true)
        safelyStopWifiDirect()
    }

    fun venueTrustStatus(): Map<String, Any> = venueTrustStore.snapshot().toMap()

    fun installVenueInventory(
        encoded: ByteArray,
        allowAuthorityBootstrap: Boolean,
    ): Map<String, Any> = venueTrustStore.install(encoded, allowAuthorityBootstrap).toMap()

    fun resetVenueTrust(confirmation: String): Map<String, Any> = buildMap {
        val reset = venueTrustStore.resetToLab(confirmation)
        put("reset", reset)
        put("status", venueTrustStore.snapshot().toMap())
    }

    private fun HyphaVenueTrustStore.Snapshot.toMap(): Map<String, Any> = buildMap {
        put("mode", mode.name.lowercase())
        put("policyState", policyState.name.lowercase())
        version?.let { put("version", it) }
        venueId?.let { put("venueId", it) }
    }

    private fun HyphaVenueTrustStore.InstallResult.toMap(): Map<String, Any> = buildMap {
        put("installed", installed)
        reason?.let { put("reason", it) }
        put("status", snapshot.toMap())
    }

    fun destroy() {
        if (destroyed) return
        destroyed = true
        stop()
        try {
            activity.unregisterReceiver(bluetoothStateReceiver)
        } catch (_: IllegalArgumentException) {
            // The activity may already have detached the receiver during teardown.
        }
    }

    fun sendEngineeringTransfer(peerToken: String, tamperCiphertext: Boolean = false) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[peerToken]
            ?: throw DiscoveryException("peer_stale", "That nearby phone is no longer in the scan table.")
        try {
            preemptAutomaticIdentityRefresh()
            gattLink.sendEngineeringTransfer(peerToken, device, tamperCiphertext)
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun identifyPeer(peerToken: String) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[peerToken]
            ?: throw DiscoveryException("peer_stale", "That nearby phone is no longer in the scan table.")
        try {
            preemptAutomaticIdentityRefresh()
            gattLink.identifyPeer(peerToken, device)
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun sendTextMessage(
        peerToken: String,
        text: String,
        replyToMessageId: String? = null,
        replyPreview: String? = null,
    ): Map<String, Any> {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[peerToken]
            ?: throw DiscoveryException("peer_stale", "That nearby phone is no longer in the scan table.")
        try {
            if (gattLink.shouldPreemptForDirectText(peerToken)) {
                preemptMeshForDirectText()
                preemptAutomaticIdentityRefresh()
            }
            val queued = gattLink.sendTextMessage(
                peerToken,
                device,
                text,
                replyToMessageId,
                replyPreview,
            )
            if (queued["transport"] == "mesh") onLocalMeshWorkChanged()
            lastAutomaticRetryCheckMs = 0L
            schedulePriorityRadioWork(delayMs = 0L)
            return queued
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun retryTextMessage(peerToken: String, messageId: String) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[peerToken]
            ?: throw DiscoveryException("peer_stale", "That nearby phone is no longer in the scan table.")
        try {
            preemptMeshForDirectText()
            preemptAutomaticIdentityRefresh()
            gattLink.retryTextMessage(peerToken, device, messageId)
            lastAutomaticRetryCheckMs = 0L
            schedulePriorityRadioWork(delayMs = 0L)
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun queueMeshText(
        peerFingerprint: String,
        text: String,
        replyToMessageId: String? = null,
        replyPreview: String? = null,
    ): Map<String, Any> = try {
        gattLink.queueMeshText(peerFingerprint, text, replyToMessageId, replyPreview)
            .also { onLocalMeshWorkChanged() }
    } catch (error: RelayGattLink.LinkException) {
        throw DiscoveryException(error.code, error.message)
    }

    fun queueLastCopyDiagnosticText(peerFingerprint: String, text: String): Map<String, Any> = try {
        gattLink.queueLastCopyDiagnosticText(peerFingerprint, text).also {
            onLocalMeshWorkChanged()
        }
    } catch (error: RelayGattLink.LinkException) {
        throw DiscoveryException(error.code, error.message)
    }

    fun contacts(): List<Map<String, Any>> = gattLink.contacts()

    fun localProfile(): Map<String, Any> = gattLink.localProfile()

    fun updateDisplayName(raw: String): Map<String, Any> = try {
        gattLink.updateDisplayName(raw).also { requestKnownContactRefresh() }
    } catch (error: RelayGattLink.LinkException) {
        throw DiscoveryException(error.code, error.message)
    }

    fun syncMesh(peerToken: String) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[peerToken]
            ?: throw DiscoveryException("peer_stale", "That nearby phone is no longer in range.")
        try {
            preemptAutomaticIdentityRefresh()
            gattLink.syncMesh(peerToken, device)
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    /** Queues authenticated attachment control behind text/receipts/mesh and ahead of bulk Wi-Fi. */
    internal fun offerCourierAttachmentPlan(
        peerToken: String,
        encodedManifest: ByteArray,
        encodedPlan: ByteArray,
    ) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val offer = try {
            RelayAttachmentPlanOffer(
                encodedManifest = encodedManifest.copyOf(),
                encodedPlan = encodedPlan.copyOf(),
            ).also(RelayAttachmentPlanOffer::validate)
        } catch (error: RuntimeException) {
            throw DiscoveryException(
                "invalid_attachment_plan",
                error.message ?: "The courier attachment plan is invalid.",
            )
        }
        val objectId = RelayCourierAttachmentPlan.decode(offer.encodedPlan).objectId.toHex()
        val existing = pendingCourierPlanOffer
        if (existing != null) {
            if (existing.blePeerToken == peerToken && existing.objectIdHex == objectId) {
                emit(
                    mapOf(
                        "type" to "attachment_custody_waiting",
                        "token" to peerToken,
                        "objectId" to objectId,
                        "automatic" to true,
                    ),
                )
                return
            }
            throw DiscoveryException(
                "attachment_control_busy",
                "Another courier attachment plan is already waiting for custody.",
            )
        }
        pendingCourierPlanOffer = PendingCourierPlanOffer(
            blePeerToken = peerToken,
            objectIdHex = objectId,
            encodedManifest = offer.encodedManifest.copyOf(),
            encodedPlan = offer.encodedPlan.copyOf(),
            durable = false,
        )
        emit(
            mapOf(
                "type" to "attachment_custody_waiting",
                "token" to peerToken,
                "objectId" to objectId,
                "automatic" to true,
            ),
        )
        schedulePriorityRadioWork(delayMs = 0L)
    }

    fun storedMessages(): List<Map<String, Any>> = try {
        gattLink.storedMessages()
    } catch (error: RuntimeException) {
        throw DiscoveryException("message_store_failed", "Saved messages could not be opened.")
    }

    fun storedMessagePage(
        peerFingerprint: String,
        beforeCreatedAtMs: Long?,
        beforeMessageIdHex: String?,
        limit: Int,
    ): Map<String, Any> = try {
        gattLink.storedMessagePage(
            peerFingerprint = peerFingerprint,
            beforeCreatedAtMs = beforeCreatedAtMs,
            beforeMessageIdHex = beforeMessageIdHex,
            limit = limit,
        )
    } catch (error: RuntimeException) {
        throw DiscoveryException("message_store_failed", "Saved messages could not be opened.")
    }

    fun conversationSummaries(): List<Map<String, Any>> = try {
        gattLink.conversationSummaries()
    } catch (error: RuntimeException) {
        throw DiscoveryException("message_store_failed", "Conversation previews could not be opened.")
    }

    fun markConversationRead(peerFingerprint: String): Int = try {
        gattLink.markConversationRead(peerFingerprint)
    } catch (error: RuntimeException) {
        throw DiscoveryException("message_store_failed", "The conversation could not be marked read.")
    }

    fun unreadCount(peerFingerprint: String): Int = try {
        gattLink.unreadCount(peerFingerprint)
    } catch (error: RuntimeException) {
        0
    }

    fun startWifiDirect(): Map<String, Any> = try {
        wifiDirect.start()
    } catch (error: RelayWifiDirect.WifiDirectException) {
        throw DiscoveryException(error.code, error.message)
    }

    fun runWifiDirectSpeedTest(peerToken: String) {
        try {
            wifiDirect.runSpeedTest(peerToken)
        } catch (error: RelayWifiDirect.WifiDirectException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun authorizeWifiUpgrade(blePeerToken: String, wifiPeerToken: String) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[blePeerToken]
            ?: throw DiscoveryException("peer_stale", "That BLE peer is no longer nearby.")
        try {
            val wifiToken = wifiDirect.prepareAuthorization(wifiPeerToken)
            gattLink.authorizeWifiUpgrade(blePeerToken, device, wifiToken)
        } catch (error: RelayWifiDirect.WifiDirectException) {
            wifiDirect.cancelAuthorization()
            throw DiscoveryException(error.code, error.message)
        } catch (error: RelayGattLink.LinkException) {
            wifiDirect.cancelAuthorization()
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun sendWifiTextMessage(
        blePeerToken: String,
        wifiPeerToken: String,
        text: String,
    ) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val device = deviceByToken[blePeerToken]
            ?: throw DiscoveryException("peer_stale", "That BLE peer is no longer nearby.")
        try {
            val wifiToken = wifiDirect.prepareTextTransfer(wifiPeerToken, text)
            gattLink.authorizeWifiUpgrade(blePeerToken, device, wifiToken)
        } catch (error: RelayWifiDirect.WifiDirectException) {
            wifiDirect.cancelPreparedTextTransfer()
            throw DiscoveryException(error.code, error.message)
        } catch (error: RelayGattLink.LinkException) {
            wifiDirect.cancelPreparedTextTransfer()
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun sendAttachment(blePeerToken: String, attachmentIdHex: String) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        val request = PendingAttachmentRequest(blePeerToken, attachmentIdHex)
        val pending = pendingAttachmentRequest
        if (pending != null) {
            emit(
                mapOf(
                    "type" to if (pending == request) {
                        "attachment_waiting_for_radio"
                    } else {
                        "attachment_waiting_for_turn"
                    },
                    "attachmentId" to attachmentIdHex,
                    "automatic" to true,
                ),
            )
            return
        }
        pendingAttachmentRequest = request
        emit(
            mapOf(
                "type" to "attachment_waiting_for_radio",
                "attachmentId" to attachmentIdHex,
                "automatic" to true,
            ),
        )
        tryStartPendingAttachment()
    }

    /** Durable courier control only; this never starts Wi-Fi or sends attachment bytes. */
    fun prepareCourierAttachment(attachmentIdHex: String): Map<String, Any> {
        val queued = try {
            gattLink.prepareCourierAttachment(attachmentIdHex)
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
        if (active) schedulePriorityRadioWork(delayMs = 0L)
        return queued
    }

    fun pauseAttachment(attachmentIdHex: String) {
        if (pendingAttachmentRequest?.attachmentIdHex == attachmentIdHex) {
            pendingAttachmentRequest = null
            mainHandler.removeCallbacks(attachmentDispatchRunnable)
        }
        if (pendingCourierPlanOffer?.objectIdHex == attachmentIdHex) {
            pendingCourierPlanOffer = null
        }
        if (pendingCourierChunkRequest?.attachmentIdHex == attachmentIdHex) {
            pendingCourierChunkRequest = null
        }
        gattLink.pauseCourierAttachmentOffer(attachmentIdHex)
        try {
            wifiDirect.pauseAttachment(attachmentIdHex)
        } catch (error: RelayWifiDirect.WifiDirectException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun cancelAttachment(attachmentIdHex: String) {
        if (pendingAttachmentRequest?.attachmentIdHex == attachmentIdHex) {
            pendingAttachmentRequest = null
            mainHandler.removeCallbacks(attachmentDispatchRunnable)
        }
        if (pendingCourierPlanOffer?.objectIdHex == attachmentIdHex) {
            pendingCourierPlanOffer = null
        }
        if (pendingCourierChunkRequest?.attachmentIdHex == attachmentIdHex) {
            pendingCourierChunkRequest = null
        }
        gattLink.removeCourierAttachmentOffer(attachmentIdHex)
        try {
            wifiDirect.cancelAttachment(attachmentIdHex)
        } catch (error: RelayWifiDirect.WifiDirectException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    fun stopWifiDirect() {
        wifiDirect.stop()
    }

    fun markPeerVerified(peerToken: String) {
        if (!active) {
            throw DiscoveryException("discovery_stopped", "Start BLE discovery first.")
        }
        try {
            gattLink.markPeerVerified(peerToken)
        } catch (error: RelayGattLink.LinkException) {
            throw DiscoveryException(error.code, error.message)
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopRadio(emitStopped: Boolean) {
        val wasRunning = active || localToken != null
        active = false
        mainHandler.removeCallbacks(advertiseRefreshRunnable)
        mainHandler.removeCallbacks(attachmentDispatchRunnable)
        pendingCourierCleanup?.cleanup?.cancellationSecret?.fill(0)
        pendingCourierCleanup = null
        pendingCourierPlanOffer = null
        pendingCourierChunkRequest = null
        pendingRecipientAttachmentRequest = null
        pendingAttachmentRequest = null
        val adapter = bluetoothAdapter
        try {
            adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        } catch (_: RuntimeException) {
            // Vendor Bluetooth stacks can reject cleanup while the radio is turning off.
        }
        try {
            adapter?.bluetoothLeScanner?.stopScan(scanCallback)
        } catch (_: RuntimeException) {
            // The scanner may already have been removed by Android.
        }
        try {
            gattLink.stop()
        } catch (_: RuntimeException) {
            // RelayGattLink also clears state defensively; never block radio recovery here.
        }
        try {
            fixedNodeLink.stop()
        } catch (_: RuntimeException) {
            // Fixed-node cleanup must not block discovery recovery.
        }
        localToken = null
        advertisedMeshHint = null
        lastEmissionByToken.clear()
        lastServiceByToken.clear()
        invalidatePendingMeshWork()
        deviceByToken.clear()
        lastSeenByToken.clear()
        remoteMeshHintByToken.clear()
        meshActivityByToken.clear()
        encounterScheduler.clear()
        meshWorkGate.clear()
        identityRefreshScheduler.clear()
        retryPeerFairness.clear()
        priorityPeerFairness.clear()
        radioAdmissionPolicy.clear()
        lastAutomaticRetryCheckMs = 0L
        if (emitStopped && wasRunning) emit(mapOf("type" to "discovery_stopped"))
    }

    private fun suspendForBluetoothOff() {
        mainHandler.removeCallbacks(recoveryRunnable)
        if (!desiredActive && !active) return
        val shouldNotify = active || localToken != null
        stopRadio(emitStopped = false)
        safelyStopWifiDirect()
        if (shouldNotify) {
            emit(
                mapOf(
                    "type" to "discovery_suspended",
                    "code" to "bluetooth_off",
                    "message" to
                        "Bluetooth is off. Relay will reconnect automatically when it is turned on.",
                    "enabled" to false,
                    "automatic" to true,
                ),
            )
        }
    }

    private fun recoverFromRadioFailure(code: String, message: String) {
        mainHandler.post {
            if (destroyed || !desiredActive || !active) return@post
            stopRadio(emitStopped = false)
            emit(
                mapOf(
                    "type" to "radio_recovery_deferred",
                    "code" to code,
                    "message" to message,
                    "automatic" to true,
                ),
            )
            scheduleRecovery()
        }
    }

    private fun scheduleRecovery() {
        if (destroyed || !desiredActive || active || bluetoothAdapter?.isEnabled != true) return
        mainHandler.removeCallbacks(recoveryRunnable)
        val delay = RADIO_RECOVERY_DELAYS_MS[
            recoveryAttempt.coerceAtMost(RADIO_RECOVERY_DELAYS_MS.lastIndex)
        ]
        recoveryAttempt = (recoveryAttempt + 1).coerceAtMost(RADIO_RECOVERY_DELAYS_MS.size)
        mainHandler.postDelayed(recoveryRunnable, delay)
    }

    private fun safelyStopWifiDirect() {
        try {
            wifiDirect.stop()
        } catch (_: RuntimeException) {
            // Wi-Fi teardown must not prevent BLE recovery or activity destruction.
        }
    }

    private fun rememberPeer(token: String, device: BluetoothDevice, nowElapsedMs: Long) {
        deviceByToken.entries
            .filter { (knownToken, knownDevice) -> knownToken != token && knownDevice == device }
            .map { it.key }
            .forEach(::removePeerToken)

        deviceByToken[token] = device
        lastSeenByToken[token] = nowElapsedMs

        pruneStalePeers(nowElapsedMs)
    }

    private fun pruneStalePeers(nowElapsedMs: Long) {
        val cutoff = nowElapsedMs - STALE_NATIVE_PEER_MS
        lastSeenByToken.entries
            .filter { it.value < cutoff }
            .map { it.key }
            .forEach(::removePeerToken)
    }

    private fun removePeerToken(token: String) {
        meshWorkGate.clearPeer(meshSchedulingKey(token))
        meshWorkGate.clearPeer("token:$token")
        meshWorkGate.markAttemptFailed(token)
        deviceByToken.remove(token)
        lastSeenByToken.remove(token)
        lastEmissionByToken.remove(token)
        lastServiceByToken.remove(token)
        remoteMeshHintByToken.remove(token)
        meshActivityByToken.remove(token)
        encounterScheduler.remove(token)
        identityRefreshScheduler.remove(token)
        gattLink.forgetObservedPeer(token)
        retryPeerFairness.forget(token)
        priorityPeerFairness.forget(token)
        if (pendingAttachmentRequest?.blePeerToken == token) {
            pendingAttachmentRequest = null
            wifiDirect.cancelPreparedAttachmentTransfer()
        }
        if (pendingCourierPlanOffer?.blePeerToken == token) {
            pendingCourierPlanOffer = null
        }
        if (pendingCourierCleanup?.blePeerToken == token) {
            pendingCourierCleanup?.cleanup?.cancellationSecret?.fill(0)
            pendingCourierCleanup = null
        }
        if (pendingCourierChunkRequest?.blePeerToken == token) {
            pendingCourierChunkRequest = null
            wifiDirect.cancelPreparedAttachmentTransfer()
        }
        if (pendingRecipientAttachmentRequest?.blePeerToken == token) {
            pendingRecipientAttachmentRequest = null
            wifiDirect.cancelPreparedAttachmentTransfer()
        }
    }

    /** Retries verified peers fairly without ever guessing among multiple unknown phones. */
    private fun maybeRetryQueuedMessage(nowElapsedMs: Long): Boolean {
        if (nowElapsedMs - lastAutomaticRetryCheckMs < AUTO_RETRY_CHECK_MS) return false
        lastAutomaticRetryCheckMs = nowElapsedMs
        val peers = deviceByToken.toMap()
        val plan = RelayTextRetryPolicy.plan(
            visiblePeerTokens = peers.keys,
            hasAuthenticatedIdentity = gattLink::hasObservedIdentity,
        )
        try {
            for (peerToken in retryPeerFairness.ordered(plan.identityDirectedTokens)) {
                val device = peers[peerToken] ?: continue
                if (gattLink.retryOldestEligibleForObservedPeer(peerToken, device) != null) {
                    retryPeerFairness.markServiced(peerToken)
                    return true
                }
            }
            val fallbackToken = plan.singleUnobservedFallback ?: return false
            val fallbackDevice = peers[fallbackToken] ?: return false
            val started = gattLink.retryOldestEligible(fallbackToken, fallbackDevice) != null
            if (started) retryPeerFairness.markServiced(fallbackToken)
            return started
        } catch (error: RelayGattLink.LinkException) {
            emit(
                mapOf(
                    "type" to "outbox_retry_deferred",
                    "code" to error.code,
                    "message" to error.message,
                ),
            )
            return false
        }
    }

    private fun maybeSyncMesh(
        peerToken: String,
        device: BluetoothDevice,
        nowElapsedMs: Long,
    ): Boolean {
        val ownToken = localToken?.toHex() ?: return false
        // Exactly one side initiates, preventing symmetric GATT connection races.
        if (ownToken >= peerToken || !encounterScheduler.canStart(peerToken, nowElapsedMs)) return false
        if (
            !meshWorkGate.canAttempt(
                peerKey = meshSchedulingKey(peerToken),
                peerToken = peerToken,
                localRevision = localMeshRevision,
                remoteHint = remoteMeshHintByToken[peerToken] ?: 0,
            )
        ) {
            return false
        }
        if (gattLink.isBusy()) {
            encounterScheduler.markBusy(peerToken, nowElapsedMs)
            return false
        }
        meshWorkGate.markAttemptStarted(
            peerToken = peerToken,
            localRevision = localMeshRevision,
            remoteHint = remoteMeshHintByToken[peerToken] ?: 0,
        )
        encounterScheduler.markStarted(peerToken, nowElapsedMs)
        meshActivityByToken[peerToken] = false
        Log.i(METRICS_TAG, "sync_attempt")
        try {
            gattLink.syncMesh(peerToken, device)
            return true
        } catch (error: RelayGattLink.LinkException) {
            meshWorkGate.markAttemptFailed(peerToken)
            if (error.code == "link_busy") {
                encounterScheduler.markBusy(peerToken, nowElapsedMs)
            } else {
                encounterScheduler.markFailed(peerToken, nowElapsedMs)
            }
            emit(
                mapOf(
                    "type" to "mesh_sync_deferred",
                    "token" to peerToken,
                    "code" to error.code,
                    "message" to error.message,
                ),
            )
            return false
        }
    }

    private fun onLocalMeshWorkChanged() {
        val update = Runnable {
            if (!active) return@Runnable
            val now = SystemClock.elapsedRealtime()
            invalidatePendingMeshWork()
            fixedNodeLink.onLocalMeshWorkChanged(now)
            advanceMeshWorkEpoch()
            deviceByToken.keys.forEach { encounterScheduler.nudge(it, now) }
            scheduleAdvertisedMeshWorkRefresh()
            schedulePriorityRadioWork()
        }
        if (Looper.myLooper() == Looper.getMainLooper()) update.run() else mainHandler.post(update)
    }

    private fun bridgeCourierManifestsToMesh() {
        try {
            courierAttachmentStore.manifestsForMesh().forEach { encodedManifest ->
                val result = meshStore.ingestEnvelope(encodedManifest)
                check(
                    result is RelayMeshStore.IngestResult.CourierStored ||
                        result is RelayMeshStore.IngestResult.AttachmentManifestStored,
                ) { "Durable courier manifest could not enter RMS2." }
            }
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not restore courier manifests into RMS2", error)
        }
    }

    private fun handleGattEvent(event: Map<String, Any>) {
        val dispatch = Runnable {
            // Any phone-link event may have ingested or acknowledged durable mesh objects.
            invalidatePendingMeshWork()
            lastPhoneLinkEventAtMs = SystemClock.elapsedRealtime()
            val custodyRequest = pendingCourierPlanOffer
            when {
                event["type"] == "attachment_courier_cleanup_confirmed" -> {
                    pendingCourierCleanup?.let { request ->
                        encounterScheduler.markSucceeded(
                            request.blePeerToken,
                            SystemClock.elapsedRealtime(),
                            movedPayload = true,
                        )
                        request.cleanup.cancellationSecret.fill(0)
                    }
                    pendingCourierCleanup = null
                }
                event["type"] == "attachment_plan_custodied" -> {
                    onLocalMeshWorkChanged()
                }
                event["type"] == "attachment_courier_copy_removed" -> {
                    onLocalMeshWorkChanged()
                }
                event["type"] == "attachment_custody_received" -> {
                    if (custodyRequest?.durable == true) {
                        encounterScheduler.markSucceeded(
                            custodyRequest.blePeerToken,
                            SystemClock.elapsedRealtime(),
                            movedPayload = true,
                        )
                    }
                    val missingChunks = (event["missingChunks"] as? List<*>)
                        ?.mapNotNull { (it as? Number)?.toInt() }
                        .orEmpty()
                    val fingerprint = event["fingerprint"] as? String
                    val encodedCustody = event["custody"] as? ByteArray
                    val planSha256 = (event["planSha256"] as? String)
                        ?.let { encoded -> runCatching { encoded.hexToBytes() }.getOrNull() }
                        ?.takeIf { it.size == RelayCourierAttachmentPlan.SHA256_BYTES }
                    pendingCourierChunkRequest = if (
                        custodyRequest != null && fingerprint != null && encodedCustody != null &&
                        planSha256 != null &&
                        missingChunks.isNotEmpty()
                    ) {
                        PendingCourierChunkRequest(
                            blePeerToken = custodyRequest.blePeerToken,
                            attachmentIdHex = custodyRequest.objectIdHex,
                            courierFingerprint = fingerprint,
                            planSha256 = planSha256.copyOf(),
                            encodedCustody = encodedCustody.copyOf(),
                        )
                    } else {
                        null
                    }
                    pendingCourierPlanOffer = null
                }
                event["type"] == "link_error" &&
                    event["purpose"] == "attachment_cleanup" -> {
                    pendingCourierCleanup?.let { request ->
                        encounterScheduler.markFailed(
                            request.blePeerToken,
                            SystemClock.elapsedRealtime(),
                        )
                        request.cleanup.cancellationSecret.fill(0)
                    }
                    pendingCourierCleanup = null
                }
                event["type"] == "link_error" &&
                    event["purpose"] == "attachment_custody" -> {
                    if (custodyRequest?.durable == true) {
                        encounterScheduler.markFailed(
                            custodyRequest.blePeerToken,
                            SystemClock.elapsedRealtime(),
                        )
                    }
                    pendingCourierPlanOffer = null
                }
                event["type"] == "link_error" &&
                    event["purpose"] == "courier_wifi_upgrade" -> {
                    pendingCourierChunkRequest = null
                    wifiDirect.cancelPreparedAttachmentTransfer()
                }
                event["type"] == "link_error" &&
                    event["purpose"] == "recipient_wifi_upgrade" -> {
                    pendingRecipientAttachmentRequest?.let { request ->
                        encounterScheduler.markFailed(
                            request.blePeerToken,
                            SystemClock.elapsedRealtime(),
                        )
                    }
                    pendingRecipientAttachmentRequest = null
                    wifiDirect.cancelPreparedAttachmentTransfer()
                }
            }
            logBackgroundMetric(event)
            updateEncounterSchedule(event)
            updateIdentityRefreshSchedule(event)
            emit(event)
            schedulePriorityRadioWork()
        }
        if (Looper.myLooper() == Looper.getMainLooper()) dispatch.run() else mainHandler.post(dispatch)
    }

    private fun handleWifiEvent(event: Map<String, Any>) {
        val dispatch = Runnable {
            invalidatePendingMeshWork()
            when (event["type"] as? String) {
                "attachment_sending",
                "attachment_delivered",
                "attachment_queued",
                "attachment_paused",
                "attachment_cancelled",
                -> pendingAttachmentRequest = null
                "courier_attachment_custodied" -> pendingCourierChunkRequest = null
                "attachment_received" -> {
                    if (event["transport"] == "courier") {
                        if (event["receiptQueued"] == true) onLocalMeshWorkChanged()
                        pendingRecipientAttachmentRequest?.let { request ->
                            encounterScheduler.markSucceeded(
                                request.blePeerToken,
                                SystemClock.elapsedRealtime(),
                                movedPayload = true,
                            )
                        }
                        pendingRecipientAttachmentRequest = null
                    }
                }
                "wifi_direct_error",
                "wifi_direct_stopped",
                -> {
                    pendingCourierChunkRequest = null
                    pendingRecipientAttachmentRequest = null
                    if (pendingAttachmentRequest != null) {
                        wifiDirect.cancelPreparedAttachmentTransfer()
                        pendingAttachmentRequest = null
                    }
                }
            }
            emit(event)
            schedulePriorityRadioWork()
        }
        if (Looper.myLooper() == Looper.getMainLooper()) dispatch.run() else mainHandler.post(dispatch)
    }

    private fun handleFixedNodeEvent(event: Map<String, Any>) {
        val dispatch = Runnable {
            invalidatePendingMeshWork()
            logBackgroundMetric(event)
            emit(event)
            if (event["type"] == "fixed_node_sync_completed") {
                gattLink.reconcileDurableAttachmentReceipts()
                if (event["meshChanged"] == true) onLocalMeshWorkChanged()
            }
            schedulePriorityRadioWork()
        }
        if (Looper.myLooper() == Looper.getMainLooper()) dispatch.run() else mainHandler.post(dispatch)
    }

    private fun handleWifiUpgradeFailure() {
        wifiDirect.cancelPreparedUpgrade()
        schedulePriorityRadioWork()
    }

    private fun schedulePriorityRadioWork(delayMs: Long = ATTACHMENT_DISPATCH_RETRY_MS) {
        mainHandler.removeCallbacks(attachmentDispatchRunnable)
        mainHandler.postDelayed(attachmentDispatchRunnable, delayMs)
    }

    /**
     * BLE delivery work is always ahead of an attachment.  Wi-Fi Direct may use a
     * separate radio, but its setup must never prevent a text retry, receipt, or
     * courier exchange from being started.
     */
    private fun serviceRadioWork(
        peerToken: String,
        device: BluetoothDevice,
        nowElapsedMs: Long,
    ) {
        if (HyphaFixedNodeSchedulingPolicy.deferPhoneWork(fixedNodeLink.isBusy())) return
        val hasUrgentMeshWork = hasLocalPendingMeshWork(nowElapsedMs) ||
            (remoteMeshHintByToken[peerToken] ?: 0) != 0
        val meshAttemptEligible = hasUrgentMeshWork && meshWorkGate.canAttempt(
            peerKey = meshSchedulingKey(peerToken),
            peerToken = peerToken,
            localRevision = localMeshRevision,
            remoteHint = remoteMeshHintByToken[peerToken] ?: 0,
        )
        if (
            radioAdmissionPolicy.shouldOfferMeshFirst(hasUrgentMeshWork) &&
            meshAttemptEligible &&
            maybeSyncMesh(peerToken, device, nowElapsedMs)
        ) {
            radioAdmissionPolicy.recordMeshAdmission()
            return
        }
        if (maybeRetryQueuedMessage(nowElapsedMs)) {
            radioAdmissionPolicy.recordDirectAdmission()
            return
        }
        if (gattLink.isBusy()) return
        if (hasUrgentMeshWork) {
            if (meshAttemptEligible) {
                if (maybeSyncMesh(peerToken, device, nowElapsedMs)) {
                    radioAdmissionPolicy.recordMeshAdmission()
                }
                return
            }
        }
        // An authenticated empty exchange has already settled this mesh snapshot. Let queued
        // attachment control proceed without discarding a genuine link-failure retry delay.
        encounterScheduler.releaseSuccessfulBackoff(peerToken, nowElapsedMs)
        if (tryStartPendingIdentityRefresh(nowElapsedMs)) return
        if (pendingCourierCleanup != null) {
            tryStartPendingCourierCleanup()
            return
        }
        if (pendingCourierPlanOffer != null) {
            tryStartPendingCourierPlanOffer()
            return
        }
        if (pendingCourierChunkRequest != null) {
            tryStartPendingCourierChunks()
            return
        }
        if (pendingRecipientAttachmentRequest != null) {
            tryStartPendingRecipientAttachment()
            return
        }
        if (stageDurableCourierCleanup(peerToken)) {
            tryStartPendingCourierCleanup()
            return
        }
        if (stageDurableCourierPlanOffer(peerToken)) {
            tryStartPendingCourierPlanOffer()
            return
        }
        if (stagePendingRecipientAttachment(peerToken, nowElapsedMs)) {
            tryStartPendingRecipientAttachment()
            return
        }
        if (pendingAttachmentRequest != null) {
            tryStartPendingAttachment()
        }
    }

    private fun servicePriorityRadioWork() {
        if (
            !active || destroyed || gattLink.isBusy() ||
            HyphaFixedNodeSchedulingPolicy.deferPhoneWork(fixedNodeLink.isBusy())
        ) return
        val now = SystemClock.elapsedRealtime()
        // Walk peers fairly until one admits work, so a peer in backoff cannot hold up a
        // different peer that has queued text or receipts until the next radio event.
        for (token in priorityPeerFairness.ordered(deviceByToken.keys)) {
            val device = deviceByToken[token] ?: continue
            priorityPeerFairness.markServiced(token)
            lastServiceByToken[token] = now
            serviceRadioWork(
                peerToken = token,
                device = device,
                nowElapsedMs = now,
            )
            if (!active || gattLink.isBusy() || fixedNodeLink.isBusy()) return
        }
    }

    private fun tryStartPendingAttachment() {
        val request = pendingAttachmentRequest ?: return
        if (!active || destroyed || gattLink.isBusy() || wifiDirect.isBusy()) return
        val device = deviceByToken[request.blePeerToken] ?: return
        try {
            val responderToken = wifiDirect.prepareAttachmentTransfer(request.attachmentIdHex)
            gattLink.authorizeWifiUpgrade(request.blePeerToken, device, responderToken)
        } catch (error: RelayGattLink.LinkException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            if (error.code == "link_busy") {
                schedulePriorityRadioWork()
            } else {
                pendingAttachmentRequest = null
                emitAttachmentDispatchError(request, error.code, error.message)
            }
        } catch (error: RelayWifiDirect.WifiDirectException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            pendingAttachmentRequest = null
            emitAttachmentDispatchError(request, error.code, error.message)
        }
    }

    private fun tryStartPendingCourierCleanup() {
        val request = pendingCourierCleanup ?: return
        if (!active || destroyed || gattLink.isBusy()) return
        val device = deviceByToken[request.blePeerToken] ?: return
        try {
            gattLink.cleanCourierAttachment(
                request.blePeerToken,
                device,
                request.cleanup,
            )
        } catch (error: RelayGattLink.LinkException) {
            if (error.code == "link_busy") {
                schedulePriorityRadioWork()
            } else {
                encounterScheduler.markFailed(
                    request.blePeerToken,
                    SystemClock.elapsedRealtime(),
                )
                request.cleanup.cancellationSecret.fill(0)
                pendingCourierCleanup = null
                emit(
                    mapOf(
                        "type" to "link_error",
                        "token" to request.blePeerToken,
                        "objectId" to request.cleanup.objectId.toHex(),
                        "purpose" to "attachment_cleanup",
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
            }
        }
    }

    private fun tryStartPendingCourierPlanOffer() {
        val request = pendingCourierPlanOffer ?: return
        if (!active || destroyed || gattLink.isBusy()) return
        val device = deviceByToken[request.blePeerToken] ?: return
        try {
            gattLink.offerCourierAttachmentPlan(
                request.blePeerToken,
                device,
                request.encodedManifest,
                request.encodedPlan,
            )
        } catch (error: RelayGattLink.LinkException) {
            if (error.code == "link_busy") {
                if (request.durable) {
                    encounterScheduler.markBusy(
                        request.blePeerToken,
                        SystemClock.elapsedRealtime(),
                    )
                }
                schedulePriorityRadioWork()
            } else {
                if (request.durable) {
                    encounterScheduler.markFailed(
                        request.blePeerToken,
                        SystemClock.elapsedRealtime(),
                    )
                }
                pendingCourierPlanOffer = null
                emit(
                    mapOf(
                        "type" to "link_error",
                        "token" to request.blePeerToken,
                        "objectId" to request.objectIdHex,
                        "purpose" to "attachment_custody",
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
            }
        }
    }

    private fun tryStartPendingCourierChunks() {
        val request = pendingCourierChunkRequest ?: return
        if (!active || destroyed || gattLink.isBusy() || wifiDirect.isBusy()) return
        val device = deviceByToken[request.blePeerToken] ?: return
        try {
            val responderToken = wifiDirect.prepareCourierAttachmentTransfer(
                attachmentIdHex = request.attachmentIdHex,
                courierFingerprint = request.courierFingerprint,
                encodedCustody = request.encodedCustody,
            )
            gattLink.authorizeCourierWifiUpgrade(
                peerToken = request.blePeerToken,
                device = device,
                responderWifiToken = responderToken,
                objectId = request.attachmentIdHex.hexToBytes(),
                planSha256 = request.planSha256,
                courierFingerprint = request.courierFingerprint,
            )
        } catch (error: RelayGattLink.LinkException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            if (error.code == "link_busy") {
                schedulePriorityRadioWork()
            } else {
                pendingCourierChunkRequest = null
                emit(
                    mapOf(
                        "type" to "link_error",
                        "token" to request.blePeerToken,
                        "objectId" to request.attachmentIdHex,
                        "purpose" to "courier_wifi_upgrade",
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
            }
        } catch (error: RelayWifiDirect.WifiDirectException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            pendingCourierChunkRequest = null
            emit(
                mapOf(
                    "type" to "link_error",
                    "token" to request.blePeerToken,
                    "objectId" to request.attachmentIdHex,
                    "purpose" to "courier_wifi_upgrade",
                    "code" to error.code,
                    "message" to error.message,
                    "automatic" to true,
                ),
            )
        }
    }

    private fun stagePendingRecipientAttachment(
        peerToken: String,
        nowElapsedMs: Long,
    ): Boolean {
        if (!encounterScheduler.canStart(peerToken, nowElapsedMs)) return false
        val pending = try {
            meshStore.pendingRecipientAttachments().firstOrNull { candidate ->
                val stored = attachmentStore.findByHexId(candidate.manifest.objectId.toHex())
                stored?.direction != RelayAttachmentStore.Direction.INCOMING ||
                    stored.status != RelayAttachmentStore.Status.READY
            }
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not inspect pending recipient attachments", error)
            null
        } ?: return false
        pendingRecipientAttachmentRequest = PendingRecipientAttachmentRequest(
            blePeerToken = peerToken,
            pending = pending,
        )
        return true
    }

    private fun tryStartPendingRecipientAttachment() {
        val request = pendingRecipientAttachmentRequest ?: return
        if (!active || destroyed || gattLink.isBusy() || wifiDirect.isBusy()) return
        val device = deviceByToken[request.blePeerToken] ?: return
        try {
            Log.i(TAG, "Starting recipient courier attachment pull")
            val responderToken = wifiDirect.prepareRecipientAttachmentTransfer(request.pending)
            gattLink.authorizeRecipientWifiUpgrade(
                peerToken = request.blePeerToken,
                device = device,
                responderWifiToken = responderToken,
                objectId = request.pending.manifest.objectId,
                planSha256 = request.pending.manifest.courierPlanSha256,
            )
        } catch (error: RelayGattLink.LinkException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            if (error.code == "link_busy") {
                schedulePriorityRadioWork()
            } else {
                encounterScheduler.markFailed(
                    request.blePeerToken,
                    SystemClock.elapsedRealtime(),
                )
                pendingRecipientAttachmentRequest = null
                emit(
                    mapOf(
                        "type" to "link_error",
                        "token" to request.blePeerToken,
                        "objectId" to request.pending.manifest.objectId.toHex(),
                        "purpose" to "recipient_wifi_upgrade",
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
            }
        } catch (error: RelayWifiDirect.WifiDirectException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            if (error.code != "recipient_attachment_complete") {
                encounterScheduler.markFailed(
                    request.blePeerToken,
                    SystemClock.elapsedRealtime(),
                )
            }
            pendingRecipientAttachmentRequest = null
            if (error.code != "recipient_attachment_complete") {
                emit(
                    mapOf(
                        "type" to "link_error",
                        "token" to request.blePeerToken,
                        "objectId" to request.pending.manifest.objectId.toHex(),
                        "purpose" to "recipient_wifi_upgrade",
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
            }
        } catch (error: RuntimeException) {
            wifiDirect.cancelPreparedAttachmentTransfer()
            pendingRecipientAttachmentRequest = null
            encounterScheduler.markFailed(
                request.blePeerToken,
                SystemClock.elapsedRealtime(),
            )
            Log.w(TAG, "Could not stage recipient courier attachment", error)
        }
    }

    private fun stageDurableCourierPlanOffer(peerToken: String): Boolean {
        val nowElapsedMs = SystemClock.elapsedRealtime()
        if (!encounterScheduler.canStart(peerToken, nowElapsedMs)) return false
        val offer = try {
            gattLink.nextCourierAttachmentOffer(peerToken)
        } catch (error: RuntimeException) {
            emit(
                mapOf(
                    "type" to "link_error",
                    "token" to peerToken,
                    "purpose" to "attachment_custody",
                    "code" to "attachment_offer_store_failed",
                    "message" to "Saved courier attachment control could not be opened.",
                    "automatic" to true,
                ),
            )
            return false
        } ?: return false
        val objectIdHex = offer.objectId.toHex()
        pendingCourierPlanOffer = PendingCourierPlanOffer(
            blePeerToken = peerToken,
            objectIdHex = objectIdHex,
            encodedManifest = offer.encodedManifest.copyOf(),
            encodedPlan = offer.encodedPlan.copyOf(),
            durable = true,
        )
        encounterScheduler.markStarted(peerToken, nowElapsedMs)
        emit(
            mapOf(
                "type" to "attachment_custody_waiting",
                "token" to peerToken,
                "objectId" to objectIdHex,
                "automatic" to true,
            ),
        )
        return true
    }

    private fun stageDurableCourierCleanup(peerToken: String): Boolean {
        val nowElapsedMs = SystemClock.elapsedRealtime()
        if (!encounterScheduler.canStart(peerToken, nowElapsedMs)) return false
        val cleanup = try {
            gattLink.nextCourierAttachmentCleanup(peerToken)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not open saved courier cleanup state", error)
            null
        } ?: return false
        pendingCourierCleanup = PendingCourierCleanup(peerToken, cleanup)
        encounterScheduler.markStarted(peerToken, nowElapsedMs)
        emit(
            mapOf(
                "type" to "attachment_cleanup_waiting",
                "token" to peerToken,
                "objectId" to cleanup.objectId.toHex(),
                "automatic" to true,
            ),
        )
        return true
    }

    private fun emitAttachmentDispatchError(
        request: PendingAttachmentRequest,
        code: String,
        message: String,
    ) {
        emit(
            mapOf(
                "type" to "attachment_dispatch_error",
                "token" to request.blePeerToken,
                "attachmentId" to request.attachmentIdHex,
                "code" to code,
                "message" to message,
            ),
        )
    }

    private fun logBackgroundMetric(event: Map<String, Any>) {
        val type = event["type"] as? String ?: return
        val bytes = (event["bytes"] as? Number)?.toLong()
        when {
            type in MESH_OUTBOUND_BYTE_EVENTS && bytes != null ->
                Log.i(METRICS_TAG, "ble_payload direction=sent phase=$type bytes=$bytes")
            type in MESH_INBOUND_BYTE_EVENTS && bytes != null ->
                Log.i(METRICS_TAG, "ble_payload direction=received phase=$type bytes=$bytes")
        }
        (event["wireBytesSent"] as? Number)?.toLong()?.let {
            Log.i(METRICS_TAG, "ble_payload direction=sent phase=$type bytes=$it")
        }
        (event["wireBytesReceived"] as? Number)?.toLong()?.let {
            Log.i(METRICS_TAG, "ble_payload direction=received phase=$type bytes=$it")
        }
        if (type == "mesh_sync_completed") {
            Log.i(
                METRICS_TAG,
                "sync_complete productive=${meshEventMovedPayload(event)} " +
                    MESH_ACTIVITY_COUNT_KEYS.joinToString(separator = " ") { key ->
                        "$key=${(event[key] as? Number)?.toInt() ?: 0}"
                    },
            )
        } else if (type == "link_error" && event["purpose"] == "mesh") {
            Log.i(METRICS_TAG, "sync_failure code=${event["code"] as? String ?: "unknown"}")
        }
    }

    private fun updateEncounterSchedule(event: Map<String, Any>) {
        val type = event["type"] as? String ?: return
        val token = event["token"] as? String
        if (type in MESH_ACTIVITY_EVENTS && token != null) {
            if (meshEventMovedPayload(event)) {
                meshActivityByToken[token] = true
                meshWorkGate.clearPeer(meshSchedulingKey(token))
            }
            scheduleAdvertisedMeshWorkRefresh()
        }
        when {
            type == "mesh_sync_completed" && token != null -> {
                val movedPayload = meshActivityByToken.remove(token) == true ||
                    meshEventMovedPayload(event)
                val nowElapsedMs = SystemClock.elapsedRealtime()
                encounterScheduler.markSucceeded(token, nowElapsedMs, movedPayload)
                if (movedPayload) {
                    meshWorkGate.markAttemptFinished(meshSchedulingKey(token), token)
                    advanceMeshWorkEpoch()
                } else {
                    val unchangedAttempt = meshWorkGate.markEmptyIfAttemptUnchanged(
                        peerKey = meshSchedulingKey(token),
                        peerToken = token,
                        localRevision = localMeshRevision,
                        remoteHint = remoteMeshHintByToken[token] ?: 0,
                    )
                    if (!unchangedAttempt) {
                        encounterScheduler.nudge(token, nowElapsedMs)
                    }
                }
            }
            type == "link_error" &&
                event["purpose"] == "mesh" &&
                token != null -> {
                meshActivityByToken.remove(token)
                meshWorkGate.markAttemptFailed(token)
                encounterScheduler.markFailed(token, SystemClock.elapsedRealtime())
            }
        }
    }

    private fun observeVerifiedContactRefresh(peerToken: String, nowElapsedMs: Long) {
        val ownToken = localToken?.toHex() ?: return
        // Exactly one side initiates passive recognition, avoiding symmetric
        // connection races. A local profile change is forced separately.
        if (ownToken >= peerToken) return
        val hasVerifiedContacts = try {
            gattLink.hasVerifiedContacts()
        } catch (_: RuntimeException) {
            false
        }
        if (hasVerifiedContacts) identityRefreshScheduler.observe(peerToken, nowElapsedMs)
    }

    private fun requestKnownContactRefresh() {
        val update = Runnable {
            if (!active || destroyed) return@Runnable
            val now = SystemClock.elapsedRealtime()
            deviceByToken.keys
                .filter(gattLink::isObservedPeerVerified)
                .forEach { identityRefreshScheduler.force(it, now) }
            schedulePriorityRadioWork(delayMs = 0L)
        }
        if (Looper.myLooper() == Looper.getMainLooper()) update.run() else mainHandler.post(update)
    }

    private fun tryStartPendingIdentityRefresh(nowElapsedMs: Long): Boolean {
        if (!active || destroyed || gattLink.isBusy()) return false
        while (true) {
            val peerToken = identityRefreshScheduler.nextEligibleToken(nowElapsedMs) ?: return false
            val device = deviceByToken[peerToken]
            if (device == null) {
                identityRefreshScheduler.remove(peerToken)
                continue
            }
            identityRefreshScheduler.markStarted(peerToken)
            return try {
                gattLink.identifyPeer(peerToken, device, automatic = true)
                Log.i(
                    METRICS_TAG,
                    "identity_refresh_started forced=${identityRefreshScheduler.isForced(peerToken)}",
                )
                true
            } catch (error: RelayGattLink.LinkException) {
                identityRefreshScheduler.markFailed(peerToken, nowElapsedMs)
                emit(
                    mapOf(
                        "type" to "identity_refresh_deferred",
                        "token" to peerToken,
                        "code" to error.code,
                        "message" to error.message,
                        "automatic" to true,
                    ),
                )
                false
            }
        }
    }

    private fun updateIdentityRefreshSchedule(event: Map<String, Any>) {
        val token = event["token"] as? String ?: return
        if (!identityRefreshScheduler.isInFlight(token)) return
        when (event["type"] as? String) {
            "peer_identity_ready",
            "identity_refresh_skipped",
            -> identityRefreshScheduler.markSucceeded(token)
            "link_error" -> if (event["purpose"] == "identity_refresh") {
                identityRefreshScheduler.markFailed(token, SystemClock.elapsedRealtime())
            }
        }
    }

    private fun preemptAutomaticIdentityRefresh() {
        val token = gattLink.cancelAutomaticIdentityRefresh() ?: return
        identityRefreshScheduler.markPreempted(token, SystemClock.elapsedRealtime())
        schedulePriorityRadioWork()
    }

    private fun preemptMeshForDirectText() {
        val token = gattLink.cancelMeshSyncForDirectText() ?: return
        meshActivityByToken.remove(token)
        meshWorkGate.markAttemptFailed(token)
        encounterScheduler.markBusy(token, SystemClock.elapsedRealtime())
    }

    private fun meshSchedulingKey(peerToken: String): String =
        gattLink.observedPeerFingerprint(peerToken)?.let { "identity:$it" } ?: "token:$peerToken"

    private fun meshEventMovedPayload(event: Map<String, Any>): Boolean =
        MESH_MOVEMENT_COUNT_KEYS.any { key -> ((event[key] as? Number)?.toInt() ?: 0) > 0 }

    private fun scheduleAdvertisedMeshWorkRefresh() {
        if (!active) return
        mainHandler.removeCallbacks(advertiseRefreshRunnable)
        mainHandler.postDelayed(advertiseRefreshRunnable, ADVERTISE_HINT_REFRESH_MS)
    }

    @SuppressLint("MissingPermission")
    private fun refreshAdvertisedMeshWork() {
        if (!active) return
        val token = localToken ?: return
        val nextHint = pendingMeshHintOrPrevious(defaultValue = 0)
        if (nextHint == advertisedMeshHint) return
        val advertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return
        try {
            advertiser.stopAdvertising(advertiseCallback)
            advertisedMeshHint = nextHint
            advertiser.startAdvertising(
                buildAdvertiseSettings(),
                buildAdvertiseData(token, nextHint),
                advertiseCallback,
            )
            emit(
                mapOf(
                    "type" to "mesh_work_hint_changed",
                    "hasWork" to (nextHint != 0),
                    "epoch" to nextHint,
                ),
            )
        } catch (_: SecurityException) {
            recoverFromRadioFailure(
                code = "permission_required",
                message = "Nearby Devices permission is required for BLE discovery.",
            )
        } catch (_: RuntimeException) {
            recoverFromRadioFailure(
                code = "advertise_refresh_failed",
                message = "Relay is refreshing nearby discovery automatically.",
            )
        }
    }

    private fun advanceMeshWorkEpoch() {
        localMeshRevision = if (localMeshRevision == Long.MAX_VALUE) 1L else localMeshRevision + 1L
        meshWorkEpoch = if (meshWorkEpoch >= 0xFF) 1 else meshWorkEpoch + 1
    }

    private fun pendingMeshHintOrPrevious(defaultValue: Int): Int = try {
        // The advertised hint must reflect durable truth, so it always takes a fresh reading.
        invalidatePendingMeshWork()
        if (hasLocalPendingMeshWork(SystemClock.elapsedRealtime())) meshWorkEpoch else 0
    } catch (_: RuntimeException) {
        advertisedMeshHint ?: defaultValue
    }

    private fun hasLocalPendingMeshWork(nowElapsedMs: Long): Boolean {
        val cached = pendingMeshWorkCache
        if (cached != null && nowElapsedMs - pendingMeshWorkCheckedAtMs < PENDING_MESH_WORK_CACHE_MS) {
            return cached
        }
        val fresh = gattLink.hasPendingMeshWork()
        pendingMeshWorkCache = fresh
        pendingMeshWorkCheckedAtMs = nowElapsedMs
        return fresh
    }

    private fun invalidatePendingMeshWork() {
        pendingMeshWorkCache = null
    }

    private fun buildAdvertiseSettings(): AdvertiseSettings = AdvertiseSettings.Builder()
        .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
        .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
        .setConnectable(true)
        .setTimeout(0)
        .build()

    private fun buildAdvertiseData(token: ByteArray, meshHint: Int): AdvertiseData =
        AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addManufacturerData(EXPERIMENTAL_MANUFACTURER_ID, PREFIX + token)
            .addServiceData(
                MESH_WORK_SERVICE_UUID,
                byteArrayOf(meshHint.toByte()),
            )
            .build()

    private fun isRelayFrame(payload: ByteArray): Boolean =
        payload.size == FRAME_LENGTH && payload.copyOfRange(0, PREFIX.size).contentEquals(PREFIX)

    private fun isFixedNodeFrame(payload: ByteArray): Boolean =
        payload.size == FIXED_NODE_FRAME_LENGTH &&
            payload.copyOfRange(0, FIXED_NODE_PREFIX.size).contentEquals(FIXED_NODE_PREFIX)

    private fun primaryPhy(result: ScanResult): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return "unknown"
        return when (result.primaryPhy) {
            BluetoothDevice.PHY_LE_1M -> "1M"
            BluetoothDevice.PHY_LE_2M -> "2M"
            BluetoothDevice.PHY_LE_CODED -> "coded"
            else -> "unknown"
        }
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0 && isNotEmpty()) { "Hex value is invalid." }
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun emit(event: Map<String, Any>) {
        // Bluetooth callbacks are delivered on Binder threads on many phones.
        // Flutter platform messages must always be sent from Android's main
        // thread; posting also lets the Bluetooth callback continue immediately.
        mainHandler.post {
            backgroundEventObserver?.invoke(event)
            eventSink?.success(event)
        }
    }

    class DiscoveryException(
        val code: String,
        override val message: String,
    ) : IllegalStateException(message)

    private data class PendingAttachmentRequest(
        val blePeerToken: String,
        val attachmentIdHex: String,
    )

    private data class PendingCourierPlanOffer(
        val blePeerToken: String,
        val objectIdHex: String,
        val encodedManifest: ByteArray,
        val encodedPlan: ByteArray,
        val durable: Boolean,
    )

    private data class PendingCourierCleanup(
        val blePeerToken: String,
        val cleanup: RelayCourierAttachmentCleanup,
    )

    private data class PendingCourierChunkRequest(
        val blePeerToken: String,
        val attachmentIdHex: String,
        val courierFingerprint: String,
        val planSha256: ByteArray,
        val encodedCustody: ByteArray,
    )

    private data class PendingRecipientAttachmentRequest(
        val blePeerToken: String,
        val pending: RelayMeshStore.PendingRecipientAttachment,
    )

    private companion object {
        const val TAG = "RelayBleDiscovery"
        // 0xFFFF is reserved for development/testing and must change before release.
        const val EXPERIMENTAL_MANUFACTURER_ID = 0xFFFF
        const val TOKEN_LENGTH = 8
        const val FRAME_LENGTH = 11
        const val FIXED_NODE_FRAME_LENGTH = 11
        const val EMIT_INTERVAL_MS = 2_000L
        const val AUTO_RETRY_CHECK_MS = 1_000L
        const val STALE_NATIVE_PEER_MS = 12_000L
        const val ADVERTISE_HINT_REFRESH_MS = 250L
        const val ATTACHMENT_DISPATCH_RETRY_MS = 350L
        const val SCAN_SERVICE_INTERVAL_MS = 400L
        const val PENDING_MESH_WORK_CACHE_MS = 1_000L
        const val FIXED_NODE_SHARE_QUIET_MS = 2_000L
        val MESH_ACTIVITY_EVENTS = setOf(
            "mesh_sync_response_ready",
            "mesh_sync_progress",
            "mesh_sync_completed",
            "mesh_sync_finalized",
        )
        val MESH_ACTIVITY_COUNT_KEYS = setOf(
            "accepted",
            "offered",
            "probed",
            "requestedProbes",
            "recognizedProbes",
            "sent",
            "received",
            "forwarded",
            "delivered",
            "finalDelivered",
            "receiptsApplied",
            "attachmentReceiptsApplied",
        )
        // Offers and probes alone do not move durable payload. Counting them as productive caused
        // 750 ms follow-up loops between nearby phones whose state had not changed.
        val MESH_MOVEMENT_COUNT_KEYS = setOf(
            "accepted",
            "requestedProbes",
            "sent",
            "received",
            "forwarded",
            "delivered",
            "finalDelivered",
            "receiptsApplied",
            "attachmentReceiptsApplied",
        )
        val MESH_OUTBOUND_BYTE_EVENTS = setOf(
            "mesh_sync_sending",
            "mesh_ack_sending",
            "mesh_final_ack_sending",
        )
        val MESH_INBOUND_BYTE_EVENTS = setOf(
            "mesh_sync_receiving",
            "mesh_ack_receiving",
            "mesh_final_ack_receiving",
        )
        const val METRICS_TAG = "RelayMetrics"
        val RADIO_RECOVERY_DELAYS_MS = longArrayOf(250L, 750L, 1_500L, 3_000L, 5_000L)
        val NON_RECOVERABLE_START_ERRORS = setOf(
            "permission_required",
            "bluetooth_unavailable",
            "advertising_unsupported",
            "secure_core_unavailable",
            "device_identity_unavailable",
            "discovery_destroyed",
        )
        val PREFIX = byteArrayOf(0x52, 0x4C, 0x01)
        val FIXED_NODE_PREFIX = byteArrayOf(0x48, 0x4E, 0x01)
        val MESH_WORK_SERVICE_UUID: ParcelUuid = ParcelUuid.fromString(
            "0000fde2-0000-1000-8000-00805f9b34fb",
        )
    }
}
