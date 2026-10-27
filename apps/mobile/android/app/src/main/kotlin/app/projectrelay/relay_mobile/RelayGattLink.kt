package app.projectrelay.relay_mobile

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.zip.CRC32

/** Foreground direct link for authenticated engineering probes and verified-peer text. */
internal class RelayGattLink(
    private val activity: Context,
    private val emit: (Map<String, Any>) -> Unit,
    private val localToken: () -> ByteArray?,
    private val localWifiToken: () -> ByteArray?,
    private val onWifiUpgradeAuthorized: (RelayWifiUpgradeAuthorization) -> Unit,
    private val onWifiUpgradeFailed: () -> Unit,
    private val meshStore: RelayMeshStore = RelayMeshStore(activity),
    private val courierAttachmentStore: RelayCourierAttachmentStore =
        RelayCourierAttachmentStore(activity),
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val random = SecureRandom()
    private val serverStateLock = Any()
    private val observedIdentityLock = Any()
    private val trustStore = RelayPeerTrustStore(activity)
    private val messageStore = RelayMessageStore(activity)
    private val attachmentStore = RelayAttachmentStore(activity)
    private val inboundTransfers = mutableMapOf<BluetoothDevice, IncomingTransfer>()
    private val serverMtuByDevice = mutableMapOf<BluetoothDevice, Int>()
    private val serverSecureStates = mutableMapOf<BluetoothDevice, ServerSecureState>()
    private val pendingServerResponses = mutableMapOf<BluetoothDevice, ServerResponse>()
    private val pendingServerMeshOffers =
        mutableMapOf<BluetoothDevice, List<RelayMeshStore.ForwardOffer>>()
    private val pendingServerMeshProbeOffers =
        mutableMapOf<BluetoothDevice, List<RelayMeshStore.RouteProbeOffer>>()
    private val pendingServerRequestedProbeIds =
        mutableMapOf<BluetoothDevice, List<ByteArray>>()
    private val observedIdentityByToken = mutableMapOf<String, ObservedIdentity>()
    private var server: BluetoothGattServer? = null
    private var secureIdentity: NativeRelayIdentity? = null
    private var deviceIdentity: RelayDeviceIdentity? = null
    private var client: BluetoothGatt? = null
    private var activeWriteCharacteristic: BluetoothGattCharacteristic? = null
    private var clientSecureSession: NativeRelaySession? = null
    private var clientRemoteIdentityPublicKey: ByteArray? = null
    private var clientPhase = ClientPhase.IDLE
    private var responseAccumulator: ResponseAccumulator? = null
    private var activePeerToken: String? = null
    private var linkStartedAtMs = 0L
    private var negotiatedMtu = DEFAULT_MTU
    private var outboundTransfer: OutgoingTransfer? = null
    private var pendingWrite: PendingWrite? = null
    private var expectedPlaintextBytes = 0
    private var expectedPlaintextCrc32 = 0L
    private var tamperCiphertextForTest = false
    private var linkPurpose = LinkPurpose.ENGINEERING
    private var identityRefreshAutomatic = false
    private var pendingTextMessage: RelayMessageCodec.TextMessage? = null
    private var pendingPeerFingerprint: String? = null
    private var pendingTextAttemptStarted = false
    private var pendingTextDelivered = false
    private var pendingTextFailureCode: String? = null
    private var pendingTextAutomaticRetry = false
    private var pendingTextTraceStartedAtMs = 0L
    private var pendingTextTraceQueuedAtMs = 0L
    private var pendingWifiUpgradeOffer: RelayMessageCodec.WifiUpgradeOffer? = null
    private var pendingCourierWifiUpgrade: PendingCourierWifiUpgrade? = null
    private var pendingRecipientWifiUpgrade: PendingRecipientWifiUpgrade? = null
    private var wifiUpgradeAuthorized = false
    private var pendingMeshOffers: List<RelayMeshStore.ForwardOffer> = emptyList()
    private var pendingMeshProbeOffers: List<RelayMeshStore.RouteProbeOffer> = emptyList()
    private var pendingMeshRequestedPeerProbeIds: List<ByteArray> = emptyList()
    private var pendingMeshSent = 0
    private var pendingMeshReceived = 0
    private var pendingAttachmentPlanOffer: RelayAttachmentPlanOffer? = null
    private var pendingAttachmentCleanup: PendingAttachmentCleanup? = null
    private var activePeerFingerprint: String? = null
    private val warmTextBudget = RelayWarmTextBudget()

    private val warmSessionTimeout = Runnable {
        val warmClient = client ?: return@Runnable
        if (linkPurpose != LinkPurpose.WARM_TEXT || clientPhase != ClientPhase.IDLE) return@Runnable
        Log.i(TAG, "Closing idle warm text session for ${activePeerToken ?: "unknown"}")
        closeClient(warmClient, disconnect = true)
    }

    private val operationTimeout = Runnable {
        val timedOutClient = client ?: return@Runnable
        val transferring = clientPhase != ClientPhase.IDLE
        Log.w(TAG, "Direct-link operation timed out; transferring=$transferring")
        emit(
            linkError(
                if (transferring) "transfer_timeout" else "gatt_timeout",
                if (transferring) {
                    "The encrypted test did not finish within 60 seconds."
                } else {
                    "The nearby phone did not connect within 12 seconds."
                },
            ),
        )
        closeClient(timedOutClient, disconnect = true)
    }

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            Log.i(TAG, "GATT service added with status=$status")
            emit(
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    mapOf("type" to "gatt_server_ready")
                } else {
                    linkError("gatt_service_failed", "GATT service setup failed ($status).")
                },
            )
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            Log.i(TAG, "Server connection changed; status=$status state=$newState")
            synchronized(serverStateLock) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    // Some Android Bluetooth stacks deliver a new connection before the
                    // disconnect callback for the previous connection from the same device.
                    // A Noise session belongs to exactly one GATT connection, so never let
                    // an old responder state leak into the fresh connection.
                    resetServerPeerState(device)
                    serverMtuByDevice[device] = DEFAULT_MTU
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    resetServerPeerState(device)
                    serverMtuByDevice.remove(device)
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            synchronized(serverStateLock) {
                serverMtuByDevice[device] = mtu.coerceAtLeast(DEFAULT_MTU)
            }
            Log.i(TAG, "Server MTU changed; mtu=$mtu")
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val result = if (
                characteristic.uuid == TRANSFER_CHARACTERISTIC_UUID &&
                !preparedWrite &&
                offset == 0
            ) {
                synchronized(serverStateLock) { handleInboundFrame(device, value) }
            } else {
                ServerWriteResult(BluetoothGatt.GATT_FAILURE)
            }
            if (responseNeeded) {
                sendServerResponse(device, requestId, result.status, null)
            }
            result.event?.let(emit)
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic,
        ) {
            if (characteristic.uuid != TRANSFER_CHARACTERISTIC_UUID || offset != 0) {
                Log.w(
                    TAG,
                    "Rejecting GATT server read; expected Relay characteristic at offset 0, " +
                        "received offset=$offset",
                )
                sendServerResponse(device, requestId, BluetoothGatt.GATT_FAILURE, null)
                return
            }
            synchronized(serverStateLock) {
                val response = pendingServerResponses[device]
                if (response == null) {
                    Log.w(TAG, "Rejecting GATT server read because no secure response is pending")
                    sendServerResponse(device, requestId, BluetoothGatt.GATT_FAILURE, null)
                    return@synchronized
                }
                val mtu = serverMtuByDevice[device] ?: DEFAULT_MTU
                val chunk = buildResponseChunk(response, mtu)
                val sent = sendServerResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    chunk.frame,
                )
                if (!sent) return@synchronized
                response.offset += chunk.payloadBytes
                response.nextSequence += 1
                if (response.offset == response.payload.size) {
                    pendingServerResponses.remove(device)
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private val clientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            Log.i(TAG, "Client state changed; status=$status state=$newState")
            if (client !== gatt) {
                safeCloseGatt(gatt)
                return
            }
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emit(linkError("gatt_connection_failed", "BLE connection failed ($status)."))
                closeClient(gatt)
                return
            }
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    emit(mapOf("type" to "link_connected", "token" to requirePeerToken()))
                    scheduleTimeout(TRANSFER_TIMEOUT_MS)
                    try {
                        gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                    } catch (error: RuntimeException) {
                        Log.w(TAG, "Bluetooth stack rejected high connection priority", error)
                    }
                    val mtuRequested = try {
                        gatt.requestMtu(PREFERRED_MTU)
                    } catch (error: RuntimeException) {
                        Log.w(TAG, "Bluetooth stack rejected MTU negotiation", error)
                        false
                    }
                    if (!mtuRequested) {
                        negotiatedMtu = DEFAULT_MTU
                        discoverRelayService(gatt)
                    }
                }
                BluetoothProfile.STATE_DISCONNECTED -> closeClient(gatt)
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            negotiatedMtu = if (status == BluetoothGatt.GATT_SUCCESS) {
                mtu.coerceAtLeast(DEFAULT_MTU)
            } else {
                DEFAULT_MTU
            }
            Log.i(TAG, "MTU negotiation completed; status=$status mtu=$negotiatedMtu")
            emit(
                mapOf(
                    "type" to "mtu_negotiated",
                    "token" to requirePeerToken(),
                    "mtu" to negotiatedMtu,
                ),
            )
            discoverRelayService(gatt)
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            Log.i(TAG, "Services discovered with status=$status")
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emit(linkError("service_discovery_failed", "Relay service discovery failed ($status)."))
                closeClient(gatt)
                return
            }
            val characteristic = gatt.getService(SERVICE_UUID)
                ?.getCharacteristic(TRANSFER_CHARACTERISTIC_UUID)
            if (characteristic == null) {
                emit(linkError("service_missing", "The nearby phone did not expose Relay's test service."))
                closeClient(gatt)
                return
            }
            activeWriteCharacteristic = characteristic
            startSecureHandshake(gatt, characteristic)
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (characteristic.uuid != TRANSFER_CHARACTERISTIC_UUID) return
            val transfer = outboundTransfer
            val completedWrite = pendingWrite
            pendingWrite = null
            if (
                status == GATT_RELAY_AUTH_REJECTED && tamperCiphertextForTest &&
                clientPhase == ClientPhase.CIPHERTEXT
            ) {
                emit(
                    mapOf(
                        "type" to "tamper_rejection_confirmed",
                        "token" to requirePeerToken(),
                    ),
                )
                closeClient(gatt, disconnect = true)
                return
            }
            if (
                status == GATT_RELAY_UNVERIFIED &&
                (clientPhase == ClientPhase.USER_MESSAGE || clientPhase == ClientPhase.WIFI_UPGRADE)
            ) {
                emit(
                    linkError(
                        "peer_not_verified_by_recipient",
                        "The other phone has not verified this safety fingerprint yet.",
                    ),
                )
                closeClient(gatt, disconnect = true)
                return
            }
            if (clientPhase == ClientPhase.ATTACHMENT_PLAN) {
                val decline = when (status) {
                    GATT_RELAY_COURIER_STORE_FULL ->
                        "courier_store_full" to "The courier has no safe attachment capacity."
                    GATT_RELAY_ATTACHMENT_EXPIRED ->
                        "attachment_expired" to "The attachment plan expired before custody."
                    GATT_RELAY_ATTACHMENT_TERMINAL ->
                        "attachment_terminal" to "The courier has terminal state for this object."
                    GATT_RELAY_AUTH_REJECTED ->
                        "attachment_custody_rejected" to
                            "The courier rejected a conflicting or invalid attachment plan."
                    else -> null
                }
                if (decline != null) {
                    emit(linkError(decline.first, decline.second))
                    closeClient(gatt, disconnect = true)
                    return
                }
            }
            if (status != BluetoothGatt.GATT_SUCCESS || transfer == null || completedWrite == null) {
                emit(linkError("transfer_write_failed", "A BLE transfer fragment failed ($status)."))
                closeClient(gatt)
                return
            }
            when (completedWrite) {
                PendingWrite.START -> {
                    emit(
                        mapOf(
                            "type" to when (transfer.kind) {
                                TransferKind.HANDSHAKE -> "secure_handshake_sending"
                                TransferKind.IDENTITY_PROOF -> "identity_proof_sending"
                                TransferKind.CIPHERTEXT -> "encrypted_transfer_sending"
                                TransferKind.USER_MESSAGE -> "text_message_sending"
                                TransferKind.WIFI_UPGRADE -> "wifi_upgrade_offer_sending"
                                TransferKind.COURIER_WIFI_UPGRADE -> "courier_wifi_upgrade_sending"
                                TransferKind.RECIPIENT_WIFI_UPGRADE -> "recipient_wifi_upgrade_sending"
                                TransferKind.CONTACT_CARD -> "contact_card_sending"
                                TransferKind.MESH_REQUEST -> "mesh_sync_sending"
                                TransferKind.MESH_ACK -> "mesh_ack_sending"
                                TransferKind.MESH_FINAL_ACK -> "mesh_final_ack_sending"
                                TransferKind.ATTACHMENT_PLAN -> "attachment_plan_sending"
                                TransferKind.ATTACHMENT_CLEANUP -> "attachment_cleanup_sending"
                            },
                            "token" to requirePeerToken(),
                            "bytes" to transfer.payload.size,
                            "mtu" to negotiatedMtu,
                        ),
                    )
                    sendNextDataFrame(gatt, characteristic, transfer)
                }
                PendingWrite.DATA -> {
                    transfer.offset += transfer.pendingChunkBytes
                    transfer.pendingChunkBytes = 0
                    transfer.nextSequence += 1
                    transfer.chunks += 1
                    if (transfer.offset == transfer.payload.size) {
                        onOutgoingPayloadSent(gatt, characteristic)
                    } else {
                        sendNextDataFrame(gatt, characteristic, transfer)
                    }
                }
            }
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            handleCharacteristicRead(gatt, characteristic, characteristic.value ?: byteArrayOf(), status)
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int,
        ) {
            handleCharacteristicRead(gatt, characteristic, value, status)
        }
    }

    @SuppressLint("MissingPermission")
    fun startServer() {
        if (server != null) return
        val identity = try {
            RelayNative.createIdentity()
        } catch (error: RuntimeException) {
            throw LinkException(
                "secure_core_unavailable",
                "Relay's Rust secure core could not create an identity.",
            )
        }
        val signingIdentity = try {
            RelayDeviceIdentity(activity.packageManager)
        } catch (error: RuntimeException) {
            identity.closeQuietly()
            throw LinkException(
                "device_identity_unavailable",
                "Relay could not open its persistent device identity.",
            )
        }
        val manager = activity.getSystemService(BluetoothManager::class.java)
        val openedServer = manager.openGattServer(activity, serverCallback)
        if (openedServer == null) {
            identity.closeQuietly()
            throw LinkException("gatt_server_failed", "Could not open the Relay GATT server.")
        }
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val characteristic = BluetoothGattCharacteristic(
            TRANSFER_CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        service.addCharacteristic(characteristic)
        server = openedServer
        secureIdentity = identity
        deviceIdentity = signingIdentity
        if (!openedServer.addService(service)) {
            openedServer.close()
            server = null
            secureIdentity = null
            deviceIdentity = null
            identity.closeQuietly()
            throw LinkException("gatt_service_failed", "Could not add the Relay GATT service.")
        }
        Log.i(TAG, "GATT server opened; service registration requested")
    }

    @SuppressLint("MissingPermission")
    fun sendEngineeringTransfer(
        peerToken: String,
        device: BluetoothDevice,
        tamperCiphertext: Boolean = false,
    ) {
        closeWarmTextSession()
        linkPurpose = LinkPurpose.ENGINEERING
        resetPendingText()
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        tamperCiphertextForTest = tamperCiphertext
        startConnection(peerToken, device)
    }

    @SuppressLint("MissingPermission")
    fun identifyPeer(
        peerToken: String,
        device: BluetoothDevice,
        automatic: Boolean = false,
    ) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A direct-link transfer is already running.")
        }
        linkPurpose = LinkPurpose.IDENTITY
        identityRefreshAutomatic = automatic
        resetPendingText()
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            linkPurpose = LinkPurpose.ENGINEERING
            identityRefreshAutomatic = false
            throw error
        }
    }

    @SuppressLint("MissingPermission")
    fun syncMesh(peerToken: String, device: BluetoothDevice) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A nearby Relay exchange is already running.")
        }
        linkPurpose = LinkPurpose.MESH_SYNC
        resetPendingText()
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        pendingMeshOffers = emptyList()
        pendingMeshProbeOffers = emptyList()
        pendingMeshRequestedPeerProbeIds = emptyList()
        pendingMeshSent = 0
        pendingMeshReceived = 0
        pendingAttachmentPlanOffer = null
        pendingAttachmentCleanup?.cleanup?.cancellationSecret?.fill(0)
        pendingAttachmentCleanup = null
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            linkPurpose = LinkPurpose.ENGINEERING
            throw error
        }
    }

    @SuppressLint("MissingPermission")
    fun offerCourierAttachmentPlan(
        peerToken: String,
        device: BluetoothDevice,
        encodedManifest: ByteArray,
        encodedPlan: ByteArray,
    ) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A nearby Relay exchange is already running.")
        }
        val offer = try {
            RelayAttachmentPlanOffer(
                encodedManifest = encodedManifest.copyOf(),
                encodedPlan = encodedPlan.copyOf(),
            ).also(RelayAttachmentPlanOffer::validate)
        } catch (error: RuntimeException) {
            throw LinkException(
                "invalid_attachment_plan",
                error.message ?: "The courier attachment plan is invalid.",
            )
        }
        linkPurpose = LinkPurpose.ATTACHMENT_CUSTODY
        resetPendingText()
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        pendingAttachmentPlanOffer = offer
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            pendingAttachmentPlanOffer = null
            linkPurpose = LinkPurpose.ENGINEERING
            throw error
        }
    }

    fun isBusy(): Boolean = client != null && !isWarmTextSession()

    fun hasPendingMeshWork(): Boolean {
        prepareReadyAttachmentReceipts()
        reconcileSenderAttachmentReceipts()
        return meshStore.hasPendingEnvelopes()
    }

    fun reconcileDurableAttachmentReceipts() {
        reconcileSenderAttachmentReceipts()
    }

    fun prepareCourierAttachment(attachmentIdHex: String): Map<String, Any> {
        val stored = attachmentStore.findByHexId(attachmentIdHex)
            ?: throw LinkException("attachment_missing", "The secured attachment was not found.")
        if (
            stored.direction != RelayAttachmentStore.Direction.OUTGOING ||
            stored.status == RelayAttachmentStore.Status.DELIVERED ||
            attachmentStore.isCancelled(stored)
        ) {
            throw LinkException(
                "attachment_not_eligible",
                "Only an unfinished outgoing attachment can enter courier control.",
            )
        }
        val offer = try {
            meshStore.queueOutgoingAttachment(stored.peerFingerprint, stored.manifest).also {
                check(meshStore.setSenderAttachmentOfferEligible(it.objectId, true)) {
                    "The courier attachment offer could not be enabled."
                }
            }
        } catch (error: RuntimeException) {
            throw LinkException(
                "attachment_mesh_queue_failed",
                error.message ?: "The courier attachment offer could not be saved.",
            )
        }
        return mapOf(
            "attachmentId" to offer.objectId.toHex(),
            "status" to "queued",
            "transport" to "courier_control",
        )
    }

    fun nextCourierAttachmentOffer(peerToken: String): RelayMeshStore.SenderAttachmentOffer? {
        val courierFingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        }
        return meshStore.nextSenderAttachmentOffer(courierFingerprint)
    }

    fun nextCourierAttachmentCleanup(peerToken: String): RelayCourierAttachmentCleanup? {
        val courierFingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        } ?: return null
        return meshStore.nextSenderAttachmentCleanup(courierFingerprint)
    }

    fun cleanCourierAttachment(
        peerToken: String,
        device: BluetoothDevice,
        cleanup: RelayCourierAttachmentCleanup,
    ) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A nearby Relay exchange is already running.")
        }
        cleanup.validate()
        val courierFingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        } ?: throw LinkException(
            "identity_missing",
            "Courier identity is unavailable for attachment cleanup.",
        )
        linkPurpose = LinkPurpose.ATTACHMENT_CLEANUP
        resetPendingText()
        pendingAttachmentCleanup?.cleanup?.cancellationSecret?.fill(0)
        pendingAttachmentCleanup = PendingAttachmentCleanup(
            cleanup = cleanup.copy(
                objectId = cleanup.objectId.copyOf(),
                planSha256 = cleanup.planSha256.copyOf(),
                cancellationSecret = cleanup.cancellationSecret.copyOf(),
            ),
            courierFingerprint = courierFingerprint,
        )
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            pendingAttachmentCleanup?.cleanup?.cancellationSecret?.fill(0)
            pendingAttachmentCleanup = null
            linkPurpose = LinkPurpose.ENGINEERING
            throw error
        } finally {
            cleanup.cancellationSecret.fill(0)
        }
    }

    fun removeCourierAttachmentOffer(attachmentIdHex: String) {
        val stored = attachmentStore.findByHexId(attachmentIdHex) ?: return
        meshStore.removeSenderAttachmentOffer(stored.manifest.attachmentId)
    }

    fun pauseCourierAttachmentOffer(attachmentIdHex: String) {
        val stored = attachmentStore.findByHexId(attachmentIdHex) ?: return
        meshStore.setSenderAttachmentOfferEligible(stored.manifest.attachmentId, false)
    }

    fun hasVerifiedContacts(): Boolean = meshStore.hasVerifiedContacts()

    fun isObservedPeerVerified(peerToken: String): Boolean {
        val observed = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]
        } ?: return false
        return trustStore.stateFor(observed.publicKey) ==
            RelayPeerTrustStore.PeerTrustState.VERIFIED
    }

    fun observedPeerMetadata(peerToken: String): Map<String, Any>? {
        val observed = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]
        } ?: return null
        val trustState = trustStore.stateFor(observed.publicKey)
        if (trustState != RelayPeerTrustStore.PeerTrustState.VERIFIED) return null
        return mapOf(
            "fingerprint" to observed.fingerprint,
            "protection" to observed.protection,
            "trustState" to trustState.wireValue,
        )
    }

    fun forgetObservedPeer(peerToken: String) {
        synchronized(observedIdentityLock) {
            observedIdentityByToken.remove(peerToken)
        }
    }

    fun hasObservedIdentity(peerToken: String): Boolean = synchronized(observedIdentityLock) {
        observedIdentityByToken.containsKey(peerToken)
    }

    fun observedPeerFingerprint(peerToken: String): String? = synchronized(observedIdentityLock) {
        observedIdentityByToken[peerToken]?.fingerprint
    }

    /** Direct user text may safely interrupt an idempotent courier inventory sync. */
    @SuppressLint("MissingPermission")
    fun cancelMeshSyncForDirectText(): String? {
        val activeClient = client ?: return null
        if (linkPurpose != LinkPurpose.MESH_SYNC) return null
        val token = activePeerToken
        closeClient(activeClient, disconnect = true)
        return token
    }

    @SuppressLint("MissingPermission")
    fun cancelAutomaticIdentityRefresh(): String? {
        val activeClient = client ?: return null
        if (linkPurpose != LinkPurpose.IDENTITY || !identityRefreshAutomatic) return null
        val token = activePeerToken
        closeClient(activeClient, disconnect = true)
        return token
    }

    fun shouldPreemptForDirectText(peerToken: String): Boolean {
        val fingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        } ?: return false
        return !messageStore.hasQueuedOutgoingForPeer(fingerprint) &&
            !meshStore.hasPendingOutgoingText(fingerprint)
    }

    @SuppressLint("MissingPermission")
    fun sendTextMessage(
        peerToken: String,
        device: BluetoothDevice,
        text: String,
        replyToMessageId: String? = null,
        replyPreview: String? = null,
    ): Map<String, Any> {
        val traceStartedAtMs = SystemClock.elapsedRealtime()
        val message = try {
            RelayMessageCodec.create(text, replyToMessageId, replyPreview)
        } catch (error: RuntimeException) {
            throw LinkException(
                "invalid_message",
                "Message must contain 1 to 2048 bytes of valid text.",
            )
        }
        val observed = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]
        } ?: throw LinkException(
            "identity_not_observed",
            "Identify this phone securely before messaging.",
        )
        if (trustStore.stateFor(observed.publicKey) != RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            throw LinkException("peer_not_verified", "Verify this phone before messaging.")
        }
        val hadDirectBacklog = messageStore.hasQueuedOutgoingForPeer(observed.fingerprint)
        val transport = RelayConversationTransportPolicy.select(
            requested = RelayTextTransport.DIRECT,
            hasDirectBacklog = hadDirectBacklog,
            hasMeshBacklog = meshStore.hasPendingOutgoingText(observed.fingerprint),
        )
        if (transport == RelayTextTransport.MESH) {
            val queued = queueMeshTextOnly(
                observed.fingerprint,
                text,
                replyToMessageId,
                replyPreview,
            )
            Log.i(
                METRICS_TAG,
                "text_timing role=sender stage=mesh_durable_queue total_ms=" +
                    (SystemClock.elapsedRealtime() - traceStartedAtMs),
            )
            emit(
                mapOf(
                    "type" to "text_message_queued",
                    "token" to peerToken,
                    "messageId" to queued.getValue("messageId"),
                    "text" to text,
                    "code" to "ordered_mesh_backlog",
                    "automatic" to false,
                ) + message.replyMap(),
            )
            return queued
        }
        val storeStartedAtMs = SystemClock.elapsedRealtime()
        try {
            messageStore.storeOutgoing(message, observed.fingerprint)
        } catch (error: RuntimeException) {
            throw LinkException("message_store_failed", "The message could not be safely stored.")
        }
        val queuedAtMs = SystemClock.elapsedRealtime()
        Log.i(
            METRICS_TAG,
            "text_timing role=sender stage=direct_durable_queue total_ms=" +
                "${queuedAtMs - traceStartedAtMs} store_ms=${queuedAtMs - storeStartedAtMs} " +
                "had_backlog=$hadDirectBacklog",
        )
        // Local durable acceptance is the truthful point at which the composer
        // can clear and show Waiting. Remote delivery still requires its real,
        // encrypted receipt before the status becomes Delivered.
        emitQueuedMessage(
            message = message,
            peerToken = peerToken,
            retryAtMs = null,
            errorCode = "locally_queued",
            automatic = false,
        )
        val queued = directMessageMap(message, observed.fingerprint)

        // The oldest queued message owns this contact's direct FIFO, including while its retry
        // backoff is active. A newer user action must not bypass it with a fresh connection.
        if (hadDirectBacklog) return queued

        if (isWarmTextSession() && activePeerToken != peerToken) {
            closeWarmTextSession()
        }
        val activeClient = client
        if (activeClient != null) {
            if (isWarmTextSession() && activePeerToken == peerToken) {
                beginPendingTextTrace(traceStartedAtMs, queuedAtMs)
                startTextOverWarmSession(
                    gatt = activeClient,
                    message = message,
                    peerFingerprint = observed.fingerprint,
                    automatic = false,
                )
            }
            // Another authenticated operation is already running. The durable
            // outbox will drain this message as soon as that operation finishes.
            return queued
        }
        beginPendingTextTrace(traceStartedAtMs, queuedAtMs)
        startFreshTextAttempt(peerToken, device, message, observed.fingerprint, automatic = false)
        return queued
    }

    @SuppressLint("MissingPermission")
    fun retryTextMessage(
        peerToken: String,
        device: BluetoothDevice,
        messageIdHex: String,
        automatic: Boolean = false,
    ) {
        val stored = messageStore.queuedOutgoing(messageIdHex)
            ?: throw LinkException(
                "queued_message_missing",
                "That message is no longer queued for delivery.",
            )
        val oldest = messageStore.oldestQueuedForPeer(stored.peerFingerprint)
        if (oldest == null || !oldest.id.contentEquals(stored.id)) {
            throw LinkException(
                "earlier_message_waiting",
                "An earlier message to this contact must finish first.",
            )
        }
        val observedFingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        }
        if (observedFingerprint != null && observedFingerprint != stored.peerFingerprint) {
            throw LinkException(
                "queued_peer_mismatch",
                "This nearby phone is not the intended recipient; the message remains queued.",
            )
        }
        if (isWarmTextSession() && activePeerToken != peerToken) closeWarmTextSession()
        val activeClient = client
        if (activeClient != null) {
            if (isWarmTextSession() && activePeerToken == peerToken) {
                startStoredTextOverWarmSession(activeClient, stored, automatic)
            } else {
                val message = RelayMessageCodec.restore(
                    stored.id,
                    stored.text,
                    stored.replyToMessageId,
                    stored.replyPreview,
                )
                emitQueuedMessage(message, peerToken, null, "link_busy", automatic)
            }
            return
        }
        startQueuedText(peerToken, device, stored, automatic)
    }

    @SuppressLint("MissingPermission")
    fun retryOldestEligible(peerToken: String, device: BluetoothDevice): String? {
        val activeClient = client
        if (activeClient != null) {
            if (!isWarmTextSession() || activePeerToken != peerToken) return null
            val fingerprint = activePeerFingerprint ?: return null
            val stored = messageStore.oldestRetryEligibleForPeer(fingerprint) ?: return null
            startStoredTextOverWarmSession(activeClient, stored, automatic = true)
            return RelayMessageCodec.idHex(stored.id)
        }
        val stored = messageStore.oldestRetryEligible() ?: return null
        val observedFingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        }
        if (observedFingerprint != null && observedFingerprint != stored.peerFingerprint) return null
        startQueuedText(peerToken, device, stored, automatic = true)
        return RelayMessageCodec.idHex(stored.id)
    }

    /** Retries only text bound to this token's already authenticated device identity. */
    @SuppressLint("MissingPermission")
    fun retryOldestEligibleForObservedPeer(
        peerToken: String,
        device: BluetoothDevice,
    ): String? {
        val fingerprint = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]?.fingerprint
        } ?: return null
        val activeClient = client
        if (activeClient != null) {
            if (!isWarmTextSession() || activePeerToken != peerToken) return null
            val stored = messageStore.oldestRetryEligibleForPeer(fingerprint) ?: return null
            startStoredTextOverWarmSession(activeClient, stored, automatic = true)
            return RelayMessageCodec.idHex(stored.id)
        }
        val stored = messageStore.oldestRetryEligibleForPeer(fingerprint) ?: return null
        startQueuedText(peerToken, device, stored, automatic = true)
        return RelayMessageCodec.idHex(stored.id)
    }

    private fun startFreshTextAttempt(
        peerToken: String,
        device: BluetoothDevice,
        message: RelayMessageCodec.TextMessage,
        peerFingerprint: String,
        automatic: Boolean,
    ) {
        val attempts = beginTextAttempt(message, peerFingerprint, automatic) ?: return
        emitTextRetrying(peerToken, message, attempts, automatic)
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            val retryAt = messageStore.markRetryableFailure(message.id, "connect_start_failed")
            emitQueuedMessage(message, peerToken, retryAt, "connect_start_failed", automatic)
            resetPendingText()
            linkPurpose = LinkPurpose.ENGINEERING
        }
    }

    private fun startQueuedText(
        peerToken: String,
        device: BluetoothDevice,
        stored: RelayMessageStore.StoredMessage,
        automatic: Boolean,
    ) {
        val message = try {
            RelayMessageCodec.restore(
                stored.id,
                stored.text,
                stored.replyToMessageId,
                stored.replyPreview,
            )
        } catch (error: RuntimeException) {
            throw LinkException("invalid_queued_message", "The queued message could not be encoded.")
        }
        val attempts = beginTextAttempt(message, stored.peerFingerprint, automatic) ?: return
        emitTextRetrying(peerToken, message, attempts, automatic)
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            val retryAt = messageStore.markRetryableFailure(message.id, "connect_start_failed")
            emitQueuedMessage(message, peerToken, retryAt, "connect_start_failed", automatic)
            resetPendingText()
            linkPurpose = LinkPurpose.ENGINEERING
        }
    }

    private fun beginTextAttempt(
        message: RelayMessageCodec.TextMessage,
        peerFingerprint: String,
        automatic: Boolean,
    ): Int? {
        val attemptStartedAtMs = SystemClock.elapsedRealtime()
        if (pendingTextTraceStartedAtMs == 0L) {
            beginPendingTextTrace(attemptStartedAtMs, 0L)
        }
        val attempts = try {
            messageStore.beginAttempt(message.id)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not begin durable text attempt", error)
            return null
        }
        mainHandler.removeCallbacks(warmSessionTimeout)
        linkPurpose = LinkPurpose.USER_TEXT
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingTextMessage = message
        pendingPeerFingerprint = peerFingerprint
        pendingTextAttemptStarted = true
        pendingTextDelivered = false
        pendingTextFailureCode = null
        pendingTextAutomaticRetry = automatic
        tamperCiphertextForTest = false
        val attemptCommittedAtMs = SystemClock.elapsedRealtime()
        logPendingTextTiming(
            stage = "attempt_started",
            nowMs = attemptCommittedAtMs,
            extra = "attempt_store_ms=${attemptCommittedAtMs - attemptStartedAtMs} automatic=$automatic",
        )
        return attempts
    }

    private fun emitTextRetrying(
        peerToken: String,
        message: RelayMessageCodec.TextMessage,
        attempts: Int,
        automatic: Boolean,
    ) {
        emit(
            mapOf(
                "type" to "text_message_retrying",
                "token" to peerToken,
                "messageId" to RelayMessageCodec.idHex(message.id),
                "text" to message.text,
                "attemptCount" to attempts,
                "automatic" to automatic,
            ) + message.replyMap(),
        )
    }

    private fun startStoredTextOverWarmSession(
        gatt: BluetoothGatt,
        stored: RelayMessageStore.StoredMessage,
        automatic: Boolean,
    ) {
        val message = try {
            RelayMessageCodec.restore(
                stored.id,
                stored.text,
                stored.replyToMessageId,
                stored.replyPreview,
            )
        } catch (error: RuntimeException) {
            throw LinkException("invalid_queued_message", "The queued message could not be encoded.")
        }
        startTextOverWarmSession(gatt, message, stored.peerFingerprint, automatic)
    }

    @SuppressLint("MissingPermission")
    private fun startTextOverWarmSession(
        gatt: BluetoothGatt,
        message: RelayMessageCodec.TextMessage,
        peerFingerprint: String,
        automatic: Boolean,
    ) {
        val characteristic = activeWriteCharacteristic
        val remotePublicKey = clientRemoteIdentityPublicKey
        if (
            client !== gatt || !isWarmTextSession() ||
            characteristic == null || remotePublicKey == null ||
            activePeerFingerprint != peerFingerprint
        ) {
            return
        }
        val attempts = beginTextAttempt(message, peerFingerprint, automatic) ?: return
        emitTextRetrying(requirePeerToken(), message, attempts, automatic)
        try {
            gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Bluetooth stack rejected warm-session high priority", error)
        }
        scheduleTimeout(TRANSFER_TIMEOUT_MS)
        startEncryptedText(gatt, characteristic, remotePublicKey)
    }

    private fun isWarmTextSession(): Boolean =
        client != null &&
            linkPurpose == LinkPurpose.WARM_TEXT &&
            clientPhase == ClientPhase.IDLE &&
            clientSecureSession?.isEstablished() == true

    @SuppressLint("MissingPermission")
    private fun closeWarmTextSession() {
        val warmClient = client ?: return
        if (isWarmTextSession()) closeClient(warmClient, disconnect = true)
    }

    @SuppressLint("MissingPermission")
    fun authorizeWifiUpgrade(
        peerToken: String,
        device: BluetoothDevice,
        responderWifiToken: ByteArray,
    ) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A direct-link transfer is already running.")
        }
        val initiatorWifiToken = localWifiToken()
        if (initiatorWifiToken == null || initiatorWifiToken.size != WIFI_TOKEN_BYTES) {
            throw LinkException("wifi_direct_stopped", "Start Wi-Fi Direct discovery first.")
        }
        val offer = try {
            RelayMessageCodec.createWifiUpgradeOffer(
                initiatorWifiToken,
                responderWifiToken,
            )
        } catch (error: RuntimeException) {
            throw LinkException("wifi_upgrade_failed", "Could not create a Wi-Fi upgrade capability.")
        }
        linkPurpose = LinkPurpose.WIFI_UPGRADE
        wifiUpgradeAuthorized = false
        resetPendingText()
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        pendingWifiUpgradeOffer = offer
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            offer.psk.fill(0)
            pendingWifiUpgradeOffer = null
            linkPurpose = LinkPurpose.ENGINEERING
            throw error
        }
    }

    /** Authorizes only a previously custodied opaque object; no contact verification is implied. */
    @SuppressLint("MissingPermission")
    fun authorizeCourierWifiUpgrade(
        peerToken: String,
        device: BluetoothDevice,
        responderWifiToken: ByteArray,
        objectId: ByteArray,
        planSha256: ByteArray,
        courierFingerprint: String,
    ) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A direct-link transfer is already running.")
        }
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Courier Wi-Fi object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Courier Wi-Fi plan digest is invalid."
        }
        val durable = meshStore.senderAttachmentCustody(objectId, courierFingerprint)
            ?: throw LinkException(
                "attachment_custody_missing",
                "Authenticated courier custody is unavailable for this Wi-Fi hop.",
            )
        require(
            durable.objectId.contentEquals(objectId) &&
                MessageDigest.isEqual(durable.planSha256, planSha256) &&
                durable.missingChunks().isNotEmpty(),
        ) { "Courier Wi-Fi custody is complete or does not match." }
        val initiatorWifiToken = localWifiToken()
        if (initiatorWifiToken == null || initiatorWifiToken.size != WIFI_TOKEN_BYTES) {
            throw LinkException("wifi_direct_stopped", "Start Wi-Fi Direct discovery first.")
        }
        val offer = try {
            RelayMessageCodec.createWifiUpgradeOffer(initiatorWifiToken, responderWifiToken)
        } catch (error: RuntimeException) {
            throw LinkException("wifi_upgrade_failed", "Could not create a courier Wi-Fi capability.")
        }
        linkPurpose = LinkPurpose.COURIER_WIFI_UPGRADE
        wifiUpgradeAuthorized = false
        resetPendingText()
        pendingWifiUpgradeOffer = offer
        pendingRecipientWifiUpgrade = null
        pendingCourierWifiUpgrade = PendingCourierWifiUpgrade(
            objectId = objectId.copyOf(),
            planSha256 = planSha256.copyOf(),
            courierFingerprint = courierFingerprint,
        )
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            offer.psk.fill(0)
            pendingWifiUpgradeOffer = null
            pendingCourierWifiUpgrade = null
            pendingRecipientWifiUpgrade = null
            linkPurpose = LinkPurpose.ENGINEERING
            throw error
        }
    }

    /** Requests an opaque object from any authenticated courier; it does not trust that courier. */
    @SuppressLint("MissingPermission")
    fun authorizeRecipientWifiUpgrade(
        peerToken: String,
        device: BluetoothDevice,
        responderWifiToken: ByteArray,
        objectId: ByteArray,
        planSha256: ByteArray,
    ) {
        closeWarmTextSession()
        if (client != null) {
            throw LinkException("link_busy", "A direct-link transfer is already running.")
        }
        require(objectId.size == RelayCourierAttachmentPlan.OBJECT_ID_BYTES) {
            "Recipient Wi-Fi object ID is invalid."
        }
        require(planSha256.size == RelayCourierAttachmentPlan.SHA256_BYTES) {
            "Recipient Wi-Fi plan digest is invalid."
        }
        val initiatorWifiToken = localWifiToken()
        if (initiatorWifiToken == null || initiatorWifiToken.size != WIFI_TOKEN_BYTES) {
            throw LinkException("wifi_direct_stopped", "Start Wi-Fi Direct discovery first.")
        }
        val offer = try {
            RelayMessageCodec.createWifiUpgradeOffer(initiatorWifiToken, responderWifiToken)
        } catch (error: RuntimeException) {
            throw LinkException("wifi_upgrade_failed", "Could not create a recipient Wi-Fi capability.")
        }
        linkPurpose = LinkPurpose.RECIPIENT_WIFI_UPGRADE
        wifiUpgradeAuthorized = false
        resetPendingText()
        pendingWifiUpgradeOffer = offer
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = PendingRecipientWifiUpgrade(
            objectId = objectId.copyOf(),
            planSha256 = planSha256.copyOf(),
        )
        tamperCiphertextForTest = false
        try {
            startConnection(peerToken, device)
        } catch (error: RuntimeException) {
            offer.psk.fill(0)
            pendingWifiUpgradeOffer = null
            pendingRecipientWifiUpgrade = null
            linkPurpose = LinkPurpose.ENGINEERING
            throw error
        }
    }

    fun queueMeshText(
        peerFingerprint: String,
        text: String,
        replyToMessageId: String? = null,
        replyPreview: String? = null,
    ): Map<String, Any> =
        if (selectTextTransport(peerFingerprint, RelayTextTransport.MESH) == RelayTextTransport.DIRECT) {
            queueDirectTextOnly(peerFingerprint, text, replyToMessageId, replyPreview)
        } else {
            queueMeshTextOnly(peerFingerprint, text, replyToMessageId, replyPreview)
        }

    private fun queueMeshTextOnly(
        peerFingerprint: String,
        text: String,
        replyToMessageId: String? = null,
        replyPreview: String? = null,
    ): Map<String, Any> {
        val queued = try {
            meshStore.queueOutgoingText(peerFingerprint, text, replyToMessageId, replyPreview)
        } catch (error: RuntimeException) {
            throw LinkException("mesh_queue_failed", error.message ?: "The mesh message could not be queued.")
        }
        return mapOf(
            "messageId" to queued.messageId.toHex(),
            "fingerprint" to queued.peerFingerprint,
            "peerFingerprint" to queued.peerFingerprint,
            "direction" to "outgoing",
            "text" to text.trim(),
            "status" to "queued",
            "transport" to "mesh",
            "createdAtMs" to queued.createdAtMs,
            "attemptCount" to 0,
        ) + queued.message.replyMap()
    }

    private fun queueDirectTextOnly(
        peerFingerprint: String,
        text: String,
        replyToMessageId: String? = null,
        replyPreview: String? = null,
    ): Map<String, Any> {
        val message = try {
            RelayMessageCodec.create(text, replyToMessageId, replyPreview)
        } catch (error: RuntimeException) {
            throw LinkException(
                "invalid_message",
                "Message must contain 1 to 2048 bytes of valid text.",
            )
        }
        try {
            messageStore.storeOutgoing(message, peerFingerprint)
        } catch (error: RuntimeException) {
            throw LinkException("message_store_failed", "The message could not be safely stored.")
        }
        return directMessageMap(message, peerFingerprint)
    }

    private fun directMessageMap(
        message: RelayMessageCodec.TextMessage,
        peerFingerprint: String,
    ): Map<String, Any> {
        val stored = requireNotNull(
            messageStore.queuedOutgoing(RelayMessageCodec.idHex(message.id)),
        ) { "Durably queued direct message disappeared." }
        return stored.toMap() + mapOf(
            "fingerprint" to peerFingerprint,
            "transport" to "direct",
        )
    }

    private fun selectTextTransport(
        peerFingerprint: String,
        requested: RelayTextTransport,
    ): RelayTextTransport = RelayConversationTransportPolicy.select(
        requested = requested,
        hasDirectBacklog = messageStore.hasQueuedOutgoingForPeer(peerFingerprint),
        hasMeshBacklog = meshStore.hasPendingOutgoingText(peerFingerprint),
    )

    fun queueLastCopyDiagnosticText(peerFingerprint: String, text: String): Map<String, Any> {
        val queued = try {
            meshStore.queueOutgoingText(peerFingerprint, text, initialCopyBudget = 1)
        } catch (error: RuntimeException) {
            throw LinkException(
                "last_copy_queue_failed",
                error.message ?: "The last-copy diagnostic message could not be queued.",
            )
        }
        return mapOf(
            "messageId" to queued.messageId.toHex(),
            "fingerprint" to queued.peerFingerprint,
            "status" to "queued",
        )
    }

    fun contacts(): List<Map<String, Any>> = meshStore.contacts()

    fun localProfile(): Map<String, Any> = mapOf(
        "displayName" to meshStore.displayName(),
        "setupComplete" to meshStore.profileSetupComplete(),
    )

    fun updateDisplayName(raw: String): Map<String, Any> = try {
        mapOf("displayName" to meshStore.updateDisplayName(raw))
    } catch (error: RuntimeException) {
        throw LinkException("invalid_display_name", error.message ?: "The profile name is invalid.")
    }

    fun storedMessages(): List<Map<String, Any>> =
        (messageStore.listRecent().map { it.toMap() } + meshStore.storedMessages())
            .sortedBy { (it["createdAtMs"] as? Number)?.toLong() ?: 0L }

    fun storedMessagePage(
        peerFingerprint: String,
        beforeCreatedAtMs: Long?,
        beforeMessageIdHex: String?,
        limit: Int,
    ): Map<String, Any> {
        val boundedLimit = limit.coerceIn(1, MAX_UI_HISTORY_PAGE_SIZE)
        val sourceLimit = boundedLimit + 1
        val candidates = (
            messageStore.listRecentPage(
                peerFingerprint = peerFingerprint,
                beforeCreatedAtMs = beforeCreatedAtMs,
                beforeMessageIdHex = beforeMessageIdHex,
                limit = sourceLimit,
            ).map { it.toMap() + ("transport" to "direct") } +
                meshStore.storedMessagePage(
                    peerFingerprint = peerFingerprint,
                    beforeCreatedAtMs = beforeCreatedAtMs,
                    beforeMessageIdHex = beforeMessageIdHex,
                    limit = sourceLimit,
                )
            )
            .associateBy { it["messageId"] as String }
            .values
            .sortedWith(::compareStoredMessagesNewestFirst)
        val pageNewestFirst = candidates.take(boundedLimit)
        val hasMore = candidates.size > boundedLimit
        val oldest = pageNewestFirst.lastOrNull()
        return buildMap {
            put("messages", pageNewestFirst.reversed())
            put("hasMore", hasMore)
            if (hasMore && oldest != null) {
                put("nextBeforeCreatedAtMs", (oldest["createdAtMs"] as Number).toLong())
                put("nextBeforeMessageId", oldest["messageId"] as String)
            }
        }
    }

    fun conversationSummaries(): List<Map<String, Any>> {
        val merged = linkedMapOf<String, MutableMap<String, Any>>()
        val summaries = buildList {
            messageStore.conversationSummaries().forEach { summary ->
                add(
                    mapOf(
                        "lastMessage" to
                            (summary.lastMessage.toMap() + ("transport" to "direct")),
                        "messageCount" to summary.messageCount,
                        "unreadCount" to summary.unreadCount,
                    ),
                )
            }
            meshStore.conversationSummaries().forEach { summary ->
                add(
                    mapOf(
                        "lastMessage" to summary.lastMessage,
                        "messageCount" to summary.messageCount,
                        "unreadCount" to summary.unreadCount,
                    ),
                )
            }
        }
        for (summary in summaries) {
            @Suppress("UNCHECKED_CAST")
            val lastMessage = summary["lastMessage"] as Map<String, Any>
            val fingerprint = lastMessage["peerFingerprint"] as String
            val count = summary["messageCount"] as Int
            val existing = merged[fingerprint]
            if (existing == null) {
                merged[fingerprint] = mutableMapOf(
                    "peerFingerprint" to fingerprint,
                    "lastMessage" to lastMessage,
                    "messageCount" to count,
                    "unreadCount" to (summary["unreadCount"] as Int),
                )
                continue
            }
            existing["messageCount"] = (existing["messageCount"] as Int) + count
            existing["unreadCount"] =
                (existing["unreadCount"] as Int) + (summary["unreadCount"] as Int)
            @Suppress("UNCHECKED_CAST")
            val existingLast = existing["lastMessage"] as Map<String, Any>
            if (compareStoredMessagesNewestFirst(lastMessage, existingLast) < 0) {
                existing["lastMessage"] = lastMessage
            }
        }
        return merged.values.sortedWith { left, right ->
            @Suppress("UNCHECKED_CAST")
            val leftMessage = left["lastMessage"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST")
            val rightMessage = right["lastMessage"] as Map<String, Any>
            compareStoredMessagesNewestFirst(leftMessage, rightMessage)
        }
    }

    fun markConversationRead(peerFingerprint: String): Int =
        messageStore.markConversationRead(peerFingerprint) +
            meshStore.markConversationRead(peerFingerprint)

    fun unreadCount(peerFingerprint: String): Int =
        messageStore.unreadCount(peerFingerprint) + meshStore.unreadCount(peerFingerprint)

    private fun compareStoredMessagesNewestFirst(
        left: Map<String, Any>,
        right: Map<String, Any>,
    ): Int {
        val time = (right["createdAtMs"] as Number).toLong().compareTo(
            (left["createdAtMs"] as Number).toLong(),
        )
        if (time != 0) return time
        return (right["messageId"] as String).compareTo(left["messageId"] as String)
    }

    @SuppressLint("MissingPermission")
    private fun startConnection(peerToken: String, device: BluetoothDevice) {
        if (client != null) {
            throw LinkException("link_busy", "A direct-link transfer is already running.")
        }
        val initiatorToken = localToken()
        if (initiatorToken == null || initiatorToken.size != TOKEN_LENGTH) {
            throw LinkException("local_token_missing", "The local discovery token is unavailable.")
        }
        val responderToken = peerToken.hexToBytesOrNull()
        if (responderToken == null || responderToken.size != TOKEN_LENGTH) {
            throw LinkException("invalid_peer_token", "The nearby session token is invalid.")
        }
        val identity = secureIdentity
            ?: throw LinkException("secure_core_unavailable", "Relay's Rust secure core is unavailable.")
        val secureSession = try {
            identity.createSession(
                isInitiator = true,
                initiatorToken = initiatorToken,
                responderToken = responderToken,
            )
        } catch (error: RuntimeException) {
            throw LinkException("secure_session_failed", "Could not start a Noise secure session.")
        }
        activePeerToken = peerToken
        activePeerFingerprint = null
        activeWriteCharacteristic = null
        clientSecureSession = secureSession
        clientRemoteIdentityPublicKey = null
        clientPhase = ClientPhase.IDLE
        responseAccumulator = null
        expectedPlaintextBytes = 0
        expectedPlaintextCrc32 = 0L
        pendingMeshOffers = emptyList()
        pendingMeshProbeOffers = emptyList()
        pendingMeshRequestedPeerProbeIds = emptyList()
        pendingMeshSent = 0
        pendingMeshReceived = 0
        warmTextBudget.reset()
        linkStartedAtMs = SystemClock.elapsedRealtime()
        if (linkPurpose == LinkPurpose.USER_TEXT) {
            logPendingTextTiming("connection_started", linkStartedAtMs)
        }
        negotiatedMtu = DEFAULT_MTU
        emit(
            buildMap {
                put("type", "link_connecting")
                put("token", peerToken)
                if (linkPurpose == LinkPurpose.IDENTITY && identityRefreshAutomatic) {
                    put("automatic", true)
                }
            },
        )
        Log.i(TAG, "Starting authenticated direct connection for $peerToken")
        val openedClient = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            device.connectGatt(
                activity,
                false,
                clientCallback,
                BluetoothDevice.TRANSPORT_LE,
                BluetoothDevice.PHY_LE_1M,
                mainHandler,
            )
        } else {
            device.connectGatt(activity, false, clientCallback, BluetoothDevice.TRANSPORT_LE)
        }
        if (openedClient == null) {
            secureSession.closeQuietly()
            clientSecureSession = null
            activePeerToken = null
            resetPendingText()
            linkPurpose = LinkPurpose.ENGINEERING
            throw LinkException("connect_start_failed", "Could not start a BLE connection.")
        }
        client = openedClient
        scheduleTimeout(LINK_TIMEOUT_MS)
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        try {
            queueInterruptedText("discovery_stopped")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Interrupted message could not be queued during radio shutdown", error)
        }
        mainHandler.removeCallbacks(operationTimeout)
        mainHandler.removeCallbacks(warmSessionTimeout)
        val closingClient = client
        client = null
        try {
            closingClient?.disconnect()
        } catch (error: RuntimeException) {
            Log.w(TAG, "GATT client disconnect was rejected during radio shutdown", error)
        }
        try {
            closingClient?.close()
        } catch (error: RuntimeException) {
            Log.w(TAG, "GATT client close was rejected during radio shutdown", error)
        }
        clientSecureSession?.closeQuietly()
        clientSecureSession = null
        activeWriteCharacteristic = null
        clientRemoteIdentityPublicKey = null
        clientPhase = ClientPhase.IDLE
        responseAccumulator = null
        activePeerToken = null
        activePeerFingerprint = null
        outboundTransfer = null
        pendingWrite = null
        expectedPlaintextBytes = 0
        expectedPlaintextCrc32 = 0L
        pendingMeshOffers = emptyList()
        pendingMeshProbeOffers = emptyList()
        pendingMeshRequestedPeerProbeIds = emptyList()
        pendingMeshSent = 0
        pendingMeshReceived = 0
        pendingAttachmentPlanOffer = null
        tamperCiphertextForTest = false
        linkPurpose = LinkPurpose.ENGINEERING
        identityRefreshAutomatic = false
        resetPendingText()
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        synchronized(serverStateLock) {
            inboundTransfers.clear()
            serverMtuByDevice.clear()
            pendingServerResponses.clear()
            pendingServerMeshOffers.clear()
            pendingServerMeshProbeOffers.clear()
            pendingServerRequestedProbeIds.clear()
            serverSecureStates.values.forEach { it.session.closeQuietly() }
            serverSecureStates.clear()
        }
        synchronized(observedIdentityLock) { observedIdentityByToken.clear() }
        val closingServer = server
        server = null
        try {
            closingServer?.clearServices()
        } catch (error: RuntimeException) {
            Log.w(TAG, "GATT service cleanup was rejected during radio shutdown", error)
        }
        try {
            closingServer?.close()
        } catch (error: RuntimeException) {
            Log.w(TAG, "GATT server close was rejected during radio shutdown", error)
        }
        secureIdentity?.closeQuietly()
        secureIdentity = null
        deviceIdentity = null
    }

    fun markPeerVerified(peerToken: String) {
        val observed = synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken]
        } ?: throw LinkException(
            "identity_not_observed",
            "Complete an identity-bound encrypted link before verifying this fingerprint.",
        )
        try {
            trustStore.markVerified(observed.publicKey)
            meshStore.markVerified(observed.fingerprint)
        } catch (error: RuntimeException) {
            throw LinkException("trust_store_failed", "The verification decision could not be saved.")
        }
        emit(
            mapOf(
                "type" to "peer_trust_updated",
                "token" to peerToken,
                "fingerprint" to observed.fingerprint,
                "protection" to observed.protection,
                "trustState" to RelayPeerTrustStore.PeerTrustState.VERIFIED.wireValue,
            ),
        )
    }

    @SuppressLint("MissingPermission")
    private fun discoverRelayService(gatt: BluetoothGatt) {
        Log.i(TAG, "Starting Relay service discovery")
        if (!gatt.discoverServices()) {
            emit(linkError("service_discovery_start_failed", "Could not inspect the Relay service."))
            closeClient(gatt)
        }
    }

    private fun startSecureHandshake(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        val token = localToken()
        if (token == null || token.size != TOKEN_LENGTH) {
            emit(linkError("local_token_missing", "The local discovery token is unavailable."))
            closeClient(gatt)
            return
        }
        val messageOne = try {
            clientSecureSession?.start()
                ?: throw IllegalStateException("Noise initiator produced no first message.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not create Noise handshake message one", error)
            emit(linkError("secure_handshake_failed", "The encrypted handshake could not start."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.HANDSHAKE_MESSAGE_1
        emit(mapOf("type" to "secure_handshake_started", "token" to requirePeerToken()))
        startOutgoingTransfer(gatt, characteristic, TransferKind.HANDSHAKE, messageOne)
    }

    private fun startOutgoingTransfer(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        kind: TransferKind,
        payload: ByteArray,
    ) {
        val token = localToken()
        if (token == null || token.size != TOKEN_LENGTH) {
            emit(linkError("local_token_missing", "The local discovery token is unavailable."))
            closeClient(gatt)
            return
        }
        val transfer = OutgoingTransfer(
            id = random.nextInt(U16_LIMIT),
            sourceToken = token.copyOf(),
            kind = kind,
            payload = payload,
            crc32 = crc32(payload),
        )
        outboundTransfer = transfer
        val startFrame = buildStartFrame(transfer)
        if (!writeFrame(gatt, characteristic, startFrame, PendingWrite.START)) {
            emit(linkError("transfer_start_failed", "Could not start the framed BLE transfer."))
            closeClient(gatt)
        }
    }

    private fun onOutgoingPayloadSent(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        outboundTransfer = null
        when (clientPhase) {
            ClientPhase.HANDSHAKE_MESSAGE_1 -> beginReadingResponse(gatt, characteristic)
            ClientPhase.HANDSHAKE_MESSAGE_3 -> startClientIdentityProof(gatt, characteristic)
            ClientPhase.IDENTITY_PROOF -> beginReadingResponse(gatt, characteristic)
            ClientPhase.CONTACT_CARD -> beginReadingResponse(gatt, characteristic)
            ClientPhase.CIPHERTEXT -> beginReadingResponse(gatt, characteristic)
            ClientPhase.USER_MESSAGE -> beginReadingResponse(gatt, characteristic)
            ClientPhase.WIFI_UPGRADE -> beginReadingResponse(gatt, characteristic)
            ClientPhase.MESH_REQUEST -> beginReadingResponse(gatt, characteristic)
            ClientPhase.MESH_ACK -> beginReadingResponse(gatt, characteristic)
            ClientPhase.ATTACHMENT_PLAN -> beginReadingResponse(gatt, characteristic)
            ClientPhase.ATTACHMENT_CLEANUP -> beginReadingResponse(gatt, characteristic)
            ClientPhase.MESH_FINAL_ACK -> {
                emit(
                    mapOf(
                        "type" to "mesh_sync_completed",
                        "token" to requirePeerToken(),
                        "sent" to pendingMeshSent,
                        "received" to pendingMeshReceived,
                    ),
                )
                closeClient(gatt, disconnect = true)
            }
            ClientPhase.IDLE -> {
                emit(linkError("invalid_secure_state", "The secure transfer entered an invalid state."))
                closeClient(gatt)
            }
        }
    }

    private fun startClientIdentityProof(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        val encryptedProof = try {
            val session = clientSecureSession
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            val signingIdentity = deviceIdentity
                ?: throw IllegalStateException("Device signing identity is unavailable.")
            val proof = signingIdentity.createProof(
                session.sessionBinding(),
                RelayDeviceIdentity.IdentityRole.INITIATOR,
            )
            session.encrypt(proof)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not create channel-bound initiator identity proof", error)
            emit(linkError("identity_proof_failed", "The device identity proof could not be created."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.IDENTITY_PROOF
        emit(mapOf("type" to "identity_proof_sending", "token" to requirePeerToken()))
        startOutgoingTransfer(gatt, characteristic, TransferKind.IDENTITY_PROOF, encryptedProof)
    }

    private fun startEncryptedPayload(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        val remotePublicKey = clientRemoteIdentityPublicKey
        if (remotePublicKey == null) {
            emit(linkError("identity_missing", "Peer device identity was not authenticated."))
            closeClient(gatt)
            return
        }
        if (linkPurpose == LinkPurpose.IDENTITY) {
            emit(
                mapOf(
                    "type" to "peer_identity_ready",
                    "token" to requirePeerToken(),
                ),
            )
            closeClient(gatt, disconnect = true)
            return
        }
        if (linkPurpose == LinkPurpose.USER_TEXT) {
            startEncryptedText(gatt, characteristic, remotePublicKey)
            return
        }
        if (linkPurpose == LinkPurpose.WIFI_UPGRADE) {
            startEncryptedWifiUpgrade(gatt, characteristic, remotePublicKey)
            return
        }
        if (linkPurpose == LinkPurpose.COURIER_WIFI_UPGRADE) {
            startEncryptedCourierWifiUpgrade(gatt, characteristic, remotePublicKey)
            return
        }
        if (linkPurpose == LinkPurpose.RECIPIENT_WIFI_UPGRADE) {
            startEncryptedRecipientWifiUpgrade(gatt, characteristic, remotePublicKey)
            return
        }
        if (linkPurpose == LinkPurpose.MESH_SYNC) {
            startEncryptedMeshRequest(gatt, characteristic)
            return
        }
        if (linkPurpose == LinkPurpose.ATTACHMENT_CUSTODY) {
            startEncryptedAttachmentPlan(gatt, characteristic)
            return
        }
        if (linkPurpose == LinkPurpose.ATTACHMENT_CLEANUP) {
            startEncryptedAttachmentCleanup(gatt, characteristic)
            return
        }
        val plaintext = ByteArray(ENGINEERING_PAYLOAD_BYTES).also(random::nextBytes)
        ENGINEERING_PAYLOAD_PREFIX.copyInto(plaintext)
        expectedPlaintextBytes = plaintext.size
        expectedPlaintextCrc32 = crc32(plaintext)
        val ciphertext = try {
            clientSecureSession?.encrypt(plaintext)
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not encrypt engineering payload", error)
            emit(linkError("encryption_failed", "The test payload could not be encrypted."))
            closeClient(gatt)
            return
        }
        if (tamperCiphertextForTest) {
            ciphertext[ciphertext.size / 2] =
                (ciphertext[ciphertext.size / 2].toInt() xor TAMPER_MASK).toByte()
            emit(mapOf("type" to "tamper_test_started", "token" to requirePeerToken()))
        }
        clientPhase = ClientPhase.CIPHERTEXT
        emit(
            mapOf(
                "type" to "secure_session_established",
                "token" to requirePeerToken(),
            ),
        )
        startOutgoingTransfer(gatt, characteristic, TransferKind.CIPHERTEXT, ciphertext)
    }

    private fun startClientContactCard(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        val fingerprint = activePeerFingerprint
        if (fingerprint == null) {
            emit(linkError("identity_missing", "Peer identity is unavailable for contact exchange."))
            closeClient(gatt)
            return
        }
        val encryptedCard = try {
            val card = meshStore.localContactCard(fingerprint).encode()
            clientSecureSession?.encrypt(card)
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not create encrypted Relay contact card", error)
            emit(linkError("contact_exchange_failed", "The Relay contact card could not be created."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.CONTACT_CARD
        emit(mapOf("type" to "contact_exchange_started", "token" to requirePeerToken()))
        startOutgoingTransfer(gatt, characteristic, TransferKind.CONTACT_CARD, encryptedCard)
    }

    private fun startEncryptedText(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        remotePublicKey: ByteArray,
    ) {
        if (trustStore.stateFor(remotePublicKey) != RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            emit(
                linkError(
                    "peer_not_verified",
                    "Compare and verify this peer's safety fingerprint before messaging.",
                ),
            )
            closeClient(gatt, disconnect = true)
            return
        }
        val message = pendingTextMessage
        if (message == null) {
            emit(linkError("message_missing", "The pending text message is unavailable."))
            closeClient(gatt)
            return
        }
        val fingerprint = try {
            requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        } catch (error: RuntimeException) {
            emit(linkError("identity_missing", "Peer identity fingerprint is unavailable."))
            closeClient(gatt)
            return
        }
        val expectedFingerprint = pendingPeerFingerprint
        if (expectedFingerprint != null && expectedFingerprint != fingerprint) {
            pendingTextFailureCode = "queued_peer_mismatch"
            emit(
                linkError(
                    "queued_peer_mismatch",
                    "This nearby phone is not the intended recipient; the message remains queued.",
                ),
            )
            closeClient(gatt, disconnect = true)
            return
        }
        val preSendStoreStartedAtMs = SystemClock.elapsedRealtime()
        try {
            // Persist before network delivery. A crash can leave a visible pending message,
            // but can never create a false delivered state.
            messageStore.storeOutgoing(message, fingerprint)
            if (!pendingTextAttemptStarted) {
                val attempts = messageStore.beginAttempt(message.id)
                pendingTextAttemptStarted = true
                emit(
                    mapOf(
                        "type" to "text_message_queued",
                        "token" to requirePeerToken(),
                        "messageId" to RelayMessageCodec.idHex(message.id),
                        "text" to message.text,
                        "fingerprint" to fingerprint,
                        "attemptCount" to attempts,
                        "automatic" to false,
                    ) + message.replyMap(),
                )
            }
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not durably store outgoing text metadata", error)
            emit(linkError("message_store_failed", "The message could not be safely stored."))
            closeClient(gatt)
            return
        }
        val preSendStoreCompletedAtMs = SystemClock.elapsedRealtime()
        logPendingTextTiming(
            stage = "recipient_verified_before_send",
            nowMs = preSendStoreCompletedAtMs,
            extra = "pre_send_store_ms=${preSendStoreCompletedAtMs - preSendStoreStartedAtMs}",
        )
        val ciphertext = try {
            clientSecureSession?.encrypt(message.encoded)
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not encrypt text message", error)
            emit(linkError("encryption_failed", "The message could not be encrypted."))
            closeClient(gatt)
            return
        }
        pendingPeerFingerprint = fingerprint
        clientPhase = ClientPhase.USER_MESSAGE
        logPendingTextTiming("ble_send_started", SystemClock.elapsedRealtime())
        emit(mapOf("type" to "secure_session_established", "token" to requirePeerToken()))
        startOutgoingTransfer(gatt, characteristic, TransferKind.USER_MESSAGE, ciphertext)
    }

    private fun startEncryptedWifiUpgrade(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        remotePublicKey: ByteArray,
    ) {
        if (trustStore.stateFor(remotePublicKey) != RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            emit(linkError("peer_not_verified", "Verify this peer before authorizing fast Wi-Fi."))
            closeClient(gatt, disconnect = true)
            return
        }
        val offer = pendingWifiUpgradeOffer
        val currentWifiToken = localWifiToken()
        if (
            offer == null || currentWifiToken == null ||
            !offer.initiatorToken.contentEquals(currentWifiToken)
        ) {
            emit(linkError("wifi_upgrade_stale", "The Wi-Fi discovery session changed."))
            closeClient(gatt)
            return
        }
        val encryptedOffer = try {
            clientSecureSession?.encrypt(offer.encoded)
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            emit(linkError("wifi_upgrade_failed", "The Wi-Fi upgrade could not be encrypted."))
            closeClient(gatt)
            return
        }
        pendingPeerFingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        clientPhase = ClientPhase.WIFI_UPGRADE
        startOutgoingTransfer(gatt, characteristic, TransferKind.WIFI_UPGRADE, encryptedOffer)
    }

    private fun startEncryptedCourierWifiUpgrade(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        remotePublicKey: ByteArray,
    ) {
        val context = pendingCourierWifiUpgrade
        val offer = pendingWifiUpgradeOffer
        val currentWifiToken = localWifiToken()
        val fingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        if (
            context == null || offer == null || currentWifiToken == null ||
            fingerprint != context.courierFingerprint ||
            !offer.initiatorToken.contentEquals(currentWifiToken)
        ) {
            emit(linkError("courier_wifi_upgrade_mismatch", "Courier Wi-Fi authorization changed."))
            closeClient(gatt)
            return
        }
        val request = RelayCourierWifiUpgradeRequest(
            objectId = context.objectId.copyOf(),
            planSha256 = context.planSha256.copyOf(),
            encodedWifiOffer = offer.encoded.copyOf(),
        )
        val encrypted = try {
            clientSecureSession?.encrypt(request.encode())
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            emit(linkError("courier_wifi_upgrade_failed", "Courier Wi-Fi authorization failed."))
            closeClient(gatt)
            return
        }
        pendingPeerFingerprint = fingerprint
        clientPhase = ClientPhase.WIFI_UPGRADE
        startOutgoingTransfer(
            gatt,
            characteristic,
            TransferKind.COURIER_WIFI_UPGRADE,
            encrypted,
        )
    }

    private fun startEncryptedRecipientWifiUpgrade(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        remotePublicKey: ByteArray,
    ) {
        val context = pendingRecipientWifiUpgrade
        val offer = pendingWifiUpgradeOffer
        val currentWifiToken = localWifiToken()
        if (
            context == null || offer == null || currentWifiToken == null ||
            !offer.initiatorToken.contentEquals(currentWifiToken)
        ) {
            emit(linkError("recipient_wifi_upgrade_mismatch", "Recipient Wi-Fi authorization changed."))
            closeClient(gatt)
            return
        }
        val request = RelayCourierWifiUpgradeRequest(
            objectId = context.objectId.copyOf(),
            planSha256 = context.planSha256.copyOf(),
            encodedWifiOffer = offer.encoded.copyOf(),
        )
        val encrypted = try {
            clientSecureSession?.encrypt(request.encode())
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            emit(linkError("recipient_wifi_upgrade_failed", "Recipient Wi-Fi authorization failed."))
            closeClient(gatt)
            return
        }
        pendingPeerFingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        clientPhase = ClientPhase.WIFI_UPGRADE
        startOutgoingTransfer(
            gatt,
            characteristic,
            TransferKind.RECIPIENT_WIFI_UPGRADE,
            encrypted,
        )
    }

    private fun startEncryptedMeshRequest(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        prepareReadyAttachmentReceipts()
        val peerFingerprint = activePeerFingerprint
        if (peerFingerprint == null) {
            emit(linkError("identity_missing", "Peer identity is unavailable for mesh sync."))
            closeClient(gatt)
            return
        }
        val encryptedRequest = try {
            val inventory = meshStore.inventory()
            val inventoryBytes = RelayMeshSyncCodec.encodedIdsBytes(inventory)
            val exchangeBudget = (
                RelayMeshSyncCodec.MAX_SYNC_BYTES -
                    RelayMeshSyncCodec.EXCHANGE_HEADER_BYTES - inventoryBytes
                )
                .coerceAtLeast(0)
            pendingMeshProbeOffers = meshStore.routeProbesForPeer(
                peerFingerprint = peerFingerprint,
                maximumProbeBytes = minOf(exchangeBudget, ROUTE_PROBE_BUDGET_BYTES),
                maximumDeliveryBytes = ROUTE_FINAL_DELIVERY_BUDGET_BYTES,
            )
            val probeBytes = RelayMeshSyncCodec.encodedEnvelopesBytes(
                pendingMeshProbeOffers.map { it.probeEnvelope },
            )
            pendingMeshOffers = meshStore.planForPeer(
                peerFingerprint,
                emptyList(),
                (exchangeBudget - probeBytes).coerceAtLeast(0),
            )
            val request = RelayMeshSyncCodec.encodeRequest(
                RelayMeshSyncCodec.Request(
                    inventory = inventory,
                    offeredEnvelopes = pendingMeshOffers.map { it.wireEnvelope },
                    routeProbes = pendingMeshProbeOffers.map { it.probeEnvelope },
                ),
            )
            clientSecureSession?.encrypt(request)
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not prepare mesh inventory exchange", error)
            emit(linkError("mesh_sync_failed", "Relay could not prepare its courier inventory."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.MESH_REQUEST
        emit(
            mapOf(
                "type" to "mesh_sync_started",
                "token" to requirePeerToken(),
                "offered" to pendingMeshOffers.size,
                "probed" to pendingMeshProbeOffers.size,
            ),
        )
        startOutgoingTransfer(gatt, characteristic, TransferKind.MESH_REQUEST, encryptedRequest)
    }

    private fun startEncryptedAttachmentPlan(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        val offer = pendingAttachmentPlanOffer
        if (offer == null) {
            emit(linkError("attachment_plan_missing", "The pending courier plan is unavailable."))
            closeClient(gatt)
            return
        }
        val encryptedOffer = try {
            clientSecureSession?.encrypt(offer.encode())
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not encrypt courier attachment plan", error)
            emit(linkError("attachment_plan_failed", "The courier plan could not be encrypted."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.ATTACHMENT_PLAN
        emit(
            mapOf(
                "type" to "attachment_plan_started",
                "token" to requirePeerToken(),
            ),
        )
        startOutgoingTransfer(
            gatt,
            characteristic,
            TransferKind.ATTACHMENT_PLAN,
            encryptedOffer,
        )
    }

    private fun startEncryptedAttachmentCleanup(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        val context = pendingAttachmentCleanup
        if (context == null || activePeerFingerprint != context.courierFingerprint) {
            emit(linkError("attachment_cleanup_mismatch", "Courier cleanup identity changed."))
            closeClient(gatt)
            return
        }
        val encrypted = try {
            clientSecureSession?.encrypt(context.cleanup.encode())
                ?: throw IllegalStateException("Noise session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not encrypt courier attachment cleanup", error)
            emit(linkError("attachment_cleanup_failed", "Courier cleanup could not be encrypted."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.ATTACHMENT_CLEANUP
        emit(
            mapOf(
                "type" to "attachment_cleanup_started",
                "token" to requirePeerToken(),
                "objectId" to context.cleanup.objectId.toHex(),
            ),
        )
        startOutgoingTransfer(
            gatt,
            characteristic,
            TransferKind.ATTACHMENT_CLEANUP,
            encrypted,
        )
    }

    private fun sendNextDataFrame(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        transfer: OutgoingTransfer,
    ) {
        // ATT permits MTU - 3 bytes, while a GATT attribute value itself is
        // capped at 512 bytes. At Android's maximum MTU (517), MTU - 3 is
        // therefore two bytes too large for writeCharacteristic.
        val maxFrameBytes = minOf(
            negotiatedMtu - ATT_VALUE_OVERHEAD,
            MAX_ATTRIBUTE_VALUE_BYTES,
        )
        val maxChunkBytes = maxFrameBytes - DATA_HEADER_BYTES
        if (maxChunkBytes <= 0 || transfer.nextSequence >= U16_LIMIT) {
            emit(linkError("invalid_transfer_geometry", "The negotiated BLE packet size is unusable."))
            closeClient(gatt)
            return
        }
        val chunkBytes = minOf(maxChunkBytes, transfer.payload.size - transfer.offset)
        val frame = ByteArray(DATA_HEADER_BYTES + chunkBytes)
        frame[0] = MAGIC_0
        frame[1] = MAGIC_1
        frame[2] = PROTOCOL_VERSION
        frame[3] = FRAME_DATA
        putU16(frame, 4, transfer.id)
        putU16(frame, 6, transfer.nextSequence)
        transfer.payload.copyInto(
            frame,
            destinationOffset = DATA_HEADER_BYTES,
            startIndex = transfer.offset,
            endIndex = transfer.offset + chunkBytes,
        )
        transfer.pendingChunkBytes = chunkBytes
        if (!writeFrame(gatt, characteristic, frame, PendingWrite.DATA)) {
            transfer.pendingChunkBytes = 0
            emit(linkError("transfer_fragment_failed", "Could not send the next BLE fragment."))
            closeClient(gatt)
        }
    }

    @SuppressLint("MissingPermission")
    private fun writeFrame(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        frame: ByteArray,
        kind: PendingWrite,
    ): Boolean {
        pendingWrite = kind
        val started = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt.writeCharacteristic(
                    characteristic,
                    frame,
                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                ) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                characteristic.value = frame
                characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                @Suppress("DEPRECATION")
                gatt.writeCharacteristic(characteristic)
            }
        } catch (error: IllegalArgumentException) {
            Log.w(TAG, "Bluetooth stack rejected ${frame.size}-byte attribute value", error)
            false
        }
        if (!started) pendingWrite = null
        return started
    }

    private fun buildStartFrame(transfer: OutgoingTransfer): ByteArray = ByteArray(START_FRAME_BYTES).also {
        it[0] = MAGIC_0
        it[1] = MAGIC_1
        it[2] = PROTOCOL_VERSION
        it[3] = transfer.kind.startFrameType
        putU16(it, 4, transfer.id)
        putU16(it, 6, transfer.payload.size)
        putU32(it, 8, transfer.crc32)
        transfer.sourceToken.copyInto(it, destinationOffset = 12)
    }

    private fun handleInboundFrame(device: BluetoothDevice, frame: ByteArray): ServerWriteResult {
        if (
            frame.size < 4 || frame.size > MAX_ATTRIBUTE_VALUE_BYTES ||
            frame[0] != MAGIC_0 || frame[1] != MAGIC_1 ||
            frame[2] != PROTOCOL_VERSION
        ) {
            return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        }
        return when (frame[3]) {
            FRAME_HANDSHAKE_START -> handleStartFrame(device, frame, TransferKind.HANDSHAKE)
            FRAME_IDENTITY_PROOF_START -> handleStartFrame(
                device,
                frame,
                TransferKind.IDENTITY_PROOF,
            )
            FRAME_CIPHERTEXT_START -> handleStartFrame(device, frame, TransferKind.CIPHERTEXT)
            FRAME_USER_MESSAGE_START -> handleStartFrame(device, frame, TransferKind.USER_MESSAGE)
            FRAME_WIFI_UPGRADE_START -> handleStartFrame(device, frame, TransferKind.WIFI_UPGRADE)
            FRAME_COURIER_WIFI_UPGRADE_START ->
                handleStartFrame(device, frame, TransferKind.COURIER_WIFI_UPGRADE)
            FRAME_RECIPIENT_WIFI_UPGRADE_START ->
                handleStartFrame(device, frame, TransferKind.RECIPIENT_WIFI_UPGRADE)
            FRAME_CONTACT_CARD_START -> handleStartFrame(device, frame, TransferKind.CONTACT_CARD)
            FRAME_MESH_REQUEST_START -> handleStartFrame(device, frame, TransferKind.MESH_REQUEST)
            FRAME_MESH_ACK_START -> handleStartFrame(device, frame, TransferKind.MESH_ACK)
            FRAME_MESH_FINAL_ACK_START -> handleStartFrame(
                device,
                frame,
                TransferKind.MESH_FINAL_ACK,
            )
            FRAME_ATTACHMENT_PLAN_START ->
                handleStartFrame(device, frame, TransferKind.ATTACHMENT_PLAN)
            FRAME_ATTACHMENT_CLEANUP_START ->
                handleStartFrame(device, frame, TransferKind.ATTACHMENT_CLEANUP)
            FRAME_DATA -> handleDataFrame(device, frame)
            else -> ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        }
    }

    private fun handleStartFrame(
        device: BluetoothDevice,
        frame: ByteArray,
        kind: TransferKind,
    ): ServerWriteResult {
        if (frame.size != START_FRAME_BYTES) return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        val totalBytes = readU16(frame, 6)
        val maximum = when (kind) {
            TransferKind.HANDSHAKE -> MAX_HANDSHAKE_BYTES
            TransferKind.IDENTITY_PROOF -> MAX_IDENTITY_PROOF_CIPHERTEXT_BYTES
            TransferKind.CIPHERTEXT -> MAX_TRANSFER_BYTES
            TransferKind.USER_MESSAGE -> MAX_TRANSFER_BYTES
            TransferKind.WIFI_UPGRADE -> MAX_IDENTITY_PROOF_CIPHERTEXT_BYTES
            TransferKind.COURIER_WIFI_UPGRADE -> MAX_COURIER_WIFI_UPGRADE_CIPHERTEXT_BYTES
            TransferKind.RECIPIENT_WIFI_UPGRADE -> MAX_COURIER_WIFI_UPGRADE_CIPHERTEXT_BYTES
            TransferKind.CONTACT_CARD -> MAX_CONTACT_CARD_CIPHERTEXT_BYTES
            TransferKind.MESH_REQUEST -> MAX_MESH_CIPHERTEXT_BYTES
            TransferKind.MESH_ACK -> MAX_MESH_CIPHERTEXT_BYTES
            TransferKind.MESH_FINAL_ACK -> MAX_MESH_CIPHERTEXT_BYTES
            TransferKind.ATTACHMENT_PLAN -> MAX_ATTACHMENT_PLAN_CIPHERTEXT_BYTES
            TransferKind.ATTACHMENT_CLEANUP -> MAX_ATTACHMENT_CLEANUP_CIPHERTEXT_BYTES
        }
        if (totalBytes !in 1..maximum) return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        val transfer = IncomingTransfer(
            id = readU16(frame, 4),
            sourceToken = frame.copyOfRange(12, START_FRAME_BYTES),
            kind = kind,
            expectedCrc32 = readU32(frame, 8),
            payload = ByteArray(totalBytes),
            startedAtMs = SystemClock.elapsedRealtime(),
        )
        inboundTransfers[device] = transfer
        Log.i(TAG, "Accepted transfer start; bytes=$totalBytes")
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to when (kind) {
                    TransferKind.HANDSHAKE -> "secure_handshake_receiving"
                    TransferKind.IDENTITY_PROOF -> "identity_proof_receiving"
                    TransferKind.CIPHERTEXT -> "encrypted_transfer_receiving"
                    TransferKind.USER_MESSAGE -> "text_message_receiving"
                    TransferKind.WIFI_UPGRADE -> "wifi_upgrade_offer_receiving"
                    TransferKind.COURIER_WIFI_UPGRADE -> "courier_wifi_upgrade_receiving"
                    TransferKind.RECIPIENT_WIFI_UPGRADE -> "recipient_wifi_upgrade_receiving"
                    TransferKind.CONTACT_CARD -> "contact_card_receiving"
                    TransferKind.MESH_REQUEST -> "mesh_sync_receiving"
                    TransferKind.MESH_ACK -> "mesh_ack_receiving"
                    TransferKind.MESH_FINAL_ACK -> "mesh_final_ack_receiving"
                    TransferKind.ATTACHMENT_PLAN -> "attachment_plan_receiving"
                    TransferKind.ATTACHMENT_CLEANUP -> "attachment_cleanup_receiving"
                },
                "token" to transfer.sourceToken.toHex(),
                "bytes" to totalBytes,
            ),
        )
    }

    private fun handleDataFrame(device: BluetoothDevice, frame: ByteArray): ServerWriteResult {
        if (frame.size <= DATA_HEADER_BYTES) return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        val transfer = inboundTransfers[device] ?: return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        val transferId = readU16(frame, 4)
        val sequence = readU16(frame, 6)
        val chunkBytes = frame.size - DATA_HEADER_BYTES
        val remaining = transfer.payload.size - transfer.receivedBytes
        if (
            transferId != transfer.id || sequence != transfer.nextSequence ||
            chunkBytes > remaining
        ) {
            inboundTransfers.remove(device)
            return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        }
        frame.copyInto(
            transfer.payload,
            destinationOffset = transfer.receivedBytes,
            startIndex = DATA_HEADER_BYTES,
        )
        transfer.receivedBytes += chunkBytes
        transfer.nextSequence += 1
        transfer.chunks += 1
        if (transfer.receivedBytes != transfer.payload.size) {
            return ServerWriteResult(BluetoothGatt.GATT_SUCCESS)
        }
        inboundTransfers.remove(device)
        if (crc32(transfer.payload) != transfer.expectedCrc32) {
            Log.w(TAG, "Rejected completed transfer with invalid CRC")
            return ServerWriteResult(BluetoothGatt.GATT_FAILURE)
        }
        Log.i(
            TAG,
            "Verified framed ${transfer.kind} payload; " +
                "bytes=${transfer.payload.size} chunks=${transfer.chunks}",
        )
        return processCompletedInboundTransfer(device, transfer)
    }

    private fun processCompletedInboundTransfer(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult = try {
        when (transfer.kind) {
            TransferKind.HANDSHAKE -> processInboundHandshake(device, transfer)
            TransferKind.IDENTITY_PROOF -> processInboundIdentityProof(device, transfer)
            TransferKind.CIPHERTEXT -> processInboundCiphertext(device, transfer)
            TransferKind.USER_MESSAGE -> processInboundTextMessage(device, transfer)
            TransferKind.WIFI_UPGRADE -> processInboundWifiUpgrade(device, transfer)
            TransferKind.COURIER_WIFI_UPGRADE -> processInboundCourierWifiUpgrade(device, transfer)
            TransferKind.RECIPIENT_WIFI_UPGRADE -> processInboundRecipientWifiUpgrade(device, transfer)
            TransferKind.CONTACT_CARD -> processInboundContactCard(device, transfer)
            TransferKind.MESH_REQUEST -> processInboundMeshRequest(device, transfer)
            TransferKind.MESH_ACK -> processInboundMeshAck(device, transfer)
            TransferKind.MESH_FINAL_ACK -> processInboundMeshFinalAck(device, transfer)
            TransferKind.ATTACHMENT_PLAN -> processInboundAttachmentPlan(device, transfer)
            TransferKind.ATTACHMENT_CLEANUP -> processInboundAttachmentCleanup(device, transfer)
        }
    } catch (error: AttachmentPlanDeclinedException) {
        Log.i(TAG, "Declined authenticated courier attachment plan; code=${error.code}")
        pendingServerResponses.remove(device)
        serverSecureStates.remove(device)?.session?.closeQuietly()
        ServerWriteResult(
            error.gattStatus,
            secureLinkError(
                transfer.sourceToken,
                error.code,
                error.message,
                automatic = true,
            ),
        )
    } catch (error: UnverifiedPeerException) {
        Log.w(TAG, "Rejected user content from an unverified peer")
        pendingServerResponses.remove(device)
        serverSecureStates.remove(device)?.session?.closeQuietly()
        ServerWriteResult(
            GATT_RELAY_UNVERIFIED,
            secureLinkError(
                transfer.sourceToken,
                "peer_not_verified",
                "User content was blocked because this identity is not verified.",
            ),
        )
    } catch (error: RuntimeException) {
        Log.w(TAG, "Rejected secure inbound payload", error)
        pendingServerResponses.remove(device)
        serverSecureStates.remove(device)?.session?.closeQuietly()
        if (
            transfer.kind == TransferKind.CIPHERTEXT ||
            transfer.kind == TransferKind.USER_MESSAGE ||
            transfer.kind == TransferKind.WIFI_UPGRADE ||
            transfer.kind == TransferKind.COURIER_WIFI_UPGRADE ||
            transfer.kind == TransferKind.RECIPIENT_WIFI_UPGRADE ||
            transfer.kind == TransferKind.CONTACT_CARD ||
            transfer.kind == TransferKind.MESH_REQUEST ||
            transfer.kind == TransferKind.MESH_ACK ||
            transfer.kind == TransferKind.MESH_FINAL_ACK ||
            transfer.kind == TransferKind.ATTACHMENT_PLAN ||
            transfer.kind == TransferKind.ATTACHMENT_CLEANUP
        ) {
            ServerWriteResult(
                GATT_RELAY_AUTH_REJECTED,
                mapOf(
                    "type" to "secure_payload_rejected",
                    "token" to transfer.sourceToken.toHex(),
                    "message" to "Invalid or unauthenticated ciphertext was rejected.",
                ),
            )
        } else {
            ServerWriteResult(
                BluetoothGatt.GATT_FAILURE,
                secureLinkError(
                    transfer.sourceToken,
                    "secure_processing_failed",
                    "The encrypted link rejected an invalid handshake payload.",
                    automatic = true,
                ),
            )
        }
    }

    private fun processInboundIdentityProof(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Identity proof arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during identity proof."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        check(state.remoteIdentityPublicKey == null) { "Duplicate identity proof was rejected." }
        val signingIdentity = deviceIdentity
            ?: throw IllegalStateException("Device signing identity is unavailable.")
        val binding = state.session.sessionBinding()
        val proofPlaintext = state.session.decrypt(transfer.payload)
        val remote = signingIdentity.verifyProof(
            proofPlaintext,
            binding,
            RelayDeviceIdentity.IdentityRole.INITIATOR,
        )
        state.remoteIdentityPublicKey = remote.publicKey.copyOf()
        val responderProof = signingIdentity.createProof(
            binding,
            RelayDeviceIdentity.IdentityRole.RESPONDER,
        )
        val encryptedResponderProof = state.session.encrypt(responderProof)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_IDENTITY_PROOF,
            payload = encryptedResponderProof,
            crc32 = crc32(encryptedResponderProof),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            // The responder did not originate this UI action. Marking the
            // preliminary proof as automatic lets the product UI hide unknown
            // identities until a full contact card follows, while verified
            // contacts can still be recognized immediately.
            identityVerifiedEvent(
                transfer.sourceToken.toHex(),
                remote.publicKey,
                automatic = true,
            ),
        )
    }

    private fun processInboundHandshake(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val current = serverSecureStates[device]
        val isMessageOne = transfer.payload.size == NOISE_XX_MESSAGE_ONE_BYTES
        val state = if (isMessageOne) {
            // A first Noise message always starts a new logical session. This also
            // recovers safely when a vendor Bluetooth stack omits or delays the old
            // GATT disconnect callback.
            current?.session?.closeQuietly()
            pendingServerResponses.remove(device)
            pendingServerMeshOffers.remove(device)
            pendingServerMeshProbeOffers.remove(device)
            pendingServerRequestedProbeIds.remove(device)
            val responderToken = localToken()
            if (responderToken == null || responderToken.size != TOKEN_LENGTH) {
                throw IllegalStateException("Local responder token is unavailable.")
            }
            val identity = secureIdentity
                ?: throw IllegalStateException("Native secure identity is unavailable.")
            ServerSecureState(
                initiatorToken = transfer.sourceToken.copyOf(),
                session = identity.createSession(
                    isInitiator = false,
                    initiatorToken = transfer.sourceToken,
                    responderToken = responderToken,
                ),
            ).also { serverSecureStates[device] = it }
        } else {
            check(current != null) { "Final handshake message arrived before message one." }
            check(current.initiatorToken.contentEquals(transfer.sourceToken)) {
                "Discovery token changed during secure handshake."
            }
            check(current.awaitingFinalHandshake) {
                "Secure responder is not awaiting a final handshake message."
            }
            current
        }

        val reply = state.session.receiveHandshake(transfer.payload)
        val event = if (reply != null) {
            check(isMessageOne) { "Unexpected responder handshake reply." }
            state.awaitingFinalHandshake = true
            pendingServerResponses[device] = ServerResponse(
                kind = RESPONSE_HANDSHAKE,
                payload = reply,
                crc32 = crc32(reply),
            )
            mapOf(
                "type" to "secure_handshake_reply_ready",
                "token" to transfer.sourceToken.toHex(),
            )
        } else {
            check(!isMessageOne) { "Responder produced no reply to handshake message one." }
            check(state.session.isEstablished()) { "Responder handshake did not establish." }
            state.awaitingFinalHandshake = false
            mapOf(
                "type" to "secure_session_established",
                "token" to transfer.sourceToken.toHex(),
            )
        }
        return ServerWriteResult(BluetoothGatt.GATT_SUCCESS, event)
    }

    private fun processInboundCiphertext(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Ciphertext arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during encrypted transfer."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        check(state.remoteIdentityPublicKey != null) {
            "Ciphertext arrived before device identity authentication."
        }
        val plaintext = state.session.decrypt(transfer.payload)
        check(
            plaintext.size == ENGINEERING_PAYLOAD_BYTES &&
                plaintext.copyOfRange(0, ENGINEERING_PAYLOAD_PREFIX.size)
                    .contentEquals(ENGINEERING_PAYLOAD_PREFIX),
        ) { "Decrypted engineering payload has invalid structure." }
        val plaintextCrc32 = crc32(plaintext)
        val receipt = buildReceipt(plaintext.size, plaintextCrc32)
        val encryptedReceipt = state.session.encrypt(receipt)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_ENCRYPTED_RECEIPT,
            payload = encryptedReceipt,
            crc32 = crc32(encryptedReceipt),
        )
        val elapsedMs = (SystemClock.elapsedRealtime() - transfer.startedAtMs).coerceAtLeast(1L)
        val throughputBps = (plaintext.size * 1_000L / elapsedMs).toInt()
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "encrypted_transfer_received",
                "token" to transfer.sourceToken.toHex(),
                "bytes" to plaintext.size,
                "chunks" to transfer.chunks,
                "elapsedMs" to elapsedMs,
                "throughputBps" to throughputBps,
            ),
        )
    }

    private fun processInboundTextMessage(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Message arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during message transfer."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Message arrived before device identity authentication.")
        if (trustStore.stateFor(remotePublicKey) != RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            throw UnverifiedPeerException()
        }
        val plaintext = state.session.decrypt(transfer.payload)
        val message = RelayMessageCodec.decode(plaintext)
        val signingIdentity = deviceIdentity
            ?: throw IllegalStateException("Device signing identity is unavailable.")
        val fingerprint = signingIdentity.safetyFingerprint(remotePublicKey)
        // The database commit completes before a delivery receipt is created.
        val incomingStoreStartedAtMs = SystemClock.elapsedRealtime()
        val inserted = messageStore.storeIncoming(message, fingerprint)
        val incomingStoredAtMs = SystemClock.elapsedRealtime()
        Log.i(
            METRICS_TAG,
            "text_timing role=recipient stage=durable_message total_ms=" +
                "${incomingStoredAtMs - transfer.startedAtMs} store_ms=" +
                "${incomingStoredAtMs - incomingStoreStartedAtMs} duplicate=${!inserted}",
        )
        val receipt = RelayMessageCodec.createReceipt(message.id)
        val encryptedReceipt = state.session.encrypt(receipt)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_MESSAGE_RECEIPT,
            payload = encryptedReceipt,
            crc32 = crc32(encryptedReceipt),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to if (inserted) "text_message_received" else "text_message_duplicate",
                "token" to transfer.sourceToken.toHex(),
                "messageId" to RelayMessageCodec.idHex(message.id),
                "text" to message.text,
                "fingerprint" to fingerprint,
            ) + message.replyMap(),
        )
    }

    private fun processInboundWifiUpgrade(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Wi-Fi upgrade arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during Wi-Fi upgrade."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Wi-Fi upgrade arrived before identity authentication.")
        if (trustStore.stateFor(remotePublicKey) != RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            throw UnverifiedPeerException()
        }
        val plaintext = state.session.decrypt(transfer.payload)
        val offer = RelayMessageCodec.decodeWifiUpgradeOffer(plaintext)
        val currentWifiToken = localWifiToken()
            ?: throw IllegalStateException("Wi-Fi Direct discovery is not active.")
        check(
            offer.responderToken.all { it == 0.toByte() } ||
                offer.responderToken.contentEquals(currentWifiToken),
        ) {
            "Wi-Fi responder token does not match this session."
        }
        val signingIdentity = deviceIdentity
            ?: throw IllegalStateException("Device signing identity is unavailable.")
        val fingerprint = signingIdentity.safetyFingerprint(remotePublicKey)
        onWifiUpgradeAuthorized(
            RelayWifiUpgradeAuthorization(
                offerId = offer.offerId.copyOf(),
                psk = offer.psk.copyOf(),
                initiatorToken = offer.initiatorToken.copyOf(),
                responderToken = currentWifiToken.copyOf(),
                peerFingerprint = fingerprint,
                isInitiator = false,
            ),
        )
        val ack = RelayMessageCodec.createWifiUpgradeAck(offer, currentWifiToken)
        val encryptedAck = state.session.encrypt(ack)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_WIFI_UPGRADE_ACK,
            payload = encryptedAck,
            crc32 = crc32(encryptedAck),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "wifi_upgrade_authorized",
                "token" to transfer.sourceToken.toHex(),
                "fingerprint" to fingerprint,
                "role" to "responder",
            ),
        )
    }

    private fun processInboundCourierWifiUpgrade(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Courier Wi-Fi upgrade arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during courier Wi-Fi upgrade."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Courier Wi-Fi upgrade arrived before identity authentication.")
        val request = RelayCourierWifiUpgradeRequest.decode(state.session.decrypt(transfer.payload))
        val durableCustody = courierAttachmentStore.custody(request.objectId)
            ?.let(RelayCourierAttachmentCustody::decode)
            ?: throw IllegalStateException("Courier Wi-Fi authorization has no durable plan.")
        check(
            MessageDigest.isEqual(durableCustody.planSha256, request.planSha256) &&
                durableCustody.missingChunks().isNotEmpty(),
        ) { "Courier Wi-Fi authorization is complete or belongs to another plan." }
        val offer = RelayMessageCodec.decodeWifiUpgradeOffer(request.encodedWifiOffer)
        val currentWifiToken = localWifiToken()
            ?: throw IllegalStateException("Wi-Fi Direct discovery is not active.")
        check(
            offer.responderToken.all { it == 0.toByte() } ||
                offer.responderToken.contentEquals(currentWifiToken),
        ) { "Courier Wi-Fi responder token does not match this session." }
        val signingIdentity = deviceIdentity
            ?: throw IllegalStateException("Device signing identity is unavailable.")
        val fingerprint = signingIdentity.safetyFingerprint(remotePublicKey)
        onWifiUpgradeAuthorized(
            RelayWifiUpgradeAuthorization(
                offerId = offer.offerId.copyOf(),
                psk = offer.psk.copyOf(),
                initiatorToken = offer.initiatorToken.copyOf(),
                responderToken = currentWifiToken.copyOf(),
                peerFingerprint = fingerprint,
                isInitiator = false,
            ),
        )
        val ack = RelayMessageCodec.createWifiUpgradeAck(offer, currentWifiToken)
        val encryptedAck = state.session.encrypt(ack)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_WIFI_UPGRADE_ACK,
            payload = encryptedAck,
            crc32 = crc32(encryptedAck),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "courier_wifi_upgrade_authorized",
                "token" to transfer.sourceToken.toHex(),
                "objectId" to request.objectId.toHex(),
                "fingerprint" to fingerprint,
                "role" to "responder",
            ),
        )
    }

    private fun processInboundRecipientWifiUpgrade(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Recipient Wi-Fi upgrade arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during recipient Wi-Fi upgrade."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Recipient Wi-Fi upgrade arrived before identity authentication.")
        val request = RelayCourierWifiUpgradeRequest.decode(state.session.decrypt(transfer.payload))
        val encodedPlan = courierAttachmentStore.plan(request.objectId)
            ?: throw IllegalStateException("Requested courier attachment plan is unavailable.")
        val plan = RelayCourierAttachmentPlan.decode(encodedPlan)
        val custody = courierAttachmentStore.custody(request.objectId)
            ?.let(RelayCourierAttachmentCustody::decode)
            ?: throw IllegalStateException("Requested courier attachment custody is unavailable.")
        check(
            MessageDigest.isEqual(plan.sha256(), request.planSha256) &&
                MessageDigest.isEqual(custody.planSha256, request.planSha256) &&
                custody.missingChunks().isEmpty(),
        ) { "Requested courier attachment is incomplete or belongs to another plan." }
        val offer = RelayMessageCodec.decodeWifiUpgradeOffer(request.encodedWifiOffer)
        val currentWifiToken = localWifiToken()
            ?: throw IllegalStateException("Wi-Fi Direct discovery is not active.")
        check(
            offer.responderToken.all { it == 0.toByte() } ||
                offer.responderToken.contentEquals(currentWifiToken),
        ) { "Recipient Wi-Fi responder token does not match this session." }
        val fingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        onWifiUpgradeAuthorized(
            RelayWifiUpgradeAuthorization(
                offerId = offer.offerId.copyOf(),
                psk = offer.psk.copyOf(),
                initiatorToken = offer.initiatorToken.copyOf(),
                responderToken = currentWifiToken.copyOf(),
                peerFingerprint = fingerprint,
                isInitiator = false,
            ),
        )
        val ack = RelayMessageCodec.createWifiUpgradeAck(offer, currentWifiToken)
        val encryptedAck = state.session.encrypt(ack)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_WIFI_UPGRADE_ACK,
            payload = encryptedAck,
            crc32 = crc32(encryptedAck),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "recipient_wifi_upgrade_authorized",
                "token" to transfer.sourceToken.toHex(),
                "objectId" to request.objectId.toHex(),
                "fingerprint" to fingerprint,
                "role" to "responder",
            ),
        )
    }

    private fun processInboundAttachmentPlan(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Attachment plan arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during attachment custody."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        check(state.remoteIdentityPublicKey != null) {
            "Attachment plan arrived before device identity authentication."
        }
        val plaintextOffer = state.session.decrypt(transfer.payload)
        val offer = RelayAttachmentPlanOffer.decode(plaintextOffer)
        val outcome = RelayAttachmentPlanControl.accept(
            courierAttachmentStore,
            plaintextOffer,
        )
        val custody = when (outcome) {
            is RelayAttachmentPlanControl.Outcome.Custodied -> outcome
            is RelayAttachmentPlanControl.Outcome.Declined -> when (outcome.reason) {
                RelayAttachmentPlanControl.DeclineReason.STORE_FULL ->
                    throw AttachmentPlanDeclinedException(
                        GATT_RELAY_COURIER_STORE_FULL,
                        "courier_store_full",
                        "The courier has no safe attachment capacity.",
                    )
                RelayAttachmentPlanControl.DeclineReason.EXPIRED ->
                    throw AttachmentPlanDeclinedException(
                        GATT_RELAY_ATTACHMENT_EXPIRED,
                        "attachment_expired",
                        "The attachment plan expired before custody.",
                    )
                RelayAttachmentPlanControl.DeclineReason.TERMINAL ->
                    throw AttachmentPlanDeclinedException(
                        GATT_RELAY_ATTACHMENT_TERMINAL,
                        "attachment_terminal",
                        "The courier has terminal state for this object.",
                    )
            }
        }
        val manifestAdmission = meshStore.ingestEnvelope(offer.encodedManifest)
        check(
            manifestAdmission is RelayMeshStore.IngestResult.CourierStored ||
                manifestAdmission is RelayMeshStore.IngestResult.AttachmentManifestStored,
        ) { "Courier attachment manifest could not enter the durable mesh." }
        Log.i(TAG, "Durable courier attachment plan admitted")
        val encryptedCustody = state.session.encrypt(custody.encodedCustody)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_ATTACHMENT_CUSTODY,
            payload = encryptedCustody,
            crc32 = crc32(encryptedCustody),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "attachment_plan_custodied",
                "token" to transfer.sourceToken.toHex(),
                "planCommitted" to true,
                "chunkCount" to custody.chunkCount,
                "missingBitmap" to custody.missingBitmap.copyOf(),
                "missingChunks" to custody.missingChunks,
                "inserted" to custody.inserted,
            ),
        )
    }

    private fun processInboundAttachmentCleanup(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Attachment cleanup arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during attachment cleanup."
        }
        check(state.session.isEstablished() && state.remoteIdentityPublicKey != null) {
            "Attachment cleanup arrived before identity authentication."
        }
        val cleanup = RelayCourierAttachmentCleanup.decode(state.session.decrypt(transfer.payload))
        try {
            val completion = courierAttachmentStore.applyRecipientCompletion(cleanup)
            if (completion != RelayCourierAttachmentStore.CompletionResult.NOT_FOUND) {
                meshStore.removeReceiptConfirmedCourierManifest(cleanup.objectId)
            }
            val acknowledgement = RelayCourierAttachmentCleanupAck(
                objectId = cleanup.objectId.copyOf(),
                planSha256 = cleanup.planSha256.copyOf(),
            )
            val encryptedAck = state.session.encrypt(acknowledgement.encode())
            pendingServerResponses[device] = ServerResponse(
                kind = RESPONSE_ATTACHMENT_CLEANUP_ACK,
                payload = encryptedAck,
                crc32 = crc32(encryptedAck),
            )
            return ServerWriteResult(
                BluetoothGatt.GATT_SUCCESS,
                mapOf(
                    "type" to "attachment_courier_copy_removed",
                    "token" to transfer.sourceToken.toHex(),
                    "objectId" to cleanup.objectId.toHex(),
                ),
            )
        } finally {
            cleanup.cancellationSecret.fill(0)
        }
    }

    private fun processInboundContactCard(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Contact card arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during contact exchange."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Contact card arrived before identity authentication.")
        val fingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        val remoteCard = RelayContactCard.decode(state.session.decrypt(transfer.payload))
        val localCard = meshStore.localContactCard(fingerprint)
        var contact = meshStore.acceptRemoteContactCard(fingerprint, remoteCard)
        if (trustStore.stateFor(remotePublicKey) == RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            meshStore.markVerified(fingerprint)
            contact = requireNotNull(meshStore.contact(fingerprint))
        }
        val encryptedLocalCard = state.session.encrypt(localCard.encode())
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_CONTACT_CARD,
            payload = encryptedLocalCard,
            crc32 = crc32(encryptedLocalCard),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "contact_exchange_ready",
                "token" to transfer.sourceToken.toHex(),
                "fingerprint" to fingerprint,
                "displayName" to contact.displayName,
                "relayId" to requireNotNull(contact.relayId),
                "trustState" to if (contact.verified) "verified" else "unverified",
            ),
        )
    }

    private fun processInboundMeshRequest(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Mesh request arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during mesh sync."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Mesh request arrived before identity authentication.")
        val fingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        val request = RelayMeshSyncCodec.decodeRequest(state.session.decrypt(transfer.payload))
        prepareReadyAttachmentReceipts()
        val received = ingestMeshOffers(
            request.offeredEnvelopes,
            destinationOnly = false,
            logLabel = "request offer",
        )
        val requestedProbeIds = meshStore.recognizedRouteProbeIds(request.routeProbes)
        pendingServerRequestedProbeIds[device] = requestedProbeIds
        val responseBudget = (
            RelayMeshSyncCodec.MAX_SYNC_BYTES - RelayMeshSyncCodec.EXCHANGE_HEADER_BYTES -
                RelayMeshSyncCodec.encodedIdsBytes(received.acceptedIds) -
                RelayMeshSyncCodec.encodedIdsBytes(requestedProbeIds)
            ).coerceAtLeast(0)
        val probeOffers = meshStore.routeProbesForPeer(
            peerFingerprint = fingerprint,
            maximumProbeBytes = minOf(responseBudget, ROUTE_PROBE_BUDGET_BYTES),
            maximumDeliveryBytes = ROUTE_FINAL_DELIVERY_BUDGET_BYTES,
        )
        val probeBytes = RelayMeshSyncCodec.encodedEnvelopesBytes(
            probeOffers.map { it.probeEnvelope },
        )
        val offers = meshStore.planForPeer(
            fingerprint,
            request.inventory,
            (responseBudget - probeBytes).coerceAtLeast(0),
        )
        pendingServerMeshOffers[device] = offers
        pendingServerMeshProbeOffers[device] = probeOffers
        val response = RelayMeshSyncCodec.encodeResponse(
            RelayMeshSyncCodec.Response(
                acceptedOfferIds = received.acceptedIds,
                offeredEnvelopes = offers.map { it.wireEnvelope },
                requestedProbeIds = requestedProbeIds,
                routeProbes = probeOffers.map { it.probeEnvelope },
            ),
        )
        val encryptedResponse = state.session.encrypt(response)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_MESH_SYNC,
            payload = encryptedResponse,
            crc32 = crc32(encryptedResponse),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "mesh_sync_response_ready",
                "token" to transfer.sourceToken.toHex(),
                "accepted" to received.acceptedIds.size,
                "offered" to offers.size,
                "probed" to probeOffers.size,
                "requestedProbes" to requestedProbeIds.size,
                "delivered" to received.delivered,
                "receiptsApplied" to received.receiptsApplied,
                "attachmentReceiptsApplied" to received.attachmentReceiptsApplied,
                "wireBytesSent" to encryptedResponse.size,
            ),
        )
    }

    private fun processInboundMeshAck(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Mesh acknowledgement arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during mesh acknowledgement."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Mesh acknowledgement arrived before identity authentication.")
        val fingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        val ack = RelayMeshSyncCodec.decodeAck(state.session.decrypt(transfer.payload))
        val offers = pendingServerMeshOffers.remove(device).orEmpty()
        meshStore.commitForwarded(fingerprint, offers, ack.acceptedOfferIds)
        val expectedFinalIds = pendingServerRequestedProbeIds.remove(device).orEmpty()
        check(
            ack.requestedEnvelopes.map { RelayMeshEnvelope.decode(it).idHex() }.toSet() ==
                expectedFinalIds.map { it.toHex() }.toSet(),
        ) { "Mesh acknowledgement did not contain the requested destination envelopes." }
        val acceptedFinals = ingestMeshOffers(
            ack.requestedEnvelopes,
            destinationOnly = true,
            logLabel = "requested destination envelope",
        )
        val probeOffers = pendingServerMeshProbeOffers[device].orEmpty()
        val requestedEnvelopes = meshStore.requestedProbeEnvelopes(
            probeOffers,
            ack.requestedProbeIds,
        )
        val completionPlaintext = RelayMeshSyncCodec.encodeCompletion(
            RelayMeshSyncCodec.Completion(
                acceptedProbeIds = acceptedFinals.acceptedIds,
                requestedEnvelopes = requestedEnvelopes,
            ),
        )
        val completion = state.session.encrypt(completionPlaintext)
        pendingServerResponses[device] = ServerResponse(
            kind = RESPONSE_MESH_COMPLETE,
            payload = completion,
            crc32 = crc32(completion),
        )
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "mesh_sync_completed",
                "token" to transfer.sourceToken.toHex(),
                "forwarded" to ack.acceptedOfferIds.size,
                "finalDelivered" to acceptedFinals.acceptedIds.size,
                "requestedProbes" to ack.requestedProbeIds.size,
                "wireBytesSent" to completion.size,
            ),
        )
    }

    private fun processInboundMeshFinalAck(
        device: BluetoothDevice,
        transfer: IncomingTransfer,
    ): ServerWriteResult {
        val state = serverSecureStates[device]
            ?: throw IllegalStateException("Mesh final acknowledgement arrived before a secure handshake.")
        check(state.initiatorToken.contentEquals(transfer.sourceToken)) {
            "Discovery token changed during mesh final acknowledgement."
        }
        check(state.session.isEstablished()) { "Secure responder is not established." }
        val remotePublicKey = state.remoteIdentityPublicKey
            ?: throw IllegalStateException("Mesh final acknowledgement arrived before identity authentication.")
        val fingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remotePublicKey)
        val accepted = RelayMeshSyncCodec.decodeFinalAck(state.session.decrypt(transfer.payload))
        val offers = pendingServerMeshProbeOffers.remove(device).orEmpty()
        meshStore.commitProbed(fingerprint, offers, accepted)
        pendingServerRequestedProbeIds.remove(device)
        return ServerWriteResult(
            BluetoothGatt.GATT_SUCCESS,
            mapOf(
                "type" to "mesh_sync_finalized",
                "token" to transfer.sourceToken.toHex(),
                "finalDelivered" to accepted.size,
            ),
        )
    }

    private fun ingestMeshOffers(
        envelopes: Collection<ByteArray>,
        destinationOnly: Boolean,
        logLabel: String,
    ): MeshIngestBatch {
        val accepted = mutableListOf<ByteArray>()
        var delivered = 0
        var receiptsApplied = 0
        var attachmentReceiptsApplied = 0
        for (wire in envelopes) {
            try {
                when (val result = meshStore.ingestEnvelope(wire, destinationOnly)) {
                    is RelayMeshStore.IngestResult.CourierStored -> Unit
                    is RelayMeshStore.IngestResult.Delivered -> {
                        delivered += 1
                        if (result.inserted) {
                            emit(
                                buildMap {
                                    put("type", "text_message_received")
                                    put("messageId", result.messageId.toHex())
                                    put("text", result.text)
                                    put("fingerprint", result.peerFingerprint)
                                    put("transport", "mesh")
                                    result.replyToMessageId?.let {
                                        put("replyToMessageId", it.toHex())
                                        put("replyPreview", requireNotNull(result.replyPreview))
                                    }
                                },
                            )
                        }
                    }
                    is RelayMeshStore.IngestResult.ReceiptApplied -> receiptsApplied += 1
                    is RelayMeshStore.IngestResult.AttachmentManifestStored -> Unit
                    is RelayMeshStore.IngestResult.AttachmentReceiptApplied ->
                        attachmentReceiptsApplied += 1
                    is RelayMeshStore.IngestResult.ProbeDeclined -> continue
                    is RelayMeshStore.IngestResult.StoreFull -> continue
                    is RelayMeshStore.IngestResult.Expired -> continue
                }
                accepted += RelayMeshEnvelope.decode(wire).messageId
            } catch (error: RuntimeException) {
                Log.w(TAG, "Rejected one invalid mesh $logLabel", error)
            }
        }
        if (attachmentReceiptsApplied > 0) reconcileSenderAttachmentReceipts()
        return MeshIngestBatch(accepted, delivered, receiptsApplied, attachmentReceiptsApplied)
    }

    /** Makes READY -> HAR1 crash recovery part of ordinary high-priority mesh inventory. */
    private fun prepareReadyAttachmentReceipts() {
        try {
            val queued = meshStore.queueReadyRecipientAttachmentReceipts(attachmentStore)
            if (queued > 0) Log.i(TAG, "Queued $queued recipient attachment receipt(s)")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not prepare pending recipient attachment receipts", error)
        }
    }

    /** Applies only already-authenticated durable HAR1 facts to the attachment payload store. */
    private fun reconcileSenderAttachmentReceipts() {
        val pending = try {
            meshStore.pendingSenderAttachmentReceipts()
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not inspect authenticated attachment receipts", error)
            return
        }
        pending.forEach { receipt ->
            try {
                val stored = attachmentStore.findByHexId(receipt.objectId.toHex())
                    ?: throw IllegalStateException("HAR1 attachment metadata is unavailable.")
                require(
                    stored.direction == RelayAttachmentStore.Direction.OUTGOING &&
                        stored.peerFingerprint == receipt.recipientFingerprint,
                ) { "HAR1 attachment recipient binding is invalid." }
                attachmentStore.markDelivered(receipt.objectId)
                courierAttachmentStore.applyRecipientReceipt(
                    receipt.objectId,
                    receipt.planSha256,
                )
                meshStore.markSenderAttachmentReceiptLocallyApplied(receipt.objectId)
                val delivered = requireNotNull(
                    attachmentStore.findByHexId(receipt.objectId.toHex()),
                ) { "Delivered attachment metadata disappeared." }
                emit(
                    delivered.toMap() + mapOf(
                        "type" to "attachment_delivered",
                        "fingerprint" to receipt.recipientFingerprint,
                        "transport" to "mesh_receipt",
                        "recipientAuthenticated" to true,
                    ),
                )
            } catch (error: RuntimeException) {
                Log.w(TAG, "Could not finish authenticated attachment receipt application", error)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun beginReadingResponse(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        responseAccumulator = null
        scheduleTimeout(TRANSFER_TIMEOUT_MS)
        requestNextResponseChunk(gatt, characteristic)
    }

    @SuppressLint("MissingPermission")
    private fun requestNextResponseChunk(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
    ) {
        if (!gatt.readCharacteristic(characteristic)) {
            emit(linkError("secure_response_read_failed", "Could not read the secure peer response."))
            closeClient(gatt)
        }
    }

    private fun handleCharacteristicRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
        status: Int,
    ) {
        if (characteristic.uuid != TRANSFER_CHARACTERISTIC_UUID) return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            Log.w(
                TAG,
                "Secure response read failed; status=$status phase=$clientPhase " +
                    "purpose=$linkPurpose mtu=$negotiatedMtu",
            )
            emit(linkError("secure_response_read_failed", "The secure peer response failed ($status)."))
            closeClient(gatt)
            return
        }
        val completed = try {
            acceptResponseChunk(value)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Rejected malformed secure response chunk", error)
            emit(linkError("invalid_secure_response", "The secure peer response was malformed."))
            closeClient(gatt)
            return
        }
        if (completed == null) {
            requestNextResponseChunk(gatt, characteristic)
            return
        }
        when (completed.kind) {
            RESPONSE_HANDSHAKE -> processClientHandshakeReply(
                gatt,
                characteristic,
                completed.payload,
            )
            RESPONSE_IDENTITY_PROOF -> processClientIdentityProof(
                gatt,
                characteristic,
                completed.payload,
            )
            RESPONSE_CONTACT_CARD -> processClientContactCard(
                gatt,
                characteristic,
                completed.payload,
            )
            RESPONSE_ENCRYPTED_RECEIPT -> processClientReceipt(gatt, completed.payload)
            RESPONSE_MESSAGE_RECEIPT -> processClientMessageReceipt(gatt, completed.payload)
            RESPONSE_WIFI_UPGRADE_ACK -> processClientWifiUpgradeAck(gatt, completed.payload)
            RESPONSE_MESH_SYNC -> processClientMeshResponse(
                gatt,
                characteristic,
                completed.payload,
            )
            RESPONSE_MESH_COMPLETE -> processClientMeshComplete(gatt, completed.payload)
            RESPONSE_ATTACHMENT_CUSTODY ->
                processClientAttachmentCustody(gatt, completed.payload)
            RESPONSE_ATTACHMENT_CLEANUP_ACK ->
                processClientAttachmentCleanupAck(gatt, completed.payload)
            else -> {
                emit(linkError("invalid_secure_response", "The secure peer response type is unknown."))
                closeClient(gatt)
            }
        }
    }

    private fun acceptResponseChunk(frame: ByteArray): CompletedResponse? {
        check(frame.size > RESPONSE_HEADER_BYTES) { "Response frame is too short." }
        check(frame.size <= MAX_ATTRIBUTE_VALUE_BYTES) { "Response frame is too large." }
        check(
            frame[0] == MAGIC_0 && frame[1] == MAGIC_1 &&
                frame[2] == PROTOCOL_VERSION && frame[3] == FRAME_RESPONSE,
        ) { "Response frame prefix is invalid." }
        val kind = frame[4]
        check(
            kind == RESPONSE_HANDSHAKE || kind == RESPONSE_IDENTITY_PROOF ||
                kind == RESPONSE_ENCRYPTED_RECEIPT || kind == RESPONSE_MESSAGE_RECEIPT ||
                kind == RESPONSE_WIFI_UPGRADE_ACK || kind == RESPONSE_CONTACT_CARD ||
                kind == RESPONSE_MESH_SYNC || kind == RESPONSE_MESH_COMPLETE ||
                kind == RESPONSE_ATTACHMENT_CUSTODY ||
                kind == RESPONSE_ATTACHMENT_CLEANUP_ACK,
        ) {
            "Response kind is invalid."
        }
        val sequence = readU16(frame, 5)
        val totalBytes = readU16(frame, 7)
        val chunkOffset = readU16(frame, 9)
        val expectedCrc32 = readU32(frame, 11)
        check(totalBytes in 1..MAX_RESPONSE_BYTES) { "Response length is invalid." }
        val accumulator = responseAccumulator ?: ResponseAccumulator(
            kind = kind,
            payload = ByteArray(totalBytes),
            expectedCrc32 = expectedCrc32,
        ).also { responseAccumulator = it }
        check(accumulator.kind == kind) { "Response kind changed between chunks." }
        check(accumulator.payload.size == totalBytes) { "Response length changed between chunks." }
        check(accumulator.expectedCrc32 == expectedCrc32) { "Response checksum changed." }
        check(sequence == accumulator.nextSequence) { "Response sequence is out of order." }
        check(chunkOffset == accumulator.receivedBytes) { "Response offset is out of order." }
        val chunkBytes = frame.size - RESPONSE_HEADER_BYTES
        check(chunkBytes <= accumulator.payload.size - accumulator.receivedBytes) {
            "Response chunk exceeds its declared length."
        }
        frame.copyInto(
            accumulator.payload,
            destinationOffset = accumulator.receivedBytes,
            startIndex = RESPONSE_HEADER_BYTES,
        )
        accumulator.receivedBytes += chunkBytes
        accumulator.nextSequence += 1
        if (accumulator.receivedBytes != accumulator.payload.size) return null
        check(crc32(accumulator.payload) == accumulator.expectedCrc32) {
            "Response checksum is invalid."
        }
        responseAccumulator = null
        return CompletedResponse(accumulator.kind, accumulator.payload)
    }

    private fun processClientHandshakeReply(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        messageTwo: ByteArray,
    ) {
        if (clientPhase != ClientPhase.HANDSHAKE_MESSAGE_1) {
            emit(linkError("invalid_secure_state", "Noise handshake reply arrived out of order."))
            closeClient(gatt)
            return
        }
        val messageThree = try {
            val session = clientSecureSession
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            val reply = session.receiveHandshake(messageTwo)
                ?: throw IllegalStateException("Noise initiator produced no third message.")
            check(session.isEstablished()) { "Noise initiator did not establish." }
            reply
        } catch (error: RuntimeException) {
            Log.w(TAG, "Noise handshake rejected message two", error)
            emit(linkError("secure_handshake_failed", "The encrypted handshake was rejected."))
            closeClient(gatt)
            return
        }
        clientPhase = ClientPhase.HANDSHAKE_MESSAGE_3
        startOutgoingTransfer(gatt, characteristic, TransferKind.HANDSHAKE, messageThree)
    }

    private fun processClientIdentityProof(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        encryptedProof: ByteArray,
    ) {
        if (clientPhase != ClientPhase.IDENTITY_PROOF) {
            emit(linkError("invalid_secure_state", "Device identity proof arrived out of order."))
            closeClient(gatt)
            return
        }
        val remote = try {
            val session = clientSecureSession
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            val signingIdentity = deviceIdentity
                ?: throw IllegalStateException("Device signing identity is unavailable.")
            val proof = session.decrypt(encryptedProof)
            signingIdentity.verifyProof(
                proof,
                session.sessionBinding(),
                RelayDeviceIdentity.IdentityRole.RESPONDER,
            )
        } catch (error: RuntimeException) {
            Log.w(TAG, "Responder identity proof verification failed", error)
            emit(linkError("identity_proof_rejected", "The peer's device identity proof was rejected."))
            closeClient(gatt)
            return
        }
        clientRemoteIdentityPublicKey = remote.publicKey.copyOf()
        activePeerFingerprint = requireNotNull(deviceIdentity).safetyFingerprint(remote.publicKey)
        emit(
            identityVerifiedEvent(
                requirePeerToken(),
                remote.publicKey,
                automatic = identityRefreshAutomatic,
            ),
        )
        if (
            linkPurpose == LinkPurpose.IDENTITY &&
            identityRefreshAutomatic &&
            trustStore.stateFor(remote.publicKey) != RelayPeerTrustStore.PeerTrustState.VERIFIED
        ) {
            emit(
                mapOf(
                    "type" to "identity_refresh_skipped",
                    "token" to requirePeerToken(),
                    "automatic" to true,
                ),
            )
            closeClient(gatt, disconnect = true)
            return
        }
        if (linkPurpose == LinkPurpose.IDENTITY || linkPurpose == LinkPurpose.USER_TEXT) {
            startClientContactCard(gatt, characteristic)
        } else {
            startEncryptedPayload(gatt, characteristic)
        }
    }

    private fun processClientContactCard(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        encryptedCard: ByteArray,
    ) {
        if (clientPhase != ClientPhase.CONTACT_CARD) {
            emit(linkError("invalid_secure_state", "Contact card arrived out of order."))
            closeClient(gatt)
            return
        }
        var contact = try {
            val fingerprint = activePeerFingerprint
                ?: throw IllegalStateException("Peer fingerprint is unavailable.")
            val plaintext = clientSecureSession?.decrypt(encryptedCard)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            val accepted = meshStore.acceptRemoteContactCard(fingerprint, RelayContactCard.decode(plaintext))
            val remoteKey = clientRemoteIdentityPublicKey
            if (remoteKey != null && trustStore.stateFor(remoteKey) == RelayPeerTrustStore.PeerTrustState.VERIFIED) {
                meshStore.markVerified(fingerprint)
                requireNotNull(meshStore.contact(fingerprint))
            } else {
                accepted
            }
        } catch (error: RuntimeException) {
            Log.w(TAG, "Responder contact card verification failed", error)
            emit(linkError("contact_exchange_failed", "The peer's Relay contact card was rejected."))
            closeClient(gatt)
            return
        }
        emit(
            mapOf(
                "type" to "contact_ready",
                "token" to requirePeerToken(),
                "fingerprint" to contact.deviceFingerprint,
                "displayName" to contact.displayName,
                "relayId" to requireNotNull(contact.relayId),
                "trustState" to if (contact.verified) "verified" else "unverified",
            ),
        )
        if (linkPurpose == LinkPurpose.IDENTITY) {
            emit(
                buildMap {
                    put("type", "peer_identity_ready")
                    put("token", requirePeerToken())
                    if (identityRefreshAutomatic) put("automatic", true)
                },
            )
            if (identityRefreshAutomatic && contact.verified) {
                enterWarmTextSession(gatt)
            } else {
                closeClient(gatt, disconnect = true)
            }
        } else {
            startEncryptedPayload(gatt, characteristic)
        }
    }

    private fun processClientMeshResponse(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        encryptedResponse: ByteArray,
    ) {
        if (clientPhase != ClientPhase.MESH_REQUEST) {
            emit(linkError("invalid_secure_state", "Mesh response arrived out of order."))
            closeClient(gatt)
            return
        }
        val peerFingerprint = activePeerFingerprint
        if (peerFingerprint == null) {
            emit(linkError("identity_missing", "Peer identity is unavailable for mesh sync."))
            closeClient(gatt)
            return
        }
        val response = try {
            val plaintext = clientSecureSession?.decrypt(encryptedResponse)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            RelayMeshSyncCodec.decodeResponse(plaintext)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Mesh response authentication failed", error)
            emit(linkError("mesh_sync_failed", "The peer's courier inventory was rejected."))
            closeClient(gatt)
            return
        }
        val received = ingestMeshOffers(
            response.offeredEnvelopes,
            destinationOnly = false,
            logLabel = "response offer",
        )
        try {
            meshStore.commitForwarded(
                peerFingerprint,
                pendingMeshOffers,
                response.acceptedOfferIds,
            )
            pendingMeshSent = response.acceptedOfferIds.size
            val requestedEnvelopes = meshStore.requestedProbeEnvelopes(
                pendingMeshProbeOffers,
                response.requestedProbeIds,
            )
            pendingMeshRequestedPeerProbeIds = meshStore.recognizedRouteProbeIds(
                response.routeProbes,
            )
            pendingMeshReceived = received.acceptedIds.size
            val ack = RelayMeshSyncCodec.encodeAck(
                RelayMeshSyncCodec.Ack(
                    acceptedOfferIds = received.acceptedIds,
                    requestedEnvelopes = requestedEnvelopes,
                    requestedProbeIds = pendingMeshRequestedPeerProbeIds,
                ),
            )
            val encryptedAck = clientSecureSession?.encrypt(ack)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            clientPhase = ClientPhase.MESH_ACK
            emit(
                mapOf(
                    "type" to "mesh_sync_progress",
                    "token" to requirePeerToken(),
                    "sent" to response.acceptedOfferIds.size,
                    "received" to received.acceptedIds.size,
                    "requestedProbes" to response.requestedProbeIds.size,
                    "recognizedProbes" to pendingMeshRequestedPeerProbeIds.size,
                    "delivered" to received.delivered,
                    "receiptsApplied" to received.receiptsApplied,
                    "attachmentReceiptsApplied" to received.attachmentReceiptsApplied,
                    "wireBytesReceived" to encryptedResponse.size,
                ),
            )
            startOutgoingTransfer(gatt, characteristic, TransferKind.MESH_ACK, encryptedAck)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not commit mesh response", error)
            emit(linkError("mesh_sync_failed", "Relay could not commit the courier exchange."))
            closeClient(gatt)
        }
    }

    private fun processClientMeshComplete(
        gatt: BluetoothGatt,
        encryptedCompletion: ByteArray,
    ) {
        if (clientPhase != ClientPhase.MESH_ACK) {
            emit(linkError("invalid_secure_state", "Mesh completion arrived out of order."))
            closeClient(gatt)
            return
        }
        val completion = try {
            val plaintext = clientSecureSession?.decrypt(encryptedCompletion)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            RelayMeshSyncCodec.decodeCompletion(plaintext)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Mesh completion authentication failed", error)
            emit(linkError("mesh_sync_failed", "The mesh completion receipt was rejected."))
            closeClient(gatt)
            return
        }
        val peerFingerprint = activePeerFingerprint
        if (peerFingerprint == null) {
            emit(linkError("identity_missing", "Peer identity is unavailable for mesh completion."))
            closeClient(gatt)
            return
        }
        val expected = pendingMeshRequestedPeerProbeIds.map { it.toHex() }.toSet()
        if (
            completion.requestedEnvelopes.map { RelayMeshEnvelope.decode(it).idHex() }.toSet() !=
            expected
        ) {
            emit(linkError("mesh_sync_failed", "The mesh completion receipt did not match."))
            closeClient(gatt)
            return
        }
        try {
            meshStore.commitProbed(
                peerFingerprint,
                pendingMeshProbeOffers,
                completion.acceptedProbeIds,
            )
            val receivedFinals = ingestMeshOffers(
                completion.requestedEnvelopes,
                destinationOnly = true,
                logLabel = "completion destination envelope",
            )
            pendingMeshReceived += receivedFinals.acceptedIds.size
            val finalAck = RelayMeshSyncCodec.encodeFinalAck(receivedFinals.acceptedIds)
            val encryptedFinalAck = clientSecureSession?.encrypt(finalAck)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            clientPhase = ClientPhase.MESH_FINAL_ACK
            emit(
                mapOf(
                    "type" to "mesh_sync_completion_received",
                    "token" to requirePeerToken(),
                    "wireBytesReceived" to encryptedCompletion.size,
                ),
            )
            startOutgoingTransfer(
                gatt,
                requireNotNull(
                    gatt.getService(SERVICE_UUID)?.getCharacteristic(TRANSFER_CHARACTERISTIC_UUID),
                ) { "Relay transfer characteristic disappeared." },
                TransferKind.MESH_FINAL_ACK,
                encryptedFinalAck,
            )
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not finalize private destination probes", error)
            emit(linkError("mesh_sync_failed", "The private destination exchange could not finish."))
            closeClient(gatt)
        }
    }

    private fun processClientAttachmentCustody(
        gatt: BluetoothGatt,
        encryptedCustody: ByteArray,
    ) {
        if (clientPhase != ClientPhase.ATTACHMENT_PLAN) {
            emit(linkError("invalid_secure_state", "Attachment custody arrived out of order."))
            closeClient(gatt)
            return
        }
        val offer = pendingAttachmentPlanOffer
        if (offer == null) {
            emit(linkError("attachment_plan_missing", "The pending courier plan is unavailable."))
            closeClient(gatt)
            return
        }
        val custody = try {
            val plaintext = clientSecureSession?.decrypt(encryptedCustody)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            RelayCourierAttachmentCustody.decode(plaintext)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Attachment custody authentication failed", error)
            emit(
                linkError(
                    "attachment_custody_rejected",
                    "The courier's encrypted custody record was rejected.",
                ),
            )
            closeClient(gatt)
            return
        }
        val plan = RelayCourierAttachmentPlan.decode(offer.encodedPlan)
        if (
            !custody.planCommitted ||
            !custody.objectId.contentEquals(plan.objectId) ||
            !MessageDigest.isEqual(custody.planSha256, plan.sha256()) ||
            custody.chunkCount != plan.chunks.size
        ) {
            emit(
                linkError(
                    "attachment_custody_mismatch",
                    "The courier's custody record did not match the offered plan.",
                ),
            )
            closeClient(gatt)
            return
        }
        val courierFingerprint = activePeerFingerprint
        if (courierFingerprint == null) {
            emit(linkError("identity_missing", "Courier identity is unavailable for custody."))
            closeClient(gatt)
            return
        }
        try {
            meshStore.recordSenderAttachmentCustody(courierFingerprint, custody.encode())
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not durably store authenticated attachment custody", error)
            emit(
                linkError(
                    "attachment_custody_store_failed",
                    "Courier custody was authenticated but could not be saved.",
                ),
            )
            closeClient(gatt)
            return
        }
        Log.i(TAG, "Authenticated attachment custody stored")
        emit(
            mapOf(
                "type" to "attachment_custody_received",
                "token" to requirePeerToken(),
                "fingerprint" to courierFingerprint,
                "objectId" to custody.objectId.toHex(),
                "planSha256" to custody.planSha256.toHex(),
                "planCommitted" to true,
                "chunkCount" to custody.chunkCount,
                "missingBitmap" to custody.missingBitmap(),
                "missingChunks" to custody.missingChunks(),
                "custody" to custody.encode(),
            ),
        )
        // Custody updates only resumable hop knowledge. No HAR1 or Delivered transition occurs here.
        closeClient(gatt, disconnect = true)
    }

    private fun processClientAttachmentCleanupAck(
        gatt: BluetoothGatt,
        encryptedAcknowledgement: ByteArray,
    ) {
        if (clientPhase != ClientPhase.ATTACHMENT_CLEANUP) {
            emit(linkError("invalid_secure_state", "Attachment cleanup arrived out of order."))
            closeClient(gatt)
            return
        }
        val context = pendingAttachmentCleanup
        if (context == null || activePeerFingerprint != context.courierFingerprint) {
            emit(linkError("attachment_cleanup_mismatch", "Courier cleanup identity changed."))
            closeClient(gatt)
            return
        }
        val acknowledgement = try {
            val plaintext = clientSecureSession?.decrypt(encryptedAcknowledgement)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
            RelayCourierAttachmentCleanupAck.decode(plaintext)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Attachment cleanup acknowledgement failed authentication", error)
            emit(linkError("attachment_cleanup_rejected", "Courier cleanup was not confirmed."))
            closeClient(gatt)
            return
        }
        if (
            !acknowledgement.objectId.contentEquals(context.cleanup.objectId) ||
            !MessageDigest.isEqual(acknowledgement.planSha256, context.cleanup.planSha256)
        ) {
            emit(linkError("attachment_cleanup_mismatch", "Courier cleanup acknowledgement changed."))
            closeClient(gatt)
            return
        }
        try {
            meshStore.completeSenderAttachmentCleanup(
                context.courierFingerprint,
                acknowledgement,
            )
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not commit courier attachment cleanup", error)
            emit(linkError("attachment_cleanup_store_failed", "Courier cleanup could not be saved."))
            closeClient(gatt)
            return
        }
        emit(
            mapOf(
                "type" to "attachment_courier_cleanup_confirmed",
                "token" to requirePeerToken(),
                "fingerprint" to context.courierFingerprint,
                "objectId" to acknowledgement.objectId.toHex(),
            ),
        )
        closeClient(gatt, disconnect = true)
    }

    private fun processClientReceipt(gatt: BluetoothGatt, encryptedReceipt: ByteArray) {
        if (clientPhase != ClientPhase.CIPHERTEXT) {
            emit(linkError("invalid_secure_state", "Encrypted receipt arrived out of order."))
            closeClient(gatt)
            return
        }
        if (tamperCiphertextForTest) {
            emit(
                linkError(
                    "tamper_not_rejected",
                    "Security failure: deliberately altered ciphertext was accepted.",
                ),
            )
            closeClient(gatt, disconnect = true)
            return
        }
        val receipt = try {
            clientSecureSession?.decrypt(encryptedReceipt)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Encrypted receipt authentication failed", error)
            emit(linkError("receipt_authentication_failed", "The encrypted receipt was rejected."))
            closeClient(gatt)
            return
        }
        if (!receiptMatches(receipt, expectedPlaintextBytes, expectedPlaintextCrc32)) {
            emit(linkError("receipt_mismatch", "The peer's encrypted receipt did not match the payload."))
            closeClient(gatt)
            return
        }
        val elapsedMs = (SystemClock.elapsedRealtime() - linkStartedAtMs).coerceAtLeast(1L)
        val throughputBps = (expectedPlaintextBytes * 1_000L / elapsedMs).toInt()
        emit(
            mapOf(
                "type" to "secure_transfer_acknowledged",
                "token" to requirePeerToken(),
                "bytes" to expectedPlaintextBytes,
                "elapsedMs" to elapsedMs,
                "throughputBps" to throughputBps,
                "mtu" to negotiatedMtu,
            ),
        )
        closeClient(gatt, disconnect = true)
    }

    @SuppressLint("MissingPermission")
    private fun enterWarmTextSession(gatt: BluetoothGatt) {
        if (
            client !== gatt || clientSecureSession?.isEstablished() != true ||
            activeWriteCharacteristic == null || activePeerFingerprint == null
        ) {
            closeClient(gatt, disconnect = true)
            return
        }
        mainHandler.removeCallbacks(operationTimeout)
        responseAccumulator = null
        outboundTransfer = null
        pendingWrite = null
        clientPhase = ClientPhase.IDLE
        linkPurpose = LinkPurpose.WARM_TEXT
        identityRefreshAutomatic = false
        resetPendingText()

        val fingerprint = requireNotNull(activePeerFingerprint)
        val next = try {
            messageStore.oldestRetryEligibleForPeer(fingerprint)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not inspect warm-session text outbox", error)
            null
        }
        if (next != null) {
            try {
                startStoredTextOverWarmSession(gatt, next, automatic = true)
                return
            } catch (error: RuntimeException) {
                Log.w(TAG, "Could not drain warm-session text outbox", error)
            }
        }
        try {
            gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_BALANCED)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Bluetooth stack rejected warm-session balanced priority", error)
        }
        emit(
            mapOf(
                "type" to "text_session_warm",
                "token" to requirePeerToken(),
                "fingerprint" to fingerprint,
                "idleTimeoutMs" to WARM_TEXT_IDLE_TIMEOUT_MS,
            ),
        )
        mainHandler.removeCallbacks(warmSessionTimeout)
        mainHandler.postDelayed(warmSessionTimeout, WARM_TEXT_IDLE_TIMEOUT_MS)
    }

    private fun processClientMessageReceipt(gatt: BluetoothGatt, encryptedReceipt: ByteArray) {
        if (clientPhase != ClientPhase.USER_MESSAGE) {
            emit(linkError("invalid_secure_state", "Message receipt arrived out of order."))
            closeClient(gatt)
            return
        }
        val message = pendingTextMessage
        if (message == null) {
            emit(linkError("message_missing", "The pending message is unavailable."))
            closeClient(gatt)
            return
        }
        logPendingTextTiming("receipt_received", SystemClock.elapsedRealtime())
        val receipt = try {
            clientSecureSession?.decrypt(encryptedReceipt)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Message receipt authentication failed", error)
            emit(linkError("receipt_authentication_failed", "The encrypted delivery receipt was rejected."))
            closeClient(gatt)
            return
        }
        if (!RelayMessageCodec.receiptMatches(receipt, message.id)) {
            emit(linkError("receipt_mismatch", "The delivery receipt belongs to a different message."))
            closeClient(gatt)
            return
        }
        val deliveryStoreStartedAtMs = SystemClock.elapsedRealtime()
        try {
            messageStore.markDelivered(message.id)
            pendingTextDelivered = true
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not commit delivered message state", error)
            emit(linkError("message_store_failed", "Delivery was confirmed but could not be saved."))
            closeClient(gatt)
            return
        }
        val deliveryCommittedAtMs = SystemClock.elapsedRealtime()
        logPendingTextTiming(
            stage = "delivery_committed",
            nowMs = deliveryCommittedAtMs,
            extra = "delivery_store_ms=${deliveryCommittedAtMs - deliveryStoreStartedAtMs}",
        )
        emit(
            mapOf(
                "type" to "text_message_delivered",
                "token" to requirePeerToken(),
                "messageId" to RelayMessageCodec.idHex(message.id),
                "text" to message.text,
                "fingerprint" to (pendingPeerFingerprint ?: "unknown"),
            ) + message.replyMap(),
        )
        logPendingTextTiming("delivery_event_emitted", SystemClock.elapsedRealtime())
        if (warmTextBudget.recordDeliveredAndMayContinue()) {
            enterWarmTextSession(gatt)
        } else {
            emit(
                mapOf(
                    "type" to "text_session_yielded",
                    "token" to requirePeerToken(),
                    "fingerprint" to (pendingPeerFingerprint ?: "unknown"),
                    "automatic" to true,
                ),
            )
            closeClient(gatt, disconnect = true)
        }
    }

    private fun processClientWifiUpgradeAck(gatt: BluetoothGatt, encryptedAck: ByteArray) {
        if (clientPhase != ClientPhase.WIFI_UPGRADE) {
            emit(linkError("invalid_secure_state", "Wi-Fi upgrade reply arrived out of order."))
            closeClient(gatt)
            return
        }
        val offer = pendingWifiUpgradeOffer
        if (offer == null) {
            emit(linkError("wifi_upgrade_failed", "The Wi-Fi upgrade capability is unavailable."))
            closeClient(gatt)
            return
        }
        val ack = try {
            clientSecureSession?.decrypt(encryptedAck)
                ?: throw IllegalStateException("Noise initiator session is unavailable.")
        } catch (error: RuntimeException) {
            emit(linkError("wifi_upgrade_failed", "The encrypted Wi-Fi authorization was rejected."))
            closeClient(gatt)
            return
        }
        val resolvedResponderToken = RelayMessageCodec.wifiUpgradeAckResponderToken(ack, offer)
        if (resolvedResponderToken == null) {
            emit(linkError("wifi_upgrade_mismatch", "The Wi-Fi authorization did not match the offer."))
            closeClient(gatt)
            return
        }
        val authorization = RelayWifiUpgradeAuthorization(
            offerId = offer.offerId.copyOf(),
            psk = offer.psk.copyOf(),
            initiatorToken = offer.initiatorToken.copyOf(),
            responderToken = resolvedResponderToken,
            peerFingerprint = pendingPeerFingerprint ?: "unknown",
            isInitiator = true,
        )
        try {
            onWifiUpgradeAuthorized(authorization)
        } catch (error: RuntimeException) {
            authorization.destroySecret()
            emit(linkError("wifi_upgrade_failed", "The authorized Wi-Fi session could not start."))
            closeClient(gatt)
            return
        }
        wifiUpgradeAuthorized = true
        emit(
            mapOf(
                "type" to "wifi_upgrade_authorized",
                "token" to requirePeerToken(),
                "fingerprint" to authorization.peerFingerprint,
                "role" to "initiator",
            ),
        )
        closeClient(gatt, disconnect = true)
    }

    private fun buildResponseChunk(response: ServerResponse, mtu: Int): ResponseChunk {
        val maximumFrameBytes = minOf(
            // A value that exactly fills ATT's MTU-1 read payload makes Android issue an
            // automatic Read Blob request. Relay chunks at the application layer, so leave
            // one byte unused to make every read unambiguously complete.
            (mtu - ATT_READ_OVERHEAD - 1).coerceAtLeast(RESPONSE_HEADER_BYTES + 1),
            MAX_ATTRIBUTE_VALUE_BYTES,
        )
        val chunkBytes = minOf(
            maximumFrameBytes - RESPONSE_HEADER_BYTES,
            response.payload.size - response.offset,
        )
        check(chunkBytes > 0) { "Secure response has no remaining payload." }
        val frame = ByteArray(RESPONSE_HEADER_BYTES + chunkBytes)
        frame[0] = MAGIC_0
        frame[1] = MAGIC_1
        frame[2] = PROTOCOL_VERSION
        frame[3] = FRAME_RESPONSE
        frame[4] = response.kind
        putU16(frame, 5, response.nextSequence)
        putU16(frame, 7, response.payload.size)
        putU16(frame, 9, response.offset)
        putU32(frame, 11, response.crc32)
        response.payload.copyInto(
            frame,
            destinationOffset = RESPONSE_HEADER_BYTES,
            startIndex = response.offset,
            endIndex = response.offset + chunkBytes,
        )
        return ResponseChunk(frame, chunkBytes)
    }

    private fun buildReceipt(plaintextBytes: Int, plaintextCrc32: Long): ByteArray =
        ByteArray(RECEIPT_BYTES).also { receipt ->
            receipt[0] = RECEIPT_MAGIC_0
            receipt[1] = RECEIPT_MAGIC_1
            receipt[2] = PROTOCOL_VERSION
            receipt[3] = RECEIPT_PAYLOAD_TYPE
            putU16(receipt, 4, plaintextBytes)
            putU32(receipt, 6, plaintextCrc32)
        }

    private fun receiptMatches(receipt: ByteArray, plaintextBytes: Int, plaintextCrc32: Long): Boolean =
        receipt.size == RECEIPT_BYTES &&
            receipt[0] == RECEIPT_MAGIC_0 && receipt[1] == RECEIPT_MAGIC_1 &&
            receipt[2] == PROTOCOL_VERSION && receipt[3] == RECEIPT_PAYLOAD_TYPE &&
            readU16(receipt, 4) == plaintextBytes && readU32(receipt, 6) == plaintextCrc32

    @SuppressLint("MissingPermission")
    private fun sendServerResponse(
        device: BluetoothDevice,
        requestId: Int,
        status: Int,
        value: ByteArray?,
    ): Boolean = try {
        server?.sendResponse(device, requestId, status, 0, value) == true
    } catch (error: RuntimeException) {
        Log.w(TAG, "Bluetooth permission or stack state rejected a GATT response", error)
        false
    }

    @SuppressLint("MissingPermission")
    private fun safeCloseGatt(gatt: BluetoothGatt) {
        try {
            gatt.close()
        } catch (error: RuntimeException) {
            Log.w(TAG, "Bluetooth permission or stack state rejected GATT close", error)
        }
    }

    @SuppressLint("MissingPermission")
    private fun closeClient(gatt: BluetoothGatt, disconnect: Boolean = false) {
        mainHandler.removeCallbacks(operationTimeout)
        mainHandler.removeCallbacks(warmSessionTimeout)
        if (disconnect) {
            try {
                gatt.disconnect()
            } catch (error: RuntimeException) {
                Log.w(TAG, "Bluetooth permission or stack state rejected GATT disconnect", error)
            }
        }
        safeCloseGatt(gatt)
        if (client !== gatt) return
        val notifyWifiUpgradeFailure =
            (linkPurpose == LinkPurpose.WIFI_UPGRADE ||
                linkPurpose == LinkPurpose.COURIER_WIFI_UPGRADE ||
                linkPurpose == LinkPurpose.RECIPIENT_WIFI_UPGRADE) &&
                !wifiUpgradeAuthorized
        queueInterruptedText(pendingTextFailureCode ?: "link_interrupted")
        client = null
        clientSecureSession?.closeQuietly()
        clientSecureSession = null
        activeWriteCharacteristic = null
        clientRemoteIdentityPublicKey = null
        clientPhase = ClientPhase.IDLE
        responseAccumulator = null
        activePeerToken = null
        activePeerFingerprint = null
        outboundTransfer = null
        pendingWrite = null
        expectedPlaintextBytes = 0
        expectedPlaintextCrc32 = 0L
        pendingMeshOffers = emptyList()
        pendingMeshProbeOffers = emptyList()
        pendingMeshRequestedPeerProbeIds = emptyList()
        pendingMeshSent = 0
        pendingMeshReceived = 0
        warmTextBudget.reset()
        pendingAttachmentPlanOffer = null
        pendingAttachmentCleanup?.cleanup?.cancellationSecret?.fill(0)
        pendingAttachmentCleanup = null
        tamperCiphertextForTest = false
        linkPurpose = LinkPurpose.ENGINEERING
        identityRefreshAutomatic = false
        resetPendingText()
        pendingWifiUpgradeOffer?.psk?.fill(0)
        pendingWifiUpgradeOffer = null
        pendingCourierWifiUpgrade = null
        pendingRecipientWifiUpgrade = null
        wifiUpgradeAuthorized = false
        if (notifyWifiUpgradeFailure) onWifiUpgradeFailed()
    }

    private fun scheduleTimeout(delayMs: Long) {
        mainHandler.removeCallbacks(operationTimeout)
        mainHandler.postDelayed(operationTimeout, delayMs)
    }

    private fun requirePeerToken(): String = activePeerToken ?: "unknown"

    private fun linkError(code: String, message: String): Map<String, Any> {
        if (linkPurpose == LinkPurpose.USER_TEXT && pendingTextAttemptStarted) {
            pendingTextFailureCode = code
        }
        return buildMap {
            put("type", "link_error")
            put("code", code)
            put("message", message)
            put("token", requirePeerToken())
            if (linkPurpose == LinkPurpose.MESH_SYNC) {
                put("automatic", true)
                put("purpose", "mesh")
            } else if (linkPurpose == LinkPurpose.ATTACHMENT_CUSTODY) {
                put("automatic", true)
                put("purpose", "attachment_custody")
            } else if (linkPurpose == LinkPurpose.ATTACHMENT_CLEANUP) {
                put("automatic", true)
                put("purpose", "attachment_cleanup")
            } else if (linkPurpose == LinkPurpose.COURIER_WIFI_UPGRADE) {
                put("automatic", true)
                put("purpose", "courier_wifi_upgrade")
            } else if (linkPurpose == LinkPurpose.RECIPIENT_WIFI_UPGRADE) {
                put("automatic", true)
                put("purpose", "recipient_wifi_upgrade")
            } else if (linkPurpose == LinkPurpose.IDENTITY && identityRefreshAutomatic) {
                put("automatic", true)
                put("purpose", "identity_refresh")
            }
            pendingTextMessage?.let {
                put("messageId", RelayMessageCodec.idHex(it.id))
                put("queued", pendingTextAttemptStarted && !pendingTextDelivered)
            }
        }
    }

    private fun queueInterruptedText(code: String) {
        if (
            linkPurpose != LinkPurpose.USER_TEXT || !pendingTextAttemptStarted ||
            pendingTextDelivered
        ) {
            return
        }
        val message = pendingTextMessage ?: return
        val retryAt = try {
            messageStore.markRetryableFailure(message.id, code)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Could not update queued retry metadata", error)
            null
        }
        emitQueuedMessage(
            message = message,
            peerToken = requirePeerToken(),
            retryAtMs = retryAt,
            errorCode = code,
            automatic = pendingTextAutomaticRetry,
        )
    }

    private fun emitQueuedMessage(
        message: RelayMessageCodec.TextMessage,
        peerToken: String,
        retryAtMs: Long?,
        errorCode: String,
        automatic: Boolean,
    ) {
        emit(
            buildMap {
                put("type", "text_message_queued")
                put("token", peerToken)
                put("messageId", RelayMessageCodec.idHex(message.id))
                put("text", message.text)
                putAll(message.replyMap())
                put("code", errorCode)
                put("automatic", automatic)
                retryAtMs?.let { put("retryAtMs", it) }
            },
        )
    }

    private fun resetPendingText() {
        pendingTextMessage = null
        pendingPeerFingerprint = null
        pendingTextAttemptStarted = false
        pendingTextDelivered = false
        pendingTextFailureCode = null
        pendingTextAutomaticRetry = false
        pendingTextTraceStartedAtMs = 0L
        pendingTextTraceQueuedAtMs = 0L
    }

    private fun beginPendingTextTrace(startedAtMs: Long, queuedAtMs: Long) {
        pendingTextTraceStartedAtMs = startedAtMs
        pendingTextTraceQueuedAtMs = queuedAtMs
    }

    private fun logPendingTextTiming(
        stage: String,
        nowMs: Long,
        extra: String = "",
    ) {
        val startedAtMs = pendingTextTraceStartedAtMs.takeIf { it > 0L } ?: nowMs
        val queueResidenceMs = pendingTextTraceQueuedAtMs.takeIf { it > 0L }
            ?.let { (nowMs - it).coerceAtLeast(0L) }
        val suffix = buildString {
            queueResidenceMs?.let { append(" queue_ms=$it") }
            if (extra.isNotBlank()) append(" $extra")
        }
        Log.i(
            METRICS_TAG,
            "text_timing role=sender stage=$stage total_ms=" +
                "${(nowMs - startedAtMs).coerceAtLeast(0L)}$suffix",
        )
    }

    private fun secureLinkError(
        sourceToken: ByteArray,
        code: String,
        message: String,
        automatic: Boolean = false,
    ): Map<String, Any> = buildMap {
        put("type", "link_error")
        put("code", code)
        put("message", message)
        put("token", sourceToken.toHex())
        if (automatic) put("automatic", true)
    }

    private fun resetServerPeerState(device: BluetoothDevice) {
        inboundTransfers.remove(device)
        pendingServerResponses.remove(device)
        pendingServerMeshOffers.remove(device)
        pendingServerMeshProbeOffers.remove(device)
        pendingServerRequestedProbeIds.remove(device)
        serverSecureStates.remove(device)?.session?.closeQuietly()
    }

    private fun identityVerifiedEvent(
        peerToken: String,
        remotePublicKey: ByteArray,
        automatic: Boolean = false,
    ): Map<String, Any> {
        val signingIdentity = requireNotNull(deviceIdentity) {
            "Device signing identity is unavailable."
        }
        val fingerprint = signingIdentity.safetyFingerprint(remotePublicKey)
        val protection = signingIdentity.protection
        val trustState = trustStore.stateFor(remotePublicKey)
        // Upgraded installs can have an explicit verification decision in the
        // original trust store and a completed, but not-yet-reconciled, mesh contact.
        // The authenticated key has just proved the same fingerprint, so carry that
        // existing decision forward instead of asking for the safety code again.
        if (trustState == RelayPeerTrustStore.PeerTrustState.VERIFIED) {
            val contact = meshStore.contact(fingerprint)
            if (contact != null && contact.isComplete && !contact.verified) {
                meshStore.markVerified(fingerprint)
            }
        }
        synchronized(observedIdentityLock) {
            observedIdentityByToken[peerToken] = ObservedIdentity(
                publicKey = remotePublicKey.copyOf(),
                fingerprint = fingerprint,
                protection = protection,
            )
        }
        return buildMap {
            put("type", "identity_proof_verified")
            put("token", peerToken)
            put("fingerprint", fingerprint)
            put("protection", protection)
            put("trustState", trustState.wireValue)
            if (automatic) put("automatic", true)
        }
    }

    private fun crc32(bytes: ByteArray): Long = CRC32().apply { update(bytes) }.value

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private fun readU16(source: ByteArray, offset: Int): Int =
        ((source[offset].toInt() and 0xFF) shl 8) or (source[offset + 1].toInt() and 0xFF)

    private fun putU32(target: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 4) {
            target[offset + index] = (value ushr (24 - index * 8)).toByte()
        }
    }

    private fun readU32(source: ByteArray, offset: Int): Long {
        var value = 0L
        for (index in 0 until 4) {
            value = (value shl 8) or (source[offset + index].toLong() and 0xFF)
        }
        return value
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

    private fun AutoCloseable.closeQuietly() {
        runCatching { close() }.onFailure { error ->
            Log.w(TAG, "Could not close native secure state cleanly", error)
        }
    }

    private data class OutgoingTransfer(
        val id: Int,
        val sourceToken: ByteArray,
        val kind: TransferKind,
        val payload: ByteArray,
        val crc32: Long,
        var offset: Int = 0,
        var nextSequence: Int = 0,
        var chunks: Int = 0,
        var pendingChunkBytes: Int = 0,
    )

    private data class IncomingTransfer(
        val id: Int,
        val sourceToken: ByteArray,
        val kind: TransferKind,
        val expectedCrc32: Long,
        val payload: ByteArray,
        val startedAtMs: Long,
        var receivedBytes: Int = 0,
        var nextSequence: Int = 0,
        var chunks: Int = 0,
    )

    private data class ServerSecureState(
        val initiatorToken: ByteArray,
        val session: NativeRelaySession,
        var remoteIdentityPublicKey: ByteArray? = null,
        var awaitingFinalHandshake: Boolean = false,
    )

    private data class ServerResponse(
        val kind: Byte,
        val payload: ByteArray,
        val crc32: Long,
        var offset: Int = 0,
        var nextSequence: Int = 0,
    )

    private data class ResponseAccumulator(
        val kind: Byte,
        val payload: ByteArray,
        val expectedCrc32: Long,
        var receivedBytes: Int = 0,
        var nextSequence: Int = 0,
    )

    private data class CompletedResponse(val kind: Byte, val payload: ByteArray)

    private data class ResponseChunk(val frame: ByteArray, val payloadBytes: Int)

    private data class ObservedIdentity(
        val publicKey: ByteArray,
        val fingerprint: String,
        val protection: String,
    )

    private data class ServerWriteResult(
        val status: Int,
        val event: Map<String, Any>? = null,
    )

    private data class MeshIngestBatch(
        val acceptedIds: List<ByteArray>,
        val delivered: Int,
        val receiptsApplied: Int,
        val attachmentReceiptsApplied: Int,
    )

    private data class PendingCourierWifiUpgrade(
        val objectId: ByteArray,
        val planSha256: ByteArray,
        val courierFingerprint: String,
    )

    private data class PendingRecipientWifiUpgrade(
        val objectId: ByteArray,
        val planSha256: ByteArray,
    )

    private data class PendingAttachmentCleanup(
        val cleanup: RelayCourierAttachmentCleanup,
        val courierFingerprint: String,
    )

    private enum class PendingWrite { START, DATA }

    private enum class LinkPurpose {
        ENGINEERING,
        IDENTITY,
        USER_TEXT,
        WARM_TEXT,
        WIFI_UPGRADE,
        COURIER_WIFI_UPGRADE,
        RECIPIENT_WIFI_UPGRADE,
        MESH_SYNC,
        ATTACHMENT_CUSTODY,
        ATTACHMENT_CLEANUP,
    }

    private enum class ClientPhase {
        IDLE,
        HANDSHAKE_MESSAGE_1,
        HANDSHAKE_MESSAGE_3,
        IDENTITY_PROOF,
        CONTACT_CARD,
        CIPHERTEXT,
        USER_MESSAGE,
        WIFI_UPGRADE,
        MESH_REQUEST,
        MESH_ACK,
        MESH_FINAL_ACK,
        ATTACHMENT_PLAN,
        ATTACHMENT_CLEANUP,
    }

    private enum class TransferKind(val startFrameType: Byte) {
        HANDSHAKE(FRAME_HANDSHAKE_START),
        IDENTITY_PROOF(FRAME_IDENTITY_PROOF_START),
        CIPHERTEXT(FRAME_CIPHERTEXT_START),
        USER_MESSAGE(FRAME_USER_MESSAGE_START),
        WIFI_UPGRADE(FRAME_WIFI_UPGRADE_START),
        COURIER_WIFI_UPGRADE(FRAME_COURIER_WIFI_UPGRADE_START),
        RECIPIENT_WIFI_UPGRADE(FRAME_RECIPIENT_WIFI_UPGRADE_START),
        CONTACT_CARD(FRAME_CONTACT_CARD_START),
        MESH_REQUEST(FRAME_MESH_REQUEST_START),
        MESH_ACK(FRAME_MESH_ACK_START),
        MESH_FINAL_ACK(FRAME_MESH_FINAL_ACK_START),
        ATTACHMENT_PLAN(FRAME_ATTACHMENT_PLAN_START),
        ATTACHMENT_CLEANUP(FRAME_ATTACHMENT_CLEANUP_START),
    }

    class LinkException(
        val code: String,
        override val message: String,
    ) : IllegalStateException(message)

    private class UnverifiedPeerException : IllegalStateException()

    private class AttachmentPlanDeclinedException(
        val gattStatus: Int,
        val code: String,
        override val message: String,
    ) : IllegalStateException(message)

    private companion object {
        const val TAG = "RelayGattLink"
        const val METRICS_TAG = "RelayMetrics"
        const val MAX_UI_HISTORY_PAGE_SIZE = 100
        const val LINK_TIMEOUT_MS = 12_000L
        const val TRANSFER_TIMEOUT_MS = 60_000L
        const val WARM_TEXT_IDLE_TIMEOUT_MS = 60_000L
        const val DEFAULT_MTU = 23
        const val PREFERRED_MTU = 517
        const val ATT_VALUE_OVERHEAD = 3
        const val ATT_READ_OVERHEAD = 1
        const val MAX_ATTRIBUTE_VALUE_BYTES = 512
        const val ENGINEERING_PAYLOAD_BYTES = 4_096
        const val MAX_HANDSHAKE_BYTES = 512
        const val MAX_IDENTITY_PROOF_CIPHERTEXT_BYTES = 512
        const val MAX_COURIER_WIFI_UPGRADE_CIPHERTEXT_BYTES = 1_024
        const val MAX_CONTACT_CARD_CIPHERTEXT_BYTES = 1_024
        const val MAX_TRANSFER_BYTES = 32_784
        const val MAX_MESH_CIPHERTEXT_BYTES = 65_000
        const val MAX_ATTACHMENT_PLAN_CIPHERTEXT_BYTES = 32_784
        const val MAX_ATTACHMENT_CLEANUP_CIPHERTEXT_BYTES = 256
        const val MAX_RESPONSE_BYTES = 65_000
        const val TOKEN_LENGTH = 8
        const val NOISE_XX_MESSAGE_ONE_BYTES = 32
        const val WIFI_TOKEN_BYTES = 8
        const val ROUTE_PROBE_BUDGET_BYTES = 8 * 1024
        const val ROUTE_FINAL_DELIVERY_BUDGET_BYTES = 12 * 1024
        const val U16_LIMIT = 65_536
        const val START_FRAME_BYTES = 20
        const val DATA_HEADER_BYTES = 8
        const val RESPONSE_HEADER_BYTES = 15
        const val RECEIPT_BYTES = 10
        const val MAGIC_0: Byte = 0x52
        const val MAGIC_1: Byte = 0x54
        const val RECEIPT_MAGIC_0: Byte = 0x52
        const val RECEIPT_MAGIC_1: Byte = 0x43
        const val PROTOCOL_VERSION: Byte = 0x01
        const val FRAME_DATA: Byte = 0x02
        const val FRAME_HANDSHAKE_START: Byte = 0x11
        const val FRAME_CIPHERTEXT_START: Byte = 0x12
        const val FRAME_IDENTITY_PROOF_START: Byte = 0x13
        const val FRAME_USER_MESSAGE_START: Byte = 0x14
        const val FRAME_WIFI_UPGRADE_START: Byte = 0x15
        const val FRAME_CONTACT_CARD_START: Byte = 0x16
        const val FRAME_MESH_REQUEST_START: Byte = 0x17
        const val FRAME_MESH_ACK_START: Byte = 0x18
        const val FRAME_MESH_FINAL_ACK_START: Byte = 0x19
        const val FRAME_ATTACHMENT_PLAN_START: Byte = 0x1A
        const val FRAME_COURIER_WIFI_UPGRADE_START: Byte = 0x1B
        const val FRAME_RECIPIENT_WIFI_UPGRADE_START: Byte = 0x1C
        const val FRAME_ATTACHMENT_CLEANUP_START: Byte = 0x1D
        const val FRAME_RESPONSE: Byte = 0x21
        const val RESPONSE_HANDSHAKE: Byte = 0x01
        const val RESPONSE_ENCRYPTED_RECEIPT: Byte = 0x02
        const val RESPONSE_IDENTITY_PROOF: Byte = 0x03
        const val RESPONSE_MESSAGE_RECEIPT: Byte = 0x04
        const val RESPONSE_WIFI_UPGRADE_ACK: Byte = 0x05
        const val RESPONSE_CONTACT_CARD: Byte = 0x06
        const val RESPONSE_MESH_SYNC: Byte = 0x07
        const val RESPONSE_MESH_COMPLETE: Byte = 0x08
        const val RESPONSE_ATTACHMENT_CUSTODY: Byte = 0x09
        const val RESPONSE_ATTACHMENT_CLEANUP_ACK: Byte = 0x0A
        const val RECEIPT_PAYLOAD_TYPE: Byte = 0x01
        const val GATT_RELAY_AUTH_REJECTED = 0x80
        const val GATT_RELAY_UNVERIFIED = 0x81
        const val GATT_RELAY_COURIER_STORE_FULL = 0x82
        const val GATT_RELAY_ATTACHMENT_EXPIRED = 0x83
        const val GATT_RELAY_ATTACHMENT_TERMINAL = 0x84
        const val TAMPER_MASK = 0x40
        val ENGINEERING_PAYLOAD_PREFIX = byteArrayOf(0x52, 0x4C, 0x59, 0x45)
        val SERVICE_UUID: UUID = UUID.fromString("7e57d004-2b97-4d12-9f65-53a4c7a36c81")
        val TRANSFER_CHARACTERISTIC_UUID: UUID =
            UUID.fromString("7e57d005-2b97-4d12-9f65-53a4c7a36c81")
    }
}
