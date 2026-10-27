package app.projectrelay.relay_mobile

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import java.util.ArrayDeque
import java.util.UUID
import java.util.zip.CRC32

/** Additive GATT client for the experimental ESP32 fixed courier. */
internal class HyphaFixedNodeLink(
    private val context: Context,
    private val meshStore: RelayMeshStore,
    private val venueTrustStore: HyphaVenueTrustStore,
    private val emit: (Map<String, Any>) -> Unit,
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val attemptByToken = mutableMapOf<String, TokenAttempt>()
    private var client: BluetoothGatt? = null
    private var characteristic: BluetoothGattCharacteristic? = null
    private var crypto: HyphaFixedNodeCrypto? = null
    private var phase = Phase.IDLE
    private var activeToken: String? = null
    private var activeFingerprint: String? = null
    private var activeVenueTrust: String? = null
    private var negotiatedMtu = DEFAULT_MTU
    private var outboundFrames = ArrayDeque<ByteArray>()
    private val responseAssembler = HyphaFixedNodeResponseAssembler(MAX_TRANSFER_BYTES)
    private var pendingOffers: List<RelayMeshStore.ForwardOffer> = emptyList()
    private var receivedThisSync = 0
    private var sentThisSync = 0
    private var deliveredThisSync = 0
    private var receiptsThisSync = 0
    private var meshChangedThisSync = false
    private var followUpRequiredThisSync = false

    private val timeout = Runnable {
        fail("fixed_node_timeout", "The fixed-node exchange timed out.")
    }

    @SuppressLint("MissingPermission")
    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (gatt != client) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("fixed_node_connection_failed", "The fixed node connection failed ($status).")
                return
            }
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "Fixed-node BLE connected")
                    scheduleTimeout(CONNECTION_TIMEOUT_MS)
                    try {
                        gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                    } catch (_: RuntimeException) {
                        // A vendor stack may reject this hint; the exchange remains bounded.
                    }
                    val mtuRequested = try {
                        gatt.requestMtu(PREFERRED_MTU)
                    } catch (_: RuntimeException) {
                        false
                    }
                    if (!mtuRequested) {
                        negotiatedMtu = DEFAULT_MTU
                        discoverServices(gatt)
                    }
                }
                BluetoothProfile.STATE_DISCONNECTED -> close()
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (gatt != client) return
            negotiatedMtu = if (status == BluetoothGatt.GATT_SUCCESS) {
                mtu.coerceAtLeast(DEFAULT_MTU)
            } else {
                DEFAULT_MTU
            }
            discoverServices(gatt)
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (gatt != client) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("fixed_node_service_failed", "Fixed-node service discovery failed ($status).")
                return
            }
            val found = gatt.getService(SERVICE_UUID)?.getCharacteristic(TRANSFER_UUID)
            if (found == null) {
                fail("fixed_node_service_missing", "The nearby device is not a Hypha fixed node.")
                return
            }
            Log.i(TAG, "Fixed-node GATT service discovered")
            characteristic = found
            val session = try {
                HyphaFixedNodeCrypto(requireTokenBytes())
            } catch (error: Exception) {
                Log.w(TAG, "Fixed-node crypto initialization failed", error)
                fail("fixed_node_crypto_failed", "The fixed-node secure session could not start.")
                return
            }
            crypto = session
            phase = Phase.HELLO
            Log.i(TAG, "Fixed-node handshake starting")
            sendTransfer(TRANSFER_HELLO, session.hello)
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            handleWriteCompleted(gatt, characteristic, status)
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            handleReadCompleted(
                gatt,
                characteristic,
                characteristic.value ?: byteArrayOf(),
                status,
            )
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int,
        ) {
            handleReadCompleted(gatt, characteristic, value, status)
        }
    }

    fun isBusy(): Boolean = client != null

    /** Starts at most one automatic sync per rotating node token during the cooldown window. */
    @SuppressLint("MissingPermission")
    fun consider(token: String, device: BluetoothDevice): Boolean {
        if (client != null) return false
        val tokenBytes = token.hexToBytesOrNull()
        if (tokenBytes?.size != HyphaFixedNodeCrypto.ADVERTISEMENT_TOKEN_BYTES) return false
        val now = SystemClock.elapsedRealtime()
        val previous = attemptByToken[token]
        if (previous != null && !HyphaFixedNodeSchedulingPolicy.canAttempt(previous.retry, now)) {
            attemptByToken[token] = previous.copy(lastSeenAtMs = now)
            return false
        }
        attemptByToken[token] = TokenAttempt(
            retry = HyphaFixedNodeSchedulingPolicy.started(now),
            lastSeenAtMs = now,
        )
        pruneAttemptWindows(now)
        activeToken = token
        activeFingerprint = null
        activeVenueTrust = null
        pendingOffers = emptyList()
        receivedThisSync = 0
        sentThisSync = 0
        deliveredThisSync = 0
        receiptsThisSync = 0
        meshChangedThisSync = false
        followUpRequiredThisSync = false
        phase = Phase.CONNECTING
        scheduleTimeout(CONNECTION_TIMEOUT_MS)
        return try {
            client = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
            } else {
                @Suppress("DEPRECATION")
                device.connectGatt(context, false, callback)
            }
            if (client == null) {
                fail("fixed_node_connection_failed", "The fixed node connection could not start.")
                false
            } else {
                emit(
                    mapOf(
                        "type" to "fixed_node_sync_started",
                        "token" to token,
                        "automatic" to true,
                    ),
                )
                true
            }
        } catch (error: SecurityException) {
            fail("permission_required", "Nearby Devices permission is required for fixed nodes.")
            false
        } catch (error: RuntimeException) {
            fail("fixed_node_connection_failed", "The fixed node connection could not start.")
            false
        }
    }

    fun stop() {
        close(disconnect = true)
        attemptByToken.clear()
    }

    /** Allows real newly queued mesh work to use the fast, rate-limited node follow-up. */
    fun onLocalMeshWorkChanged(nowElapsedMs: Long = SystemClock.elapsedRealtime()) {
        attemptByToken.keys.toList().forEach { token ->
            val attempt = attemptByToken[token] ?: return@forEach
            attemptByToken[token] = attempt.copy(
                retry = HyphaFixedNodeSchedulingPolicy.localWorkChanged(
                    current = attempt.retry,
                    nowElapsedMs = nowElapsedMs,
                ),
            )
        }
    }

    @SuppressLint("MissingPermission")
    private fun discoverServices(gatt: BluetoothGatt) {
        phase = Phase.DISCOVERING
        scheduleTimeout(CONNECTION_TIMEOUT_MS)
        if (!gatt.discoverServices()) {
            fail("fixed_node_service_failed", "Fixed-node service discovery could not start.")
        }
    }

    private fun prepareMeshRequest(): ByteArray {
        val fingerprint = checkNotNull(activeFingerprint) {
            "Fixed-node identity is unavailable for mesh planning."
        }
        val inventory = meshStore.inventory(limit = MAX_NODE_INVENTORY_IDS)
        val availableBytes = (
            RelayMeshSyncCodec.MAX_SYNC_BYTES - RelayMeshSyncCodec.EXCHANGE_HEADER_BYTES -
                RelayMeshSyncCodec.encodedIdsBytes(inventory)
            ).coerceAtLeast(0)
        pendingOffers = meshStore.planForPeer(
            peerFingerprint = fingerprint,
            peerInventory = emptyList(),
            maximumBytes = minOf(availableBytes, MAX_NODE_OFFER_BYTES),
        )
        return RelayMeshSyncCodec.encodeRequest(
            RelayMeshSyncCodec.Request(
                inventory = inventory,
                offeredEnvelopes = pendingOffers.map { it.wireEnvelope },
                // The first fixed-node slice cannot recognize private routes and never receives
                // last-copy probes. Those records remain safely on the phone.
                routeProbes = emptyList(),
            ),
        )
    }

    private fun processMeshResponse(plaintext: ByteArray): ByteArray {
        val response = RelayMeshSyncCodec.decodeResponse(plaintext)
        check(response.requestedProbeIds.isEmpty() && response.routeProbes.isEmpty()) {
            "Fixed node advertised unsupported private-route behavior."
        }
        val ingested = ingest(response.offeredEnvelopes)
        val fingerprint = checkNotNull(activeFingerprint)
        val acceptedOfferIds = response.acceptedOfferIds.mapTo(hashSetOf()) { it.toHex() }
        val acceptedOffers = pendingOffers.count { it.messageId.toHex() in acceptedOfferIds }
        meshStore.commitForwarded(fingerprint, pendingOffers, response.acceptedOfferIds)
        pendingOffers = emptyList()
        sentThisSync += acceptedOffers
        receivedThisSync += ingested.acceptedIds.size
        deliveredThisSync += ingested.delivered
        receiptsThisSync += ingested.receiptsApplied
        meshChangedThisSync = meshChangedThisSync || acceptedOffers > 0 || ingested.changed
        followUpRequiredThisSync = followUpRequiredThisSync || ingested.followUpRequired
        return RelayMeshSyncCodec.encodeAck(
            RelayMeshSyncCodec.Ack(
                acceptedOfferIds = ingested.acceptedIds,
                requestedEnvelopes = emptyList(),
                requestedProbeIds = emptyList(),
            ),
        )
    }

    private fun processCompletion(plaintext: ByteArray): ByteArray {
        val completion = RelayMeshSyncCodec.decodeCompletion(plaintext)
        check(completion.acceptedProbeIds.isEmpty() && completion.requestedEnvelopes.isEmpty()) {
            "Fixed node returned unsupported private-route completion data."
        }
        return RelayMeshSyncCodec.encodeFinalAck(emptyList())
    }

    private fun ingest(envelopes: Collection<ByteArray>): IngestBatch {
        val accepted = mutableListOf<ByteArray>()
        var delivered = 0
        var receipts = 0
        var changed = false
        var followUpRequired = false
        envelopes.forEach { wire ->
            try {
                when (val result = meshStore.ingestEnvelope(wire, destinationOnly = false)) {
                    is RelayMeshStore.IngestResult.CourierStored -> {
                        changed = changed || result.inserted
                    }
                    is RelayMeshStore.IngestResult.Delivered -> {
                        if (result.inserted) {
                            delivered += 1
                            changed = true
                            followUpRequired = true
                            emit(
                                buildMap {
                                    put("type", "text_message_received")
                                    put("messageId", result.messageId.toHex())
                                    put("text", result.text)
                                    put("fingerprint", result.peerFingerprint)
                                    put("transport", "fixed_node")
                                    put("automatic", true)
                                    result.replyToMessageId?.let {
                                        put("replyToMessageId", it.toHex())
                                        put("replyPreview", requireNotNull(result.replyPreview))
                                    }
                                },
                            )
                        }
                    }
                    is RelayMeshStore.IngestResult.ReceiptApplied -> {
                        if (result.changed) {
                            receipts += 1
                            changed = true
                        }
                    }
                    is RelayMeshStore.IngestResult.AttachmentReceiptApplied -> {
                        if (result.inserted) {
                            receipts += 1
                            changed = true
                        }
                    }
                    is RelayMeshStore.IngestResult.AttachmentManifestStored -> {
                        changed = changed || result.inserted
                    }
                    is RelayMeshStore.IngestResult.ProbeDeclined,
                    is RelayMeshStore.IngestResult.StoreFull,
                    is RelayMeshStore.IngestResult.Expired,
                    -> return@forEach
                }
                accepted += RelayMeshEnvelope.decode(wire).messageId
            } catch (error: RuntimeException) {
                Log.w(TAG, "Rejected an invalid fixed-node envelope", error)
            }
        }
        return IngestBatch(accepted, delivered, receipts, changed, followUpRequired)
    }

    private fun processResponse(kind: Int, payload: ByteArray) {
        try {
            when (phase) {
                Phase.HELLO -> {
                    check(kind == RESPONSE_HELLO) { "Fixed node returned the wrong hello response." }
                    val session = checkNotNull(crypto)
                    val fingerprint = session.acceptHelloResponse(payload)
                    val authorization = venueTrustStore.authorize(session.nodeIdentityPublicKey())
                    if (!authorization.allowed) {
                        fail(
                            "fixed_node_not_approved",
                            authorization.reason ?: "This fixed node is not approved for this venue.",
                        )
                        return
                    }
                    activeFingerprint = fingerprint
                    activeVenueTrust = authorization.trustLabel
                    Log.i(TAG, "Fixed-node identity authenticated trust=${authorization.trustLabel}")
                    emit(
                        mapOf(
                            "type" to "fixed_node_authenticated",
                            "token" to requireNotNull(activeToken),
                            "fingerprint" to fingerprint,
                            "trustState" to "authenticated",
                            "venueTrust" to authorization.trustLabel,
                            "nodeStatus" to authorization.nodeStatus.name.lowercase(),
                            "automatic" to true,
                        ),
                    )
                    phase = Phase.FINISH
                    sendSecure(HyphaFixedNodeCrypto.FINISH_MAGIC)
                }
                Phase.FINISH -> {
                    check(kind == RESPONSE_SECURE) { "Fixed node rejected session confirmation." }
                    check(checkNotNull(crypto).decrypt(payload)
                        .contentEquals(HyphaFixedNodeCrypto.WELCOME_MAGIC)) {
                        "Fixed node returned an invalid welcome record."
                    }
                    phase = Phase.REQUEST
                    sendSecure(prepareMeshRequest())
                }
                Phase.REQUEST -> {
                    check(kind == RESPONSE_SECURE) { "Fixed node rejected the mesh request." }
                    val ack = processMeshResponse(checkNotNull(crypto).decrypt(payload))
                    phase = Phase.ACK
                    sendSecure(ack)
                }
                Phase.ACK -> {
                    check(kind == RESPONSE_SECURE) { "Fixed node rejected mesh custody." }
                    val finalAck = processCompletion(checkNotNull(crypto).decrypt(payload))
                    phase = Phase.FINAL
                    sendSecure(finalAck)
                }
                Phase.FINAL -> {
                    check(kind == RESPONSE_SECURE) { "Fixed node rejected mesh completion." }
                    check(checkNotNull(crypto).decrypt(payload)
                        .contentEquals(HyphaFixedNodeCrypto.DONE_MAGIC)) {
                        "Fixed node returned an invalid completion record."
                    }
                    val token = requireNotNull(activeToken)
                    val fingerprint = requireNotNull(activeFingerprint)
                    val now = SystemClock.elapsedRealtime()
                    attemptByToken[token]?.let { attempt ->
                        attemptByToken[token] = attempt.copy(
                            retry = HyphaFixedNodeSchedulingPolicy.completed(
                                current = attempt.retry,
                                nowElapsedMs = now,
                                followUpRequired = followUpRequiredThisSync,
                            ),
                            lastSeenAtMs = now,
                        )
                    }
                    Log.i(
                        TAG,
                        "Fixed-node sync completed sent=$sentThisSync received=$receivedThisSync " +
                            "delivered=$deliveredThisSync receiptsApplied=$receiptsThisSync",
                    )
                    emit(
                        mapOf(
                            "type" to "fixed_node_sync_completed",
                            "token" to token,
                            "fingerprint" to fingerprint,
                            "venueTrust" to requireNotNull(activeVenueTrust),
                            "sent" to sentThisSync,
                            "received" to receivedThisSync,
                            "delivered" to deliveredThisSync,
                            "receiptsApplied" to receiptsThisSync,
                            "meshChanged" to meshChangedThisSync,
                            "followUpRequired" to followUpRequiredThisSync,
                            "automatic" to true,
                        ),
                    )
                    close(disconnect = true)
                }
                else -> error("Fixed-node response arrived out of order.")
            }
        } catch (error: RuntimeException) {
            Log.w(TAG, "Fixed-node response was rejected", error)
            fail("fixed_node_sync_failed", "The authenticated fixed-node exchange was rejected.")
        }
    }

    private fun sendSecure(plaintext: ByteArray) {
        val encrypted = checkNotNull(crypto).encrypt(plaintext)
        sendTransfer(TRANSFER_SECURE, encrypted)
    }

    private fun sendTransfer(type: Int, payload: ByteArray) {
        check(payload.isNotEmpty() && payload.size <= MAX_TRANSFER_BYTES) {
            "Fixed-node transfer has an invalid length."
        }
        responseAssembler.reset()
        outboundFrames.clear()
        val start = ByteArray(START_FRAME_BYTES)
        FRAME_START_MAGIC.copyInto(start)
        start[4] = type.toByte()
        putU16(start, 6, payload.size)
        putU32(start, 8, crc32(payload))
        outboundFrames.add(start)
        val frameBytes = (negotiatedMtu - ATT_VALUE_OVERHEAD).coerceAtLeast(DEFAULT_MTU - ATT_VALUE_OVERHEAD)
        val chunkBytes = frameBytes - DATA_HEADER_BYTES
        var offset = 0
        var sequence = 0
        while (offset < payload.size) {
            val count = minOf(chunkBytes, payload.size - offset)
            val frame = ByteArray(DATA_HEADER_BYTES + count)
            FRAME_DATA_MAGIC.copyInto(frame)
            putU16(frame, 4, sequence)
            payload.copyInto(frame, DATA_HEADER_BYTES, offset, offset + count)
            outboundFrames.add(frame)
            offset += count
            sequence += 1
        }
        scheduleTimeout(TRANSFER_TIMEOUT_MS)
        writeNextFrame()
    }

    @SuppressLint("MissingPermission")
    private fun writeNextFrame() {
        val gatt = client ?: return
        val target = characteristic ?: return
        val frame = outboundFrames.pollFirst()
        if (frame == null) {
            beginRead()
            return
        }
        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeCharacteristic(
                target,
                frame,
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            target.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            @Suppress("DEPRECATION")
            target.value = frame
            @Suppress("DEPRECATION")
            gatt.writeCharacteristic(target)
        }
        if (!started) fail("fixed_node_write_failed", "A fixed-node BLE frame could not start.")
    }

    private fun handleWriteCompleted(
        gatt: BluetoothGatt,
        completed: BluetoothGattCharacteristic,
        status: Int,
    ) {
        if (gatt != client || completed.uuid != TRANSFER_UUID) return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("fixed_node_write_failed", "A fixed-node BLE frame failed ($status).")
            return
        }
        writeNextFrame()
    }

    @SuppressLint("MissingPermission")
    private fun beginRead() {
        val gatt = client ?: return
        val source = characteristic ?: return
        if (!gatt.readCharacteristic(source)) {
            fail("fixed_node_read_failed", "The fixed-node response could not start.")
        }
    }

    private fun handleReadCompleted(
        gatt: BluetoothGatt,
        source: BluetoothGattCharacteristic,
        frame: ByteArray,
        status: Int,
    ) {
        if (gatt != client || source.uuid != TRANSFER_UUID) return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("fixed_node_read_failed", "A fixed-node response frame failed ($status).")
            return
        }
        val completed = try {
            responseAssembler.accept(frame)
        } catch (error: RuntimeException) {
            Log.w(TAG, "Fixed-node response framing was rejected", error)
            fail("fixed_node_response_invalid", "The fixed-node response framing was rejected.")
            return
        }
        if (completed == null) {
            beginRead()
        } else {
            processResponse(completed.kind, completed.payload)
        }
    }

    private fun requireTokenBytes(): ByteArray = requireNotNull(activeToken).hexToBytesOrNull()
        ?.takeIf { it.size == HyphaFixedNodeCrypto.ADVERTISEMENT_TOKEN_BYTES }
        ?: error("Fixed-node advertisement token is invalid.")

    private fun scheduleTimeout(delayMs: Long) {
        mainHandler.removeCallbacks(timeout)
        mainHandler.postDelayed(timeout, delayMs)
    }

    private fun fail(code: String, message: String) {
        val token = activeToken
        val now = SystemClock.elapsedRealtime()
        token?.let { failedToken ->
            attemptByToken[failedToken] = TokenAttempt(
                retry = HyphaFixedNodeSchedulingPolicy.failed(now),
                lastSeenAtMs = now,
            )
        }
        Log.w(TAG, "Fixed-node sync failed code=$code phase=$phase")
        emit(
            buildMap {
                put("type", "fixed_node_error")
                put("code", code)
                put("message", message)
                put("automatic", true)
                token?.let { put("token", it) }
            },
        )
        close(disconnect = true)
    }

    @SuppressLint("MissingPermission")
    private fun close(disconnect: Boolean = false) {
        mainHandler.removeCallbacks(timeout)
        val closing = client
        client = null
        characteristic = null
        phase = Phase.IDLE
        outboundFrames.clear()
        responseAssembler.reset()
        pendingOffers = emptyList()
        crypto?.close()
        crypto = null
        activeToken = null
        activeFingerprint = null
        activeVenueTrust = null
        negotiatedMtu = DEFAULT_MTU
        if (closing != null) {
            if (disconnect) runCatching { closing.disconnect() }
            runCatching { closing.close() }
        }
    }

    private fun crc32(bytes: ByteArray): Long = CRC32().apply { update(bytes) }.value

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private fun putU32(target: ByteArray, offset: Int, value: Long) {
        target[offset] = (value ushr 24).toByte()
        target[offset + 1] = (value ushr 16).toByte()
        target[offset + 2] = (value ushr 8).toByte()
        target[offset + 3] = value.toByte()
    }

    private fun ByteArray.toHex(): String = joinToString("") { byte ->
        "%02x".format(byte.toInt() and 0xff)
    }

    private fun pruneAttemptWindows(nowElapsedMs: Long) {
        attemptByToken.entries.removeAll { nowElapsedMs - it.value.lastSeenAtMs > TOKEN_RETENTION_MS }
        while (attemptByToken.size > MAX_TRACKED_NODE_TOKENS) {
            val oldest = attemptByToken.minByOrNull { it.value.lastSeenAtMs }?.key ?: break
            attemptByToken.remove(oldest)
        }
    }

    private fun String.hexToBytesOrNull(): ByteArray? {
        if (length % 2 != 0 || any { !it.isDigit() && it.lowercaseChar() !in 'a'..'f' }) return null
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private enum class Phase {
        IDLE,
        CONNECTING,
        DISCOVERING,
        HELLO,
        FINISH,
        REQUEST,
        ACK,
        FINAL,
    }

    private data class IngestBatch(
        val acceptedIds: List<ByteArray>,
        val delivered: Int,
        val receiptsApplied: Int,
        val changed: Boolean,
        val followUpRequired: Boolean,
    )

    private data class TokenAttempt(
        val retry: HyphaFixedNodeSchedulingPolicy.RetryWindow,
        val lastSeenAtMs: Long,
    )

    private companion object {
        const val TAG = "HyphaFixedNodeLink"
        const val DEFAULT_MTU = 23
        const val PREFERRED_MTU = 247
        const val ATT_VALUE_OVERHEAD = 3
        const val START_FRAME_BYTES = 12
        const val DATA_HEADER_BYTES = 8
        const val MAX_TRANSFER_BYTES = 16 * 1024
        const val MAX_NODE_OFFER_BYTES = 8 * 1024
        const val MAX_NODE_INVENTORY_IDS = 96
        const val CONNECTION_TIMEOUT_MS = 12_000L
        const val TRANSFER_TIMEOUT_MS = 60_000L
        const val TOKEN_RETENTION_MS = 60L * 60L * 1_000L
        const val MAX_TRACKED_NODE_TOKENS = 64
        const val TRANSFER_HELLO = 1
        const val TRANSFER_SECURE = 2
        const val RESPONSE_HELLO = HyphaFixedNodeResponseAssembler.RESPONSE_HELLO
        const val RESPONSE_SECURE = HyphaFixedNodeResponseAssembler.RESPONSE_SECURE
        val FRAME_START_MAGIC = "HNF1".encodeToByteArray()
        val FRAME_DATA_MAGIC = "HND1".encodeToByteArray()
        val SERVICE_UUID: UUID = UUID.fromString("7e57d014-2b97-4d12-9f65-53a4c7a36c81")
        val TRANSFER_UUID: UUID = UUID.fromString("7e57d015-2b97-4d12-9f65-53a4c7a36c81")
    }
}
