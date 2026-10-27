package app.projectrelay.relay_mobile

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {
    private var pendingPermissionResult: MethodChannel.Result? = null
    private var pendingPermissionRequestCode: Int? = null
    private lateinit var bleDiscovery: RelayBleDiscovery
    private lateinit var backgroundPreferences: RelayBackgroundPreferences
    private lateinit var attachmentStore: RelayAttachmentStore
    private lateinit var attachmentPreviewStore: RelayAttachmentPreviewStore
    private val attachmentExecutor = Executors.newSingleThreadExecutor()
    private val messageReadExecutor = Executors.newSingleThreadExecutor()
    private var pendingAttachmentPick: PendingAttachmentPick? = null
    private var pendingVenueInventoryPick: PendingVenueInventoryPick? = null
    private var pendingConversationFingerprint: String? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        captureConversationTarget(intent)
        bleDiscovery = relayRadioRuntime().discovery
        backgroundPreferences = RelayBackgroundPreferences(this)
        attachmentStore = RelayAttachmentStore(this)
        attachmentPreviewStore = RelayAttachmentPreviewStore(this, attachmentStore)
        attachmentExecutor.execute {
            runCatching { attachmentStore.pruneReleasedPayloads() }
        }
        EventChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            RADIO_EVENTS_CHANNEL,
        ).setStreamHandler(bleDiscovery)
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            RADIO_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getRadioCapabilities" -> result.success(readRadioCapabilities())
                "getVenueTrustStatus" -> result.success(bleDiscovery.venueTrustStatus())
                "pickVenueInventory" -> pickVenueInventory(
                    call.argument<Boolean>("allowAuthorityBootstrap") == true,
                    result,
                )
                "installVenueInventory" -> {
                    val inventory = call.argument<ByteArray>("inventory")
                    if (inventory == null) {
                        result.error(
                            "inventory_required",
                            "A signed HVI1 venue inventory is required.",
                            null,
                        )
                    } else {
                        result.success(
                            bleDiscovery.installVenueInventory(
                                inventory,
                                call.argument<Boolean>("allowAuthorityBootstrap") == true,
                            ),
                        )
                    }
                }
                "resetVenueTrust" -> result.success(
                    bleDiscovery.resetVenueTrust(call.argument<String>("confirmation").orEmpty()),
                )
                "requestRadioPermissions" -> requestRadioPermissions(result)
                "requestWifiDirectPermissions" -> requestWifiDirectPermissions(result)
                "getBackgroundSettings" -> result.success(backgroundPreferences.snapshot())
                "setBackgroundRelayEnabled" -> setBackgroundRelayEnabled(
                    call.argument<Boolean>("enabled"),
                    result,
                )
                "setRestartAfterReboot" -> setRestartAfterReboot(
                    call.argument<Boolean>("enabled"),
                    result,
                )
                "requestNotificationPermission" -> requestNotificationPermission(result)
                "dismissNotificationOnboarding" -> {
                    backgroundPreferences.notificationOnboardingDismissed = true
                    result.success(backgroundPreferences.snapshot())
                }
                "openNotificationSettings" -> openSystemSettings(
                    backgroundPreferences::openNotificationSettings,
                    result,
                )
                "openBatterySettings" -> openSystemSettings(
                    backgroundPreferences::openBatterySettings,
                    result,
                )
                "pickAttachment" -> pickAttachment(
                    call.argument<String>("fingerprint"),
                    call.argument<String>("kind"),
                    result,
                )
                "sendAttachment" -> sendAttachment(
                    call.argument<String>("bleToken"),
                    call.argument<String>("attachmentId"),
                    result,
                )
                "prepareCourierAttachment" -> prepareCourierAttachment(
                    call.argument<String>("attachmentId"),
                    result,
                )
                "pauseAttachment" -> pauseAttachment(
                    call.argument<String>("attachmentId"),
                    result,
                )
                "cancelAttachment" -> cancelAttachment(
                    call.argument<String>("attachmentId"),
                    result,
                )
                "getStoredAttachments" -> result.success(
                    attachmentStore.listRecent().map(RelayAttachmentStore.StoredAttachment::toMap),
                )
                "loadAttachmentPreview" -> loadAttachmentPreview(
                    call.argument<String>("attachmentId"),
                    result,
                )
                "openAttachment" -> openAttachment(
                    call.argument<String>("attachmentId"),
                    result,
                )
                "startBleDiscovery" -> startBleDiscovery(result)
                "stopBleDiscovery" -> {
                    bleDiscovery.stop()
                    RelayForegroundService.stop(this)
                    result.success(null)
                }
                "sendEngineeringTransfer" -> sendEngineeringTransfer(
                    call.argument<String>("token"),
                    tamperCiphertext = false,
                    result = result,
                )
                "sendTamperedEngineeringTransfer" -> sendEngineeringTransfer(
                    call.argument<String>("token"),
                    tamperCiphertext = true,
                    result = result,
                )
                "identifyPeer" -> identifyPeer(
                    call.argument<String>("token"),
                    result,
                )
                "sendTextMessage" -> sendTextMessage(
                    call.argument<String>("token"),
                    call.argument<String>("text"),
                    call.argument<String>("replyToMessageId"),
                    call.argument<String>("replyPreview"),
                    result,
                )
                "retryTextMessage" -> retryTextMessage(
                    call.argument<String>("token"),
                    call.argument<String>("messageId"),
                    result,
                )
                "queueMeshText" -> queueMeshText(
                    call.argument<String>("fingerprint"),
                    call.argument<String>("text"),
                    call.argument<String>("replyToMessageId"),
                    call.argument<String>("replyPreview"),
                    result,
                )
                "queueLastCopyDiagnosticText" -> queueLastCopyDiagnosticText(
                    call.argument<String>("fingerprint"),
                    call.argument<String>("text"),
                    result,
                )
                "syncMesh" -> syncMesh(call.argument<String>("token"), result)
                "getRelayContacts" -> result.success(bleDiscovery.contacts())
                "getLocalProfile" -> result.success(bleDiscovery.localProfile())
                "updateDisplayName" -> updateDisplayName(
                    call.argument<String>("displayName"),
                    result,
                )
                "sendWifiTextMessage" -> sendWifiTextMessage(
                    call.argument<String>("bleToken"),
                    call.argument<String>("wifiToken"),
                    call.argument<String>("text"),
                    result,
                )
                "getStoredMessages" -> getStoredMessages(result)
                "getStoredMessagePage" -> getStoredMessagePage(
                    call.argument<String>("fingerprint"),
                    call.argument<Number>("beforeCreatedAtMs")?.toLong(),
                    call.argument<String>("beforeMessageId"),
                    call.argument<Number>("limit")?.toInt(),
                    result,
                )
                "getConversationSummaries" -> getConversationSummaries(result)
                "markConversationRead" -> markConversationRead(
                    call.argument<String>("fingerprint"),
                    result,
                )
                "consumePendingConversationOpen" -> {
                    val fingerprint = pendingConversationFingerprint
                    pendingConversationFingerprint = null
                    result.success(fingerprint)
                }
                "startWifiDirect" -> startWifiDirect(result)
                "stopWifiDirect" -> {
                    bleDiscovery.stopWifiDirect()
                    result.success(null)
                }
                "runWifiDirectSpeedTest" -> runWifiDirectSpeedTest(
                    call.argument<String>("token"),
                    result,
                )
                "authorizeWifiUpgrade" -> authorizeWifiUpgrade(
                    call.argument<String>("bleToken"),
                    call.argument<String>("wifiToken"),
                    result,
                )
                "markPeerVerified" -> markPeerVerified(
                    call.argument<String>("token"),
                    result,
                )
                else -> result.notImplemented()
            }
        }
    }

    override fun onStart() {
        super.onStart()
        relayRadioRuntime().uiVisible = true
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        captureConversationTarget(intent)
    }

    override fun onStop() {
        relayRadioRuntime().uiVisible = false
        if (!backgroundPreferences.backgroundRelayEnabled) bleDiscovery.stop()
        super.onStop()
    }

    private fun captureConversationTarget(intent: Intent?) {
        val fingerprint = intent?.getStringExtra(
            RelayForegroundService.EXTRA_CONVERSATION_FINGERPRINT,
        )
        if (!fingerprint.isNullOrBlank()) pendingConversationFingerprint = fingerprint
    }

    private fun startBleDiscovery(result: MethodChannel.Result) {
        if (missingRadioPermissions().isNotEmpty()) {
            result.error(
                "permission_required",
                "Nearby Devices permission is required for BLE discovery.",
                null,
            )
            return
        }
        try {
            val session = bleDiscovery.start()
            if (backgroundPreferences.backgroundRelayEnabled) {
                RelayForegroundService.start(this)
            }
            result.success(session)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            if (error.code == "bluetooth_off" && backgroundPreferences.backgroundRelayEnabled) {
                RelayForegroundService.start(this)
            }
            result.error(error.code, error.message, null)
        } catch (_: RuntimeException) {
            bleDiscovery.stop()
            result.error(
                "background_service_failed",
                "Android could not keep offline delivery active.",
                null,
            )
        }
    }

    private fun sendEngineeringTransfer(
        peerToken: String?,
        tamperCiphertext: Boolean,
        result: MethodChannel.Result,
    ) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby session token is required.", null)
            return
        }
        try {
            bleDiscovery.sendEngineeringTransfer(peerToken, tamperCiphertext)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun identifyPeer(peerToken: String?, result: MethodChannel.Result) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby session token is required.", null)
            return
        }
        try {
            bleDiscovery.identifyPeer(peerToken)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun markPeerVerified(peerToken: String?, result: MethodChannel.Result) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby session token is required.", null)
            return
        }
        try {
            bleDiscovery.markPeerVerified(peerToken)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun sendTextMessage(
        peerToken: String?,
        text: String?,
        replyToMessageId: String?,
        replyPreview: String?,
        result: MethodChannel.Result,
    ) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby session token is required.", null)
            return
        }
        if (text.isNullOrEmpty()) {
            result.error("invalid_message", "Enter a message first.", null)
            return
        }
        try {
            result.success(
                bleDiscovery.sendTextMessage(
                    peerToken,
                    text,
                    replyToMessageId,
                    replyPreview,
                ),
            )
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun sendWifiTextMessage(
        blePeerToken: String?,
        wifiPeerToken: String?,
        text: String?,
        result: MethodChannel.Result,
    ) {
        if (blePeerToken.isNullOrBlank() || wifiPeerToken.isNullOrBlank()) {
            result.error("invalid_token", "Nearby BLE and Wi-Fi peer tokens are required.", null)
            return
        }
        if (text.isNullOrEmpty()) {
            result.error("invalid_message", "Enter a message first.", null)
            return
        }
        try {
            bleDiscovery.sendWifiTextMessage(blePeerToken, wifiPeerToken, text)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun retryTextMessage(
        peerToken: String?,
        messageId: String?,
        result: MethodChannel.Result,
    ) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby session token is required.", null)
            return
        }
        if (messageId.isNullOrBlank()) {
            result.error("invalid_message_id", "A queued message ID is required.", null)
            return
        }
        try {
            bleDiscovery.retryTextMessage(peerToken, messageId)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun queueMeshText(
        peerFingerprint: String?,
        text: String?,
        replyToMessageId: String?,
        replyPreview: String?,
        result: MethodChannel.Result,
    ) {
        if (peerFingerprint.isNullOrBlank()) {
            result.error("invalid_contact", "Choose a Relay contact first.", null)
            return
        }
        if (text.isNullOrBlank()) {
            result.error("invalid_message", "Enter a message first.", null)
            return
        }
        try {
            result.success(
                bleDiscovery.queueMeshText(
                    peerFingerprint,
                    text,
                    replyToMessageId,
                    replyPreview,
                ),
            )
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun queueLastCopyDiagnosticText(
        peerFingerprint: String?,
        text: String?,
        result: MethodChannel.Result,
    ) {
        if (peerFingerprint.isNullOrBlank()) {
            result.error("invalid_contact", "Choose a Relay contact first.", null)
            return
        }
        if (text.isNullOrBlank()) {
            result.error("invalid_message", "Enter a diagnostic message first.", null)
            return
        }
        try {
            result.success(
                bleDiscovery.queueLastCopyDiagnosticText(peerFingerprint, text),
            )
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun syncMesh(peerToken: String?, result: MethodChannel.Result) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby session token is required.", null)
            return
        }
        try {
            bleDiscovery.syncMesh(peerToken)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun updateDisplayName(displayName: String?, result: MethodChannel.Result) {
        if (displayName == null) {
            result.error("invalid_display_name", "Enter a profile name.", null)
            return
        }
        try {
            result.success(bleDiscovery.updateDisplayName(displayName))
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun getStoredMessages(result: MethodChannel.Result) {
        // Opening a growing encrypted history performs SQLite reads and one
        // authenticated decryption per message. Never do that work on Android's
        // main thread: it also owns IME/focus and frame delivery for Flutter.
        messageReadExecutor.execute {
            try {
                val messages = bleDiscovery.storedMessages()
                runOnUiThread { result.success(messages) }
            } catch (error: RelayBleDiscovery.DiscoveryException) {
                runOnUiThread { result.error(error.code, error.message, null) }
            }
        }
    }

    private fun getStoredMessagePage(
        peerFingerprint: String?,
        beforeCreatedAtMs: Long?,
        beforeMessageIdHex: String?,
        limit: Int?,
        result: MethodChannel.Result,
    ) {
        if (peerFingerprint.isNullOrBlank()) {
            result.error("invalid_contact", "Choose a Hypha conversation first.", null)
            return
        }
        if ((beforeCreatedAtMs == null) != (beforeMessageIdHex == null)) {
            result.error("invalid_history_cursor", "The message history cursor is incomplete.", null)
            return
        }
        messageReadExecutor.execute {
            try {
                val page = bleDiscovery.storedMessagePage(
                    peerFingerprint = peerFingerprint,
                    beforeCreatedAtMs = beforeCreatedAtMs,
                    beforeMessageIdHex = beforeMessageIdHex,
                    limit = limit ?: DEFAULT_HISTORY_PAGE_SIZE,
                )
                runOnUiThread { result.success(page) }
            } catch (error: RelayBleDiscovery.DiscoveryException) {
                runOnUiThread { result.error(error.code, error.message, null) }
            }
        }
    }

    private fun getConversationSummaries(result: MethodChannel.Result) {
        messageReadExecutor.execute {
            try {
                val summaries = bleDiscovery.conversationSummaries()
                runOnUiThread { result.success(summaries) }
            } catch (error: RelayBleDiscovery.DiscoveryException) {
                runOnUiThread { result.error(error.code, error.message, null) }
            }
        }
    }

    private fun markConversationRead(
        peerFingerprint: String?,
        result: MethodChannel.Result,
    ) {
        if (peerFingerprint.isNullOrBlank()) {
            result.error("invalid_contact", "Choose a Hypha conversation first.", null)
            return
        }
        messageReadExecutor.execute {
            try {
                val changed = bleDiscovery.markConversationRead(peerFingerprint)
                RelayForegroundService.clearConversationNotification(this, peerFingerprint)
                runOnUiThread { result.success(changed) }
            } catch (error: RelayBleDiscovery.DiscoveryException) {
                runOnUiThread { result.error(error.code, error.message, null) }
            }
        }
    }

    private fun startWifiDirect(result: MethodChannel.Result) {
        val missing = requiredWifiDirectPermissions().filter {
            checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            result.error(
                "wifi_permission_required",
                "Nearby Wi-Fi permission is required for Wi-Fi Direct.",
                null,
            )
            return
        }
        try {
            result.success(bleDiscovery.startWifiDirect())
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun runWifiDirectSpeedTest(peerToken: String?, result: MethodChannel.Result) {
        if (peerToken.isNullOrBlank()) {
            result.error("invalid_token", "A nearby Wi-Fi Direct token is required.", null)
            return
        }
        try {
            bleDiscovery.runWifiDirectSpeedTest(peerToken)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun authorizeWifiUpgrade(
        blePeerToken: String?,
        wifiPeerToken: String?,
        result: MethodChannel.Result,
    ) {
        if (blePeerToken.isNullOrBlank() || wifiPeerToken.isNullOrBlank()) {
            result.error(
                "invalid_token",
                "Nearby BLE and Wi-Fi peer tokens are required.",
                null,
            )
            return
        }
        try {
            bleDiscovery.authorizeWifiUpgrade(blePeerToken, wifiPeerToken)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun pickAttachment(
        peerFingerprint: String?,
        rawKind: String?,
        result: MethodChannel.Result,
    ) {
        if (pendingAttachmentPick != null) {
            result.error("attachment_picker_busy", "Another attachment picker is already open.", null)
            return
        }
        if (peerFingerprint.isNullOrBlank()) {
            result.error("invalid_contact", "Choose a verified contact first.", null)
            return
        }
        val kind = when (rawKind) {
            "image" -> RelayAttachmentManifest.Kind.IMAGE
            "file" -> RelayAttachmentManifest.Kind.FILE
            else -> {
                result.error("invalid_attachment_kind", "Choose an image or file.", null)
                return
            }
        }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = if (kind == RelayAttachmentManifest.Kind.IMAGE) "image/*" else "*/*"
        }
        pendingAttachmentPick = PendingAttachmentPick(peerFingerprint, kind, result)
        try {
            startActivityForResult(intent, ATTACHMENT_PICK_REQUEST)
        } catch (_: ActivityNotFoundException) {
            pendingAttachmentPick = null
            result.error("attachment_picker_unavailable", "Android has no file picker.", null)
        }
    }

    private fun pickVenueInventory(
        allowAuthorityBootstrap: Boolean,
        result: MethodChannel.Result,
    ) {
        if (pendingVenueInventoryPick != null || pendingAttachmentPick != null) {
            result.error("venue_picker_busy", "Another document picker is already open.", null)
            return
        }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
        }
        pendingVenueInventoryPick = PendingVenueInventoryPick(allowAuthorityBootstrap, result)
        try {
            startActivityForResult(intent, VENUE_INVENTORY_PICK_REQUEST)
        } catch (_: ActivityNotFoundException) {
            pendingVenueInventoryPick = null
            result.error("venue_picker_unavailable", "Android has no file picker.", null)
        }
    }

    @Deprecated("The Android document picker still returns through this framework callback.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VENUE_INVENTORY_PICK_REQUEST) {
            val pending = pendingVenueInventoryPick ?: return
            pendingVenueInventoryPick = null
            val uri = data?.data
            if (resultCode != Activity.RESULT_OK || uri == null) {
                pending.result.success(null)
                return
            }
            attachmentExecutor.execute {
                try {
                    val encoded = contentResolver.openInputStream(uri)?.use { input ->
                        val output = ByteArrayOutputStream()
                        val buffer = ByteArray(1024)
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            output.write(buffer, 0, read)
                            check(output.size() <= MAX_VENUE_INVENTORY_BYTES) {
                                "The HVI1 inventory is too large."
                            }
                        }
                        output.toByteArray()
                    } ?: error("The selected HVI1 inventory could not be read.")
                    val installed = bleDiscovery.installVenueInventory(
                        encoded,
                        pending.allowAuthorityBootstrap,
                    )
                    runOnUiThread { pending.result.success(installed) }
                } catch (error: Exception) {
                    runOnUiThread {
                        pending.result.error(
                            "venue_inventory_import_failed",
                            error.message ?: "The signed venue inventory could not be imported.",
                            null,
                        )
                    }
                }
            }
            return
        }
        if (requestCode != ATTACHMENT_PICK_REQUEST) return
        val pending = pendingAttachmentPick ?: return
        pendingAttachmentPick = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            pending.result.success(null)
            return
        }
        attachmentExecutor.execute {
            try {
                val stored = attachmentStore.importOutgoing(
                    contentResolver,
                    uri,
                    pending.peerFingerprint,
                    pending.kind,
                )
                // Create the tiny encrypted local thumbnail before authenticated delivery can
                // release the sender's full encrypted payload.
                val attachmentIdHex = stored.manifest.attachmentId.joinToString("") { byte ->
                    "%02x".format(byte.toInt() and 0xFF)
                }
                runCatching { attachmentPreviewStore.loadOrCreate(attachmentIdHex) }
                runOnUiThread { pending.result.success(stored.toMap()) }
            } catch (error: Exception) {
                runOnUiThread {
                    pending.result.error(
                        "attachment_import_failed",
                        error.message ?: "The selected attachment could not be secured.",
                        null,
                    )
                }
            }
        }
    }

    private fun sendAttachment(
        blePeerToken: String?,
        attachmentIdHex: String?,
        result: MethodChannel.Result,
    ) {
        if (blePeerToken.isNullOrBlank() || attachmentIdHex.isNullOrBlank()) {
            result.error("invalid_attachment_target", "A nearby verified recipient is required.", null)
            return
        }
        try {
            bleDiscovery.sendAttachment(blePeerToken, attachmentIdHex)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun prepareCourierAttachment(
        attachmentIdHex: String?,
        result: MethodChannel.Result,
    ) {
        if (attachmentIdHex.isNullOrBlank()) {
            result.error("invalid_attachment", "Attachment ID is required.", null)
            return
        }
        try {
            result.success(bleDiscovery.prepareCourierAttachment(attachmentIdHex))
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun pauseAttachment(attachmentIdHex: String?, result: MethodChannel.Result) {
        if (attachmentIdHex.isNullOrBlank()) {
            result.error("invalid_attachment", "Attachment ID is required.", null)
            return
        }
        try {
            bleDiscovery.pauseAttachment(attachmentIdHex)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun cancelAttachment(attachmentIdHex: String?, result: MethodChannel.Result) {
        if (attachmentIdHex.isNullOrBlank()) {
            result.error("invalid_attachment", "Attachment ID is required.", null)
            return
        }
        try {
            bleDiscovery.cancelAttachment(attachmentIdHex)
            result.success(null)
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            result.error(error.code, error.message, null)
        }
    }

    private fun openAttachment(attachmentIdHex: String?, result: MethodChannel.Result) {
        if (attachmentIdHex.isNullOrBlank()) {
            result.error("invalid_attachment", "Attachment ID is required.", null)
            return
        }
        attachmentExecutor.execute {
            try {
                val stored = attachmentStore.findByHexId(attachmentIdHex)
                    ?: throw IllegalStateException("Attachment was not found.")
                val exported = attachmentStore.exportVerified(stored.manifest.attachmentId)
                val uri = FileProvider.getUriForFile(
                    this,
                    "$packageName.attachments",
                    exported,
                )
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, stored.manifest.mimeType)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                runOnUiThread {
                    try {
                        startActivity(intent)
                        result.success(null)
                    } catch (_: ActivityNotFoundException) {
                        result.error(
                            "attachment_viewer_unavailable",
                            "No installed app can open this file type.",
                            null,
                        )
                    }
                }
            } catch (error: Exception) {
                runOnUiThread {
                    result.error(
                        "attachment_open_failed",
                        error.message ?: "The attachment could not be opened safely.",
                        null,
                    )
                }
            }
        }
    }

    private fun loadAttachmentPreview(attachmentIdHex: String?, result: MethodChannel.Result) {
        if (attachmentIdHex.isNullOrBlank()) {
            result.error("invalid_attachment", "Attachment ID is required.", null)
            return
        }
        attachmentExecutor.execute {
            val preview = runCatching {
                attachmentPreviewStore.loadOrCreate(attachmentIdHex)
            }.getOrNull()
            runOnUiThread { result.success(preview) }
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != pendingPermissionRequestCode) return
        val granted = grantResults.isNotEmpty() &&
            grantResults.all { it == PackageManager.PERMISSION_GRANTED }
        pendingPermissionResult?.success(granted)
        pendingPermissionResult = null
        pendingPermissionRequestCode = null
    }

    private fun setBackgroundRelayEnabled(enabled: Boolean?, result: MethodChannel.Result) {
        if (enabled == null) {
            result.error("invalid_setting", "Background relay state is required.", null)
            return
        }
        backgroundPreferences.backgroundRelayEnabled = enabled
        if (enabled) {
            try {
                if (missingRadioPermissions().isEmpty()) bleDiscovery.start()
            } catch (_: RelayBleDiscovery.DiscoveryException) {
                // The foreground service reports Bluetooth-off recovery honestly.
            }
            RelayForegroundService.start(this)
        } else {
            // Keep foreground discovery usable until the visible activity leaves.
            RelayForegroundService.stop(this)
        }
        result.success(backgroundPreferences.snapshot())
    }

    private fun setRestartAfterReboot(enabled: Boolean?, result: MethodChannel.Result) {
        if (enabled == null) {
            result.error("invalid_setting", "Restart preference is required.", null)
            return
        }
        if (enabled && !backgroundPreferences.backgroundRelayEnabled) {
            result.error(
                "background_relay_disabled",
                "Turn on background relay before enabling restart after reboot.",
                null,
            )
            return
        }
        backgroundPreferences.restartAfterReboot = enabled
        result.success(backgroundPreferences.snapshot())
    }

    private fun requestNotificationPermission(result: MethodChannel.Result) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            result.success(true)
            return
        }
        requestPermissions(
            listOf(Manifest.permission.POST_NOTIFICATIONS),
            NOTIFICATION_PERMISSION_REQUEST,
            result,
        )
    }

    private fun openSystemSettings(action: () -> Unit, result: MethodChannel.Result) {
        try {
            action()
            result.success(null)
        } catch (_: RuntimeException) {
            result.error("settings_unavailable", "Android settings could not be opened.", null)
        }
    }

    private fun requestRadioPermissions(result: MethodChannel.Result) {
        if (pendingPermissionResult != null) {
            result.error("request_in_progress", "A permission request is already active.", null)
            return
        }
        val missing = missingRadioPermissions()
        if (missing.isEmpty()) {
            result.success(true)
            return
        }
        pendingPermissionResult = result
        pendingPermissionRequestCode = RADIO_PERMISSION_REQUEST
        requestPermissions(missing.toTypedArray(), RADIO_PERMISSION_REQUEST)
    }

    private fun requestWifiDirectPermissions(result: MethodChannel.Result) {
        requestPermissions(
            requiredWifiDirectPermissions(),
            WIFI_PERMISSION_REQUEST,
            result,
        )
    }

    private fun requestPermissions(
        requiredPermissions: List<String>,
        requestCode: Int,
        result: MethodChannel.Result,
    ) {
        if (pendingPermissionResult != null) {
            result.error("request_in_progress", "A permission request is already active.", null)
            return
        }
        val missing = requiredPermissions.filter {
            checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            result.success(true)
            return
        }
        pendingPermissionResult = result
        pendingPermissionRequestCode = requestCode
        requestPermissions(missing.toTypedArray(), requestCode)
    }

    private fun requiredRadioPermissions(): List<String> {
        val permissions = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions += Manifest.permission.BLUETOOTH_SCAN
            permissions += Manifest.permission.BLUETOOTH_ADVERTISE
            permissions += Manifest.permission.BLUETOOTH_CONNECT
        } else {
            permissions += Manifest.permission.ACCESS_COARSE_LOCATION
            permissions += Manifest.permission.ACCESS_FINE_LOCATION
        }
        return permissions
    }

    private fun requiredWifiDirectPermissions(): List<String> = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU ->
            listOf(Manifest.permission.NEARBY_WIFI_DEVICES)
        else -> listOf(
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }

    private fun missingRadioPermissions(): List<String> = requiredRadioPermissions().filter {
        checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
    }

    @SuppressLint("InlinedApi")
    private fun readRadioCapabilities(): Map<String, Any> {
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        val adapter = bluetoothManager?.adapter
        val wifiManager = applicationContext.getSystemService(WifiManager::class.java)
        val locationManager = getSystemService(LocationManager::class.java)
        var permissionRequired = false

        fun protectedFlag(read: () -> Boolean): Boolean =
            try {
                read()
            } catch (_: SecurityException) {
                permissionRequired = true
                false
            }

        val sdkInt = Build.VERSION.SDK_INT
        return mapOf(
            "sdkInt" to sdkInt,
            "bluetoothPresent" to (adapter != null),
            "bluetoothEnabled" to protectedFlag { adapter?.isEnabled == true },
            "multipleAdvertisementSupported" to protectedFlag {
                adapter?.isMultipleAdvertisementSupported == true
            },
            "le2MPhySupported" to protectedFlag {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                    adapter?.isLe2MPhySupported == true
            },
            "leCodedPhySupported" to protectedFlag {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                    adapter?.isLeCodedPhySupported == true
            },
            "extendedAdvertisingSupported" to protectedFlag {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                    adapter?.isLeExtendedAdvertisingSupported == true
            },
            "wifiAwareSupported" to packageManager.hasSystemFeature(
                PackageManager.FEATURE_WIFI_AWARE,
            ),
            "wifiDirectSupported" to packageManager.hasSystemFeature(
                PackageManager.FEATURE_WIFI_DIRECT,
            ),
            "wifiEnabled" to protectedFlag { wifiManager?.isWifiEnabled == true },
            "wifiDirectPermissionRequired" to requiredWifiDirectPermissions().any {
                checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
            },
            "locationServicesEnabled" to (
                Build.VERSION.SDK_INT < Build.VERSION_CODES.P || locationManager.isLocationEnabled
            ),
            "rangingApiAvailable" to (sdkInt >= 36),
            "secureCoreReady" to RelayNative.runSelfTest(),
            "permissionRequired" to permissionRequired,
        )
    }

    private companion object {
        const val RADIO_CHANNEL = "app.projectrelay/radio"
        const val RADIO_EVENTS_CHANNEL = "app.projectrelay/radio_events"
        const val RADIO_PERMISSION_REQUEST = 4100
        const val WIFI_PERMISSION_REQUEST = 4101
        const val NOTIFICATION_PERMISSION_REQUEST = 4102
        const val ATTACHMENT_PICK_REQUEST = 4200
        const val VENUE_INVENTORY_PICK_REQUEST = 4201
        const val MAX_VENUE_INVENTORY_BYTES = 4_469
        const val DEFAULT_HISTORY_PAGE_SIZE = 40
    }

    private data class PendingAttachmentPick(
        val peerFingerprint: String,
        val kind: RelayAttachmentManifest.Kind,
        val result: MethodChannel.Result,
    )

    private data class PendingVenueInventoryPick(
        val allowAuthorityBootstrap: Boolean,
        val result: MethodChannel.Result,
    )
}
