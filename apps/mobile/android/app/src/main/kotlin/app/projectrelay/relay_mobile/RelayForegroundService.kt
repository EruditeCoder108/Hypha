package app.projectrelay.relay_mobile

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log

/** Keeps the BLE courier engine alive after the Flutter activity leaves the screen. */
class RelayForegroundService : Service() {
    private lateinit var runtime: RelayRadioRuntime
    private lateinit var backgroundPreferences: RelayBackgroundPreferences
    private val notificationManager: NotificationManager
        get() = getSystemService(NotificationManager::class.java)

    override fun onCreate() {
        super.onCreate()
        runtime = relayRadioRuntime()
        backgroundPreferences = RelayBackgroundPreferences(this)
        createNotificationChannels()
        promoteToForeground("Starting offline relay...")
        runtime.discovery.setBackgroundEventObserver(::onRadioEvent)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!backgroundPreferences.backgroundRelayEnabled ||
            !RelayProfileStore(this).setupComplete()
        ) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        Log.i(METRICS_TAG, "service_start sticky=${intent == null}")
        promoteToForeground("Ready to carry offline messages")
        try {
            runtime.discovery.start()
        } catch (error: RelayBleDiscovery.DiscoveryException) {
            val status = if (error.code == "bluetooth_off") {
                "Waiting for Bluetooth"
            } else {
                "Open Hypha to restore nearby messaging"
            }
            promoteToForeground(status)
            Log.i(TAG, "Background radio start deferred: ${error.code}")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        runtime.discovery.setBackgroundEventObserver(null)
        if (!runtime.uiVisible) runtime.discovery.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun onRadioEvent(event: Map<String, Any>) {
        when (event["type"] as? String) {
            "discovery_started" -> promoteToForeground("Ready to carry offline messages")
            "discovery_suspended" -> promoteToForeground("Waiting for Bluetooth")
            "radio_recovery_deferred" -> promoteToForeground("Restoring nearby messaging...")
            "text_message_received" -> if (!runtime.uiVisible) notifyIncomingMessage(event)
            "attachment_received" -> if (!runtime.uiVisible) notifyIncomingAttachment(event)
        }
    }

    private fun promoteToForeground(status: String) {
        val notification = serviceNotification(status)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                SERVICE_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(SERVICE_NOTIFICATION_ID, notification)
        }
    }

    private fun serviceNotification(status: String): Notification {
        return notificationBuilder(SERVICE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_hypha)
            .setContentTitle("Hypha is active")
            .setContentText(status)
            .setContentIntent(openAppPendingIntent())
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
    }

    private fun notifyIncomingMessage(event: Map<String, Any>) {
        val fingerprint = event["fingerprint"] as? String
        val sender = fingerprint?.let { peer ->
            runtime.discovery.contacts().firstOrNull { it["fingerprint"] == peer }
                ?.get("displayName") as? String
        } ?: "Hypha contact"
        val messageId = event["messageId"] as? String ?: System.nanoTime().toString()
        val unreadCount = fingerprint?.let(::unreadCountForConversation) ?: 1
        val notification = notificationBuilder(MESSAGE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_hypha)
            .setContentTitle(sender)
            .setContentText("New encrypted offline message")
            .setContentIntent(openAppPendingIntent(fingerprint))
            .setNumber(unreadCount.coerceAtLeast(1))
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .build()
        val tag = fingerprint ?: messageId
        notificationManager.notify(tag, CONVERSATION_MESSAGE_NOTIFICATION_ID, notification)
    }

    private fun notifyIncomingAttachment(event: Map<String, Any>) {
        val fingerprint = event["fingerprint"] as? String
        val sender = fingerprint?.let { peer ->
            runtime.discovery.contacts().firstOrNull { it["fingerprint"] == peer }
                ?.get("displayName") as? String
        } ?: "Hypha contact"
        val attachmentId = event["attachmentId"] as? String ?: System.nanoTime().toString()
        val notification = notificationBuilder(MESSAGE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_hypha)
            .setContentTitle(sender)
            .setContentText("Encrypted attachment ready")
            .setContentIntent(openAppPendingIntent(fingerprint))
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .build()
        val tag = fingerprint ?: attachmentId
        notificationManager.notify(tag, CONVERSATION_ATTACHMENT_NOTIFICATION_ID, notification)
    }

    private fun unreadCountForConversation(fingerprint: String): Int =
        runtime.discovery.unreadCount(fingerprint).coerceAtLeast(1)

    private fun openAppPendingIntent(peerFingerprint: String? = null): PendingIntent {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            peerFingerprint?.let { putExtra(EXTRA_CONVERSATION_FINGERPRINT, it) }
        }
        return PendingIntent.getActivity(
            this,
            peerFingerprint?.hashCode()?.and(Int.MAX_VALUE) ?: 0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        notificationManager.createNotificationChannel(
            NotificationChannel(
                SERVICE_CHANNEL_ID,
                "Offline relay",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Keeps encrypted nearby delivery available in the background."
                setShowBadge(false)
            },
        )
        notificationManager.createNotificationChannel(
            NotificationChannel(
                MESSAGE_CHANNEL_ID,
                "Offline arrivals",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Private alerts for encrypted offline messages and attachments."
            },
        )
    }

    @SuppressLint("NewApi")
    private fun notificationBuilder(channelId: String): Notification.Builder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            Notification.Builder(this)
        }

    companion object {
        private const val TAG = "RelayBackground"
        private const val METRICS_TAG = "RelayMetrics"
        private const val SERVICE_CHANNEL_ID = "relay_background"
        private const val MESSAGE_CHANNEL_ID = "relay_messages"
        private const val SERVICE_NOTIFICATION_ID = 4101
        private const val CONVERSATION_MESSAGE_NOTIFICATION_ID = 4201
        private const val CONVERSATION_ATTACHMENT_NOTIFICATION_ID = 4202
        internal const val EXTRA_CONVERSATION_FINGERPRINT =
            "app.projectrelay.extra.CONVERSATION_FINGERPRINT"

        fun start(context: Context): Boolean {
            val preferences = RelayBackgroundPreferences(context)
            if (!RelayProfileStore(context).setupComplete() ||
                !preferences.backgroundRelayEnabled ||
                !preferences.hasRadioPermissions()
            ) {
                return false
            }
            val intent = Intent(context, RelayForegroundService::class.java)
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                true
            } catch (error: RuntimeException) {
                Log.i(TAG, "Android rejected background relay start: ${error.javaClass.simpleName}")
                false
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, RelayForegroundService::class.java))
        }

        fun clearConversationNotification(context: Context, fingerprint: String) {
            val manager = context.getSystemService(NotificationManager::class.java)
            manager?.cancel(fingerprint, CONVERSATION_MESSAGE_NOTIFICATION_ID)
            manager?.cancel(fingerprint, CONVERSATION_ATTACHMENT_NOTIFICATION_ID)
        }
    }
}
