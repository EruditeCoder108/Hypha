package app.projectrelay.relay_mobile

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

/** Durable user choices and honest Android state for background delivery. */
internal class RelayBackgroundPreferences(context: Context) {
    private val appContext = context.applicationContext
    private val preferences = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    var backgroundRelayEnabled: Boolean
        get() = preferences.getBoolean(KEY_BACKGROUND_RELAY_ENABLED, true)
        set(value) {
            preferences.edit().putBoolean(KEY_BACKGROUND_RELAY_ENABLED, value).apply()
        }

    var restartAfterReboot: Boolean
        get() = preferences.getBoolean(KEY_RESTART_AFTER_REBOOT, false)
        set(value) {
            preferences.edit().putBoolean(KEY_RESTART_AFTER_REBOOT, value).apply()
        }

    var notificationOnboardingDismissed: Boolean
        get() = preferences.getBoolean(KEY_NOTIFICATION_ONBOARDING_DISMISSED, false)
        set(value) {
            preferences.edit().putBoolean(KEY_NOTIFICATION_ONBOARDING_DISMISSED, value).apply()
        }

    fun hasRadioPermissions(): Boolean = requiredRadioPermissions().all {
        appContext.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
    }

    fun snapshot(): Map<String, Any> {
        val notificationPermissionGranted =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                appContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        val notificationManager = appContext.getSystemService(NotificationManager::class.java)
        val powerManager = appContext.getSystemService(PowerManager::class.java)
        val batteryOptimizationExempt =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.M ||
                powerManager?.isIgnoringBatteryOptimizations(appContext.packageName) == true

        return mapOf(
            "backgroundRelayEnabled" to backgroundRelayEnabled,
            "restartAfterReboot" to restartAfterReboot,
            "notificationPermissionRequired" to !notificationPermissionGranted,
            "notificationsEnabled" to (
                notificationPermissionGranted && notificationManager?.areNotificationsEnabled() != false
            ),
            "notificationOnboardingDismissed" to notificationOnboardingDismissed,
            "batteryOptimizationExempt" to batteryOptimizationExempt,
            "manufacturer" to Build.MANUFACTURER,
            "model" to Build.MODEL,
            "sdkInt" to Build.VERSION.SDK_INT,
        )
    }

    fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, appContext.packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        appContext.startActivity(intent)
    }

    fun openBatterySettings() {
        // Offer Android's one-tap exemption dialog first; OEM battery managers otherwise stop
        // background encounters on many popular devices. Fall back to the app details page.
        val powerManager = appContext.getSystemService(PowerManager::class.java)
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            powerManager?.isIgnoringBatteryOptimizations(appContext.packageName) == false
        ) {
            val request = Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:${appContext.packageName}"),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                appContext.startActivity(request)
                return
            } catch (_: RuntimeException) {
                // Some OEM builds remove the dialog; continue to the app details page.
            }
        }
        val appDetails = Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.parse("package:${appContext.packageName}"),
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            appContext.startActivity(appDetails)
        } catch (_: RuntimeException) {
            appContext.startActivity(
                Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    private fun requiredRadioPermissions(): List<String> = if (
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    ) {
        listOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        listOf(
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }

    private companion object {
        const val PREFERENCES_NAME = "relay_background_preferences"
        const val KEY_BACKGROUND_RELAY_ENABLED = "background_relay_enabled"
        const val KEY_RESTART_AFTER_REBOOT = "restart_after_reboot"
        const val KEY_NOTIFICATION_ONBOARDING_DISMISSED =
            "notification_onboarding_dismissed"
    }
}
