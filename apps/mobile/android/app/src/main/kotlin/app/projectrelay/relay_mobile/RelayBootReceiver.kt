package app.projectrelay.relay_mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/** Restarts the opted-in connected-device relay after Android finishes booting. */
class RelayBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val preferences = RelayBackgroundPreferences(context)
        if (!preferences.backgroundRelayEnabled || !preferences.restartAfterReboot) return
        if (!preferences.hasRadioPermissions()) {
            Log.i(TAG, "Boot relay deferred because Nearby Devices permission is missing")
            return
        }
        Log.i(METRICS_TAG, "boot_start_requested")
        if (!RelayForegroundService.start(context)) {
            Log.i(TAG, "Android deferred the opted-in boot relay start")
        }
    }

    private companion object {
        const val TAG = "RelayBackground"
        const val METRICS_TAG = "RelayMetrics"
    }
}
