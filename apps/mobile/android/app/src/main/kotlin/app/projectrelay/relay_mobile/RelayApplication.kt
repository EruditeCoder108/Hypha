package app.projectrelay.relay_mobile

import android.app.Application
import android.content.Context

class RelayApplication : Application() {
    internal val radioRuntime: RelayRadioRuntime by lazy {
        RelayRadioRuntime(applicationContext)
    }
}

internal class RelayRadioRuntime(context: Context) {
    val discovery = RelayBleDiscovery(context.applicationContext)

    @Volatile
    var uiVisible: Boolean = false
}

internal fun Context.relayRadioRuntime(): RelayRadioRuntime =
    (applicationContext as RelayApplication).radioRuntime
