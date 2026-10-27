package app.projectrelay.relay_mobile

import android.content.Context

/** Local profile data shared only inside an explicit authenticated contact exchange. */
internal class RelayProfileStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE,
    )

    fun displayName(): String = preferences.getString(DISPLAY_NAME_KEY, null)
        ?.let(RelayContactCard::normalizedDisplayName)
        ?: DEFAULT_DISPLAY_NAME

    fun setupComplete(): Boolean = preferences.getBoolean(
        PROFILE_SETUP_COMPLETE_KEY,
        preferences.contains(DISPLAY_NAME_KEY),
    )

    fun updateDisplayName(raw: String): String {
        val normalized = RelayContactCard.normalizedDisplayName(raw)
        check(
            preferences.edit()
                .putString(DISPLAY_NAME_KEY, normalized)
                .putBoolean(PROFILE_SETUP_COMPLETE_KEY, true)
                .commit(),
        ) {
            "Relay profile name could not be saved."
        }
        return normalized
    }

    private companion object {
        const val PREFERENCES_NAME = "relay_profile_v1"
        const val DISPLAY_NAME_KEY = "display_name"
        const val PROFILE_SETUP_COMPLETE_KEY = "profile_setup_complete"
        const val DEFAULT_DISPLAY_NAME = "Hypha user"
    }
}
