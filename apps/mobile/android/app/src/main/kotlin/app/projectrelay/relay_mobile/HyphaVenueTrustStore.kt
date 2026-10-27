package app.projectrelay.relay_mobile

import android.content.Context
import android.util.Base64
import java.security.MessageDigest

/** Fail-closed Lab/Managed Venue state and rollback fence for HVI1. */
internal class HyphaVenueTrustStore(context: Context) {
    enum class Mode { LAB, MANAGED }
    enum class PolicyState { LAB, READY, UNAVAILABLE }

    data class Snapshot(
        val mode: Mode,
        val policyState: PolicyState,
        val version: Long?,
        val venueId: String?,
    )

    data class Authorization(
        val allowed: Boolean,
        val nodeStatus: HyphaVenueInventory.NodeStatus,
        val trustLabel: String,
        val reason: String?,
    )

    data class InstallResult(
        val installed: Boolean,
        val reason: String?,
        val snapshot: Snapshot,
    )

    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE,
    )
    private var state: State = loadState()

    @Synchronized
    fun snapshot(): Snapshot = state.snapshot()

    @Synchronized
    fun authorize(identityPublicKey: ByteArray): Authorization = when (val current = state) {
        State.Lab -> Authorization(
            allowed = true,
            nodeStatus = HyphaVenueInventory.NodeStatus.UNKNOWN,
            trustLabel = "lab_authenticated",
            reason = null,
        )
        is State.ManagedUnavailable -> Authorization(
            allowed = false,
            nodeStatus = HyphaVenueInventory.NodeStatus.UNKNOWN,
            trustLabel = "managed_unavailable",
            reason = "The managed venue inventory is unavailable.",
        )
        is State.ManagedReady -> {
            val status = current.inventory.statusFor(identityPublicKey)
            Authorization(
                allowed = status == HyphaVenueInventory.NodeStatus.ACTIVE,
                nodeStatus = status,
                trustLabel = if (status == HyphaVenueInventory.NodeStatus.ACTIVE) {
                    "managed_approved"
                } else {
                    "managed_rejected"
                },
                reason = when (status) {
                    HyphaVenueInventory.NodeStatus.ACTIVE -> null
                    HyphaVenueInventory.NodeStatus.REVOKED -> "This fixed node was revoked."
                    HyphaVenueInventory.NodeStatus.REPLACED -> "This fixed node was replaced."
                    HyphaVenueInventory.NodeStatus.UNKNOWN ->
                        "This fixed node is not in the venue inventory."
                },
            )
        }
    }

    @Synchronized
    fun install(encoded: ByteArray, allowAuthorityBootstrap: Boolean): InstallResult {
        val inventory = try {
            HyphaVenueInventory.parseAndVerify(encoded)
        } catch (error: IllegalArgumentException) {
            return failed(error.message ?: "The HVI1 inventory is invalid.")
        }
        val managed = preferences.getBoolean(KEY_MANAGED, false)
        if (!managed && !allowAuthorityBootstrap) {
            return failed("Entering Managed Venue mode requires explicit local bootstrap approval.")
        }
        if (managed) {
            val authority = decodePreference(KEY_AUTHORITY)
                ?: return failed("The managed venue authority anchor is unavailable.")
            val venue = decodePreference(KEY_VENUE)
                ?: return failed("The managed venue id anchor is unavailable.")
            val highestVersion = preferences.getLong(KEY_HIGHEST_VERSION, 0L)
            if (!MessageDigest.isEqual(authority, inventory.authorityPublicKey())) {
                return failed("The HVI1 authority does not match this managed venue.")
            }
            if (!MessageDigest.isEqual(venue, inventory.venueId())) {
                return failed("The HVI1 venue id does not match this managed venue.")
            }
            if (inventory.version < highestVersion ||
                (inventory.version == highestVersion && state is State.ManagedReady)
            ) {
                return failed("The HVI1 inventory version is not newer than the rollback fence.")
            }
        }
        val committed = preferences.edit()
            .putBoolean(KEY_MANAGED, true)
            .putString(KEY_INVENTORY, encoded.toBase64())
            .putString(KEY_AUTHORITY, inventory.authorityPublicKey().toBase64())
            .putString(KEY_VENUE, inventory.venueId().toBase64())
            .putLong(KEY_HIGHEST_VERSION, inventory.version)
            .commit()
        if (!committed) return failed("The managed venue inventory could not be saved.")
        state = State.ManagedReady(inventory)
        return InstallResult(true, null, state.snapshot())
    }

    @Synchronized
    fun resetToLab(confirmation: String): Boolean {
        if (confirmation != RESET_CONFIRMATION) return false
        if (!preferences.edit().clear().commit()) return false
        state = State.Lab
        return true
    }

    private fun failed(reason: String): InstallResult = InstallResult(
        installed = false,
        reason = reason,
        snapshot = state.snapshot(),
    )

    private fun loadState(): State {
        if (!preferences.getBoolean(KEY_MANAGED, false)) return State.Lab
        val version = preferences.getLong(KEY_HIGHEST_VERSION, 0L)
        val venue = decodePreference(KEY_VENUE)
        val authority = decodePreference(KEY_AUTHORITY)
        if (version <= 0L || venue?.size != 16 || authority?.size != 65) {
            return State.ManagedUnavailable(version.takeIf { it > 0L }, venue)
        }
        val encoded = decodePreference(KEY_INVENTORY)
            ?: return State.ManagedUnavailable(version, venue)
        val inventory = runCatching { HyphaVenueInventory.parseAndVerify(encoded) }.getOrNull()
            ?: return State.ManagedUnavailable(version, venue)
        if (inventory.version != version ||
            !MessageDigest.isEqual(inventory.venueId(), venue) ||
            !MessageDigest.isEqual(inventory.authorityPublicKey(), authority)
        ) {
            return State.ManagedUnavailable(version, venue)
        }
        return State.ManagedReady(inventory)
    }

    private fun decodePreference(key: String): ByteArray? = preferences.getString(key, null)?.let {
        runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull()
    }

    private sealed interface State {
        fun snapshot(): Snapshot

        data object Lab : State {
            override fun snapshot() = Snapshot(Mode.LAB, PolicyState.LAB, null, null)
        }

        data class ManagedReady(val inventory: HyphaVenueInventory) : State {
            override fun snapshot() = Snapshot(
                Mode.MANAGED,
                PolicyState.READY,
                inventory.version,
                inventory.venueId().toHex(),
            )
        }

        data class ManagedUnavailable(
            val version: Long?,
            val venueId: ByteArray?,
        ) : State {
            override fun snapshot() = Snapshot(
                Mode.MANAGED,
                PolicyState.UNAVAILABLE,
                version,
                venueId?.toHex(),
            )
        }
    }

    internal companion object {
        const val PREFERENCES_NAME = "hypha_venue_trust_v1"
        const val KEY_INVENTORY = "inventory"
        const val RESET_CONFIRMATION = "RESET HYPHA VENUE TRUST"
        private const val KEY_MANAGED = "managed"
        private const val KEY_AUTHORITY = "authority"
        private const val KEY_VENUE = "venue"
        private const val KEY_HIGHEST_VERSION = "highest_version"

        private fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)

        private fun ByteArray.toHex(): String = joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
    }
}
