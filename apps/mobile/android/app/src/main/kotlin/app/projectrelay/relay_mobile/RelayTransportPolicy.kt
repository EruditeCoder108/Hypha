package app.projectrelay.relay_mobile

/** Keeps text/control on BLE. Attachments currently have a Wi-Fi Direct data plane only. */
internal object RelayTransportPolicy {
    fun textTransport(): String = "ble"

    /** A small attachment must wait for Wi-Fi, never for an unimplemented BLE file path. */
    fun canUseWifiForAttachment(): Boolean = true
}
