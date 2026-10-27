package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Test

class RelayTransportPolicyTest {
    @Test
    fun `text always stays on BLE`() {
        assertEquals("ble", RelayTransportPolicy.textTransport())
    }

    @Test
    fun `all attachments use Wi-Fi until a BLE attachment data plane exists`() {
        assertEquals(true, RelayTransportPolicy.canUseWifiForAttachment())
    }
}
