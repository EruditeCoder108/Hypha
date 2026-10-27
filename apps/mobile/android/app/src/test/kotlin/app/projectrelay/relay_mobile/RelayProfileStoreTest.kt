package app.projectrelay.relay_mobile

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class RelayProfileStoreTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("relay_profile_v1", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @After
    fun tearDown() {
        context.getSharedPreferences("relay_profile_v1", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun firstInstallRequiresANameBeforeProfileExchange() {
        val profile = RelayProfileStore(context)

        assertEquals("Hypha user", profile.displayName())
        assertFalse(profile.setupComplete())

        assertEquals("Maya Singh", profile.updateDisplayName("  Maya   Singh  "))
        assertTrue(RelayProfileStore(context).setupComplete())
        assertEquals("Maya Singh", RelayProfileStore(context).displayName())
    }
}
