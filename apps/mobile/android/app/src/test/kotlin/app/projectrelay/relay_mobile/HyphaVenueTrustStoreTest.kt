package app.projectrelay.relay_mobile

import android.content.Context
import android.util.Base64
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class HyphaVenueTrustStoreTest {
    private lateinit var context: Context
    private lateinit var authority: KeyPair
    private lateinit var activeNode: KeyPair
    private lateinit var revokedNode: KeyPair
    private lateinit var replacedNode: KeyPair
    private val venueId = ByteArray(16) { index -> (index + 1).toByte() }

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences(
            HyphaVenueTrustStore.PREFERENCES_NAME,
            Context.MODE_PRIVATE,
        ).edit().clear().commit()
        authority = generateP256()
        activeNode = generateP256()
        revokedNode = generateP256()
        replacedNode = generateP256()
    }

    @Test
    fun `signed inventory distinguishes active revoked replaced and unknown nodes`() {
        val inventory = HyphaVenueInventory.parseAndVerify(inventory(version = 1))

        assertEquals(
            HyphaVenueInventory.NodeStatus.ACTIVE,
            inventory.statusFor(encodePublic(activeNode)),
        )
        assertEquals(
            HyphaVenueInventory.NodeStatus.REVOKED,
            inventory.statusFor(encodePublic(revokedNode)),
        )
        assertEquals(
            HyphaVenueInventory.NodeStatus.REPLACED,
            inventory.statusFor(encodePublic(replacedNode)),
        )
        assertEquals(
            HyphaVenueInventory.NodeStatus.UNKNOWN,
            inventory.statusFor(encodePublic(generateP256())),
        )
    }

    @Test
    fun `invalid signature malformed entries and unsupported schema are rejected`() {
        val badSignature = inventory(version = 1).also { it[it.lastIndex] = (it.last() + 1).toByte() }
        assertFails { HyphaVenueInventory.parseAndVerify(badSignature) }

        assertFails {
            HyphaVenueInventory.parseAndVerify(
                inventory(
                    version = 1,
                    entries = listOf(
                        FixtureEntry(activeNode, STATUS_ACTIVE),
                        FixtureEntry(activeNode, STATUS_REVOKED),
                    ),
                ),
            )
        }
        assertFails { HyphaVenueInventory.parseAndVerify(inventory(version = 1, schema = 2)) }
        assertFails { HyphaVenueInventory.parseAndVerify(inventory(version = 1).copyOf(40)) }
    }

    @Test
    fun `managed mode requires explicit bootstrap and survives restart`() {
        val encoded = inventory(version = 7)
        val store = HyphaVenueTrustStore(context)

        assertEquals(HyphaVenueTrustStore.Mode.LAB, store.snapshot().mode)
        assertFalse(store.install(encoded, allowAuthorityBootstrap = false).installed)
        assertTrue(store.install(encoded, allowAuthorityBootstrap = true).installed)

        val restarted = HyphaVenueTrustStore(context)
        assertEquals(HyphaVenueTrustStore.Mode.MANAGED, restarted.snapshot().mode)
        assertEquals(HyphaVenueTrustStore.PolicyState.READY, restarted.snapshot().policyState)
        assertEquals(7L, restarted.snapshot().version)
        assertTrue(restarted.authorize(encodePublic(activeNode)).allowed)
        assertFalse(restarted.authorize(encodePublic(revokedNode)).allowed)
        assertFalse(restarted.authorize(encodePublic(generateP256())).allowed)
    }

    @Test
    fun `updates require same venue authority and a higher version`() {
        val store = HyphaVenueTrustStore(context)
        assertTrue(store.install(inventory(version = 4), allowAuthorityBootstrap = true).installed)

        assertFalse(store.install(inventory(version = 3), false).installed)
        assertFalse(store.install(inventory(version = 4), false).installed)
        assertFalse(
            store.install(
                inventory(version = 5, venue = ByteArray(16) { 0x33 }),
                false,
            ).installed,
        )
        val otherAuthority = generateP256()
        assertFalse(
            store.install(
                inventory(version = 5, signingAuthority = otherAuthority),
                false,
            ).installed,
        )
        assertTrue(store.install(inventory(version = 5), false).installed)
        assertEquals(5L, HyphaVenueTrustStore(context).snapshot().version)
    }

    @Test
    fun `replacement update rejects old key and approves new key`() {
        val newNode = generateP256()
        val store = HyphaVenueTrustStore(context)
        assertTrue(store.install(inventory(version = 1), true).installed)
        assertTrue(store.authorize(encodePublic(activeNode)).allowed)

        val replacement = inventory(
            version = 2,
            entries = listOf(
                FixtureEntry(activeNode, STATUS_REPLACED),
                FixtureEntry(newNode, STATUS_ACTIVE),
            ),
        )
        assertTrue(store.install(replacement, false).installed)
        assertFalse(store.authorize(encodePublic(activeNode)).allowed)
        assertEquals(
            HyphaVenueInventory.NodeStatus.REPLACED,
            store.authorize(encodePublic(activeNode)).nodeStatus,
        )
        assertTrue(store.authorize(encodePublic(newNode)).allowed)
    }

    @Test
    fun `corrupt stored inventory stays managed and exact fenced version can recover`() {
        val encoded = inventory(version = 9)
        val store = HyphaVenueTrustStore(context)
        assertTrue(store.install(encoded, true).installed)
        context.getSharedPreferences(
            HyphaVenueTrustStore.PREFERENCES_NAME,
            Context.MODE_PRIVATE,
        ).edit().putString(
            HyphaVenueTrustStore.KEY_INVENTORY,
            Base64.encodeToString(byteArrayOf(1, 2, 3), Base64.NO_WRAP),
        ).commit()

        val corrupt = HyphaVenueTrustStore(context)
        assertEquals(HyphaVenueTrustStore.Mode.MANAGED, corrupt.snapshot().mode)
        assertEquals(HyphaVenueTrustStore.PolicyState.UNAVAILABLE, corrupt.snapshot().policyState)
        assertFalse(corrupt.authorize(encodePublic(activeNode)).allowed)
        assertTrue(corrupt.install(encoded, false).installed)
        assertTrue(HyphaVenueTrustStore(context).authorize(encodePublic(activeNode)).allowed)
    }

    @Test
    fun `returning to lab requires exact local reset confirmation`() {
        val store = HyphaVenueTrustStore(context)
        assertTrue(store.install(inventory(version = 1), true).installed)
        assertFalse(store.resetToLab("reset"))
        assertEquals(HyphaVenueTrustStore.Mode.MANAGED, store.snapshot().mode)
        assertTrue(store.resetToLab(HyphaVenueTrustStore.RESET_CONFIRMATION))
        assertEquals(HyphaVenueTrustStore.Mode.LAB, HyphaVenueTrustStore(context).snapshot().mode)
        assertTrue(HyphaVenueTrustStore(context).authorize(encodePublic(generateP256())).allowed)
    }

    private fun inventory(
        version: Long,
        venue: ByteArray = venueId,
        signingAuthority: KeyPair = authority,
        entries: List<FixtureEntry> = listOf(
            FixtureEntry(activeNode, STATUS_ACTIVE),
            FixtureEntry(revokedNode, STATUS_REVOKED),
            FixtureEntry(replacedNode, STATUS_REPLACED),
        ),
        schema: Int = 1,
    ): ByteArray {
        val encodedEntries = entries.map { entry ->
            encodePublic(entry.key) + byteArrayOf(ROLE_COURIER.toByte(), entry.status.toByte())
        }.sortedWith { left, right -> compareUnsigned(left, right) }
        val authorityPublic = encodePublic(signingAuthority)
        val unsigned = ByteBuffer.allocate(99 + encodedEntries.sumOf { it.size })
            .order(ByteOrder.BIG_ENDIAN)
            .put("HVI1".encodeToByteArray())
            .put(schema.toByte())
            .put(1.toByte())
            .putShort(0.toShort())
            .putLong(version)
            .put(venue)
            .put(authorityPublic)
            .putShort(encodedEntries.size.toShort())
            .apply { encodedEntries.forEach(::put) }
            .array()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingAuthority.private)
            update(INVENTORY_DOMAIN)
            update(unsigned)
            sign()
        }
        return ByteBuffer.allocate(unsigned.size + 2 + signature.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(unsigned)
            .putShort(signature.size.toShort())
            .put(signature)
            .array()
    }

    private fun generateP256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun encodePublic(pair: KeyPair): ByteArray {
        val key = pair.public as ECPublicKey
        return byteArrayOf(4) + key.w.affineX.fixed(32) + key.w.affineY.fixed(32)
    }

    private fun BigInteger.fixed(bytes: Int): ByteArray {
        val encoded = toByteArray().let { value ->
            if (value.size > 1 && value[0] == 0.toByte()) value.copyOfRange(1, value.size) else value
        }
        return ByteArray(bytes - encoded.size) + encoded
    }

    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        left.indices.forEach { index ->
            val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
            if (difference != 0) return difference
        }
        return left.size - right.size
    }

    private fun assertFails(block: () -> Unit) {
        var failed = false
        try {
            block()
        } catch (_: IllegalArgumentException) {
            failed = true
        }
        assertTrue("Expected invalid HVI1 input to fail", failed)
    }

    private data class FixtureEntry(val key: KeyPair, val status: Int)

    private companion object {
        const val ROLE_COURIER = 1
        const val STATUS_ACTIVE = 1
        const val STATUS_REVOKED = 2
        const val STATUS_REPLACED = 3
        val INVENTORY_DOMAIN = "Hypha venue inventory v1\u0000".encodeToByteArray()
    }
}
