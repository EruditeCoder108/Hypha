package app.projectrelay.relay_mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayMeshSyncCodecTest {
    @Test
    fun requestRoundTripKeepsCourierOffersSeparateFromPrivateRouteProbes() {
        val regular = envelope(idByte = 1, copies = 4).encode()
        val finalCopy = envelope(idByte = 2, copies = 1)
        val probe = finalCopy.asRouteProbe().encode()
        val request = RelayMeshSyncCodec.Request(
            inventory = listOf(ByteArray(16) { 9 }),
            offeredEnvelopes = listOf(regular),
            routeProbes = listOf(probe),
        )

        val decoded = RelayMeshSyncCodec.decodeRequest(RelayMeshSyncCodec.encodeRequest(request))

        assertTrue(decoded.inventory.single().contentEquals(request.inventory.single()))
        assertTrue(decoded.offeredEnvelopes.single().contentEquals(regular))
        assertTrue(decoded.routeProbes.single().contentEquals(probe))
        assertEquals(1, RelayMeshEnvelope.decode(decoded.routeProbes.single()).ciphertext.size)
    }

    @Test
    fun responseAckCompletionAndFinalAckRoundTrip() {
        val firstId = ByteArray(16) { 1 }
        val secondId = ByteArray(16) { 2 }
        val regular = envelope(idByte = 3, copies = 2).encode()
        val probe = envelope(idByte = 4, copies = 1).asRouteProbe().encode()
        val finalEnvelope = envelope(idByte = 5, copies = 1).forRecognizedDestination().encode()

        val response = RelayMeshSyncCodec.decodeResponse(
            RelayMeshSyncCodec.encodeResponse(
                RelayMeshSyncCodec.Response(
                    acceptedOfferIds = listOf(firstId),
                    offeredEnvelopes = listOf(regular),
                    requestedProbeIds = listOf(secondId),
                    routeProbes = listOf(probe),
                ),
            ),
        )
        assertTrue(response.acceptedOfferIds.single().contentEquals(firstId))
        assertTrue(response.requestedProbeIds.single().contentEquals(secondId))

        val ack = RelayMeshSyncCodec.decodeAck(
            RelayMeshSyncCodec.encodeAck(
                RelayMeshSyncCodec.Ack(
                    acceptedOfferIds = listOf(firstId),
                    requestedEnvelopes = listOf(finalEnvelope),
                    requestedProbeIds = listOf(secondId),
                ),
            ),
        )
        assertTrue(ack.requestedEnvelopes.single().contentEquals(finalEnvelope))

        val completion = RelayMeshSyncCodec.decodeCompletion(
            RelayMeshSyncCodec.encodeCompletion(
                RelayMeshSyncCodec.Completion(
                    acceptedProbeIds = listOf(firstId),
                    requestedEnvelopes = listOf(finalEnvelope),
                ),
            ),
        )
        assertTrue(completion.acceptedProbeIds.single().contentEquals(firstId))

        val finalAck = RelayMeshSyncCodec.decodeFinalAck(
            RelayMeshSyncCodec.encodeFinalAck(listOf(secondId)),
        )
        assertTrue(finalAck.single().contentEquals(secondId))
    }

    @Test
    fun routeProbeRejectsRealCiphertextAndNonFinalCopies() {
        val realCiphertext = envelope(idByte = 6, copies = 1).encode()
        val multipleCopies = envelope(idByte = 7, copies = 2).copy(
            ciphertext = RelayMeshSyncCodec.ROUTE_PROBE_CIPHERTEXT.copyOf(),
        ).encode()

        assertThrows(IllegalArgumentException::class.java) {
            RelayMeshSyncCodec.encodeRequest(
                RelayMeshSyncCodec.Request(emptyList(), emptyList(), listOf(realCiphertext)),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            RelayMeshSyncCodec.encodeRequest(
                RelayMeshSyncCodec.Request(emptyList(), emptyList(), listOf(multipleCopies)),
            )
        }
    }

    @Test
    fun portableEnvelopeAgeAdvancesAndExpiresAtItsLifetime() {
        val original = envelope(idByte = 8, copies = 4).copy(
            lifetimeMs = 1_000,
            ageMs = 250,
        )

        assertEquals(749L, original.agedBy(499)?.ageMs)
        assertEquals(250L, original.agedBy(-100)?.ageMs)
        assertEquals(null, original.agedBy(750))
        assertEquals(null, original.agedBy(5_000))
    }

    private fun envelope(idByte: Int, copies: Int): RelayMeshEnvelope = RelayMeshEnvelope(
        messageId = ByteArray(16) { idByte.toByte() },
        destinationHint = ByteArray(16) { (idByte + 1).toByte() },
        lifetimeMs = 60_000,
        ageMs = 0,
        hopLimit = 16,
        hopsTaken = 0,
        copyBudget = copies,
        priority = 2,
        ciphertext = ByteArray(32) { (idByte + 2).toByte() },
    )
}
