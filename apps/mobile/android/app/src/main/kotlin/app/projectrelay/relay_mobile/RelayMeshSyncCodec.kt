package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/** Bounded inventory, courier envelope, and private destination-probe exchange. */
internal object RelayMeshSyncCodec {
    data class Request(
        val inventory: List<ByteArray>,
        val offeredEnvelopes: List<ByteArray>,
        val routeProbes: List<ByteArray>,
    )

    data class Response(
        val acceptedOfferIds: List<ByteArray>,
        val offeredEnvelopes: List<ByteArray>,
        val requestedProbeIds: List<ByteArray>,
        val routeProbes: List<ByteArray>,
    )

    data class Ack(
        val acceptedOfferIds: List<ByteArray>,
        val requestedEnvelopes: List<ByteArray>,
        val requestedProbeIds: List<ByteArray>,
    )

    data class Completion(
        val acceptedProbeIds: List<ByteArray>,
        val requestedEnvelopes: List<ByteArray>,
    )

    fun encodeRequest(request: Request): ByteArray = encodeExchange(
        magic = REQUEST_MAGIC,
        primaryIds = request.inventory,
        primaryEnvelopes = request.offeredEnvelopes,
        secondaryIds = emptyList(),
        secondaryEnvelopes = request.routeProbes,
        secondaryEnvelopesAreProbes = true,
    )

    fun decodeRequest(encoded: ByteArray): Request {
        val decoded = decodeExchange(encoded, REQUEST_MAGIC, secondaryEnvelopesAreProbes = true)
        require(decoded.secondaryIds.isEmpty()) { "Mesh request reserved IDs are not empty." }
        return Request(decoded.primaryIds, decoded.primaryEnvelopes, decoded.secondaryEnvelopes)
    }

    fun encodeResponse(response: Response): ByteArray = encodeExchange(
        magic = RESPONSE_MAGIC,
        primaryIds = response.acceptedOfferIds,
        primaryEnvelopes = response.offeredEnvelopes,
        secondaryIds = response.requestedProbeIds,
        secondaryEnvelopes = response.routeProbes,
        secondaryEnvelopesAreProbes = true,
    )

    fun decodeResponse(encoded: ByteArray): Response {
        val decoded = decodeExchange(encoded, RESPONSE_MAGIC, secondaryEnvelopesAreProbes = true)
        return Response(
            acceptedOfferIds = decoded.primaryIds,
            offeredEnvelopes = decoded.primaryEnvelopes,
            requestedProbeIds = decoded.secondaryIds,
            routeProbes = decoded.secondaryEnvelopes,
        )
    }

    fun encodeAck(ack: Ack): ByteArray = encodeExchange(
        magic = ACK_MAGIC,
        primaryIds = ack.acceptedOfferIds,
        primaryEnvelopes = ack.requestedEnvelopes,
        secondaryIds = ack.requestedProbeIds,
        secondaryEnvelopes = emptyList(),
        secondaryEnvelopesAreProbes = false,
    )

    fun decodeAck(encoded: ByteArray): Ack {
        val decoded = decodeExchange(encoded, ACK_MAGIC, secondaryEnvelopesAreProbes = false)
        require(decoded.secondaryEnvelopes.isEmpty()) {
            "Mesh acknowledgement reserved envelopes are not empty."
        }
        return Ack(decoded.primaryIds, decoded.primaryEnvelopes, decoded.secondaryIds)
    }

    fun encodeCompletion(completion: Completion): ByteArray = encodeExchange(
        magic = COMPLETION_MAGIC,
        primaryIds = completion.acceptedProbeIds,
        primaryEnvelopes = completion.requestedEnvelopes,
        secondaryIds = emptyList(),
        secondaryEnvelopes = emptyList(),
        secondaryEnvelopesAreProbes = false,
    )

    fun decodeCompletion(encoded: ByteArray): Completion {
        val decoded = decodeExchange(encoded, COMPLETION_MAGIC, secondaryEnvelopesAreProbes = false)
        require(decoded.secondaryIds.isEmpty() && decoded.secondaryEnvelopes.isEmpty()) {
            "Mesh completion reserved fields are not empty."
        }
        return Completion(decoded.primaryIds, decoded.primaryEnvelopes)
    }

    fun encodeFinalAck(acceptedProbeIds: List<ByteArray>): ByteArray = encodeExchange(
        magic = FINAL_ACK_MAGIC,
        primaryIds = acceptedProbeIds,
        primaryEnvelopes = emptyList(),
        secondaryIds = emptyList(),
        secondaryEnvelopes = emptyList(),
        secondaryEnvelopesAreProbes = false,
    )

    fun decodeFinalAck(encoded: ByteArray): List<ByteArray> {
        val decoded = decodeExchange(encoded, FINAL_ACK_MAGIC, secondaryEnvelopesAreProbes = false)
        require(
            decoded.primaryEnvelopes.isEmpty() && decoded.secondaryIds.isEmpty() &&
                decoded.secondaryEnvelopes.isEmpty(),
        ) { "Mesh final acknowledgement reserved fields are not empty." }
        return decoded.primaryIds
    }

    fun encodedEnvelopesBytes(envelopes: Collection<ByteArray>): Int =
        envelopes.sumOf { Int.SIZE_BYTES + it.size }

    fun encodedIdsBytes(ids: Collection<ByteArray>): Int = ids.size * MESSAGE_ID_BYTES

    private fun encodeExchange(
        magic: ByteArray,
        primaryIds: List<ByteArray>,
        primaryEnvelopes: List<ByteArray>,
        secondaryIds: List<ByteArray>,
        secondaryEnvelopes: List<ByteArray>,
        secondaryEnvelopesAreProbes: Boolean,
    ): ByteArray {
        validateIds(primaryIds)
        validateIds(secondaryIds)
        require(primaryEnvelopes.size <= MAX_ENVELOPES && secondaryEnvelopes.size <= MAX_PROBES) {
            "Too many mesh envelopes in one exchange."
        }
        val canonicalPrimary = canonicalEnvelopes(primaryEnvelopes, probes = false)
        val canonicalSecondary = canonicalEnvelopes(
            secondaryEnvelopes,
            probes = secondaryEnvelopesAreProbes,
        )
        require(
            (canonicalPrimary + canonicalSecondary)
                .map { RelayMeshEnvelope.decode(it).idHex() }
                .distinct()
                .size == canonicalPrimary.size + canonicalSecondary.size,
        ) { "Mesh exchange contains duplicate envelopes." }
        val encodedSize = EXCHANGE_HEADER_BYTES + encodedIdsBytes(primaryIds) +
            encodedEnvelopesBytes(canonicalPrimary) + encodedIdsBytes(secondaryIds) +
            encodedEnvelopesBytes(canonicalSecondary)
        require(encodedSize <= MAX_SYNC_BYTES) { "Mesh exchange exceeds the BLE transfer bound." }
        return ByteBuffer.allocate(encodedSize)
            .order(ByteOrder.BIG_ENDIAN)
            .put(magic)
            .put(VERSION)
            .put(0)
            .putShort(primaryIds.size.toShort())
            .putShort(canonicalPrimary.size.toShort())
            .putShort(secondaryIds.size.toShort())
            .putShort(canonicalSecondary.size.toShort())
            .also { buffer ->
                primaryIds.forEach(buffer::put)
                putEnvelopes(buffer, canonicalPrimary)
                secondaryIds.forEach(buffer::put)
                putEnvelopes(buffer, canonicalSecondary)
            }
            .array()
    }

    private fun decodeExchange(
        encoded: ByteArray,
        magic: ByteArray,
        secondaryEnvelopesAreProbes: Boolean,
    ): Exchange {
        require(encoded.size in EXCHANGE_HEADER_BYTES..MAX_SYNC_BYTES) {
            "Mesh exchange has an invalid length."
        }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        requirePrefix(buffer, magic)
        val primaryIdCount = buffer.short.toInt() and 0xFFFF
        val primaryEnvelopeCount = buffer.short.toInt() and 0xFFFF
        val secondaryIdCount = buffer.short.toInt() and 0xFFFF
        val secondaryEnvelopeCount = buffer.short.toInt() and 0xFFFF
        require(primaryIdCount <= MAX_IDS && secondaryIdCount <= MAX_IDS) {
            "Mesh exchange ID counts exceed their bounds."
        }
        require(primaryEnvelopeCount <= MAX_ENVELOPES && secondaryEnvelopeCount <= MAX_PROBES) {
            "Mesh exchange envelope counts exceed their bounds."
        }
        val primaryIds = takeIds(buffer, primaryIdCount)
        val primaryEnvelopes = takeEnvelopes(buffer, primaryEnvelopeCount, probes = false)
        val secondaryIds = takeIds(buffer, secondaryIdCount)
        val secondaryEnvelopes = takeEnvelopes(
            buffer,
            secondaryEnvelopeCount,
            probes = secondaryEnvelopesAreProbes,
        )
        require(!buffer.hasRemaining()) { "Mesh exchange contains trailing data." }
        require(
            (primaryEnvelopes + secondaryEnvelopes)
                .map { RelayMeshEnvelope.decode(it).idHex() }
                .distinct()
                .size == primaryEnvelopes.size + secondaryEnvelopes.size,
        ) { "Mesh exchange contains duplicate envelopes." }
        return Exchange(primaryIds, primaryEnvelopes, secondaryIds, secondaryEnvelopes)
    }

    private fun canonicalEnvelopes(envelopes: List<ByteArray>, probes: Boolean): List<ByteArray> =
        envelopes.map { encoded ->
            RelayMeshEnvelope.decode(encoded).also { envelope ->
                if (probes) requireRouteProbe(envelope)
            }.encode()
        }

    private fun putEnvelopes(buffer: ByteBuffer, envelopes: List<ByteArray>) {
        envelopes.forEach { envelope ->
            buffer.putInt(envelope.size)
            buffer.put(envelope)
        }
    }

    private fun takeEnvelopes(buffer: ByteBuffer, count: Int, probes: Boolean): List<ByteArray> =
        List(count) {
            require(buffer.remaining() >= Int.SIZE_BYTES) { "Mesh envelope length is truncated." }
            val length = buffer.int
            require(length in (RelayMeshEnvelope.HEADER_BYTES + 1)..RelayMeshEnvelope.MAX_ENCODED_BYTES) {
                "Mesh envelope length is invalid."
            }
            require(length <= buffer.remaining()) { "Mesh envelope is truncated." }
            ByteArray(length).also(buffer::get).let { encoded ->
                RelayMeshEnvelope.decode(encoded).also { envelope ->
                    if (probes) requireRouteProbe(envelope)
                }.encode()
            }
        }

    private fun requireRouteProbe(envelope: RelayMeshEnvelope) {
        require(
            envelope.copyBudget == 1 && envelope.ciphertext.contentEquals(ROUTE_PROBE_CIPHERTEXT),
        ) { "Mesh route probe is not a canonical last-copy hint." }
    }

    private fun takeIds(buffer: ByteBuffer, count: Int): List<ByteArray> {
        require(buffer.remaining() >= count * MESSAGE_ID_BYTES) { "Mesh ID list is truncated." }
        return List(count) { ByteArray(MESSAGE_ID_BYTES).also(buffer::get) }.also(::validateIds)
    }

    private fun requirePrefix(buffer: ByteBuffer, magic: ByteArray) {
        require(ByteArray(magic.size).also(buffer::get).contentEquals(magic)) {
            "Mesh exchange has an invalid prefix."
        }
        require(buffer.get() == VERSION) { "Mesh exchange version is unsupported." }
        require(buffer.get() == 0.toByte()) { "Mesh exchange reserved byte is not zero." }
    }

    private fun validateIds(ids: List<ByteArray>) {
        require(ids.size <= MAX_IDS) { "Mesh inventory contains too many IDs." }
        require(ids.all { it.size == MESSAGE_ID_BYTES }) { "Mesh inventory ID is invalid." }
        require(ids.map { it.idHex() }.distinct().size == ids.size) {
            "Mesh inventory contains duplicate IDs."
        }
    }

    private fun ByteArray.idHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xFF)
    }

    private data class Exchange(
        val primaryIds: List<ByteArray>,
        val primaryEnvelopes: List<ByteArray>,
        val secondaryIds: List<ByteArray>,
        val secondaryEnvelopes: List<ByteArray>,
    )

    const val MAX_SYNC_BYTES = 32_784
    const val MAX_IDS = 512
    const val EXCHANGE_HEADER_BYTES = 14
    val ROUTE_PROBE_CIPHERTEXT = byteArrayOf(0)
    private const val MAX_ENVELOPES = 48
    private const val MAX_PROBES = 128
    private const val MESSAGE_ID_BYTES = 16
    private const val VERSION: Byte = 2
    private val REQUEST_MAGIC = "RMS2".toByteArray(StandardCharsets.US_ASCII)
    private val RESPONSE_MAGIC = "RMR2".toByteArray(StandardCharsets.US_ASCII)
    private val ACK_MAGIC = "RMA2".toByteArray(StandardCharsets.US_ASCII)
    private val COMPLETION_MAGIC = "RMC2".toByteArray(StandardCharsets.US_ASCII)
    private val FINAL_ACK_MAGIC = "RMF2".toByteArray(StandardCharsets.US_ASCII)
}
