package app.projectrelay.relay_mobile

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/** Narrow Kotlin facade over Relay's Rust secure-session core. */
internal object RelayNative {
    private val loaded = runCatching {
        System.loadLibrary("relay_jni")
    }.isSuccess

    val isAvailable: Boolean
        get() = loaded

    fun runSelfTest(): Boolean = loaded && runCatching { nativeRunSelfTest() }.getOrDefault(false)

    fun createIdentity(): NativeRelayIdentity {
        check(loaded) { "Relay's native secure core is unavailable." }
        return NativeRelayIdentity(nativeCreateIdentity().requireHandle())
    }

    fun destroyIdentity(handle: Long) = nativeDestroyIdentity(handle)

    fun createSession(
        identityHandle: Long,
        isInitiator: Boolean,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): Long = nativeCreateSession(
        identityHandle,
        isInitiator,
        initiatorToken,
        responderToken,
    ).requireHandle()

    fun createFastSession(
        isInitiator: Boolean,
        psk: ByteArray,
        offerId: ByteArray,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): NativeRelaySession = NativeRelaySession(
        nativeCreateFastSession(
            isInitiator,
            psk,
            offerId,
            initiatorToken,
            responderToken,
        ).requireHandle(),
    )

    fun destroySession(handle: Long) = nativeDestroySession(handle)

    fun startSession(handle: Long): ByteArray? = nativeStartSession(handle)

    fun receiveHandshake(handle: Long, incoming: ByteArray): ByteArray? =
        nativeReceiveHandshake(handle, incoming)

    fun isEstablished(handle: Long): Boolean = nativeIsEstablished(handle)

    fun sessionBinding(handle: Long): ByteArray = nativeSessionBinding(handle)

    fun encrypt(handle: Long, plaintext: ByteArray): ByteArray = nativeEncrypt(handle, plaintext)

    fun decrypt(handle: Long, ciphertext: ByteArray): ByteArray = nativeDecrypt(handle, ciphertext)

    fun encodeTextMessage(messageId: ByteArray, utf8: ByteArray): ByteArray =
        nativeEncodeTextMessage(messageId, utf8)

    fun encodeReplyMessage(
        messageId: ByteArray,
        utf8: ByteArray,
        replyToMessageId: ByteArray,
        previewUtf8: ByteArray,
    ): ByteArray = nativeEncodeReplyMessage(messageId, utf8, replyToMessageId, previewUtf8)

    fun validateTextMessage(encoded: ByteArray): Boolean = nativeValidateTextMessage(encoded)

    fun encodeDeliveryReceipt(messageId: ByteArray): ByteArray =
        nativeEncodeDeliveryReceipt(messageId)

    fun validateDeliveryReceipt(encoded: ByteArray, expectedId: ByteArray): Boolean =
        nativeValidateDeliveryReceipt(encoded, expectedId)

    fun encodeWifiUpgradeOffer(
        offerId: ByteArray,
        psk: ByteArray,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): ByteArray = nativeEncodeWifiUpgradeOffer(
        offerId,
        psk,
        initiatorToken,
        responderToken,
    )

    fun validateWifiUpgradeOffer(encoded: ByteArray): Boolean =
        nativeValidateWifiUpgradeOffer(encoded)

    fun encodeWifiUpgradeAck(
        encodedOffer: ByteArray,
        responderToken: ByteArray,
    ): ByteArray = nativeEncodeWifiUpgradeAck(encodedOffer, responderToken)

    fun validateWifiUpgradeAck(encodedAck: ByteArray, encodedOffer: ByteArray): Boolean =
        nativeValidateWifiUpgradeAck(encodedAck, encodedOffer)

    fun createE2eAccount(stateKey: ByteArray): ByteArray {
        requireStateKey(stateKey)
        return nativeE2eCreateAccount(stateKey)
    }

    fun issueE2eContactBundle(
        accountPickle: ByteArray,
        stateKey: ByteArray,
    ): E2eIssueResult {
        requireStateKey(stateKey)
        val reader = E2eResultReader(
            nativeE2eIssueContactBundle(accountPickle, stateKey),
            E2E_ISSUE_MAGIC,
        )
        val updatedAccount = reader.sized(MAX_PICKLE_BYTES)
        val contactBundle = reader.fixed(CONTACT_BUNDLE_BYTES)
        reader.requireFinished()
        return E2eIssueResult(updatedAccount, contactBundle)
    }

    fun e2eRelayId(contactBundle: ByteArray): ByteArray {
        require(contactBundle.size == CONTACT_BUNDLE_BYTES) { "Invalid Relay contact bundle." }
        return nativeE2eRelayId(contactBundle).also {
            check(it.size == RELAY_ID_BYTES) { "Native Relay ID has an invalid length." }
        }
    }

    fun startE2eConversation(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
    ): ByteArray {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        return nativeE2eStartConversation(
            accountPickle,
            stateKey,
            localBundle,
            remoteBundle,
        ).also {
            check(it.isNotEmpty() && it.size <= MAX_PICKLE_BYTES) {
                "Native E2E session state has an invalid length."
            }
        }
    }

    fun encryptE2eText(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        messageId: ByteArray,
        sequence: Long,
        text: String,
    ): E2eEncryptResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        require(messageId.size == MESSAGE_ID_BYTES) { "Invalid Relay message ID." }
        require(sequence > 0L) { "Message sequence must be positive." }
        val utf8 = text.toByteArray(StandardCharsets.UTF_8)
        val reader = E2eResultReader(
            nativeE2eEncryptText(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                messageId,
                sequence,
                utf8,
            ),
            E2E_ENCRYPT_MAGIC,
        )
        val updatedSession = reader.sized(MAX_PICKLE_BYTES)
        val envelope = reader.sized(MAX_ENVELOPE_BYTES)
        reader.requireFinished()
        return E2eEncryptResult(updatedSession, envelope)
    }

    fun encryptE2eMessage(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        sequence: Long,
        message: RelayMessageCodec.TextMessage,
    ): E2eEncryptResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        require(sequence > 0L) { "Message sequence must be positive." }
        val reader = E2eResultReader(
            nativeE2eEncryptMessage(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                sequence,
                message.encoded,
            ),
            E2E_ENCRYPT_MAGIC,
        )
        val updatedSession = reader.sized(MAX_PICKLE_BYTES)
        val envelope = reader.sized(MAX_ENVELOPE_BYTES)
        reader.requireFinished()
        return E2eEncryptResult(updatedSession, envelope)
    }

    fun encryptE2eReceipt(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelopeId: ByteArray,
        sequence: Long,
        deliveredMessageId: ByteArray,
    ): E2eEncryptResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        require(envelopeId.size == MESSAGE_ID_BYTES) { "Invalid receipt envelope ID." }
        require(deliveredMessageId.size == MESSAGE_ID_BYTES) { "Invalid delivered message ID." }
        require(sequence > 0L) { "Receipt sequence must be positive." }
        val reader = E2eResultReader(
            nativeE2eEncryptReceipt(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                envelopeId,
                sequence,
                deliveredMessageId,
            ),
            E2E_ENCRYPT_MAGIC,
        )
        val updatedSession = reader.sized(MAX_PICKLE_BYTES)
        val envelope = reader.sized(MAX_ENVELOPE_BYTES)
        reader.requireFinished()
        return E2eEncryptResult(updatedSession, envelope)
    }

    fun encryptE2eAttachmentManifest(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        sequence: Long,
        manifest: RelayRecipientAttachmentManifest,
    ): E2eEncryptResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        require(sequence > 0L) { "Attachment sequence must be positive." }
        val reader = E2eResultReader(
            nativeE2eEncryptAttachmentManifest(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                sequence,
                manifest.encode(),
            ),
            E2E_ENCRYPT_MAGIC,
        )
        val updatedSession = reader.sized(MAX_PICKLE_BYTES)
        val envelope = reader.sized(MAX_ENVELOPE_BYTES)
        reader.requireFinished()
        return E2eEncryptResult(updatedSession, envelope)
    }

    fun encryptE2eAttachmentReceipt(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelopeId: ByteArray,
        sequence: Long,
        receipt: RelayRecipientAttachmentReceipt,
    ): E2eEncryptResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        require(envelopeId.size == MESSAGE_ID_BYTES) { "Invalid attachment receipt envelope ID." }
        require(sequence > 0L) { "Attachment receipt sequence must be positive." }
        val reader = E2eResultReader(
            nativeE2eEncryptAttachmentReceipt(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                envelopeId,
                sequence,
                receipt.encode(),
            ),
            E2E_ENCRYPT_MAGIC,
        )
        val updatedSession = reader.sized(MAX_PICKLE_BYTES)
        val envelope = reader.sized(MAX_ENVELOPE_BYTES)
        reader.requireFinished()
        return E2eEncryptResult(updatedSession, envelope)
    }

    fun e2eRecognizes(localBundle: ByteArray, envelope: ByteArray): Boolean {
        require(localBundle.size == CONTACT_BUNDLE_BYTES) { "Invalid Relay contact bundle." }
        return nativeE2eRecognizes(localBundle, envelope)
    }

    fun acceptE2eConversation(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        envelope: ByteArray,
    ): E2eReceiveResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        val reader = E2eResultReader(
            nativeE2eAcceptConversation(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                envelope,
            ),
            E2E_ACCEPT_MAGIC,
        )
        val updatedAccount = reader.sized(MAX_PICKLE_BYTES)
        val received = reader.receivedText(updatedAccount)
        reader.requireFinished()
        return received
    }

    fun acceptE2ePayloadConversation(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        envelope: ByteArray,
    ): E2eAcceptPayloadResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        val reader = E2eResultReader(
            nativeE2eAcceptPayloadConversation(
                accountPickle,
                stateKey,
                localBundle,
                remoteBundle,
                envelope,
            ),
            E2E_ACCEPT_PAYLOAD_MAGIC,
        )
        val updatedAccount = reader.sized(MAX_PICKLE_BYTES)
        val received = reader.receivedPayload()
        reader.requireFinished()
        return E2eAcceptPayloadResult(updatedAccount, received)
    }

    fun decryptE2eText(
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelope: ByteArray,
    ): E2eReceiveResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        val reader = E2eResultReader(
            nativeE2eDecryptText(
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                envelope,
            ),
            E2E_DECRYPT_MAGIC,
        )
        val received = reader.receivedText(null)
        reader.requireFinished()
        return received
    }

    fun decryptE2ePayload(
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelope: ByteArray,
    ): E2ePayloadResult {
        requireStateKey(stateKey)
        requireBundles(localBundle, remoteBundle)
        val reader = E2eResultReader(
            nativeE2eDecryptPayload(
                stateKey,
                localBundle,
                remoteBundle,
                sessionPickle,
                isInitiator,
                envelope,
            ),
            E2E_PAYLOAD_MAGIC,
        )
        val received = reader.receivedPayload()
        reader.requireFinished()
        return received
    }

    private fun requireStateKey(stateKey: ByteArray) {
        require(stateKey.size == E2E_STATE_KEY_BYTES) { "Invalid E2E state-protection key." }
    }

    private fun requireBundles(localBundle: ByteArray, remoteBundle: ByteArray) {
        require(localBundle.size == CONTACT_BUNDLE_BYTES) { "Invalid local contact bundle." }
        require(remoteBundle.size == CONTACT_BUNDLE_BYTES) { "Invalid remote contact bundle." }
    }

    private fun Long.requireHandle(): Long {
        check(this > 0L) { "Relay's native secure core returned an invalid handle." }
        return this
    }

    private external fun nativeRunSelfTest(): Boolean
    private external fun nativeCreateIdentity(): Long
    private external fun nativeDestroyIdentity(handle: Long)
    private external fun nativeCreateSession(
        identityHandle: Long,
        isInitiator: Boolean,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): Long
    private external fun nativeDestroySession(handle: Long)
    private external fun nativeCreateFastSession(
        isInitiator: Boolean,
        psk: ByteArray,
        offerId: ByteArray,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): Long
    private external fun nativeStartSession(handle: Long): ByteArray?
    private external fun nativeReceiveHandshake(handle: Long, incoming: ByteArray): ByteArray?
    private external fun nativeIsEstablished(handle: Long): Boolean
    private external fun nativeSessionBinding(handle: Long): ByteArray
    private external fun nativeEncrypt(handle: Long, plaintext: ByteArray): ByteArray
    private external fun nativeDecrypt(handle: Long, ciphertext: ByteArray): ByteArray
    private external fun nativeEncodeTextMessage(messageId: ByteArray, utf8: ByteArray): ByteArray
    private external fun nativeEncodeReplyMessage(
        messageId: ByteArray,
        utf8: ByteArray,
        replyToMessageId: ByteArray,
        previewUtf8: ByteArray,
    ): ByteArray
    private external fun nativeValidateTextMessage(encoded: ByteArray): Boolean
    private external fun nativeEncodeDeliveryReceipt(messageId: ByteArray): ByteArray
    private external fun nativeValidateDeliveryReceipt(
        encoded: ByteArray,
        expectedId: ByteArray,
    ): Boolean
    private external fun nativeEncodeWifiUpgradeOffer(
        offerId: ByteArray,
        psk: ByteArray,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): ByteArray
    private external fun nativeValidateWifiUpgradeOffer(encoded: ByteArray): Boolean
    private external fun nativeEncodeWifiUpgradeAck(
        encodedOffer: ByteArray,
        responderToken: ByteArray,
    ): ByteArray
    private external fun nativeValidateWifiUpgradeAck(
        encodedAck: ByteArray,
        encodedOffer: ByteArray,
    ): Boolean
    private external fun nativeE2eCreateAccount(stateKey: ByteArray): ByteArray
    private external fun nativeE2eIssueContactBundle(
        accountPickle: ByteArray,
        stateKey: ByteArray,
    ): ByteArray
    private external fun nativeE2eRelayId(contactBundle: ByteArray): ByteArray
    private external fun nativeE2eStartConversation(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
    ): ByteArray
    private external fun nativeE2eEncryptText(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        messageId: ByteArray,
        sequence: Long,
        utf8: ByteArray,
    ): ByteArray
    private external fun nativeE2eEncryptMessage(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        sequence: Long,
        encodedMessage: ByteArray,
    ): ByteArray
    private external fun nativeE2eEncryptReceipt(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelopeId: ByteArray,
        sequence: Long,
        deliveredMessageId: ByteArray,
    ): ByteArray
    private external fun nativeE2eEncryptAttachmentManifest(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        sequence: Long,
        encodedManifest: ByteArray,
    ): ByteArray
    private external fun nativeE2eEncryptAttachmentReceipt(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelopeId: ByteArray,
        sequence: Long,
        encodedReceipt: ByteArray,
    ): ByteArray
    private external fun nativeE2eRecognizes(
        localBundle: ByteArray,
        envelope: ByteArray,
    ): Boolean
    private external fun nativeE2eAcceptConversation(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        envelope: ByteArray,
    ): ByteArray
    private external fun nativeE2eAcceptPayloadConversation(
        accountPickle: ByteArray,
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        envelope: ByteArray,
    ): ByteArray
    private external fun nativeE2eDecryptText(
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelope: ByteArray,
    ): ByteArray
    private external fun nativeE2eDecryptPayload(
        stateKey: ByteArray,
        localBundle: ByteArray,
        remoteBundle: ByteArray,
        sessionPickle: ByteArray,
        isInitiator: Boolean,
        envelope: ByteArray,
    ): ByteArray

    private const val E2E_STATE_KEY_BYTES = 32
    private const val CONTACT_BUNDLE_BYTES = 200
    private const val RELAY_ID_BYTES = 8
    private const val MESSAGE_ID_BYTES = 16
    private const val MAX_PICKLE_BYTES = 64 * 1024
    private const val MAX_ENVELOPE_BYTES = 64 * 1024 + 64
    private val E2E_ISSUE_MAGIC = "REI1".toByteArray(StandardCharsets.US_ASCII)
    private val E2E_ENCRYPT_MAGIC = "REE1".toByteArray(StandardCharsets.US_ASCII)
    private val E2E_ACCEPT_MAGIC = "REA1".toByteArray(StandardCharsets.US_ASCII)
    private val E2E_DECRYPT_MAGIC = "RED1".toByteArray(StandardCharsets.US_ASCII)
    private val E2E_PAYLOAD_MAGIC = "RDP1".toByteArray(StandardCharsets.US_ASCII)
    private val E2E_ACCEPT_PAYLOAD_MAGIC = "RAP1".toByteArray(StandardCharsets.US_ASCII)
    internal const val E2E_PAYLOAD_TEXT: Byte = 1
    internal const val E2E_PAYLOAD_RECEIPT: Byte = 2
    internal const val E2E_PAYLOAD_ATTACHMENT_MANIFEST: Byte = 3
    internal const val E2E_PAYLOAD_ATTACHMENT_RECEIPT: Byte = 4
}

internal data class E2eIssueResult(
    val accountPickle: ByteArray,
    val contactBundle: ByteArray,
)

internal data class E2eEncryptResult(
    val sessionPickle: ByteArray,
    val envelope: ByteArray,
)

internal data class E2eAcceptPayloadResult(
    val accountPickle: ByteArray,
    val payload: E2ePayloadResult,
)

internal data class E2eReceiveResult(
    val accountPickle: ByteArray?,
    val sessionPickle: ByteArray,
    val sequence: Long,
    val message: RelayMessageCodec.TextMessage,
) {
    val messageId: ByteArray get() = message.id
    val text: String get() = message.text
}

internal sealed interface E2ePayloadResult {
    val sessionPickle: ByteArray
    val sequence: Long
    val envelopeId: ByteArray

    data class Text(
        override val sessionPickle: ByteArray,
        override val sequence: Long,
        override val envelopeId: ByteArray,
        val message: RelayMessageCodec.TextMessage,
    ) : E2ePayloadResult {
        val text: String get() = message.text
    }

    data class Receipt(
        override val sessionPickle: ByteArray,
        override val sequence: Long,
        override val envelopeId: ByteArray,
        val deliveredMessageId: ByteArray,
    ) : E2ePayloadResult

    data class AttachmentManifest(
        override val sessionPickle: ByteArray,
        override val sequence: Long,
        override val envelopeId: ByteArray,
        val manifest: RelayRecipientAttachmentManifest,
    ) : E2ePayloadResult

    data class AttachmentReceipt(
        override val sessionPickle: ByteArray,
        override val sequence: Long,
        override val envelopeId: ByteArray,
        val receipt: RelayRecipientAttachmentReceipt,
    ) : E2ePayloadResult
}

private class E2eResultReader(
    encoded: ByteArray,
    expectedMagic: ByteArray,
) {
    private val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)

    init {
        check(encoded.size >= expectedMagic.size) { "Native E2E result is truncated." }
        check(fixed(expectedMagic.size).contentEquals(expectedMagic)) {
            "Native E2E result has an invalid type."
        }
    }

    fun sized(maximum: Int): ByteArray {
        check(buffer.remaining() >= Int.SIZE_BYTES) { "Native E2E length is truncated." }
        val length = buffer.int
        check(length in 1..maximum && length <= buffer.remaining()) {
            "Native E2E field has an invalid length."
        }
        return fixed(length)
    }

    fun fixed(length: Int): ByteArray {
        check(length >= 0 && length <= buffer.remaining()) { "Native E2E result is truncated." }
        return ByteArray(length).also(buffer::get)
    }

    fun receivedText(accountPickle: ByteArray?): E2eReceiveResult {
        val sessionPickle = sized(64 * 1024)
        check(buffer.remaining() >= Long.SIZE_BYTES + 16 + Int.SIZE_BYTES) {
            "Native received message is truncated."
        }
        val sequence = buffer.long
        check(sequence > 0L) { "Native received sequence is invalid." }
        val messageId = fixed(16)
        val message = RelayMessageCodec.decodeTrusted(sized(MAX_DIRECT_MESSAGE_BYTES))
        check(message.id.contentEquals(messageId)) { "Native received message ID is inconsistent." }
        return E2eReceiveResult(
            accountPickle = accountPickle,
            sessionPickle = sessionPickle,
            sequence = sequence,
            message = message,
        )
    }

    fun receivedPayload(): E2ePayloadResult {
        val sessionPickle = sized(64 * 1024)
        check(buffer.remaining() >= Long.SIZE_BYTES + 16 + 1) {
            "Native received payload is truncated."
        }
        val sequence = buffer.long
        check(sequence > 0L) { "Native received sequence is invalid." }
        val envelopeId = fixed(16)
        return when (val payloadType = buffer.get()) {
            RelayNative.E2E_PAYLOAD_TEXT -> {
                val message = RelayMessageCodec.decodeTrusted(sized(MAX_DIRECT_MESSAGE_BYTES))
                check(message.id.contentEquals(envelopeId)) {
                    "Native received message ID does not match its envelope."
                }
                E2ePayloadResult.Text(
                    sessionPickle = sessionPickle,
                    sequence = sequence,
                    envelopeId = envelopeId,
                    message = message,
                )
            }
            RelayNative.E2E_PAYLOAD_RECEIPT -> E2ePayloadResult.Receipt(
                sessionPickle = sessionPickle,
                sequence = sequence,
                envelopeId = envelopeId,
                deliveredMessageId = fixed(16),
            )
            RelayNative.E2E_PAYLOAD_ATTACHMENT_MANIFEST -> E2ePayloadResult.AttachmentManifest(
                sessionPickle = sessionPickle,
                sequence = sequence,
                envelopeId = envelopeId,
                manifest = RelayRecipientAttachmentManifest.decode(
                    sized(RelayRecipientAttachmentManifest.MAX_ENCODED_BYTES),
                ).also { manifest ->
                    check(manifest.objectId.contentEquals(envelopeId)) {
                        "Native attachment manifest ID does not match its envelope."
                    }
                },
            )
            RelayNative.E2E_PAYLOAD_ATTACHMENT_RECEIPT -> E2ePayloadResult.AttachmentReceipt(
                sessionPickle = sessionPickle,
                sequence = sequence,
                envelopeId = envelopeId,
                receipt = RelayRecipientAttachmentReceipt.decode(
                    fixed(RelayRecipientAttachmentReceipt.ENCODED_BYTES),
                ),
            )
            else -> error("Native E2E payload type $payloadType is unsupported.")
        }
    }

    fun requireFinished() {
        check(!buffer.hasRemaining()) { "Native E2E result contains trailing data." }
    }

    private companion object {
        const val MAX_DIRECT_MESSAGE_BYTES = 44 + 256 + 2_048
    }
}

internal class NativeRelayIdentity(
    private var handle: Long,
) : AutoCloseable {
    fun createSession(
        isInitiator: Boolean,
        initiatorToken: ByteArray,
        responderToken: ByteArray,
    ): NativeRelaySession {
        check(handle != 0L) { "Relay identity is closed." }
        val sessionHandle = RelayNative.createSession(
            handle,
            isInitiator,
            initiatorToken,
            responderToken,
        )
        return NativeRelaySession(sessionHandle)
    }

    override fun close() {
        if (handle == 0L) return
        RelayNative.destroyIdentity(handle)
        handle = 0L
    }
}

internal class NativeRelaySession(
    private var handle: Long,
) : AutoCloseable {
    fun start(): ByteArray? = withHandle(RelayNative::startSession)

    fun receiveHandshake(incoming: ByteArray): ByteArray? = withHandle { session ->
        RelayNative.receiveHandshake(session, incoming)
    }

    fun isEstablished(): Boolean = withHandle(RelayNative::isEstablished)

    fun sessionBinding(): ByteArray = withHandle(RelayNative::sessionBinding)

    fun encrypt(plaintext: ByteArray): ByteArray = withHandle { session ->
        RelayNative.encrypt(session, plaintext)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray = withHandle { session ->
        RelayNative.decrypt(session, ciphertext)
    }

    override fun close() {
        if (handle == 0L) return
        RelayNative.destroySession(handle)
        handle = 0L
    }

    private fun <T> withHandle(operation: (Long) -> T): T {
        check(handle != 0L) { "Relay secure session is closed." }
        return operation(handle)
    }
}
