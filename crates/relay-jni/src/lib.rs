//! Panic-contained Android bridge for Relay's Rust secure-session core.
//!
//! Raw key material never crosses JNI. Kotlin receives opaque integer handles
//! and bounded handshake/ciphertext byte arrays only.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{LazyLock, Mutex, MutexGuard},
};

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JByteArray, JObject},
    sys::{JNI_FALSE, JNI_TRUE, jboolean, jlong},
};
use relay_e2e::{
    CONTACT_BUNDLE_LEN, ContactBundle, ConversationRole, ConversationSession, DeliveryPolicy,
    E2eAccount, ReceivedContent, ReceivedPayload,
};
use relay_message::{
    DeliveryReceipt, DirectText, OFFER_ID_BYTES as MESSAGE_OFFER_ID_BYTES, ReplyReference,
    UPGRADE_PSK_BYTES, WIFI_TOKEN_BYTES, WifiUpgradeAck, WifiUpgradeOffer,
    attachment::{AttachmentContentError, RecipientAttachmentManifest, RecipientAttachmentReceipt},
};
use relay_secure::{PSK_BYTES, SecureSession, SessionRole, StaticKeypair, generate_static_keypair};
use relay_wire::{Envelope, MessageId};

const TOKEN_BYTES: usize = 8;
const OFFER_ID_BYTES: usize = 16;
const PROLOGUE_PREFIX: &[u8] = b"ProjectRelay\0direct\0noise-xx\0v1\0ble-gatt\0";
const FAST_PROLOGUE_PREFIX: &[u8] = b"ProjectRelay\0upgrade\0noise-nnpsk0\0v1\0wifi-direct\0";
const E2E_PROTECTION_KEY_BYTES: usize = 32;
const MAX_E2E_PICKLE_BYTES: usize = 64 * 1024;
const E2E_ISSUE_MAGIC: [u8; 4] = *b"REI1";
const E2E_ENCRYPT_MAGIC: [u8; 4] = *b"REE1";
const E2E_ACCEPT_MAGIC: [u8; 4] = *b"REA1";
const E2E_DECRYPT_MAGIC: [u8; 4] = *b"RED1";
const E2E_PAYLOAD_MAGIC: [u8; 4] = *b"RDP1";
const E2E_ACCEPT_PAYLOAD_MAGIC: [u8; 4] = *b"RAP1";
const E2E_PAYLOAD_TEXT: u8 = 1;
const E2E_PAYLOAD_RECEIPT: u8 = 2;
const E2E_PAYLOAD_ATTACHMENT_MANIFEST: u8 = 3;
const E2E_PAYLOAD_ATTACHMENT_RECEIPT: u8 = 4;

#[derive(Debug)]
struct NativeError(String);

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for NativeError {}

impl From<relay_secure::SecureError> for NativeError {
    fn from(error: relay_secure::SecureError) -> Self {
        Self(error.to_string())
    }
}

impl From<relay_e2e::E2eError> for NativeError {
    fn from(error: relay_e2e::E2eError) -> Self {
        Self(error.to_string())
    }
}

impl From<AttachmentContentError> for NativeError {
    fn from(error: AttachmentContentError) -> Self {
        Self(error.to_string())
    }
}

impl From<relay_wire::DecodeError> for NativeError {
    fn from(error: relay_wire::DecodeError) -> Self {
        Self(error.to_string())
    }
}

impl From<relay_wire::ValidationError> for NativeError {
    fn from(error: relay_wire::ValidationError) -> Self {
        Self(error.to_string())
    }
}

impl From<jni::errors::Error> for NativeError {
    fn from(error: jni::errors::Error) -> Self {
        Self(error.to_string())
    }
}

type NativeResult<T> = Result<T, NativeError>;

#[derive(Default)]
struct Registry {
    next_handle: jlong,
    identities: BTreeMap<jlong, StaticKeypair>,
    sessions: BTreeMap<jlong, SecureSession>,
}

impl Registry {
    fn create_identity(&mut self) -> NativeResult<jlong> {
        let identity = generate_static_keypair()?;
        let handle = self.allocate_handle()?;
        self.identities.insert(handle, identity);
        Ok(handle)
    }

    fn create_session(
        &mut self,
        identity_handle: jlong,
        role: SessionRole,
        initiator_token: [u8; TOKEN_BYTES],
        responder_token: [u8; TOKEN_BYTES],
    ) -> NativeResult<jlong> {
        let prologue = build_prologue(initiator_token, responder_token);
        let session = {
            let identity = self
                .identities
                .get(&identity_handle)
                .ok_or_else(|| NativeError("unknown secure identity handle".to_owned()))?;
            SecureSession::new(role, identity.private(), &prologue)?
        };
        let handle = self.allocate_handle()?;
        self.sessions.insert(handle, session);
        Ok(handle)
    }

    fn create_fast_session(
        &mut self,
        role: SessionRole,
        psk: [u8; PSK_BYTES],
        offer_id: [u8; OFFER_ID_BYTES],
        initiator_token: [u8; TOKEN_BYTES],
        responder_token: [u8; TOKEN_BYTES],
    ) -> NativeResult<jlong> {
        let prologue = build_fast_prologue(offer_id, initiator_token, responder_token);
        let session = SecureSession::new_psk(role, &psk, &prologue)?;
        let handle = self.allocate_handle()?;
        self.sessions.insert(handle, session);
        Ok(handle)
    }

    fn start_session(&mut self, handle: jlong) -> NativeResult<Option<Vec<u8>>> {
        self.session_mut(handle)?.start().map_err(Into::into)
    }

    fn receive_handshake(
        &mut self,
        handle: jlong,
        incoming: &[u8],
    ) -> NativeResult<Option<Vec<u8>>> {
        self.session_mut(handle)?
            .receive_handshake(incoming)
            .map_err(Into::into)
    }

    fn encrypt(&mut self, handle: jlong, plaintext: &[u8]) -> NativeResult<Vec<u8>> {
        self.session_mut(handle)?
            .encrypt(plaintext)
            .map_err(Into::into)
    }

    fn decrypt(&mut self, handle: jlong, ciphertext: &[u8]) -> NativeResult<Vec<u8>> {
        self.session_mut(handle)?
            .decrypt(ciphertext)
            .map_err(Into::into)
    }

    fn is_established(&self, handle: jlong) -> NativeResult<bool> {
        self.sessions
            .get(&handle)
            .map(SecureSession::is_established)
            .ok_or_else(|| NativeError("unknown secure session handle".to_owned()))
    }

    fn session_binding(&self, handle: jlong) -> NativeResult<Vec<u8>> {
        self.sessions
            .get(&handle)
            .ok_or_else(|| NativeError("unknown secure session handle".to_owned()))?
            .handshake_hash()
            .map(|binding| binding.to_vec())
            .ok_or_else(|| NativeError("secure session is not established".to_owned()))
    }

    fn destroy_identity(&mut self, handle: jlong) {
        self.identities.remove(&handle);
    }

    fn destroy_session(&mut self, handle: jlong) {
        self.sessions.remove(&handle);
    }

    fn session_mut(&mut self, handle: jlong) -> NativeResult<&mut SecureSession> {
        self.sessions
            .get_mut(&handle)
            .ok_or_else(|| NativeError("unknown secure session handle".to_owned()))
    }

    fn allocate_handle(&mut self) -> NativeResult<jlong> {
        let next = self
            .next_handle
            .checked_add(1)
            .filter(|handle| *handle > 0)
            .ok_or_else(|| NativeError("native handle space exhausted".to_owned()))?;
        self.next_handle = next;
        Ok(next)
    }
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));

fn registry() -> NativeResult<MutexGuard<'static, Registry>> {
    REGISTRY
        .lock()
        .map_err(|_| NativeError("secure-session registry is unavailable".to_owned()))
}

fn token(bytes: Vec<u8>) -> NativeResult<[u8; TOKEN_BYTES]> {
    bytes
        .try_into()
        .map_err(|_| NativeError("encounter token must contain exactly 8 bytes".to_owned()))
}

fn fixed_bytes<const SIZE: usize>(bytes: Vec<u8>, label: &str) -> NativeResult<[u8; SIZE]> {
    bytes
        .try_into()
        .map_err(|_| NativeError(format!("{label} must contain exactly {SIZE} bytes")))
}

fn message_id(bytes: Vec<u8>) -> NativeResult<MessageId> {
    bytes
        .try_into()
        .map(MessageId)
        .map_err(|_| NativeError("message ID must contain exactly 16 bytes".to_owned()))
}

fn protection_key(bytes: Vec<u8>) -> NativeResult<[u8; E2E_PROTECTION_KEY_BYTES]> {
    fixed_bytes(bytes, "end-to-end state protection key")
}

fn encrypted_pickle(bytes: Vec<u8>, label: &str) -> NativeResult<String> {
    if bytes.is_empty() || bytes.len() > MAX_E2E_PICKLE_BYTES {
        return Err(NativeError(format!("{label} has an invalid length")));
    }
    String::from_utf8(bytes).map_err(|_| NativeError(format!("{label} is not valid UTF-8")))
}

fn contact_bundle(bytes: &[u8]) -> NativeResult<ContactBundle> {
    if bytes.len() != CONTACT_BUNDLE_LEN {
        return Err(NativeError(format!(
            "contact bundle must contain exactly {CONTACT_BUNDLE_LEN} bytes"
        )));
    }
    ContactBundle::decode(bytes).map_err(Into::into)
}

fn mesh_envelope(bytes: &[u8]) -> NativeResult<Envelope> {
    Envelope::decode(bytes).map_err(Into::into)
}

const fn conversation_role(is_initiator: jboolean) -> ConversationRole {
    if is_initiator == JNI_FALSE {
        ConversationRole::Responder
    } else {
        ConversationRole::Initiator
    }
}

fn append_sized(output: &mut Vec<u8>, bytes: &[u8], label: &str) -> NativeResult<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| NativeError(format!("{label} is too large to encode")))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_issue_result(account_pickle: &str, bundle: &ContactBundle) -> NativeResult<Vec<u8>> {
    let account_bytes = account_pickle.as_bytes();
    let mut output = Vec::with_capacity(8 + account_bytes.len() + CONTACT_BUNDLE_LEN);
    output.extend_from_slice(&E2E_ISSUE_MAGIC);
    append_sized(&mut output, account_bytes, "account pickle")?;
    output.extend_from_slice(&bundle.encode());
    Ok(output)
}

fn encode_encrypt_result(session_pickle: &str, envelope: &Envelope) -> NativeResult<Vec<u8>> {
    let session_bytes = session_pickle.as_bytes();
    let envelope_bytes = envelope.encode()?;
    let mut output = Vec::with_capacity(12 + session_bytes.len() + envelope_bytes.len());
    output.extend_from_slice(&E2E_ENCRYPT_MAGIC);
    append_sized(&mut output, session_bytes, "session pickle")?;
    append_sized(&mut output, &envelope_bytes, "mesh envelope")?;
    Ok(output)
}

fn append_received_text(
    output: &mut Vec<u8>,
    received: &relay_e2e::ReceivedText,
) -> NativeResult<()> {
    output.extend_from_slice(&received.sequence.to_be_bytes());
    output.extend_from_slice(&received.message.id.0);
    append_sized(
        output,
        &received
            .message
            .encode()
            .map_err(|error| NativeError(error.to_string()))?,
        "received message",
    )
}

fn encode_accept_result(
    account_pickle: &str,
    session_pickle: &str,
    received: &relay_e2e::ReceivedText,
) -> NativeResult<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&E2E_ACCEPT_MAGIC);
    append_sized(&mut output, account_pickle.as_bytes(), "account pickle")?;
    append_sized(&mut output, session_pickle.as_bytes(), "session pickle")?;
    append_received_text(&mut output, received)?;
    Ok(output)
}

fn encode_decrypt_result(
    session_pickle: &str,
    received: &relay_e2e::ReceivedText,
) -> NativeResult<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&E2E_DECRYPT_MAGIC);
    append_sized(&mut output, session_pickle.as_bytes(), "session pickle")?;
    append_received_text(&mut output, received)?;
    Ok(output)
}

fn encode_payload_result(
    session_pickle: &str,
    envelope_id: MessageId,
    received: &ReceivedPayload,
) -> NativeResult<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&E2E_PAYLOAD_MAGIC);
    append_sized(&mut output, session_pickle.as_bytes(), "session pickle")?;
    append_received_payload(&mut output, envelope_id, received)?;
    Ok(output)
}

fn encode_accept_payload_result(
    account_pickle: &str,
    session_pickle: &str,
    envelope_id: MessageId,
    received: &ReceivedPayload,
) -> NativeResult<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&E2E_ACCEPT_PAYLOAD_MAGIC);
    append_sized(&mut output, account_pickle.as_bytes(), "account pickle")?;
    append_sized(&mut output, session_pickle.as_bytes(), "session pickle")?;
    append_received_payload(&mut output, envelope_id, received)?;
    Ok(output)
}

fn append_received_payload(
    output: &mut Vec<u8>,
    envelope_id: MessageId,
    received: &ReceivedPayload,
) -> NativeResult<()> {
    output.extend_from_slice(&received.sequence.to_be_bytes());
    output.extend_from_slice(&envelope_id.0);
    match &received.content {
        ReceivedContent::Text(message) => {
            output.push(E2E_PAYLOAD_TEXT);
            append_sized(
                output,
                &message
                    .encode()
                    .map_err(|error| NativeError(error.to_string()))?,
                "received message",
            )?;
        }
        ReceivedContent::DeliveryReceipt(receipt) => {
            output.push(E2E_PAYLOAD_RECEIPT);
            output.extend_from_slice(&receipt.id.0);
        }
        ReceivedContent::AttachmentManifest(manifest) => {
            output.push(E2E_PAYLOAD_ATTACHMENT_MANIFEST);
            append_sized(output, &manifest.encode()?, "recipient attachment manifest")?;
        }
        ReceivedContent::AttachmentReceipt(receipt) => {
            output.push(E2E_PAYLOAD_ATTACHMENT_RECEIPT);
            output.extend_from_slice(&receipt.encode());
        }
    }
    Ok(())
}

fn e2e_create_account(protection_key: &[u8; E2E_PROTECTION_KEY_BYTES]) -> Vec<u8> {
    E2eAccount::new()
        .encrypted_pickle(protection_key)
        .into_bytes()
}

fn e2e_issue_contact_bundle(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
) -> NativeResult<Vec<u8>> {
    let mut account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let bundle = account.issue_contact_bundle()?;
    let updated_account = account.encrypted_pickle(protection_key);
    encode_issue_result(&updated_account, &bundle)
}

fn e2e_start_conversation(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
) -> NativeResult<Vec<u8>> {
    let account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let session = account.start_conversation(local_bundle, remote_bundle)?;
    Ok(session
        .encrypted_ratchet_pickle(protection_key)
        .into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn e2e_encrypt_text(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    id: MessageId,
    sequence: u64,
    text: String,
) -> NativeResult<Vec<u8>> {
    let account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let envelope = account.encrypt_text(
        &mut session,
        id,
        sequence,
        text,
        DeliveryPolicy::delayed_text(),
    )?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_encrypt_result(&updated_session, &envelope)
}

#[allow(clippy::too_many_arguments)]
fn e2e_encrypt_message(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    sequence: u64,
    message: &DirectText,
) -> NativeResult<Vec<u8>> {
    let account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let envelope = account.encrypt_message(
        &mut session,
        sequence,
        message,
        DeliveryPolicy::delayed_text(),
    )?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_encrypt_result(&updated_session, &envelope)
}

#[allow(clippy::too_many_arguments)]
fn e2e_encrypt_receipt(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    envelope_id: MessageId,
    sequence: u64,
    delivered_id: MessageId,
) -> NativeResult<Vec<u8>> {
    let account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let envelope = account.encrypt_receipt(
        &mut session,
        envelope_id,
        sequence,
        delivered_id,
        DeliveryPolicy::delivery_receipt(),
    )?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_encrypt_result(&updated_session, &envelope)
}

#[allow(clippy::too_many_arguments)]
fn e2e_encrypt_attachment_manifest(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    sequence: u64,
    manifest: &RecipientAttachmentManifest,
) -> NativeResult<Vec<u8>> {
    let account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let envelope = account.encrypt_attachment_manifest(
        &mut session,
        sequence,
        manifest,
        DeliveryPolicy::attachment_manifest(),
    )?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_encrypt_result(&updated_session, &envelope)
}

#[allow(clippy::too_many_arguments)]
fn e2e_encrypt_attachment_receipt(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    envelope_id: MessageId,
    sequence: u64,
    receipt: RecipientAttachmentReceipt,
) -> NativeResult<Vec<u8>> {
    let account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let envelope = account.encrypt_attachment_receipt(
        &mut session,
        envelope_id,
        sequence,
        receipt,
        DeliveryPolicy::delivery_receipt(),
    )?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_encrypt_result(&updated_session, &envelope)
}

fn e2e_accept_conversation(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    envelope: &Envelope,
) -> NativeResult<Vec<u8>> {
    let mut account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let (session, received) = account.accept_conversation(local_bundle, remote_bundle, envelope)?;
    let updated_account = account.encrypted_pickle(protection_key);
    let session_pickle = session.encrypted_ratchet_pickle(protection_key);
    encode_accept_result(&updated_account, &session_pickle, &received)
}

fn e2e_accept_payload_conversation(
    account_pickle: &str,
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    envelope: &Envelope,
) -> NativeResult<Vec<u8>> {
    let mut account = E2eAccount::from_encrypted_pickle(account_pickle, protection_key)?;
    let (session, received) =
        account.accept_payload_conversation(local_bundle, remote_bundle, envelope)?;
    let updated_account = account.encrypted_pickle(protection_key);
    let session_pickle = session.encrypted_ratchet_pickle(protection_key);
    encode_accept_payload_result(&updated_account, &session_pickle, envelope.id, &received)
}

fn e2e_decrypt_text(
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    envelope: &Envelope,
) -> NativeResult<Vec<u8>> {
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let received = session.decrypt_text(envelope)?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_decrypt_result(&updated_session, &received)
}

fn e2e_decrypt_payload(
    protection_key: &[u8; E2E_PROTECTION_KEY_BYTES],
    local_bundle: &ContactBundle,
    remote_bundle: &ContactBundle,
    session_pickle: &str,
    role: ConversationRole,
    envelope: &Envelope,
) -> NativeResult<Vec<u8>> {
    let mut session = ConversationSession::restore(
        role,
        local_bundle,
        remote_bundle,
        session_pickle,
        protection_key,
    )?;
    let received = session.decrypt_payload(envelope)?;
    let updated_session = session.encrypted_ratchet_pickle(protection_key);
    encode_payload_result(&updated_session, envelope.id, &received)
}

fn encode_text_message(id: MessageId, utf8: Vec<u8>) -> NativeResult<Vec<u8>> {
    let text = String::from_utf8(utf8)
        .map_err(|_| NativeError("message text is not valid UTF-8".to_owned()))?;
    DirectText {
        id,
        text,
        reply: None,
    }
    .encode()
    .map_err(|error| NativeError(error.to_string()))
}

fn encode_reply_message(
    id: MessageId,
    utf8: Vec<u8>,
    reply_to: MessageId,
    preview_utf8: Vec<u8>,
) -> NativeResult<Vec<u8>> {
    let text = String::from_utf8(utf8)
        .map_err(|_| NativeError("message text is not valid UTF-8".to_owned()))?;
    let preview = String::from_utf8(preview_utf8)
        .map_err(|_| NativeError("reply preview is not valid UTF-8".to_owned()))?;
    DirectText {
        id,
        text,
        reply: Some(ReplyReference {
            message_id: reply_to,
            preview,
        }),
    }
    .encode()
    .map_err(|error| NativeError(error.to_string()))
}

fn validate_text_message(encoded: &[u8]) -> bool {
    DirectText::decode(encoded).is_ok()
}

fn encode_delivery_receipt(id: MessageId) -> Vec<u8> {
    DeliveryReceipt { id }.encode().to_vec()
}

fn validate_delivery_receipt(encoded: &[u8], expected_id: MessageId) -> bool {
    DeliveryReceipt::decode(encoded).is_ok_and(|receipt| receipt.id == expected_id)
}

fn encode_wifi_upgrade_offer(
    offer_id: [u8; MESSAGE_OFFER_ID_BYTES],
    psk: [u8; UPGRADE_PSK_BYTES],
    initiator_token: [u8; WIFI_TOKEN_BYTES],
    responder_token: [u8; WIFI_TOKEN_BYTES],
) -> Vec<u8> {
    WifiUpgradeOffer {
        offer_id,
        psk,
        initiator_token,
        responder_token,
    }
    .encode()
    .to_vec()
}

fn encode_wifi_upgrade_ack(
    offer: WifiUpgradeOffer,
    responder_token: [u8; WIFI_TOKEN_BYTES],
) -> Vec<u8> {
    WifiUpgradeAck {
        offer_id: offer.offer_id,
        initiator_token: offer.initiator_token,
        responder_token,
    }
    .encode()
    .to_vec()
}

fn wifi_upgrade_ack_matches(ack: WifiUpgradeAck, offer: WifiUpgradeOffer) -> bool {
    ack.offer_id == offer.offer_id
        && ack.initiator_token == offer.initiator_token
        && ack.responder_token != [0; WIFI_TOKEN_BYTES]
        && (offer.responder_token == [0; WIFI_TOKEN_BYTES]
            || ack.responder_token == offer.responder_token)
}

fn build_prologue(
    initiator_token: [u8; TOKEN_BYTES],
    responder_token: [u8; TOKEN_BYTES],
) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(PROLOGUE_PREFIX.len() + TOKEN_BYTES * 2);
    prologue.extend_from_slice(PROLOGUE_PREFIX);
    prologue.extend_from_slice(&initiator_token);
    prologue.extend_from_slice(&responder_token);
    prologue
}

fn build_fast_prologue(
    offer_id: [u8; OFFER_ID_BYTES],
    initiator_token: [u8; TOKEN_BYTES],
    responder_token: [u8; TOKEN_BYTES],
) -> Vec<u8> {
    let mut prologue =
        Vec::with_capacity(FAST_PROLOGUE_PREFIX.len() + OFFER_ID_BYTES + TOKEN_BYTES * 2);
    prologue.extend_from_slice(FAST_PROLOGUE_PREFIX);
    prologue.extend_from_slice(&offer_id);
    prologue.extend_from_slice(&initiator_token);
    prologue.extend_from_slice(&responder_token);
    prologue
}

fn self_test() -> NativeResult<bool> {
    let initiator_keys = generate_static_keypair()?;
    let responder_keys = generate_static_keypair()?;
    let prologue = build_prologue([1; TOKEN_BYTES], [2; TOKEN_BYTES]);
    let mut initiator =
        SecureSession::new(SessionRole::Initiator, initiator_keys.private(), &prologue)?;
    let mut responder =
        SecureSession::new(SessionRole::Responder, responder_keys.private(), &prologue)?;
    let message_1 = initiator
        .start()?
        .ok_or_else(|| NativeError("initiator produced no first message".to_owned()))?;
    let message_2 = responder
        .receive_handshake(&message_1)?
        .ok_or_else(|| NativeError("responder produced no second message".to_owned()))?;
    let message_3 = initiator
        .receive_handshake(&message_2)?
        .ok_or_else(|| NativeError("initiator produced no third message".to_owned()))?;
    if responder.receive_handshake(&message_3)?.is_some() {
        return Err(NativeError(
            "responder produced an unexpected fourth message".to_owned(),
        ));
    }
    if initiator.handshake_hash() != responder.handshake_hash() {
        return Err(NativeError(
            "Noise peers produced different channel bindings".to_owned(),
        ));
    }
    let ciphertext = initiator.encrypt(b"Relay Android secure-core self-test")?;
    Ok(responder.decrypt(&ciphertext)? == b"Relay Android secure-core self-test")
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeRunSelfTest<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|_env| -> NativeResult<jboolean> {
        Ok(if self_test()? { JNI_TRUE } else { JNI_FALSE })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeCreateIdentity<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
) -> jlong {
    let outcome = unowned_env.with_env(|_env| registry()?.create_identity());
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeDestroyIdentity<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
) {
    let outcome = unowned_env.with_env(|_env| -> NativeResult<()> {
        registry()?.destroy_identity(handle);
        Ok(())
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeCreateSession<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    identity_handle: jlong,
    is_initiator: jboolean,
    initiator_token: JByteArray<'caller>,
    responder_token: JByteArray<'caller>,
) -> jlong {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jlong> {
        let initiator_token = token(env.convert_byte_array(&initiator_token)?)?;
        let responder_token = token(env.convert_byte_array(&responder_token)?)?;
        let role = if is_initiator == JNI_FALSE {
            SessionRole::Responder
        } else {
            SessionRole::Initiator
        };
        registry()?.create_session(identity_handle, role, initiator_token, responder_token)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeCreateFastSession<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    is_initiator: jboolean,
    psk: JByteArray<'caller>,
    offer_id: JByteArray<'caller>,
    initiator_token: JByteArray<'caller>,
    responder_token: JByteArray<'caller>,
) -> jlong {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jlong> {
        let psk = fixed_bytes::<PSK_BYTES>(env.convert_byte_array(&psk)?, "upgrade PSK")?;
        let offer_id =
            fixed_bytes::<OFFER_ID_BYTES>(env.convert_byte_array(&offer_id)?, "upgrade offer ID")?;
        let initiator_token = token(env.convert_byte_array(&initiator_token)?)?;
        let responder_token = token(env.convert_byte_array(&responder_token)?)?;
        let role = if is_initiator == JNI_FALSE {
            SessionRole::Responder
        } else {
            SessionRole::Initiator
        };
        registry()?.create_fast_session(role, psk, offer_id, initiator_token, responder_token)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeDestroySession<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
) {
    let outcome = unowned_env.with_env(|_env| -> NativeResult<()> {
        registry()?.destroy_session(handle);
        Ok(())
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeStartSession<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let message = registry()?.start_session(handle)?;
        message.map_or_else(
            || Ok(JByteArray::null()),
            |bytes| env.byte_array_from_slice(&bytes).map_err(Into::into),
        )
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeReceiveHandshake<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
    incoming: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let incoming = env.convert_byte_array(&incoming)?;
        let reply = registry()?.receive_handshake(handle, &incoming)?;
        reply.map_or_else(
            || Ok(JByteArray::null()),
            |bytes| env.byte_array_from_slice(&bytes).map_err(Into::into),
        )
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeIsEstablished<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
) -> jboolean {
    let outcome = unowned_env.with_env(|_env| -> NativeResult<jboolean> {
        Ok(if registry()?.is_established(handle)? {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeSessionBinding<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let binding = registry()?.session_binding(handle)?;
        env.byte_array_from_slice(&binding).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeEncrypt<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
    plaintext: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let plaintext = env.convert_byte_array(&plaintext)?;
        let ciphertext = registry()?.encrypt(handle, &plaintext)?;
        env.byte_array_from_slice(&ciphertext).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeDecrypt<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    handle: jlong,
    ciphertext: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let ciphertext = env.convert_byte_array(&ciphertext)?;
        let plaintext = registry()?.decrypt(handle, &ciphertext)?;
        env.byte_array_from_slice(&plaintext).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeEncodeTextMessage<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    id: JByteArray<'caller>,
    utf8: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let id = message_id(env.convert_byte_array(&id)?)?;
        let utf8 = env.convert_byte_array(&utf8)?;
        let encoded = encode_text_message(id, utf8)?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeEncodeReplyMessage<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    id: JByteArray<'caller>,
    utf8: JByteArray<'caller>,
    reply_to: JByteArray<'caller>,
    preview_utf8: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let id = message_id(env.convert_byte_array(&id)?)?;
        let utf8 = env.convert_byte_array(&utf8)?;
        let reply_to = message_id(env.convert_byte_array(&reply_to)?)?;
        let preview_utf8 = env.convert_byte_array(&preview_utf8)?;
        let encoded = encode_reply_message(id, utf8, reply_to, preview_utf8)?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeValidateTextMessage<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    encoded: JByteArray<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jboolean> {
        let encoded = env.convert_byte_array(&encoded)?;
        Ok(if validate_text_message(&encoded) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeEncodeDeliveryReceipt<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    id: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let id = message_id(env.convert_byte_array(&id)?)?;
        let encoded = encode_delivery_receipt(id);
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeValidateDeliveryReceipt<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    encoded: JByteArray<'caller>,
    expected_id: JByteArray<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jboolean> {
        let encoded = env.convert_byte_array(&encoded)?;
        let expected_id = message_id(env.convert_byte_array(&expected_id)?)?;
        Ok(if validate_delivery_receipt(&encoded, expected_id) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeEncodeWifiUpgradeOffer<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    offer_id: JByteArray<'caller>,
    psk: JByteArray<'caller>,
    initiator_token: JByteArray<'caller>,
    responder_token: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let offer_id = fixed_bytes(env.convert_byte_array(&offer_id)?, "upgrade offer ID")?;
        let psk = fixed_bytes(env.convert_byte_array(&psk)?, "upgrade PSK")?;
        let initiator_token =
            fixed_bytes(env.convert_byte_array(&initiator_token)?, "Wi-Fi token")?;
        let responder_token =
            fixed_bytes(env.convert_byte_array(&responder_token)?, "Wi-Fi token")?;
        let encoded = encode_wifi_upgrade_offer(offer_id, psk, initiator_token, responder_token);
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeValidateWifiUpgradeOffer<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    encoded: JByteArray<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jboolean> {
        let encoded = env.convert_byte_array(&encoded)?;
        Ok(if WifiUpgradeOffer::decode(&encoded).is_ok() {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeEncodeWifiUpgradeAck<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    encoded_offer: JByteArray<'caller>,
    responder_token: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let encoded_offer = env.convert_byte_array(&encoded_offer)?;
        let offer = WifiUpgradeOffer::decode(&encoded_offer)
            .map_err(|error| NativeError(error.to_string()))?;
        let responder_token =
            fixed_bytes(env.convert_byte_array(&responder_token)?, "Wi-Fi token")?;
        let encoded = encode_wifi_upgrade_ack(offer, responder_token);
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeValidateWifiUpgradeAck<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    encoded_ack: JByteArray<'caller>,
    encoded_offer: JByteArray<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jboolean> {
        let encoded_ack = env.convert_byte_array(&encoded_ack)?;
        let encoded_offer = env.convert_byte_array(&encoded_offer)?;
        let valid = WifiUpgradeAck::decode(&encoded_ack)
            .ok()
            .zip(WifiUpgradeOffer::decode(&encoded_offer).ok())
            .is_some_and(|(ack, offer)| wifi_upgrade_ack_matches(ack, offer));
        Ok(if valid { JNI_TRUE } else { JNI_FALSE })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eCreateAccount<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    state_key: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let pickle = e2e_create_account(&key);
        env.byte_array_from_slice(&pickle).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eIssueContactBundle<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let encoded = e2e_issue_contact_bundle(&account_pickle, &key)?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eRelayId<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    encoded_bundle: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let bundle = contact_bundle(&env.convert_byte_array(&encoded_bundle)?)?;
        let relay_id = bundle.identity().relay_id();
        env.byte_array_from_slice(&relay_id).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eStartConversation<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session = e2e_start_conversation(&account_pickle, &key, &local_bundle, &remote_bundle)?;
        env.byte_array_from_slice(&session).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eEncryptText<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    id: JByteArray<'caller>,
    sequence: jlong,
    utf8: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let id = message_id(env.convert_byte_array(&id)?)?;
        let sequence = u64::try_from(sequence)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| NativeError("message sequence must be positive".to_owned()))?;
        let text = String::from_utf8(env.convert_byte_array(&utf8)?)
            .map_err(|_| NativeError("message text is not valid UTF-8".to_owned()))?;
        let encoded = e2e_encrypt_text(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            id,
            sequence,
            text,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eEncryptMessage<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    sequence: jlong,
    encoded_message: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let sequence = u64::try_from(sequence)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| NativeError("message sequence must be positive".to_owned()))?;
        let message = DirectText::decode(&env.convert_byte_array(&encoded_message)?)
            .map_err(|error| NativeError(error.to_string()))?;
        let encoded = e2e_encrypt_message(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            sequence,
            &message,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eEncryptReceipt<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    envelope_id: JByteArray<'caller>,
    sequence: jlong,
    delivered_id: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let envelope_id = message_id(env.convert_byte_array(&envelope_id)?)?;
        let delivered_id = message_id(env.convert_byte_array(&delivered_id)?)?;
        let sequence = u64::try_from(sequence)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| NativeError("receipt sequence must be positive".to_owned()))?;
        let encoded = e2e_encrypt_receipt(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            envelope_id,
            sequence,
            delivered_id,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eEncryptAttachmentManifest<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    sequence: jlong,
    encoded_manifest: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let sequence = u64::try_from(sequence)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| NativeError("attachment sequence must be positive".to_owned()))?;
        let manifest =
            RecipientAttachmentManifest::decode(&env.convert_byte_array(&encoded_manifest)?)?;
        let encoded = e2e_encrypt_attachment_manifest(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            sequence,
            &manifest,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eEncryptAttachmentReceipt<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    envelope_id: JByteArray<'caller>,
    sequence: jlong,
    encoded_receipt: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let envelope_id = message_id(env.convert_byte_array(&envelope_id)?)?;
        let sequence = u64::try_from(sequence)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                NativeError("attachment receipt sequence must be positive".to_owned())
            })?;
        let receipt =
            RecipientAttachmentReceipt::decode(&env.convert_byte_array(&encoded_receipt)?)?;
        let encoded = e2e_encrypt_attachment_receipt(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            envelope_id,
            sequence,
            receipt,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eRecognizes<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    local_bundle: JByteArray<'caller>,
    encoded_envelope: JByteArray<'caller>,
) -> jboolean {
    let outcome = unowned_env.with_env(|env| -> NativeResult<jboolean> {
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let envelope = mesh_envelope(&env.convert_byte_array(&encoded_envelope)?)?;
        Ok(if local_bundle.recognizes(&envelope)? {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eAcceptConversation<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    encoded_envelope: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let envelope = mesh_envelope(&env.convert_byte_array(&encoded_envelope)?)?;
        let encoded = e2e_accept_conversation(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &envelope,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eAcceptPayloadConversation<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    account_pickle: JByteArray<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    encoded_envelope: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let account_pickle = encrypted_pickle(
            env.convert_byte_array(&account_pickle)?,
            "encrypted account pickle",
        )?;
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let envelope = mesh_envelope(&env.convert_byte_array(&encoded_envelope)?)?;
        let encoded = e2e_accept_payload_conversation(
            &account_pickle,
            &key,
            &local_bundle,
            &remote_bundle,
            &envelope,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eDecryptText<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    encoded_envelope: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let envelope = mesh_envelope(&env.convert_byte_array(&encoded_envelope)?)?;
        let encoded = e2e_decrypt_text(
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            &envelope,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_projectrelay_relay_1mobile_RelayNative_nativeE2eDecryptPayload<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _object: JObject<'caller>,
    state_key: JByteArray<'caller>,
    local_bundle: JByteArray<'caller>,
    remote_bundle: JByteArray<'caller>,
    session_pickle: JByteArray<'caller>,
    is_initiator: jboolean,
    encoded_envelope: JByteArray<'caller>,
) -> JByteArray<'caller> {
    let outcome = unowned_env.with_env(|env| -> NativeResult<JByteArray<'caller>> {
        let key = protection_key(env.convert_byte_array(&state_key)?)?;
        let local_bundle = contact_bundle(&env.convert_byte_array(&local_bundle)?)?;
        let remote_bundle = contact_bundle(&env.convert_byte_array(&remote_bundle)?)?;
        let session_pickle = encrypted_pickle(
            env.convert_byte_array(&session_pickle)?,
            "encrypted session pickle",
        )?;
        let envelope = mesh_envelope(&env.convert_byte_array(&encoded_envelope)?)?;
        let encoded = e2e_decrypt_payload(
            &key,
            &local_bundle,
            &remote_bundle,
            &session_pickle,
            conversation_role(is_initiator),
            &envelope,
        )?;
        env.byte_array_from_slice(&encoded).map_err(Into::into)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_keeps_private_keys_native_and_exchanges_ciphertext() {
        let mut registry = Registry::default();
        let initiator_identity = registry.create_identity().expect("initiator identity");
        let responder_identity = registry.create_identity().expect("responder identity");
        let initiator = registry
            .create_session(
                initiator_identity,
                SessionRole::Initiator,
                [1; TOKEN_BYTES],
                [2; TOKEN_BYTES],
            )
            .expect("initiator session");
        let responder = registry
            .create_session(
                responder_identity,
                SessionRole::Responder,
                [1; TOKEN_BYTES],
                [2; TOKEN_BYTES],
            )
            .expect("responder session");
        let first = registry
            .start_session(initiator)
            .expect("start")
            .expect("first");
        let second = registry
            .receive_handshake(responder, &first)
            .expect("receive first")
            .expect("second");
        let third = registry
            .receive_handshake(initiator, &second)
            .expect("receive second")
            .expect("third");
        assert_eq!(
            registry
                .receive_handshake(responder, &third)
                .expect("receive third"),
            None
        );
        assert!(registry.is_established(initiator).expect("initiator state"));
        assert!(registry.is_established(responder).expect("responder state"));
        assert_eq!(
            registry
                .session_binding(initiator)
                .expect("initiator binding"),
            registry
                .session_binding(responder)
                .expect("responder binding"),
        );

        let ciphertext = registry
            .encrypt(initiator, b"native-only secret")
            .expect("encrypt");
        assert_eq!(
            registry.decrypt(responder, &ciphertext).expect("decrypt"),
            b"native-only secret"
        );
    }

    #[test]
    fn android_self_test_exercises_the_complete_secure_path() {
        assert!(self_test().expect("self test"));
    }

    #[test]
    fn message_codec_rejects_bad_content_and_binds_receipts() {
        let id = MessageId([7; 16]);
        let encoded = encode_text_message(id, b"hello offline".to_vec()).expect("encode text");
        assert!(validate_text_message(&encoded));

        let mut malformed = encoded;
        malformed.push(0);
        assert!(!validate_text_message(&malformed));

        let receipt = encode_delivery_receipt(id);
        assert!(validate_delivery_receipt(&receipt, id));
        assert!(!validate_delivery_receipt(&receipt, MessageId([8; 16])));
    }

    #[test]
    fn registry_establishes_a_psk_bound_fast_session() {
        let mut registry = Registry::default();
        let psk = [9; PSK_BYTES];
        let offer = [3; OFFER_ID_BYTES];
        let initiator = registry
            .create_fast_session(SessionRole::Initiator, psk, offer, [1; 8], [2; 8])
            .expect("initiator");
        let responder = registry
            .create_fast_session(SessionRole::Responder, psk, offer, [1; 8], [2; 8])
            .expect("responder");
        let first = registry
            .start_session(initiator)
            .expect("start")
            .expect("one");
        let second = registry
            .receive_handshake(responder, &first)
            .expect("receive one")
            .expect("two");
        assert_eq!(
            registry
                .receive_handshake(initiator, &second)
                .expect("receive two"),
            None
        );
        let ciphertext = registry
            .encrypt(initiator, b"encrypted Wi-Fi record")
            .expect("encrypt");
        assert_eq!(
            registry.decrypt(responder, &ciphertext).expect("decrypt"),
            b"encrypted Wi-Fi record"
        );
    }

    #[test]
    fn wifi_upgrade_ack_binds_exact_or_ble_resolved_responder_token() {
        let offer = encode_wifi_upgrade_offer([1; 16], [2; 32], [3; 8], [4; 8]);
        let decoded = WifiUpgradeOffer::decode(&offer).expect("offer");
        let ack = encode_wifi_upgrade_ack(decoded, [4; 8]);
        let parsed_ack = WifiUpgradeAck::decode(&ack).expect("ack");
        assert_eq!(parsed_ack.offer_id, [1; 16]);
        assert_eq!(parsed_ack.initiator_token, [3; 8]);
        assert_eq!(parsed_ack.responder_token, [4; 8]);

        let unresolved = encode_wifi_upgrade_offer([5; 16], [6; 32], [7; 8], [0; 8]);
        let resolved_ack = encode_wifi_upgrade_ack(
            WifiUpgradeOffer::decode(&unresolved).expect("unresolved offer"),
            [8; 8],
        );
        let parsed = WifiUpgradeAck::decode(&resolved_ack).expect("resolved ack");
        assert_eq!(parsed.responder_token, [8; 8]);
        let unresolved_offer = WifiUpgradeOffer::decode(&unresolved).expect("offer");
        assert!(wifi_upgrade_ack_matches(parsed, unresolved_offer));

        let wrong_responder = WifiUpgradeAck {
            responder_token: [9; 8],
            ..parsed_ack
        };
        assert!(!wifi_upgrade_ack_matches(wrong_responder, decoded));
        let zero_responder = WifiUpgradeAck {
            responder_token: [0; 8],
            ..parsed
        };
        assert!(!wifi_upgrade_ack_matches(zero_responder, unresolved_offer));
    }

    #[test]
    fn stateless_android_e2e_operations_persist_every_ratchet_advance() {
        let alice_key = [0xA1; E2E_PROTECTION_KEY_BYTES];
        let bob_key = [0xB2; E2E_PROTECTION_KEY_BYTES];
        let courier_key = [0xC3; E2E_PROTECTION_KEY_BYTES];

        let (alice_account, alice_bundle) = issue_for_test(&alice_key);
        let (bob_account, bob_bundle) = issue_for_test(&bob_key);
        let (_, courier_bundle) = issue_for_test(&courier_key);

        let alice_session =
            e2e_start_conversation(&alice_account, &alice_key, &alice_bundle, &bob_bundle)
                .expect("start Alice session");
        let alice_session = String::from_utf8(alice_session).expect("session pickle UTF-8");
        let outbound = e2e_encrypt_text(
            &alice_account,
            &alice_key,
            &alice_bundle,
            &bob_bundle,
            &alice_session,
            ConversationRole::Initiator,
            MessageId([0x11; 16]),
            1,
            "mesh hello".to_owned(),
        )
        .expect("encrypt Alice message");
        let (alice_session, envelope) = parse_encrypt_result_for_test(&outbound);
        assert!(bob_bundle.recognizes(&envelope).expect("Bob route"));
        assert!(!courier_bundle.recognizes(&envelope).expect("courier route"));

        let accepted = e2e_accept_conversation(
            &bob_account,
            &bob_key,
            &bob_bundle,
            &alice_bundle,
            &envelope,
        )
        .expect("Bob accepts first message");
        let (bob_account, bob_session, sequence, id, message) =
            parse_accept_result_for_test(&accepted);
        assert_eq!(sequence, 1);
        assert_eq!(id, MessageId([0x11; 16]));
        assert_eq!(message.text, "mesh hello");

        let receipt = e2e_encrypt_receipt(
            &bob_account,
            &bob_key,
            &bob_bundle,
            &alice_bundle,
            &bob_session,
            ConversationRole::Responder,
            MessageId([0x33; 16]),
            1,
            MessageId([0x11; 16]),
        )
        .expect("encrypt Bob receipt");
        let (bob_session, receipt_envelope) = parse_encrypt_result_for_test(&receipt);
        assert_receipt_routing(&alice_bundle, &courier_bundle, &receipt_envelope);
        let decrypted_receipt = e2e_decrypt_payload(
            &alice_key,
            &alice_bundle,
            &bob_bundle,
            &alice_session,
            ConversationRole::Initiator,
            &receipt_envelope,
        )
        .expect("Alice decrypts mesh receipt");
        let (alice_session, receipt_sequence, receipt_envelope_id, payload_type, payload) =
            parse_payload_result_for_test(&decrypted_receipt);
        assert_eq!(receipt_sequence, 1);
        assert_eq!(receipt_envelope_id, MessageId([0x33; 16]));
        assert_eq!(payload_type, E2E_PAYLOAD_RECEIPT);
        assert_eq!(payload, [0x11; 16]);

        let reply_message = DirectText {
            id: MessageId([0x22; 16]),
            text: "mesh reply".to_owned(),
            reply: Some(ReplyReference {
                message_id: MessageId([0x11; 16]),
                preview: "mesh hello".to_owned(),
            }),
        };
        let reply = e2e_encrypt_message(
            &bob_account,
            &bob_key,
            &bob_bundle,
            &alice_bundle,
            &bob_session,
            ConversationRole::Responder,
            2,
            &reply_message,
        )
        .expect("encrypt Bob reply");
        let (_, reply_envelope) = parse_encrypt_result_for_test(&reply);
        let decrypted = e2e_decrypt_text(
            &alice_key,
            &alice_bundle,
            &bob_bundle,
            &alice_session,
            ConversationRole::Initiator,
            &reply_envelope,
        )
        .expect("Alice decrypts reply");
        let (_, reply_sequence, reply_id, received_reply) =
            parse_decrypt_result_for_test(&decrypted);
        assert_typed_reply(reply_sequence, reply_id, &received_reply, &reply_message);
    }

    fn assert_typed_reply(
        sequence: u64,
        id: MessageId,
        actual: &DirectText,
        expected: &DirectText,
    ) {
        assert_eq!(sequence, 2);
        assert_eq!(id, MessageId([0x22; 16]));
        assert_eq!(actual, expected);
    }

    #[test]
    fn stateless_android_attachment_payloads_remain_recipient_private() {
        let alice_key = [0xA4; E2E_PROTECTION_KEY_BYTES];
        let bob_key = [0xB5; E2E_PROTECTION_KEY_BYTES];
        let courier_key = [0xC6; E2E_PROTECTION_KEY_BYTES];
        let (alice_account, alice_bundle) = issue_for_test(&alice_key);
        let (bob_account, bob_bundle) = issue_for_test(&bob_key);
        let (_, courier_bundle) = issue_for_test(&courier_key);
        let alice_session =
            e2e_start_conversation(&alice_account, &alice_key, &alice_bundle, &bob_bundle)
                .expect("start attachment session");
        let alice_session = String::from_utf8(alice_session).expect("session pickle UTF-8");
        let manifest = RecipientAttachmentManifest {
            object_id: MessageId([0x41; 16]),
            kind: relay_message::attachment::AttachmentKind::File,
            courier_plan_sha256: [0x42; 32],
            content_key: [0x43; 32],
            plaintext_bytes: 30 * 1024 * 1024,
            plaintext_sha256: [0x44; 32],
            mime_type: "application/octet-stream".to_owned(),
            file_name: "private.bin".to_owned(),
        };
        let encrypted = e2e_encrypt_attachment_manifest(
            &alice_account,
            &alice_key,
            &alice_bundle,
            &bob_bundle,
            &alice_session,
            ConversationRole::Initiator,
            1,
            &manifest,
        )
        .expect("encrypt attachment manifest");
        let (alice_session, envelope) = parse_encrypt_result_for_test(&encrypted);
        assert_eq!(envelope.id, manifest.object_id);
        assert_eq!(envelope.priority, relay_wire::Priority::Manifest);
        assert!(bob_bundle.recognizes(&envelope).expect("Bob route"));
        assert!(!courier_bundle.recognizes(&envelope).expect("courier route"));
        assert!(
            !envelope
                .ciphertext
                .windows(manifest.file_name.len())
                .any(|part| part == manifest.file_name.as_bytes())
        );

        let accepted = e2e_accept_payload_conversation(
            &bob_account,
            &bob_key,
            &bob_bundle,
            &alice_bundle,
            &envelope,
        )
        .expect("accept first attachment payload");
        let (bob_account, bob_session, sequence, envelope_id, payload_type, payload) =
            parse_accept_payload_result_for_test(&accepted);
        assert_eq!(sequence, 1);
        assert_eq!(envelope_id, manifest.object_id);
        assert_eq!(payload_type, E2E_PAYLOAD_ATTACHMENT_MANIFEST);
        assert_eq!(
            RecipientAttachmentManifest::decode(&payload).expect("decoded private manifest"),
            manifest
        );

        let attachment_receipt = RecipientAttachmentReceipt {
            object_id: manifest.object_id,
            courier_plan_sha256: manifest.courier_plan_sha256,
        };
        let encrypted_receipt = e2e_encrypt_attachment_receipt(
            &bob_account,
            &bob_key,
            &bob_bundle,
            &alice_bundle,
            &bob_session,
            ConversationRole::Responder,
            MessageId([0x52; 16]),
            1,
            attachment_receipt,
        )
        .expect("encrypt attachment receipt");
        let (_, receipt_envelope) = parse_encrypt_result_for_test(&encrypted_receipt);
        assert_receipt_routing(&alice_bundle, &courier_bundle, &receipt_envelope);
        let decrypted = e2e_decrypt_payload(
            &alice_key,
            &alice_bundle,
            &bob_bundle,
            &alice_session,
            ConversationRole::Initiator,
            &receipt_envelope,
        )
        .expect("decrypt attachment receipt");
        let (_, receipt_sequence, receipt_envelope_id, receipt_type, receipt_payload) =
            parse_payload_result_for_test(&decrypted);
        assert_eq!(receipt_sequence, 1);
        assert_eq!(receipt_envelope_id, MessageId([0x52; 16]));
        assert_eq!(receipt_type, E2E_PAYLOAD_ATTACHMENT_RECEIPT);
        assert_eq!(
            RecipientAttachmentReceipt::decode(&receipt_payload)
                .expect("decoded attachment receipt"),
            attachment_receipt
        );
    }

    fn assert_receipt_routing(
        sender_bundle: &ContactBundle,
        courier_bundle: &ContactBundle,
        receipt: &Envelope,
    ) {
        assert!(
            sender_bundle
                .recognizes(receipt)
                .expect("sender receipt route")
        );
        assert!(
            !courier_bundle
                .recognizes(receipt)
                .expect("courier receipt route")
        );
    }

    fn issue_for_test(key: &[u8; E2E_PROTECTION_KEY_BYTES]) -> (String, ContactBundle) {
        let account = String::from_utf8(e2e_create_account(key)).expect("account pickle UTF-8");
        let encoded = e2e_issue_contact_bundle(&account, key).expect("issue contact bundle");
        assert_eq!(encoded[..4], E2E_ISSUE_MAGIC);
        let mut offset = 4;
        let account = String::from_utf8(take_sized_for_test(&encoded, &mut offset))
            .expect("updated account pickle UTF-8");
        let bundle = ContactBundle::decode(&encoded[offset..]).expect("contact bundle");
        (account, bundle)
    }

    fn parse_encrypt_result_for_test(encoded: &[u8]) -> (String, Envelope) {
        assert_eq!(encoded[..4], E2E_ENCRYPT_MAGIC);
        let mut offset = 4;
        let session = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("session pickle UTF-8");
        let envelope =
            Envelope::decode(&take_sized_for_test(encoded, &mut offset)).expect("mesh envelope");
        assert_eq!(offset, encoded.len());
        (session, envelope)
    }

    fn parse_accept_result_for_test(
        encoded: &[u8],
    ) -> (String, String, u64, MessageId, DirectText) {
        assert_eq!(encoded[..4], E2E_ACCEPT_MAGIC);
        let mut offset = 4;
        let account = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("account pickle UTF-8");
        let session = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("session pickle UTF-8");
        let (sequence, id, message) = take_received_for_test(encoded, &mut offset);
        assert_eq!(offset, encoded.len());
        (account, session, sequence, id, message)
    }

    fn parse_decrypt_result_for_test(encoded: &[u8]) -> (String, u64, MessageId, DirectText) {
        assert_eq!(encoded[..4], E2E_DECRYPT_MAGIC);
        let mut offset = 4;
        let session = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("session pickle UTF-8");
        let (sequence, id, message) = take_received_for_test(encoded, &mut offset);
        assert_eq!(offset, encoded.len());
        (session, sequence, id, message)
    }

    fn parse_accept_payload_result_for_test(
        encoded: &[u8],
    ) -> (String, String, u64, MessageId, u8, Vec<u8>) {
        assert_eq!(encoded[..4], E2E_ACCEPT_PAYLOAD_MAGIC);
        let mut offset = 4;
        let account = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("account pickle UTF-8");
        let session = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("session pickle UTF-8");
        let (sequence, envelope_id, payload_type, payload) =
            take_payload_for_test(encoded, &mut offset);
        assert_eq!(offset, encoded.len());
        (
            account,
            session,
            sequence,
            envelope_id,
            payload_type,
            payload,
        )
    }

    fn parse_payload_result_for_test(encoded: &[u8]) -> (String, u64, MessageId, u8, Vec<u8>) {
        assert_eq!(encoded[..4], E2E_PAYLOAD_MAGIC);
        let mut offset = 4;
        let session = String::from_utf8(take_sized_for_test(encoded, &mut offset))
            .expect("session pickle UTF-8");
        let (sequence, envelope_id, payload_type, payload) =
            take_payload_for_test(encoded, &mut offset);
        assert_eq!(offset, encoded.len());
        (session, sequence, envelope_id, payload_type, payload)
    }

    fn take_payload_for_test(encoded: &[u8], offset: &mut usize) -> (u64, MessageId, u8, Vec<u8>) {
        let sequence =
            u64::from_be_bytes(encoded[*offset..*offset + 8].try_into().expect("sequence"));
        *offset += 8;
        let envelope_id = MessageId(
            encoded[*offset..*offset + 16]
                .try_into()
                .expect("envelope ID"),
        );
        *offset += 16;
        let payload_type = encoded[*offset];
        *offset += 1;
        let payload = match payload_type {
            E2E_PAYLOAD_TEXT | E2E_PAYLOAD_ATTACHMENT_MANIFEST => {
                take_sized_for_test(encoded, offset)
            }
            E2E_PAYLOAD_RECEIPT => {
                let value = encoded[*offset..*offset + 16].to_vec();
                *offset += 16;
                value
            }
            E2E_PAYLOAD_ATTACHMENT_RECEIPT => {
                let value = encoded
                    [*offset..*offset + relay_message::attachment::RECIPIENT_RECEIPT_BYTES]
                    .to_vec();
                *offset += relay_message::attachment::RECIPIENT_RECEIPT_BYTES;
                value
            }
            _ => panic!("unexpected payload type"),
        };
        (sequence, envelope_id, payload_type, payload)
    }

    fn take_received_for_test(encoded: &[u8], offset: &mut usize) -> (u64, MessageId, DirectText) {
        let sequence =
            u64::from_be_bytes(encoded[*offset..*offset + 8].try_into().expect("sequence"));
        *offset += 8;
        let id = MessageId(
            encoded[*offset..*offset + 16]
                .try_into()
                .expect("message ID"),
        );
        *offset += 16;
        let message = DirectText::decode(&take_sized_for_test(encoded, offset))
            .expect("canonical direct text");
        assert_eq!(message.id, id);
        (sequence, id, message)
    }

    fn take_sized_for_test(encoded: &[u8], offset: &mut usize) -> Vec<u8> {
        let length =
            u32::from_be_bytes(encoded[*offset..*offset + 4].try_into().expect("length")) as usize;
        *offset += 4;
        let value = encoded[*offset..*offset + length].to_vec();
        *offset += length;
        value
    }
}
