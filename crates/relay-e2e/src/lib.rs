//! Recipient-only encryption for store-carry-forward Relay envelopes.
//!
//! Hop encryption protects a single BLE or Wi-Fi connection. This crate is a
//! separate layer: an arbitrary courier can carry an [`Envelope`], while only
//! the contact holding the matching ratchet and per-contact route secret can
//! recognize and decrypt it.

use core::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use relay_message::{
    DeliveryReceipt, DirectText, MAX_DIRECT_TEXT_ENCODED_BYTES, RECEIPT_LEN,
    attachment::{
        MAX_FILE_NAME_BYTES, MAX_MIME_TYPE_BYTES, PRIVATE_MANIFEST_HEADER_BYTES,
        RecipientAttachmentManifest, RecipientAttachmentReceipt,
    },
};
use relay_wire::{
    Envelope, MAX_COPY_BUDGET, MAX_LIFETIME_MS, MessageId, Priority, ValidationError,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vodozemac::{
    Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature,
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
};
use zeroize::Zeroize;

pub const ROUTE_SECRET_BYTES: usize = 32;
pub const CONTACT_BUNDLE_LEN: usize = 200;
pub const MAX_IN_FLIGHT_MESSAGES: usize = 32;

const CONTACT_MAGIC: [u8; 4] = *b"RCB1";
const CONTACT_VERSION: u8 = 1;
const CONTACT_UNSIGNED_LEN: usize = 136;
const CONTACT_SIGNATURE_OFFSET: usize = CONTACT_UNSIGNED_LEN;
const CONTACT_SIGNATURE_DOMAIN: &[u8] = b"ProjectRelay/contact-bundle/v1\0";

const SIGNED_MAGIC: [u8; 4] = *b"RSP1";
const SIGNED_VERSION: u8 = 1;
const SIGNED_TEXT_TYPE: u8 = 1;
const SIGNED_RECEIPT_TYPE: u8 = 2;
const SIGNED_ATTACHMENT_MANIFEST_TYPE: u8 = 3;
const SIGNED_ATTACHMENT_RECEIPT_TYPE: u8 = 4;
const SIGNED_HEADER_LEN: usize = 98;
const SIGNATURE_BYTES: usize = 64;
const MAX_PRIVATE_MANIFEST_BYTES: usize =
    PRIVATE_MANIFEST_HEADER_BYTES + MAX_MIME_TYPE_BYTES + MAX_FILE_NAME_BYTES;
const MAX_TEXT_OR_RECEIPT_BYTES: usize = if MAX_DIRECT_TEXT_ENCODED_BYTES > RECEIPT_LEN {
    MAX_DIRECT_TEXT_ENCODED_BYTES
} else {
    RECEIPT_LEN
};
const MAX_SIGNED_CONTENT_BYTES: usize = if MAX_TEXT_OR_RECEIPT_BYTES > MAX_PRIVATE_MANIFEST_BYTES {
    MAX_TEXT_OR_RECEIPT_BYTES
} else {
    MAX_PRIVATE_MANIFEST_BYTES
};

const OLM_FRAME_MAGIC: [u8; 4] = *b"ROL1";
const OLM_FRAME_VERSION: u8 = 1;
const OLM_FRAME_HEADER_LEN: usize = 12;

const SEALED_MAGIC: [u8; 4] = *b"RSE1";
const SEALED_VERSION: u8 = 1;
const SEALED_HEADER_LEN: usize = 20;
const NONCE_BYTES: usize = 12;
const AEAD_TAG_BYTES: usize = 16;
const SEALED_LENGTH_PREFIX_BYTES: usize = 4;
const SEALED_BUCKETS: [usize; 5] = [512, 1_024, 2_048, 4_096, 8_192];

/// Largest encoded courier record produced by the bounded direct-text formats.
pub const MAX_DIRECT_TEXT_ENVELOPE_BYTES: usize =
    relay_wire::HEADER_LEN + SEALED_HEADER_LEN + SEALED_BUCKETS[3] + AEAD_TAG_BYTES;

const DESTINATION_DOMAIN: &[u8] = b"ProjectRelay/destination/v1\0";
const SEAL_KEY_DOMAIN: &[u8] = b"ProjectRelay/sealed-header-key/v1\0";
const SIGNED_PAYLOAD_DOMAIN: &[u8] = b"ProjectRelay/signed-payload/v1\0";
const RELAY_ID_DOMAIN: &[u8] = b"ProjectRelay/contact-id/v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E2eError {
    RandomUnavailable,
    InvalidContactBundle,
    LocalBundleMismatch,
    InvalidPolicy,
    InvalidEnvelope,
    NotDestination,
    InvalidFrame,
    InvalidPayload,
    IdentityMismatch,
    AuthenticationFailed,
    SessionCreationFailed,
    EncryptionFailed,
    DecryptionFailed,
    StateProtectionFailed,
    ExpectedPreKey,
}

impl fmt::Display for E2eError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomUnavailable => "secure randomness is unavailable",
            Self::InvalidContactBundle => "contact bundle is malformed or unauthenticated",
            Self::LocalBundleMismatch => "contact bundle does not belong to this account",
            Self::InvalidPolicy => "mesh delivery policy is outside protocol bounds",
            Self::InvalidEnvelope => "mesh envelope violates protocol bounds",
            Self::NotDestination => "envelope is not addressed to this contact route",
            Self::InvalidFrame => "encrypted frame is malformed",
            Self::InvalidPayload => "decrypted application payload is malformed",
            Self::IdentityMismatch => "decrypted endpoint identity does not match the contact",
            Self::AuthenticationFailed => "end-to-end authentication failed",
            Self::SessionCreationFailed => "asynchronous end-to-end session creation failed",
            Self::EncryptionFailed => "end-to-end encryption failed",
            Self::DecryptionFailed => "end-to-end decryption failed",
            Self::StateProtectionFailed => "encrypted ratchet state could not be restored",
            Self::ExpectedPreKey => "initial mesh message did not contain a prekey frame",
        })
    }
}

impl std::error::Error for E2eError {}

impl From<ValidationError> for E2eError {
    fn from(_: ValidationError) -> Self {
        Self::InvalidEnvelope
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactIdentity {
    pub signing_key: [u8; 32],
    pub curve_identity_key: [u8; 32],
}

impl ContactIdentity {
    /// A stable, compact identifier for disambiguating duplicate display names.
    /// It is shown only after contact exchange and is never advertised by radio.
    #[must_use]
    pub fn relay_id(self) -> [u8; 8] {
        let digest = Sha256::new()
            .chain_update(RELAY_ID_DOMAIN)
            .chain_update(self.signing_key)
            .chain_update(self.curve_identity_key)
            .finalize();
        let mut id = [0_u8; 8];
        id.copy_from_slice(&digest[..8]);
        id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContactBundle {
    identity: ContactIdentity,
    one_time_key: [u8; 32],
    inbound_route_secret: [u8; ROUTE_SECRET_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl fmt::Debug for ContactBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContactBundle")
            .field("relay_id", &self.identity.relay_id())
            .field("route_secret", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Drop for ContactBundle {
    fn drop(&mut self) {
        self.inbound_route_secret.zeroize();
    }
}

impl ContactBundle {
    #[must_use]
    pub const fn identity(&self) -> ContactIdentity {
        self.identity
    }

    #[must_use]
    pub fn encode(&self) -> [u8; CONTACT_BUNDLE_LEN] {
        let mut encoded = [0_u8; CONTACT_BUNDLE_LEN];
        encoded[..CONTACT_UNSIGNED_LEN].copy_from_slice(&self.unsigned_bytes());
        encoded[CONTACT_SIGNATURE_OFFSET..].copy_from_slice(&self.signature);
        encoded
    }

    /// Parses and verifies one exact contact bundle.
    ///
    /// # Errors
    ///
    /// Rejects incorrect length, reserved bits, malformed keys, or signature
    /// substitution before the bundle can create a session.
    pub fn decode(encoded: &[u8]) -> Result<Self, E2eError> {
        if encoded.len() != CONTACT_BUNDLE_LEN
            || encoded[..4] != CONTACT_MAGIC
            || encoded[4] != CONTACT_VERSION
            || encoded[5..8] != [0, 0, 0]
        {
            return Err(E2eError::InvalidContactBundle);
        }
        let bundle = Self {
            identity: ContactIdentity {
                signing_key: read_array(encoded, 8)?,
                curve_identity_key: read_array(encoded, 40)?,
            },
            one_time_key: read_array(encoded, 72)?,
            inbound_route_secret: read_array(encoded, 104)?,
            signature: read_array(encoded, CONTACT_SIGNATURE_OFFSET)?,
        };
        bundle.verify()?;
        Ok(bundle)
    }

    /// Checks whether an opaque envelope is addressed to this exact
    /// per-contact route without advancing any cryptographic session state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid local bundle or invalid envelope.
    pub fn recognizes(&self, envelope: &Envelope) -> Result<bool, E2eError> {
        self.verify()?;
        envelope.validate()?;
        let expected = destination_hint(&self.inbound_route_secret, envelope);
        Ok(bool::from(expected.ct_eq(&envelope.destination_hint)))
    }

    fn unsigned_bytes(&self) -> [u8; CONTACT_UNSIGNED_LEN] {
        let mut encoded = [0_u8; CONTACT_UNSIGNED_LEN];
        encoded[..4].copy_from_slice(&CONTACT_MAGIC);
        encoded[4] = CONTACT_VERSION;
        encoded[8..40].copy_from_slice(&self.identity.signing_key);
        encoded[40..72].copy_from_slice(&self.identity.curve_identity_key);
        encoded[72..104].copy_from_slice(&self.one_time_key);
        encoded[104..136].copy_from_slice(&self.inbound_route_secret);
        encoded
    }

    fn verify(&self) -> Result<(), E2eError> {
        let signing_key = Ed25519PublicKey::from_slice(&self.identity.signing_key)
            .map_err(|_| E2eError::InvalidContactBundle)?;
        Curve25519PublicKey::from_slice(&self.identity.curve_identity_key)
            .map_err(|_| E2eError::InvalidContactBundle)?;
        Curve25519PublicKey::from_slice(&self.one_time_key)
            .map_err(|_| E2eError::InvalidContactBundle)?;
        let signature = Ed25519Signature::from_slice(&self.signature)
            .map_err(|_| E2eError::InvalidContactBundle)?;
        let input = signature_input(CONTACT_SIGNATURE_DOMAIN, &self.unsigned_bytes());
        signing_key
            .verify(&input, &signature)
            .map_err(|_| E2eError::InvalidContactBundle)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryPolicy {
    pub lifetime_ms: u64,
    pub hop_limit: u8,
    pub copy_budget: u16,
    pub priority: Priority,
}

impl DeliveryPolicy {
    #[must_use]
    pub const fn delayed_text() -> Self {
        Self {
            lifetime_ms: 7 * 24 * 60 * 60 * 1_000,
            hop_limit: 16,
            copy_budget: 24,
            priority: Priority::DirectText,
        }
    }

    #[must_use]
    pub const fn delivery_receipt() -> Self {
        Self {
            lifetime_ms: 7 * 24 * 60 * 60 * 1_000,
            hop_limit: 16,
            copy_budget: 24,
            priority: Priority::Control,
        }
    }

    #[must_use]
    pub const fn attachment_manifest() -> Self {
        Self {
            lifetime_ms: 7 * 24 * 60 * 60 * 1_000,
            hop_limit: 16,
            copy_budget: 2,
            priority: Priority::Manifest,
        }
    }

    const fn validate(self) -> Result<(), E2eError> {
        if self.lifetime_ms == 0
            || self.lifetime_ms > MAX_LIFETIME_MS
            || self.hop_limit == 0
            || self.copy_budget == 0
            || self.copy_budget > MAX_COPY_BUDGET
            || !matches!(
                self.priority,
                Priority::Control | Priority::DirectText | Priority::Manifest
            )
        {
            Err(E2eError::InvalidPolicy)
        } else {
            Ok(())
        }
    }
}

pub struct E2eAccount {
    account: Account,
}

impl fmt::Debug for E2eAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("E2eAccount")
            .field("identity", &self.identity())
            .finish_non_exhaustive()
    }
}

impl Default for E2eAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl E2eAccount {
    #[must_use]
    pub fn new() -> Self {
        Self {
            account: Account::new(),
        }
    }

    #[must_use]
    pub fn identity(&self) -> ContactIdentity {
        ContactIdentity {
            signing_key: *self.account.ed25519_key().as_bytes(),
            curve_identity_key: self.account.curve25519_key().to_bytes(),
        }
    }

    /// Issues one contact-specific asynchronous prekey and private route.
    /// The returned bytes belong only in an authenticated direct exchange or
    /// a user-confirmed QR contact card.
    ///
    /// # Errors
    ///
    /// Returns an error if randomness is unavailable or unpublished keys from
    /// an interrupted earlier issuance still require persistence.
    pub fn issue_contact_bundle(&mut self) -> Result<ContactBundle, E2eError> {
        if !self.account.one_time_keys().is_empty() {
            return Err(E2eError::StateProtectionFailed);
        }
        let mut route_secret = [0_u8; ROUTE_SECRET_BYTES];
        getrandom::getrandom(&mut route_secret).map_err(|_| E2eError::RandomUnavailable)?;
        self.account.generate_one_time_keys(1);
        let unpublished = self.account.one_time_keys();
        let one_time_key = unpublished
            .values()
            .next()
            .ok_or(E2eError::StateProtectionFailed)?
            .to_bytes();
        let mut bundle = ContactBundle {
            identity: self.identity(),
            one_time_key,
            inbound_route_secret: route_secret,
            signature: [0_u8; SIGNATURE_BYTES],
        };
        let input = signature_input(CONTACT_SIGNATURE_DOMAIN, &bundle.unsigned_bytes());
        bundle.signature = self.account.sign(input).to_bytes();
        self.account.mark_keys_as_published();
        Ok(bundle)
    }

    /// Creates the initiator side of an asynchronous recipient session.
    ///
    /// # Errors
    ///
    /// Rejects invalid, substituted, or incorrectly local contact material and
    /// non-contributory prekeys.
    pub fn start_conversation(
        &self,
        local_bundle: &ContactBundle,
        remote_bundle: &ContactBundle,
    ) -> Result<ConversationSession, E2eError> {
        self.verify_local_bundle(local_bundle)?;
        remote_bundle.verify()?;
        let remote_identity =
            Curve25519PublicKey::from_slice(&remote_bundle.identity.curve_identity_key)
                .map_err(|_| E2eError::InvalidContactBundle)?;
        let remote_one_time = Curve25519PublicKey::from_slice(&remote_bundle.one_time_key)
            .map_err(|_| E2eError::InvalidContactBundle)?;
        let session = self
            .account
            .create_outbound_session(session_config(), remote_identity, remote_one_time)
            .map_err(|_| E2eError::SessionCreationFailed)?;
        Ok(ConversationSession::new(
            ConversationRole::Initiator,
            local_bundle,
            remote_bundle,
            session,
        ))
    }

    /// Accepts and decrypts the first asynchronous message from a verified
    /// contact, returning the ratchet that must be persisted atomically with
    /// the received message.
    ///
    /// # Errors
    ///
    /// Rejects a wrong route, non-prekey frame, substituted contact identity,
    /// invalid prekey, failed ratchet authentication, or invalid signed text.
    pub fn accept_conversation(
        &mut self,
        local_bundle: &ContactBundle,
        remote_bundle: &ContactBundle,
        envelope: &Envelope,
    ) -> Result<(ConversationSession, ReceivedText), E2eError> {
        let (session, received) =
            self.accept_payload_conversation(local_bundle, remote_bundle, envelope)?;
        let ReceivedContent::Text(message) = received.content else {
            return Err(E2eError::InvalidPayload);
        };
        Ok((
            session,
            ReceivedText {
                message,
                sequence: received.sequence,
            },
        ))
    }

    /// Accepts and decrypts the first typed payload from a verified contact.
    /// This additive entry point permits a recipient-private attachment
    /// manifest to establish the same ratchet as text.
    ///
    /// # Errors
    ///
    /// Rejects a wrong route, non-prekey frame, substituted contact identity,
    /// invalid prekey, failed ratchet authentication, or invalid signed content.
    pub fn accept_payload_conversation(
        &mut self,
        local_bundle: &ContactBundle,
        remote_bundle: &ContactBundle,
        envelope: &Envelope,
    ) -> Result<(ConversationSession, ReceivedPayload), E2eError> {
        self.verify_local_bundle(local_bundle)?;
        remote_bundle.verify()?;
        if !local_bundle.recognizes(envelope)? {
            return Err(E2eError::NotDestination);
        }
        let frame = open_olm_frame(&local_bundle.inbound_route_secret, envelope)?;
        let OlmMessage::PreKey(prekey) = frame else {
            return Err(E2eError::ExpectedPreKey);
        };
        if prekey.one_time_key().to_bytes() != local_bundle.one_time_key {
            return Err(E2eError::SessionCreationFailed);
        }
        let remote_curve =
            Curve25519PublicKey::from_slice(&remote_bundle.identity.curve_identity_key)
                .map_err(|_| E2eError::InvalidContactBundle)?;
        let result = self
            .account
            .create_inbound_session(session_config(), remote_curve, &prekey)
            .map_err(|_| E2eError::SessionCreationFailed)?;
        let received = verify_signed_payload(
            &result.plaintext,
            remote_bundle.identity,
            local_bundle.identity,
            envelope.id,
        )?;
        let session = ConversationSession::new(
            ConversationRole::Responder,
            local_bundle,
            remote_bundle,
            result.session,
        );
        Ok((session, received))
    }

    /// Encrypts one signed text record into an opaque courier envelope.
    /// The caller must atomically persist the advanced session and envelope
    /// before making the envelope visible to transports.
    ///
    /// # Errors
    ///
    /// Rejects invalid text, sequence zero, invalid policy, a session owned by
    /// another account, randomness failure, or cryptographic failure.
    pub fn encrypt_text(
        &self,
        session: &mut ConversationSession,
        id: MessageId,
        sequence: u64,
        text: String,
        policy: DeliveryPolicy,
    ) -> Result<Envelope, E2eError> {
        let message = DirectText {
            id,
            text,
            reply: None,
        };
        self.encrypt_message(session, sequence, &message, policy)
    }

    /// Encrypts one validated v1 text or v2 reply record into an opaque courier envelope.
    ///
    /// # Errors
    ///
    /// Rejects malformed message content, sequence zero, invalid policy, mismatched session
    /// identity, randomness failure, or a cryptographic failure.
    pub fn encrypt_message(
        &self,
        session: &mut ConversationSession,
        sequence: u64,
        message: &DirectText,
        policy: DeliveryPolicy,
    ) -> Result<Envelope, E2eError> {
        if policy.priority != Priority::DirectText {
            return Err(E2eError::InvalidPolicy);
        }
        let id = message.id;
        let content = message.encode().map_err(|_| E2eError::InvalidPayload)?;
        self.encrypt_payload(session, id, sequence, SIGNED_TEXT_TYPE, &content, policy)
    }

    /// Encrypts a recipient-authenticated delivery receipt into an opaque
    /// courier envelope. The receipt envelope has its own random ID and binds
    /// the ID of the delivered text inside signed ratcheted ciphertext.
    ///
    /// # Errors
    ///
    /// Rejects invalid sequence/policy/session state or cryptographic failure.
    pub fn encrypt_receipt(
        &self,
        session: &mut ConversationSession,
        envelope_id: MessageId,
        sequence: u64,
        delivered_id: MessageId,
        policy: DeliveryPolicy,
    ) -> Result<Envelope, E2eError> {
        if policy.priority != Priority::Control {
            return Err(E2eError::InvalidPolicy);
        }
        let content = DeliveryReceipt { id: delivered_id }.encode();
        self.encrypt_payload(
            session,
            envelope_id,
            sequence,
            SIGNED_RECEIPT_TYPE,
            &content,
            policy,
        )
    }

    /// Encrypts recipient-private attachment metadata into an opaque manifest
    /// envelope. The envelope ID is the attachment object ID.
    ///
    /// # Errors
    ///
    /// Rejects invalid private metadata, sequence/policy/session state, or
    /// cryptographic failure.
    pub fn encrypt_attachment_manifest(
        &self,
        session: &mut ConversationSession,
        sequence: u64,
        manifest: &RecipientAttachmentManifest,
        policy: DeliveryPolicy,
    ) -> Result<Envelope, E2eError> {
        if policy.priority != Priority::Manifest {
            return Err(E2eError::InvalidPolicy);
        }
        let content = manifest.encode().map_err(|_| E2eError::InvalidPayload)?;
        self.encrypt_payload(
            session,
            manifest.object_id,
            sequence,
            SIGNED_ATTACHMENT_MANIFEST_TYPE,
            &content,
            policy,
        )
    }

    /// Encrypts the recipient's authenticated attachment-completion receipt.
    /// Custody records must never call this method or produce this content.
    ///
    /// # Errors
    ///
    /// Rejects invalid sequence/policy/session state or cryptographic failure.
    pub fn encrypt_attachment_receipt(
        &self,
        session: &mut ConversationSession,
        envelope_id: MessageId,
        sequence: u64,
        receipt: RecipientAttachmentReceipt,
        policy: DeliveryPolicy,
    ) -> Result<Envelope, E2eError> {
        if policy.priority != Priority::Control {
            return Err(E2eError::InvalidPolicy);
        }
        self.encrypt_payload(
            session,
            envelope_id,
            sequence,
            SIGNED_ATTACHMENT_RECEIPT_TYPE,
            &receipt.encode(),
            policy,
        )
    }

    fn encrypt_payload(
        &self,
        session: &mut ConversationSession,
        id: MessageId,
        sequence: u64,
        payload_type: u8,
        content: &[u8],
        policy: DeliveryPolicy,
    ) -> Result<Envelope, E2eError> {
        policy.validate()?;
        if sequence == 0 || session.local != self.identity() {
            return Err(E2eError::IdentityMismatch);
        }
        let signed = encode_signed_payload(
            &self.account,
            session.local,
            session.remote,
            id,
            sequence,
            payload_type,
            content,
        )?;

        // Obtain all fallible randomness before advancing the double ratchet.
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::getrandom(&mut nonce).map_err(|_| E2eError::RandomUnavailable)?;
        let olm = session
            .session
            .encrypt(&signed)
            .map_err(|_| E2eError::EncryptionFailed)?;
        let frame = encode_olm_frame(&olm)?;

        let mut envelope = Envelope {
            id,
            destination_hint: [0_u8; 16],
            lifetime_ms: policy.lifetime_ms,
            age_ms: 0,
            hop_limit: policy.hop_limit,
            hops_taken: 0,
            copy_budget: policy.copy_budget,
            priority: policy.priority,
            ciphertext: Vec::new(),
        };
        envelope.destination_hint = destination_hint(&session.outbound_route_secret, &envelope);
        envelope.ciphertext =
            seal_olm_frame(&session.outbound_route_secret, &envelope, &frame, nonce)?;
        envelope.validate()?;
        Ok(envelope)
    }

    #[must_use]
    pub fn encrypted_pickle(&self, protection_key: &[u8; 32]) -> String {
        self.account.pickle().encrypt(protection_key)
    }

    /// Restores account secrets from vodozemac's authenticated encrypted
    /// pickle. Plain private keys never leave this crate.
    ///
    /// # Errors
    ///
    /// Returns an error for an incorrect key, tampering, or malformed state.
    pub fn from_encrypted_pickle(
        encrypted: &str,
        protection_key: &[u8; 32],
    ) -> Result<Self, E2eError> {
        let pickle = AccountPickle::from_encrypted(encrypted, protection_key)
            .map_err(|_| E2eError::StateProtectionFailed)?;
        Ok(Self {
            account: Account::from_pickle(pickle),
        })
    }

    fn verify_local_bundle(&self, bundle: &ContactBundle) -> Result<(), E2eError> {
        bundle.verify()?;
        if bundle.identity == self.identity() {
            Ok(())
        } else {
            Err(E2eError::LocalBundleMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationRole {
    Initiator,
    Responder,
}

pub struct ConversationSession {
    role: ConversationRole,
    local: ContactIdentity,
    remote: ContactIdentity,
    inbound_route_secret: [u8; ROUTE_SECRET_BYTES],
    outbound_route_secret: [u8; ROUTE_SECRET_BYTES],
    session: Session,
}

impl fmt::Debug for ConversationSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationSession")
            .field("role", &self.role)
            .field("local", &self.local.relay_id())
            .field("remote", &self.remote.relay_id())
            .field("route_secrets", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Drop for ConversationSession {
    fn drop(&mut self) {
        self.inbound_route_secret.zeroize();
        self.outbound_route_secret.zeroize();
    }
}

impl ConversationSession {
    const fn new(
        role: ConversationRole,
        local_bundle: &ContactBundle,
        remote_bundle: &ContactBundle,
        session: Session,
    ) -> Self {
        Self {
            role,
            local: local_bundle.identity,
            remote: remote_bundle.identity,
            inbound_route_secret: local_bundle.inbound_route_secret,
            outbound_route_secret: remote_bundle.inbound_route_secret,
            session,
        }
    }

    #[must_use]
    pub const fn remote_identity(&self) -> ContactIdentity {
        self.remote
    }

    /// Recognizes this conversation's incoming route before touching ratchet
    /// state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid envelope.
    pub fn recognizes(&self, envelope: &Envelope) -> Result<bool, E2eError> {
        envelope.validate()?;
        let expected = destination_hint(&self.inbound_route_secret, envelope);
        Ok(bool::from(expected.ct_eq(&envelope.destination_hint)))
    }

    /// Decrypts a later message in this ratchet. The advanced ratchet and
    /// plaintext-at-rest record must be committed atomically before a receipt.
    ///
    /// # Errors
    ///
    /// Rejects a wrong route, tampered sealed header, ratchet failure, identity
    /// substitution, malformed content, or mismatched message ID.
    pub fn decrypt_text(&mut self, envelope: &Envelope) -> Result<ReceivedText, E2eError> {
        let received = self.decrypt_payload(envelope)?;
        let ReceivedContent::Text(message) = received.content else {
            return Err(E2eError::InvalidPayload);
        };
        Ok(ReceivedText {
            message,
            sequence: received.sequence,
        })
    }

    /// Decrypts either a user text or an end-to-end delivery receipt while
    /// advancing the same authenticated conversation ratchet.
    ///
    /// # Errors
    ///
    /// Rejects wrong routes, malformed frames, failed ratchets, substituted
    /// identities, and invalid signed application payloads.
    pub fn decrypt_payload(&mut self, envelope: &Envelope) -> Result<ReceivedPayload, E2eError> {
        if !self.recognizes(envelope)? {
            return Err(E2eError::NotDestination);
        }
        let frame = open_olm_frame(&self.inbound_route_secret, envelope)?;
        let mut plaintext = self
            .session
            .decrypt(&frame)
            .map_err(|_| E2eError::DecryptionFailed)?;
        let result = verify_signed_payload(&plaintext, self.remote, self.local, envelope.id);
        plaintext.zeroize();
        result
    }

    #[must_use]
    pub fn encrypted_ratchet_pickle(&self, protection_key: &[u8; 32]) -> String {
        self.session.pickle().encrypt(protection_key)
    }

    /// Restores an encrypted ratchet and rebinds it to the two verified contact
    /// bundles held in the encrypted contact store.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bundles, incorrect state key, tampering, or
    /// a ratchet whose initiator keys do not match the declared role.
    pub fn restore(
        role: ConversationRole,
        local_bundle: &ContactBundle,
        remote_bundle: &ContactBundle,
        encrypted_ratchet: &str,
        protection_key: &[u8; 32],
    ) -> Result<Self, E2eError> {
        local_bundle.verify()?;
        remote_bundle.verify()?;
        let pickle = SessionPickle::from_encrypted(encrypted_ratchet, protection_key)
            .map_err(|_| E2eError::StateProtectionFailed)?;
        let session = Session::from_pickle(pickle);
        let keys = session.session_keys();
        let expected_initiator = match role {
            ConversationRole::Initiator => local_bundle.identity.curve_identity_key,
            ConversationRole::Responder => remote_bundle.identity.curve_identity_key,
        };
        let expected_prekey = match role {
            ConversationRole::Initiator => remote_bundle.one_time_key,
            ConversationRole::Responder => local_bundle.one_time_key,
        };
        if keys.identity_key.to_bytes() != expected_initiator
            || keys.one_time_key.to_bytes() != expected_prekey
        {
            return Err(E2eError::IdentityMismatch);
        }
        Ok(Self::new(role, local_bundle, remote_bundle, session))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedText {
    pub message: DirectText,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceivedContent {
    Text(DirectText),
    DeliveryReceipt(DeliveryReceipt),
    AttachmentManifest(RecipientAttachmentManifest),
    AttachmentReceipt(RecipientAttachmentReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedPayload {
    pub content: ReceivedContent,
    pub sequence: u64,
}

const fn session_config() -> SessionConfig {
    SessionConfig::version_2()
}

fn encode_signed_payload(
    account: &Account,
    sender: ContactIdentity,
    recipient: ContactIdentity,
    envelope_id: MessageId,
    sequence: u64,
    payload_type: u8,
    content: &[u8],
) -> Result<Vec<u8>, E2eError> {
    if !matches!(
        payload_type,
        SIGNED_TEXT_TYPE
            | SIGNED_RECEIPT_TYPE
            | SIGNED_ATTACHMENT_MANIFEST_TYPE
            | SIGNED_ATTACHMENT_RECEIPT_TYPE
    ) || content.is_empty()
        || content.len() > MAX_SIGNED_CONTENT_BYTES
    {
        return Err(E2eError::InvalidPayload);
    }
    let content_len = u16::try_from(content.len()).map_err(|_| E2eError::InvalidPayload)?;
    let mut unsigned = Vec::with_capacity(SIGNED_HEADER_LEN + content.len());
    unsigned.extend_from_slice(&SIGNED_MAGIC);
    unsigned.push(SIGNED_VERSION);
    unsigned.push(payload_type);
    unsigned.extend_from_slice(&[0, 0]);
    unsigned.extend_from_slice(&sender.signing_key);
    unsigned.extend_from_slice(&recipient.signing_key);
    unsigned.extend_from_slice(&envelope_id.0);
    unsigned.extend_from_slice(&sequence.to_be_bytes());
    unsigned.extend_from_slice(&content_len.to_be_bytes());
    debug_assert_eq!(unsigned.len(), SIGNED_HEADER_LEN);
    unsigned.extend_from_slice(content);
    let input = signature_input(SIGNED_PAYLOAD_DOMAIN, &unsigned);
    let signature = account.sign(input);
    unsigned.extend_from_slice(&signature.to_bytes());
    Ok(unsigned)
}

fn verify_signed_payload(
    encoded: &[u8],
    expected_sender: ContactIdentity,
    expected_recipient: ContactIdentity,
    expected_id: MessageId,
) -> Result<ReceivedPayload, E2eError> {
    let minimum = SIGNED_HEADER_LEN
        .checked_add(SIGNATURE_BYTES)
        .ok_or(E2eError::InvalidPayload)?;
    if encoded.len() < minimum
        || encoded[..4] != SIGNED_MAGIC
        || encoded[4] != SIGNED_VERSION
        || !matches!(
            encoded[5],
            SIGNED_TEXT_TYPE
                | SIGNED_RECEIPT_TYPE
                | SIGNED_ATTACHMENT_MANIFEST_TYPE
                | SIGNED_ATTACHMENT_RECEIPT_TYPE
        )
        || encoded[6..8] != [0, 0]
    {
        return Err(E2eError::InvalidPayload);
    }
    let sender = read_array(encoded, 8)?;
    let recipient = read_array(encoded, 40)?;
    let id = MessageId(read_array(encoded, 72)?);
    let sequence = u64::from_be_bytes(read_array(encoded, 88)?);
    let content_len = usize::from(u16::from_be_bytes(read_array(encoded, 96)?));
    if sender != expected_sender.signing_key
        || recipient != expected_recipient.signing_key
        || id != expected_id
        || sequence == 0
        || content_len == 0
        || content_len > MAX_SIGNED_CONTENT_BYTES
    {
        return Err(E2eError::IdentityMismatch);
    }
    let signature_offset = SIGNED_HEADER_LEN
        .checked_add(content_len)
        .ok_or(E2eError::InvalidPayload)?;
    let expected_len = signature_offset
        .checked_add(SIGNATURE_BYTES)
        .ok_or(E2eError::InvalidPayload)?;
    if encoded.len() != expected_len {
        return Err(E2eError::InvalidPayload);
    }
    let public_key = Ed25519PublicKey::from_slice(&expected_sender.signing_key)
        .map_err(|_| E2eError::InvalidPayload)?;
    let signature = Ed25519Signature::from_slice(&encoded[signature_offset..])
        .map_err(|_| E2eError::InvalidPayload)?;
    let input = signature_input(SIGNED_PAYLOAD_DOMAIN, &encoded[..signature_offset]);
    public_key
        .verify(&input, &signature)
        .map_err(|_| E2eError::AuthenticationFailed)?;
    let content = &encoded[SIGNED_HEADER_LEN..signature_offset];
    let content = match encoded[5] {
        SIGNED_TEXT_TYPE => {
            let message = DirectText::decode(content).map_err(|_| E2eError::InvalidPayload)?;
            if message.id != expected_id {
                return Err(E2eError::IdentityMismatch);
            }
            ReceivedContent::Text(message)
        }
        SIGNED_RECEIPT_TYPE => ReceivedContent::DeliveryReceipt(
            DeliveryReceipt::decode(content).map_err(|_| E2eError::InvalidPayload)?,
        ),
        SIGNED_ATTACHMENT_MANIFEST_TYPE => {
            let manifest = RecipientAttachmentManifest::decode(content)
                .map_err(|_| E2eError::InvalidPayload)?;
            if manifest.object_id != expected_id {
                return Err(E2eError::IdentityMismatch);
            }
            ReceivedContent::AttachmentManifest(manifest)
        }
        SIGNED_ATTACHMENT_RECEIPT_TYPE => ReceivedContent::AttachmentReceipt(
            RecipientAttachmentReceipt::decode(content).map_err(|_| E2eError::InvalidPayload)?,
        ),
        _ => return Err(E2eError::InvalidPayload),
    };
    Ok(ReceivedPayload { content, sequence })
}

fn encode_olm_frame(message: &OlmMessage) -> Result<Vec<u8>, E2eError> {
    let (message_type, ciphertext) = message.to_parts();
    let message_type = u8::try_from(message_type).map_err(|_| E2eError::InvalidFrame)?;
    let ciphertext_len = u32::try_from(ciphertext.len()).map_err(|_| E2eError::InvalidFrame)?;
    let mut frame = Vec::with_capacity(OLM_FRAME_HEADER_LEN + ciphertext.len());
    frame.extend_from_slice(&OLM_FRAME_MAGIC);
    frame.push(OLM_FRAME_VERSION);
    frame.push(message_type);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&ciphertext_len.to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

fn decode_olm_frame(frame: &[u8]) -> Result<OlmMessage, E2eError> {
    if frame.len() < OLM_FRAME_HEADER_LEN
        || frame[..4] != OLM_FRAME_MAGIC
        || frame[4] != OLM_FRAME_VERSION
        || frame[6..8] != [0, 0]
    {
        return Err(E2eError::InvalidFrame);
    }
    let declared = u32::from_be_bytes(read_array(frame, 8)?) as usize;
    let expected = OLM_FRAME_HEADER_LEN
        .checked_add(declared)
        .ok_or(E2eError::InvalidFrame)?;
    if declared == 0 || frame.len() != expected {
        return Err(E2eError::InvalidFrame);
    }
    OlmMessage::from_parts(usize::from(frame[5]), &frame[OLM_FRAME_HEADER_LEN..])
        .map_err(|_| E2eError::InvalidFrame)
}

fn seal_olm_frame(
    route_secret: &[u8; ROUTE_SECRET_BYTES],
    envelope: &Envelope,
    frame: &[u8],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, E2eError> {
    let required = SEALED_LENGTH_PREFIX_BYTES
        .checked_add(frame.len())
        .ok_or(E2eError::InvalidFrame)?;
    let padded_len = SEALED_BUCKETS
        .into_iter()
        .find(|bucket| *bucket >= required)
        .ok_or(E2eError::InvalidFrame)?;
    let frame_len = u32::try_from(frame.len()).map_err(|_| E2eError::InvalidFrame)?;
    let mut padded = vec![0_u8; padded_len];
    padded[..SEALED_LENGTH_PREFIX_BYTES].copy_from_slice(&frame_len.to_be_bytes());
    padded[SEALED_LENGTH_PREFIX_BYTES..required].copy_from_slice(frame);

    let mut key = seal_key(route_secret, envelope.id);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let associated = immutable_routing_data(envelope);
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &padded,
                aad: &associated,
            },
        )
        .map_err(|_| E2eError::EncryptionFailed)?;
    key.zeroize();
    padded.zeroize();

    let mut sealed = Vec::with_capacity(SEALED_HEADER_LEN + encrypted.len());
    sealed.extend_from_slice(&SEALED_MAGIC);
    sealed.push(SEALED_VERSION);
    sealed.extend_from_slice(&[0, 0, 0]);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&encrypted);
    Ok(sealed)
}

fn open_olm_frame(
    route_secret: &[u8; ROUTE_SECRET_BYTES],
    envelope: &Envelope,
) -> Result<OlmMessage, E2eError> {
    envelope.validate()?;
    let sealed = &envelope.ciphertext;
    if sealed.len() < SEALED_HEADER_LEN + AEAD_TAG_BYTES
        || sealed[..4] != SEALED_MAGIC
        || sealed[4] != SEALED_VERSION
        || sealed[5..8] != [0, 0, 0]
    {
        return Err(E2eError::InvalidFrame);
    }
    let nonce: [u8; NONCE_BYTES] = read_array(sealed, 8)?;
    let mut key = seal_key(route_secret, envelope.id);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let associated = immutable_routing_data(envelope);
    let mut padded = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sealed[SEALED_HEADER_LEN..],
                aad: &associated,
            },
        )
        .map_err(|_| E2eError::AuthenticationFailed)?;
    key.zeroize();
    if !SEALED_BUCKETS.contains(&padded.len()) || padded.len() < SEALED_LENGTH_PREFIX_BYTES {
        padded.zeroize();
        return Err(E2eError::InvalidFrame);
    }
    let frame_len = u32::from_be_bytes(read_array(&padded, 0)?) as usize;
    let frame_end = SEALED_LENGTH_PREFIX_BYTES
        .checked_add(frame_len)
        .ok_or(E2eError::InvalidFrame)?;
    if frame_len == 0 || frame_end > padded.len() {
        padded.zeroize();
        return Err(E2eError::InvalidFrame);
    }
    let result = decode_olm_frame(&padded[SEALED_LENGTH_PREFIX_BYTES..frame_end]);
    padded.zeroize();
    result
}

fn destination_hint(route_secret: &[u8; ROUTE_SECRET_BYTES], envelope: &Envelope) -> [u8; 16] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(route_secret).expect("HMAC accepts fixed 32-byte keys");
    mac.update(DESTINATION_DOMAIN);
    mac.update(&immutable_routing_data_without_hint(envelope));
    let digest = mac.finalize().into_bytes();
    let mut hint = [0_u8; 16];
    hint.copy_from_slice(&digest[..16]);
    hint
}

fn seal_key(route_secret: &[u8; ROUTE_SECRET_BYTES], id: MessageId) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(route_secret).expect("HMAC accepts fixed 32-byte keys");
    mac.update(SEAL_KEY_DOMAIN);
    mac.update(&id.0);
    mac.finalize().into_bytes().into()
}

fn immutable_routing_data_without_hint(envelope: &Envelope) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 1 + 16 + 8 + 1 + 1);
    data.extend_from_slice(b"RHN1");
    data.push(1);
    data.extend_from_slice(&envelope.id.0);
    data.extend_from_slice(&envelope.lifetime_ms.to_be_bytes());
    data.push(envelope.hop_limit);
    data.push(envelope.priority as u8);
    data
}

fn immutable_routing_data(envelope: &Envelope) -> Vec<u8> {
    let mut data = immutable_routing_data_without_hint(envelope);
    data.extend_from_slice(&envelope.destination_hint);
    data
}

fn signature_input(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + message.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(message);
    input
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], E2eError> {
    input
        .get(offset..offset + N)
        .ok_or(E2eError::InvalidFrame)?
        .try_into()
        .map_err(|_| E2eError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campus_text_and_receipt_policies_use_the_efficiency_knee() {
        assert_eq!(DeliveryPolicy::delayed_text().copy_budget, 24);
        assert_eq!(DeliveryPolicy::delivery_receipt().copy_budget, 24);
        assert_eq!(DeliveryPolicy::attachment_manifest().copy_budget, 2);
        assert_eq!(
            DeliveryPolicy::attachment_manifest().priority,
            Priority::Manifest
        );
    }
    use relay_core::{CoreCommand, CoreEvent, Node};
    use relay_router::{ForwardPlan, PeerSnapshot};

    fn policy() -> DeliveryPolicy {
        DeliveryPolicy {
            lifetime_ms: 60_000,
            hop_limit: 8,
            copy_budget: 4,
            priority: Priority::DirectText,
        }
    }

    fn transfer(nodes: &mut [Node], from: usize, to: usize, plan: ForwardPlan) {
        let mut outbound = nodes[from]
            .envelope(plan.message_id)
            .cloned()
            .expect("source has envelope");
        outbound.copy_budget = plan.transferred_copies;
        outbound.hops_taken = outbound.hops_taken.saturating_add(1);
        let encoded = outbound.encode().expect("encode on physical hop");
        let decoded = Envelope::decode(&encoded).expect("decode on physical hop");
        assert!(matches!(
            nodes[from]
                .apply(CoreCommand::CommitForward(plan))
                .as_slice(),
            [CoreEvent::ForwardCommitted(_)]
        ));
        assert!(matches!(
            nodes[to].apply(CoreCommand::Receive(decoded)).as_slice(),
            [CoreEvent::EnvelopeStored(_)]
        ));
    }

    fn forward_once(nodes: &mut [Node], from: usize, to: usize, is_destination: bool) {
        let peer = PeerSnapshot {
            peer_token: u64::try_from(to).expect("small test index"),
            is_destination,
            already_has_message: false,
            accepts_courier_data: true,
            encounter_score: 500,
            queue_pressure: 0,
        };
        let plan = nodes[from]
            .apply(CoreCommand::PeerEncounter(peer))
            .into_iter()
            .find_map(|event| match event {
                CoreEvent::ForwardPlanned(plan) => Some(plan),
                _ => None,
            })
            .expect("routing produces a bounded transfer");
        transfer(nodes, from, to, plan);
    }

    fn assert_ciphertext_hides(envelope: &Envelope, private_values: &[&[u8]]) {
        for private_value in private_values {
            assert!(
                !envelope
                    .ciphertext
                    .windows(private_value.len())
                    .any(|part| part == *private_value)
            );
        }
    }

    #[test]
    fn contact_bundle_is_exact_and_tamper_evident() {
        let mut account = E2eAccount::new();
        let bundle = account.issue_contact_bundle().expect("contact bundle");
        let encoded = bundle.encode();
        let decoded = ContactBundle::decode(&encoded).expect("verified decode");
        assert_eq!(decoded.identity(), bundle.identity());

        let mut changed = encoded;
        changed[104] ^= 0x80;
        assert_eq!(
            ContactBundle::decode(&changed),
            Err(E2eError::InvalidContactBundle)
        );
        assert_eq!(
            ContactBundle::decode(&encoded[..encoded.len() - 1]),
            Err(E2eError::InvalidContactBundle)
        );
    }

    #[test]
    fn maximum_reply_fits_the_fixed_node_record_limit_and_survives_a_courier() {
        let mut alice = E2eAccount::new();
        let mut carol = E2eAccount::new();
        let alice_bundle = alice.issue_contact_bundle().expect("Alice bundle");
        let carol_bundle = carol.issue_contact_bundle().expect("Carol bundle");
        let mut alice_session = alice
            .start_conversation(&alice_bundle, &carol_bundle)
            .expect("Alice session");
        let message = DirectText {
            id: MessageId([0x31; 16]),
            text: "m".repeat(relay_message::MAX_TEXT_BYTES),
            reply: Some(relay_message::ReplyReference {
                message_id: MessageId([0x22; 16]),
                preview: "p".repeat(relay_message::MAX_REPLY_PREVIEW_BYTES),
            }),
        };

        let envelope = alice
            .encrypt_message(&mut alice_session, 1, &message, policy())
            .expect("maximum reply envelope");
        assert_eq!(envelope.encoded_len(), MAX_DIRECT_TEXT_ENVELOPE_BYTES);

        let (_session, received) = carol
            .accept_conversation(&carol_bundle, &alice_bundle, &envelope)
            .expect("recipient decrypts maximum reply");
        assert_eq!(received.message, message);
    }

    #[test]
    fn opaque_text_crosses_a_courier_and_only_recipient_decrypts() {
        let mut alice = E2eAccount::new();
        let mut courier = E2eAccount::new();
        let mut carol = E2eAccount::new();
        let alice_bundle = alice.issue_contact_bundle().expect("Alice bundle");
        let courier_bundle = courier.issue_contact_bundle().expect("courier bundle");
        let carol_bundle = carol.issue_contact_bundle().expect("Carol bundle");

        let mut alice_session = alice
            .start_conversation(&alice_bundle, &carol_bundle)
            .expect("Alice starts asynchronous session");
        let id = MessageId([0xA5; 16]);
        let plaintext = "meet me at the library after class";
        let envelope = alice
            .encrypt_text(&mut alice_session, id, 1, plaintext.to_owned(), policy())
            .expect("recipient-only envelope");

        assert!(carol_bundle.recognizes(&envelope).expect("valid route"));
        assert!(!courier_bundle.recognizes(&envelope).expect("valid route"));
        let mut private_route_probe = envelope.clone();
        private_route_probe.ciphertext = vec![0];
        assert!(
            carol_bundle
                .recognizes(&private_route_probe)
                .expect("recipient recognizes header-only route probe")
        );
        assert!(
            !courier_bundle
                .recognizes(&private_route_probe)
                .expect("courier cannot recognize header-only route probe")
        );
        assert_ciphertext_hides(
            &envelope,
            &[
                plaintext.as_bytes(),
                &alice.identity().signing_key,
                &carol.identity().signing_key,
            ],
        );

        // Even a malicious courier rewriting only the outer address cannot use
        // its unrelated one-time key to create Carol's recipient session.
        let mut forged_for_courier = envelope.clone();
        forged_for_courier.destination_hint =
            destination_hint(&courier_bundle.inbound_route_secret, &forged_for_courier);
        assert!(matches!(
            courier.accept_conversation(&courier_bundle, &alice_bundle, &forged_for_courier),
            Err(E2eError::AuthenticationFailed)
        ));

        let mut nodes = vec![Node::default(), Node::default(), Node::default()];
        assert!(matches!(
            nodes[0]
                .apply(CoreCommand::AcceptLocal(envelope))
                .as_slice(),
            [CoreEvent::EnvelopeStored(_)]
        ));
        forward_once(&mut nodes, 0, 1, false);
        forward_once(&mut nodes, 1, 2, true);

        let delivered = nodes[2]
            .envelope(id)
            .expect("Carol receives opaque envelope");
        let (mut carol_session, received) = carol
            .accept_conversation(&carol_bundle, &alice_bundle, delivered)
            .expect("Carol alone decrypts");
        assert_eq!(received.sequence, 1);
        assert_eq!(received.message.text, plaintext);

        let receipt_envelope_id = MessageId([0xB4; 16]);
        assert!(matches!(
            carol.encrypt_receipt(&mut carol_session, receipt_envelope_id, 1, id, policy()),
            Err(E2eError::InvalidPolicy)
        ));
        let receipt = carol
            .encrypt_receipt(
                &mut carol_session,
                receipt_envelope_id,
                1,
                id,
                DeliveryPolicy::delivery_receipt(),
            )
            .expect("recipient creates an authenticated mesh receipt");
        assert!(alice_bundle.recognizes(&receipt).expect("Alice route"));
        assert!(!courier_bundle.recognizes(&receipt).expect("courier route"));
        let received_receipt = alice_session
            .decrypt_payload(&receipt)
            .expect("Alice authenticates receipt");
        assert_eq!(received_receipt.sequence, 1);
        assert_eq!(
            received_receipt.content,
            ReceivedContent::DeliveryReceipt(DeliveryReceipt { id })
        );

        let reply_id = MessageId([0xC3; 16]);
        let reply = carol
            .encrypt_text(
                &mut carol_session,
                reply_id,
                2,
                "got it".to_owned(),
                policy(),
            )
            .expect("ratcheted reply");
        assert!(alice_bundle.recognizes(&reply).expect("Alice route"));
        let received_reply = alice_session
            .decrypt_text(&reply)
            .expect("Alice decrypts reply");
        assert_eq!(received_reply.message.text, "got it");
    }

    #[test]
    fn opaque_attachment_manifest_and_recipient_receipt_cross_a_courier() {
        let mut alice = E2eAccount::new();
        let mut courier = E2eAccount::new();
        let mut carol = E2eAccount::new();
        let alice_bundle = alice.issue_contact_bundle().expect("Alice bundle");
        let courier_bundle = courier.issue_contact_bundle().expect("courier bundle");
        let carol_bundle = carol.issue_contact_bundle().expect("Carol bundle");
        let mut alice_session = alice
            .start_conversation(&alice_bundle, &carol_bundle)
            .expect("Alice attachment session");
        let object_id = MessageId([0xD1; 16]);
        let manifest = RecipientAttachmentManifest {
            object_id,
            kind: relay_message::attachment::AttachmentKind::File,
            courier_plan_sha256: [0x22; 32],
            content_key: [0x33; 32],
            plaintext_bytes: 30 * 1024 * 1024,
            plaintext_sha256: [0x44; 32],
            mime_type: "application/octet-stream".to_owned(),
            file_name: "private-report.pdf".to_owned(),
        };
        assert!(matches!(
            alice.encrypt_attachment_manifest(
                &mut alice_session,
                1,
                &manifest,
                DeliveryPolicy::delayed_text(),
            ),
            Err(E2eError::InvalidPolicy)
        ));
        let envelope = alice
            .encrypt_attachment_manifest(
                &mut alice_session,
                1,
                &manifest,
                DeliveryPolicy::attachment_manifest(),
            )
            .expect("recipient-private manifest");
        assert_eq!(envelope.id, object_id);
        assert_eq!(envelope.priority, Priority::Manifest);
        assert_eq!(envelope.copy_budget, 2);
        assert!(carol_bundle.recognizes(&envelope).expect("Carol route"));
        assert!(!courier_bundle.recognizes(&envelope).expect("courier route"));
        assert_ciphertext_hides(
            &envelope,
            &[
                manifest.file_name.as_bytes(),
                manifest.mime_type.as_bytes(),
                manifest.content_key.as_slice(),
            ],
        );

        let (mut carol_session, received) = carol
            .accept_payload_conversation(&carol_bundle, &alice_bundle, &envelope)
            .expect("manifest may establish a conversation");
        assert_eq!(received.sequence, 1);
        assert_eq!(
            received.content,
            ReceivedContent::AttachmentManifest(manifest.clone())
        );

        let receipt_record = RecipientAttachmentReceipt {
            object_id,
            courier_plan_sha256: manifest.courier_plan_sha256,
        };
        let receipt_envelope = carol
            .encrypt_attachment_receipt(
                &mut carol_session,
                MessageId([0xE2; 16]),
                1,
                receipt_record,
                DeliveryPolicy::delivery_receipt(),
            )
            .expect("recipient-authenticated attachment receipt");
        assert_eq!(receipt_envelope.priority, Priority::Control);
        assert!(
            alice_bundle
                .recognizes(&receipt_envelope)
                .expect("Alice route")
        );
        assert!(
            !courier_bundle
                .recognizes(&receipt_envelope)
                .expect("courier route")
        );
        let received_receipt = alice_session
            .decrypt_payload(&receipt_envelope)
            .expect("Alice authenticates attachment completion");
        assert_eq!(received_receipt.sequence, 1);
        assert_eq!(
            received_receipt.content,
            ReceivedContent::AttachmentReceipt(receipt_record)
        );
    }

    #[test]
    fn sealed_header_rejects_immutable_route_tampering_before_ratchet() {
        let mut alice = E2eAccount::new();
        let mut carol = E2eAccount::new();
        let alice_bundle = alice.issue_contact_bundle().expect("Alice bundle");
        let carol_bundle = carol.issue_contact_bundle().expect("Carol bundle");
        let mut alice_session = alice
            .start_conversation(&alice_bundle, &carol_bundle)
            .expect("session");
        let envelope = alice
            .encrypt_text(
                &mut alice_session,
                MessageId([9; 16]),
                1,
                "auth route".to_owned(),
                policy(),
            )
            .expect("envelope");
        let mut altered = envelope.clone();
        altered.lifetime_ms -= 1;
        assert!(
            !carol_bundle
                .recognizes(&altered)
                .expect("valid outer bounds")
        );
        assert!(matches!(
            carol.accept_conversation(&carol_bundle, &alice_bundle, &altered),
            Err(E2eError::NotDestination)
        ));

        let (_session, received) = carol
            .accept_conversation(&carol_bundle, &alice_bundle, &envelope)
            .expect("untampered envelope still works");
        assert_eq!(received.message.text, "auth route");
    }

    #[test]
    fn encrypted_account_and_ratchet_state_restore() {
        let protection_key = [0x55; 32];
        let mut alice = E2eAccount::new();
        let mut carol = E2eAccount::new();
        let alice_bundle = alice.issue_contact_bundle().expect("Alice bundle");
        let carol_bundle = carol.issue_contact_bundle().expect("Carol bundle");
        let mut alice_session = alice
            .start_conversation(&alice_bundle, &carol_bundle)
            .expect("session");
        let account_pickle = alice.encrypted_pickle(&protection_key);
        let ratchet_pickle = alice_session.encrypted_ratchet_pickle(&protection_key);
        let restored_alice =
            E2eAccount::from_encrypted_pickle(&account_pickle, &protection_key).expect("account");
        alice_session = ConversationSession::restore(
            ConversationRole::Initiator,
            &alice_bundle,
            &carol_bundle,
            &ratchet_pickle,
            &protection_key,
        )
        .expect("ratchet");
        let envelope = restored_alice
            .encrypt_text(
                &mut alice_session,
                MessageId([7; 16]),
                1,
                "survives process death".to_owned(),
                policy(),
            )
            .expect("post-restore encryption");
        let (_session, received) = carol
            .accept_conversation(&carol_bundle, &alice_bundle, &envelope)
            .expect("recipient decrypts");
        assert_eq!(received.message.text, "survives process death");
    }
}
