//! Bounded, transport-neutral secure sessions for Project Relay.
//!
//! This is a Phase 0 engineering implementation. The selected Noise library
//! has not received a formal audit, so passing these tests is not a release
//! security claim.

use std::fmt;

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use zeroize::Zeroize;

pub const NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const FAST_NOISE_PROTOCOL_NAME: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
pub const MAX_PROLOGUE_BYTES: usize = 128;
pub const MAX_HANDSHAKE_BYTES: usize = 512;
pub const MAX_TRANSPORT_PLAINTEXT_BYTES: usize = 32 * 1024;
pub const AEAD_TAG_BYTES: usize = 16;
pub const STATIC_KEY_BYTES: usize = 32;
pub const HANDSHAKE_HASH_BYTES: usize = 32;
pub const PSK_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

pub struct StaticKeypair {
    private: [u8; STATIC_KEY_BYTES],
    public: [u8; STATIC_KEY_BYTES],
}

impl Drop for StaticKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl StaticKeypair {
    #[must_use]
    pub const fn private(&self) -> &[u8; STATIC_KEY_BYTES] {
        &self.private
    }

    #[must_use]
    pub const fn public(&self) -> &[u8; STATIC_KEY_BYTES] {
        &self.public
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureError {
    InvalidConfiguration,
    InvalidState,
    UnexpectedDirection,
    EmptyInput,
    InputTooLarge,
    AuthenticationFailed,
    InvalidRemoteStatic,
}

impl fmt::Display for SecureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid secure-session configuration",
            Self::InvalidState => "secure session is not in the required state",
            Self::UnexpectedDirection => "unexpected secure-session message direction",
            Self::EmptyInput => "secure-session input is empty",
            Self::InputTooLarge => "secure-session input exceeds its hard limit",
            Self::AuthenticationFailed => "secure-session authentication failed",
            Self::InvalidRemoteStatic => "peer supplied an invalid static key",
        })
    }
}

impl std::error::Error for SecureError {}

pub type SecureResult<T> = Result<T, SecureError>;

enum SessionState {
    Handshake(Box<HandshakeState>),
    Transport(Box<TransportState>),
    Failed,
}

/// Caller-driven Noise XX state machine with strict Relay limits.
pub struct SecureSession {
    role: SessionRole,
    state: SessionState,
    expect_remote_static: bool,
    remote_static: Option<[u8; STATIC_KEY_BYTES]>,
    handshake_hash: Option<[u8; HANDSHAKE_HASH_BYTES]>,
}

impl fmt::Debug for SecureSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureSession")
            .field("role", &self.role)
            .field("established", &self.is_established())
            .field("has_remote_static", &self.remote_static.is_some())
            .field("has_handshake_hash", &self.handshake_hash.is_some())
            .finish_non_exhaustive()
    }
}

impl SecureSession {
    /// Creates one side of a bounded Noise XX handshake.
    ///
    /// # Errors
    ///
    /// Returns [`SecureError::InputTooLarge`] for an oversized prologue or
    /// [`SecureError::InvalidConfiguration`] if the pinned suite or key cannot
    /// initialize.
    pub fn new(
        role: SessionRole,
        static_private: &[u8; STATIC_KEY_BYTES],
        prologue: &[u8],
    ) -> SecureResult<Self> {
        if prologue.len() > MAX_PROLOGUE_BYTES {
            return Err(SecureError::InputTooLarge);
        }
        let parameters: NoiseParams = NOISE_PROTOCOL_NAME
            .parse()
            .map_err(|_| SecureError::InvalidConfiguration)?;
        let builder = Builder::new(parameters)
            .prologue(prologue)
            .map_err(|_| SecureError::InvalidConfiguration)?
            .local_private_key(static_private)
            .map_err(|_| SecureError::InvalidConfiguration)?;
        let handshake = match role {
            SessionRole::Initiator => builder.build_initiator(),
            SessionRole::Responder => builder.build_responder(),
        }
        .map_err(|_| SecureError::InvalidConfiguration)?;
        Ok(Self {
            role,
            state: SessionState::Handshake(Box::new(handshake)),
            expect_remote_static: true,
            remote_static: None,
            handshake_hash: None,
        })
    }

    /// Creates one side of a bounded, single-use PSK-authenticated Noise
    /// handshake for a transport upgrade authorized by an existing verified
    /// direct session.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized prologue or invalid Noise setup.
    pub fn new_psk(
        role: SessionRole,
        psk: &[u8; PSK_BYTES],
        prologue: &[u8],
    ) -> SecureResult<Self> {
        if prologue.len() > MAX_PROLOGUE_BYTES {
            return Err(SecureError::InputTooLarge);
        }
        let parameters: NoiseParams = FAST_NOISE_PROTOCOL_NAME
            .parse()
            .map_err(|_| SecureError::InvalidConfiguration)?;
        let builder = Builder::new(parameters)
            .prologue(prologue)
            .map_err(|_| SecureError::InvalidConfiguration)?
            .psk(0, psk)
            .map_err(|_| SecureError::InvalidConfiguration)?;
        let handshake = match role {
            SessionRole::Initiator => builder.build_initiator(),
            SessionRole::Responder => builder.build_responder(),
        }
        .map_err(|_| SecureError::InvalidConfiguration)?;
        Ok(Self {
            role,
            state: SessionState::Handshake(Box::new(handshake)),
            expect_remote_static: false,
            remote_static: None,
            handshake_hash: None,
        })
    }

    /// Produces message one for an initiator. A responder returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error when called outside the expected handshake turn or if
    /// the cryptographic implementation rejects message construction.
    pub fn start(&mut self) -> SecureResult<Option<Vec<u8>>> {
        if self.role == SessionRole::Responder {
            return Ok(None);
        }
        self.write_handshake_message().map(Some)
    }

    /// Accepts one complete bounded handshake message and returns the reply.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, out-of-turn, malformed, or
    /// unauthenticated input. Any input/authentication failure poisons the
    /// session so it cannot be reused.
    pub fn receive_handshake(&mut self, incoming: &[u8]) -> SecureResult<Option<Vec<u8>>> {
        if incoming.is_empty() {
            return self.fail(SecureError::EmptyInput);
        }
        if incoming.len() > MAX_HANDSHAKE_BYTES {
            return self.fail(SecureError::InputTooLarge);
        }

        let mut payload = [0_u8; MAX_HANDSHAKE_BYTES];
        let read_result = match &mut self.state {
            SessionState::Handshake(handshake) => {
                if handshake.is_my_turn() {
                    return self.fail(SecureError::UnexpectedDirection);
                }
                handshake.read_message(incoming, &mut payload)
            }
            SessionState::Transport(_) | SessionState::Failed => {
                return Err(SecureError::InvalidState);
            }
        };
        let Ok(payload_bytes) = read_result else {
            return self.fail(SecureError::AuthenticationFailed);
        };
        if payload_bytes != 0 {
            return self.fail(SecureError::InvalidConfiguration);
        }
        if self.handshake_finished()? {
            self.promote_to_transport()?;
            return Ok(None);
        }
        self.write_handshake_message().map(Some)
    }

    /// Encrypts one bounded ordered transport message.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized plaintext, a session that has not
    /// completed its handshake, or a cipher-state failure.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> SecureResult<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(SecureError::EmptyInput);
        }
        if plaintext.len() > MAX_TRANSPORT_PLAINTEXT_BYTES {
            return Err(SecureError::InputTooLarge);
        }
        let mut ciphertext = vec![0_u8; plaintext.len() + AEAD_TAG_BYTES];
        let result = match &mut self.state {
            SessionState::Transport(transport) => {
                transport.write_message(plaintext, &mut ciphertext)
            }
            SessionState::Handshake(_) | SessionState::Failed => {
                return Err(SecureError::InvalidState);
            }
        };
        let Ok(written) = result else {
            return self.fail(SecureError::AuthenticationFailed);
        };
        ciphertext.truncate(written);
        Ok(ciphertext)
    }

    /// Authenticates and decrypts one bounded ordered transport message.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/oversized ciphertext, a session that has
    /// not completed its handshake, replay, tampering, or other authentication
    /// failure. Authentication failure permanently poisons this session.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> SecureResult<Vec<u8>> {
        if ciphertext.len() < AEAD_TAG_BYTES {
            return self.fail(SecureError::EmptyInput);
        }
        if ciphertext.len() > MAX_TRANSPORT_PLAINTEXT_BYTES + AEAD_TAG_BYTES {
            return self.fail(SecureError::InputTooLarge);
        }
        let mut plaintext = vec![0_u8; ciphertext.len() - AEAD_TAG_BYTES];
        let result = match &mut self.state {
            SessionState::Transport(transport) => {
                transport.read_message(ciphertext, &mut plaintext)
            }
            SessionState::Handshake(_) | SessionState::Failed => {
                return Err(SecureError::InvalidState);
            }
        };
        let Ok(read) = result else {
            return self.fail(SecureError::AuthenticationFailed);
        };
        plaintext.truncate(read);
        Ok(plaintext)
    }

    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, SessionState::Transport(_))
    }

    #[must_use]
    pub const fn remote_static(&self) -> Option<&[u8; STATIC_KEY_BYTES]> {
        self.remote_static.as_ref()
    }

    /// Returns Noise's completed handshake hash for application channel binding.
    #[must_use]
    pub const fn handshake_hash(&self) -> Option<&[u8; HANDSHAKE_HASH_BYTES]> {
        if self.is_established() {
            self.handshake_hash.as_ref()
        } else {
            None
        }
    }

    fn write_handshake_message(&mut self) -> SecureResult<Vec<u8>> {
        let mut outgoing = vec![0_u8; MAX_HANDSHAKE_BYTES];
        let result = match &mut self.state {
            SessionState::Handshake(handshake) => {
                if !handshake.is_my_turn() {
                    return self.fail(SecureError::UnexpectedDirection);
                }
                handshake.write_message(&[], &mut outgoing)
            }
            SessionState::Transport(_) | SessionState::Failed => {
                return Err(SecureError::InvalidState);
            }
        };
        let Ok(written) = result else {
            return self.fail(SecureError::AuthenticationFailed);
        };
        outgoing.truncate(written);
        if self.handshake_finished()? {
            self.promote_to_transport()?;
        }
        Ok(outgoing)
    }

    fn handshake_finished(&self) -> SecureResult<bool> {
        match &self.state {
            SessionState::Handshake(handshake) => Ok(handshake.is_handshake_finished()),
            SessionState::Transport(_) | SessionState::Failed => Err(SecureError::InvalidState),
        }
    }

    fn promote_to_transport(&mut self) -> SecureResult<()> {
        let previous = std::mem::replace(&mut self.state, SessionState::Failed);
        let SessionState::Handshake(handshake) = previous else {
            return Err(SecureError::InvalidState);
        };
        let remote_static = match handshake.get_remote_static() {
            Some(remote) => Some(
                remote
                    .try_into()
                    .map_err(|_| SecureError::InvalidRemoteStatic)?,
            ),
            None if !self.expect_remote_static => None,
            None => return Err(SecureError::InvalidRemoteStatic),
        };
        let handshake_hash: [u8; HANDSHAKE_HASH_BYTES] = handshake
            .get_handshake_hash()
            .try_into()
            .map_err(|_| SecureError::InvalidConfiguration)?;
        let transport = handshake
            .into_transport_mode()
            .map_err(|_| SecureError::AuthenticationFailed)?;
        self.remote_static = remote_static;
        self.handshake_hash = Some(handshake_hash);
        self.state = SessionState::Transport(Box::new(transport));
        Ok(())
    }

    fn fail<T>(&mut self, error: SecureError) -> SecureResult<T> {
        self.state = SessionState::Failed;
        Err(error)
    }
}

/// Generates a fresh X25519 static keypair using Snow's configured resolver.
///
/// # Errors
///
/// Returns [`SecureError::InvalidConfiguration`] if the selected provider
/// cannot obtain randomness or returns an unexpected key size.
pub fn generate_static_keypair() -> SecureResult<StaticKeypair> {
    let parameters: NoiseParams = NOISE_PROTOCOL_NAME
        .parse()
        .map_err(|_| SecureError::InvalidConfiguration)?;
    let generated = Builder::new(parameters)
        .generate_keypair()
        .map_err(|_| SecureError::InvalidConfiguration)?;
    let private = generated
        .private
        .as_slice()
        .try_into()
        .map_err(|_| SecureError::InvalidConfiguration)?;
    let public = generated
        .public
        .as_slice()
        .try_into()
        .map_err(|_| SecureError::InvalidConfiguration)?;
    Ok(StaticKeypair { private, public })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish(prologue: &[u8]) -> (SecureSession, SecureSession, StaticKeypair, StaticKeypair) {
        let initiator_keys = generate_static_keypair().expect("initiator key generation");
        let responder_keys = generate_static_keypair().expect("responder key generation");
        let mut initiator =
            SecureSession::new(SessionRole::Initiator, initiator_keys.private(), prologue)
                .expect("initiator");
        let mut responder =
            SecureSession::new(SessionRole::Responder, responder_keys.private(), prologue)
                .expect("responder");

        let message_1 = initiator.start().expect("start").expect("message one");
        let message_2 = responder
            .receive_handshake(&message_1)
            .expect("read one")
            .expect("message two");
        let message_3 = initiator
            .receive_handshake(&message_2)
            .expect("read two")
            .expect("message three");
        assert!(initiator.is_established());
        assert!(!responder.is_established());
        assert_eq!(
            responder.receive_handshake(&message_3).expect("read three"),
            None
        );
        assert!(responder.is_established());
        (initiator, responder, initiator_keys, responder_keys)
    }

    #[test]
    fn xx_establishes_and_exposes_the_expected_remote_static_keys() {
        let (initiator, responder, initiator_keys, responder_keys) =
            establish(b"Relay/direct/v1/encounter-a/encounter-b");
        assert_eq!(initiator.remote_static(), Some(responder_keys.public()));
        assert_eq!(responder.remote_static(), Some(initiator_keys.public()));
        assert_eq!(initiator.handshake_hash(), responder.handshake_hash());
        assert!(initiator.handshake_hash().is_some());
    }

    #[test]
    fn transport_encrypts_both_directions() {
        let (mut initiator, mut responder, _, _) = establish(b"Relay/direct/v1/test");
        let first_plaintext = b"bounded offline message";
        let first_ciphertext = initiator.encrypt(first_plaintext).expect("encrypt");
        assert!(
            !first_ciphertext
                .windows(first_plaintext.len())
                .any(|part| part == first_plaintext)
        );
        assert_eq!(
            responder.decrypt(&first_ciphertext).expect("decrypt"),
            first_plaintext
        );

        let reply = b"authenticated reply";
        let reply_ciphertext = responder.encrypt(reply).expect("encrypt reply");
        assert_eq!(
            initiator.decrypt(&reply_ciphertext).expect("decrypt reply"),
            reply
        );
    }

    #[test]
    fn tampering_fails_closed() {
        let (mut initiator, mut responder, _, _) = establish(b"Relay/direct/v1/test");
        let mut ciphertext = initiator.encrypt(b"do not alter").expect("encrypt");
        ciphertext[0] ^= 0x80;
        assert_eq!(
            responder.decrypt(&ciphertext),
            Err(SecureError::AuthenticationFailed)
        );
        assert_eq!(
            responder.decrypt(&ciphertext),
            Err(SecureError::InvalidState)
        );
    }

    #[test]
    fn replayed_ciphertext_is_rejected() {
        let (mut initiator, mut responder, _, _) = establish(b"Relay/direct/v1/test");
        let ciphertext = initiator.encrypt(b"once only").expect("encrypt");
        assert_eq!(
            responder.decrypt(&ciphertext).expect("first read"),
            b"once only"
        );
        assert_eq!(
            responder.decrypt(&ciphertext),
            Err(SecureError::AuthenticationFailed)
        );
    }

    #[test]
    fn different_prologues_cannot_finish_the_handshake() {
        let initiator_keys = generate_static_keypair().expect("initiator keys");
        let responder_keys = generate_static_keypair().expect("responder keys");
        let mut initiator = SecureSession::new(
            SessionRole::Initiator,
            initiator_keys.private(),
            b"Relay/direct/v1/a/b",
        )
        .expect("initiator");
        let mut responder = SecureSession::new(
            SessionRole::Responder,
            responder_keys.private(),
            b"Relay/direct/v1/x/y",
        )
        .expect("responder");
        let message_1 = initiator.start().expect("start").expect("message one");
        let message_2 = responder
            .receive_handshake(&message_1)
            .expect("read one")
            .expect("message two");
        assert_eq!(
            initiator.receive_handshake(&message_2),
            Err(SecureError::AuthenticationFailed)
        );
    }

    #[test]
    fn bounds_are_enforced_before_noise_processing() {
        let keys = generate_static_keypair().expect("keys");
        assert_eq!(
            SecureSession::new(
                SessionRole::Initiator,
                keys.private(),
                &[0_u8; MAX_PROLOGUE_BYTES + 1],
            )
            .expect_err("oversized prologue"),
            SecureError::InputTooLarge
        );
        let mut responder = SecureSession::new(
            SessionRole::Responder,
            keys.private(),
            b"Relay/direct/v1/test",
        )
        .expect("responder");
        assert_eq!(
            responder.receive_handshake(&vec![0_u8; MAX_HANDSHAKE_BYTES + 1]),
            Err(SecureError::InputTooLarge)
        );
    }

    #[test]
    fn psk_upgrade_encrypts_records_and_rejects_the_wrong_ticket() {
        let prologue = b"Relay/upgrade/v1/offer/tokens";
        let mut initiator =
            SecureSession::new_psk(SessionRole::Initiator, &[7; PSK_BYTES], prologue)
                .expect("initiator");
        let mut responder =
            SecureSession::new_psk(SessionRole::Responder, &[7; PSK_BYTES], prologue)
                .expect("responder");
        let first = initiator.start().expect("start").expect("message one");
        let second = responder
            .receive_handshake(&first)
            .expect("receive one")
            .expect("message two");
        assert!(responder.is_established());
        assert_eq!(
            initiator.receive_handshake(&second).expect("receive two"),
            None
        );
        assert!(initiator.is_established());
        assert_eq!(initiator.remote_static(), None);
        assert_eq!(initiator.handshake_hash(), responder.handshake_hash());
        let ciphertext = initiator
            .encrypt(b"fast encrypted record")
            .expect("encrypt");
        assert_eq!(
            responder.decrypt(&ciphertext).expect("decrypt"),
            b"fast encrypted record"
        );

        let mut wrong = SecureSession::new_psk(SessionRole::Responder, &[8; PSK_BYTES], prologue)
            .expect("wrong responder");
        assert_eq!(
            wrong.receive_handshake(&first),
            Err(SecureError::AuthenticationFailed)
        );
    }
}
