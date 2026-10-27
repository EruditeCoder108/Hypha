//! Bounded, deterministic relay-envelope encoding.
//!
//! This is an intentionally small Phase 0 format. Cryptographic payload
//! construction belongs above this crate; parsers here treat it as opaque.

pub mod attachment;

use core::fmt;

pub const MAGIC: [u8; 4] = *b"RLY1";
pub const WIRE_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 64;
pub const MAX_CIPHERTEXT_LEN: usize = 64 * 1024;
pub const MAX_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_COPY_BUDGET: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct MessageId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Priority {
    Control = 0,
    Safety = 1,
    DirectText = 2,
    RoomHistory = 3,
    Manifest = 4,
    Bulk = 5,
}

impl TryFrom<u8> for Priority {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Safety),
            2 => Ok(Self::DirectText),
            3 => Ok(Self::RoomHistory),
            4 => Ok(Self::Manifest),
            5 => Ok(Self::Bulk),
            other => Err(DecodeError::UnknownPriority(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub id: MessageId,
    pub destination_hint: [u8; 16],
    pub lifetime_ms: u64,
    pub age_ms: u64,
    pub hop_limit: u8,
    pub hops_taken: u8,
    pub copy_budget: u16,
    pub priority: Priority,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Checks all resource and routing bounds before storage or encoding.
    ///
    /// # Errors
    ///
    /// Returns the first violated envelope invariant.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.lifetime_ms == 0 || self.lifetime_ms > MAX_LIFETIME_MS {
            return Err(ValidationError::InvalidLifetime(self.lifetime_ms));
        }
        if self.age_ms > self.lifetime_ms {
            return Err(ValidationError::AlreadyExpired);
        }
        if self.hop_limit == 0 || self.hops_taken > self.hop_limit {
            return Err(ValidationError::InvalidHopState {
                taken: self.hops_taken,
                limit: self.hop_limit,
            });
        }
        if self.copy_budget == 0 || self.copy_budget > MAX_COPY_BUDGET {
            return Err(ValidationError::InvalidCopyBudget(self.copy_budget));
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(ValidationError::InvalidCiphertextLength(
                self.ciphertext.len(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.age_ms >= self.lifetime_ms
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.ciphertext.len()
    }

    /// Encodes the envelope into the canonical Phase 0 binary layout.
    ///
    /// # Errors
    ///
    /// Returns an invariant error before allocating output for invalid input.
    pub fn encode(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate()?;
        let ciphertext_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| ValidationError::InvalidCiphertextLength(self.ciphertext.len()))?;
        let mut output = Vec::with_capacity(self.encoded_len());
        output.extend_from_slice(&MAGIC);
        output.push(WIRE_VERSION);
        output.push(self.priority as u8);
        output.extend_from_slice(&[0, 0]);
        output.extend_from_slice(&self.id.0);
        output.extend_from_slice(&self.destination_hint);
        output.extend_from_slice(&self.lifetime_ms.to_be_bytes());
        output.extend_from_slice(&self.age_ms.to_be_bytes());
        output.push(self.hop_limit);
        output.push(self.hops_taken);
        output.extend_from_slice(&self.copy_budget.to_be_bytes());
        output.extend_from_slice(&ciphertext_len.to_be_bytes());
        output.extend_from_slice(&self.ciphertext);
        debug_assert_eq!(output.len(), self.encoded_len());
        Ok(output)
    }

    /// Decodes exactly one bounded envelope and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a structural, length, version, or envelope-invariant error.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < HEADER_LEN {
            return Err(DecodeError::Truncated);
        }
        if input[..4] != MAGIC {
            return Err(DecodeError::InvalidMagic);
        }
        if input[4] != WIRE_VERSION {
            return Err(DecodeError::UnsupportedVersion(input[4]));
        }
        let priority = Priority::try_from(input[5])?;
        if input[6..8] != [0, 0] {
            return Err(DecodeError::ReservedBitsSet);
        }

        let id = MessageId(read_array::<16>(input, 8)?);
        let destination_hint = read_array::<16>(input, 24)?;
        let lifetime_ms = u64::from_be_bytes(read_array::<8>(input, 40)?);
        let age_ms = u64::from_be_bytes(read_array::<8>(input, 48)?);
        let hop_limit = input[56];
        let hops_taken = input[57];
        let copy_budget = u16::from_be_bytes(read_array::<2>(input, 58)?);
        let ciphertext_len = u32::from_be_bytes(read_array::<4>(input, 60)?) as usize;

        if ciphertext_len == 0 || ciphertext_len > MAX_CIPHERTEXT_LEN {
            return Err(DecodeError::InvalidCiphertextLength(ciphertext_len));
        }
        let expected_len = HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(DecodeError::LengthOverflow)?;
        if input.len() != expected_len {
            return Err(DecodeError::LengthMismatch {
                declared: expected_len,
                actual: input.len(),
            });
        }

        let envelope = Self {
            id,
            destination_hint,
            lifetime_ms,
            age_ms,
            hop_limit,
            hops_taken,
            copy_budget,
            priority,
            ciphertext: input[HEADER_LEN..].to_vec(),
        };
        envelope.validate().map_err(DecodeError::InvalidEnvelope)?;
        Ok(envelope)
    }
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], DecodeError> {
    input
        .get(offset..offset + N)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .map_err(|_| DecodeError::Truncated)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidLifetime(u64),
    AlreadyExpired,
    InvalidHopState { taken: u8, limit: u8 },
    InvalidCopyBudget(u16),
    InvalidCiphertextLength(usize),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownPriority(u8),
    ReservedBitsSet,
    InvalidCiphertextLength(usize),
    LengthOverflow,
    LengthMismatch { declared: usize, actual: usize },
    InvalidEnvelope(ValidationError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_envelope() -> Envelope {
        Envelope {
            id: MessageId([7; 16]),
            destination_hint: [9; 16],
            lifetime_ms: 60_000,
            age_ms: 1_000,
            hop_limit: 8,
            hops_taken: 2,
            copy_budget: 4,
            priority: Priority::DirectText,
            ciphertext: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn round_trip_is_exact_and_deterministic() {
        let envelope = valid_envelope();
        let first = envelope.encode().expect("valid envelope");
        let second = envelope.encode().expect("valid envelope");
        assert_eq!(first, second);
        assert_eq!(first.len(), HEADER_LEN + 4);
        assert_eq!(Envelope::decode(&first), Ok(envelope));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = valid_envelope().encode().expect("valid envelope");
        bytes.push(0);
        assert!(matches!(
            Envelope::decode(&bytes),
            Err(DecodeError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn rejects_reserved_bits() {
        let mut bytes = valid_envelope().encode().expect("valid envelope");
        bytes[6] = 1;
        assert_eq!(Envelope::decode(&bytes), Err(DecodeError::ReservedBitsSet));
    }

    #[test]
    fn rejects_expired_input() {
        let mut envelope = valid_envelope();
        envelope.age_ms = envelope.lifetime_ms + 1;
        assert_eq!(envelope.encode(), Err(ValidationError::AlreadyExpired));
    }
}
