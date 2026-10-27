//! Additive Hypha Link attachment records for opaque courier custody.

use core::fmt;

use crate::{MessageId, Priority};

pub const ATTACHMENT_WIRE_VERSION: u8 = 1;
pub const ATTACHMENT_PLAN_MAGIC: [u8; 4] = *b"HAP1";
pub const ATTACHMENT_CHUNK_MAGIC: [u8; 4] = *b"HAC1";
pub const ATTACHMENT_CUSTODY_MAGIC: [u8; 4] = *b"HCU1";
pub const CHUNK_PLAINTEXT_BYTES: usize = 192 * 1024;
pub const GCM_TAG_BYTES: usize = 16;
pub const MIN_CHUNK_CIPHERTEXT_BYTES: usize = GCM_TAG_BYTES + 1;
pub const MAX_CHUNK_CIPHERTEXT_BYTES: usize = CHUNK_PLAINTEXT_BYTES + GCM_TAG_BYTES;
pub const MAX_ATTACHMENT_PLAINTEXT_BYTES: u64 = 96 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 512;
pub const MAX_ATTACHMENT_CIPHERTEXT_BYTES: u64 =
    MAX_ATTACHMENT_PLAINTEXT_BYTES + GCM_TAG_BYTES as u64 * MAX_CHUNKS as u64;
pub const SHA256_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const ATTACHMENT_PLAN_HEADER_BYTES: usize = 64;
pub const ATTACHMENT_CHUNK_DESCRIPTOR_BYTES: usize = 36;
pub const MAX_ATTACHMENT_PLAN_BYTES: usize =
    ATTACHMENT_PLAN_HEADER_BYTES + MAX_CHUNKS * ATTACHMENT_CHUNK_DESCRIPTOR_BYTES;
pub const ATTACHMENT_CHUNK_HEADER_BYTES: usize = 72;
pub const ATTACHMENT_CUSTODY_HEADER_BYTES: usize = 58;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectClass {
    Text,
    RecipientReceipt,
    AttachmentManifest,
    AttachmentChunk,
    AudioManifest,
    AudioChunk,
    ContactUpdate,
    GroupControl,
}

impl ObjectClass {
    #[must_use]
    pub const fn priority(self) -> Priority {
        match self {
            Self::RecipientReceipt | Self::GroupControl => Priority::Control,
            Self::ContactUpdate => Priority::Safety,
            Self::Text => Priority::DirectText,
            Self::AttachmentManifest | Self::AudioManifest => Priority::Manifest,
            Self::AttachmentChunk | Self::AudioChunk => Priority::Bulk,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentChunkDescriptor {
    pub ciphertext_bytes: u32,
    pub ciphertext_sha256: [u8; SHA256_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentPlan {
    pub object_id: MessageId,
    pub cancellation_commitment: [u8; SHA256_BYTES],
    pub total_ciphertext_bytes: u64,
    pub chunks: Vec<AttachmentChunkDescriptor>,
}

impl AttachmentPlan {
    /// Validates the complete fixed-size chunk plan before storage or encoding.
    ///
    /// # Errors
    ///
    /// Returns the first violated length, count, or total-size bound.
    pub fn validate(&self) -> Result<(), AttachmentWireError> {
        if self.chunks.is_empty() || self.chunks.len() > MAX_CHUNKS {
            return Err(AttachmentWireError::InvalidChunkCount(self.chunks.len()));
        }
        let mut total = 0_u64;
        for (index, descriptor) in self.chunks.iter().enumerate() {
            let length = usize::try_from(descriptor.ciphertext_bytes)
                .map_err(|_| AttachmentWireError::InvalidChunkLength(usize::MAX))?;
            if !(MIN_CHUNK_CIPHERTEXT_BYTES..=MAX_CHUNK_CIPHERTEXT_BYTES).contains(&length) {
                return Err(AttachmentWireError::InvalidChunkLength(length));
            }
            if index + 1 != self.chunks.len() && length != MAX_CHUNK_CIPHERTEXT_BYTES {
                return Err(AttachmentWireError::ShortIntermediateChunk { index, length });
            }
            total = total
                .checked_add(u64::from(descriptor.ciphertext_bytes))
                .ok_or(AttachmentWireError::LengthOverflow)?;
        }
        if total != self.total_ciphertext_bytes {
            return Err(AttachmentWireError::TotalCiphertextMismatch {
                declared: self.total_ciphertext_bytes,
                actual: total,
            });
        }
        if total > MAX_ATTACHMENT_CIPHERTEXT_BYTES {
            return Err(AttachmentWireError::AttachmentTooLarge(total));
        }
        Ok(())
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        ATTACHMENT_PLAN_HEADER_BYTES + self.chunks.len() * ATTACHMENT_CHUNK_DESCRIPTOR_BYTES
    }

    /// Encodes one canonical courier-readable attachment plan.
    ///
    /// # Errors
    ///
    /// Returns a validation error before allocating for invalid input.
    pub fn encode(&self) -> Result<Vec<u8>, AttachmentWireError> {
        self.validate()?;
        let chunk_count = u16::try_from(self.chunks.len())
            .map_err(|_| AttachmentWireError::InvalidChunkCount(self.chunks.len()))?;
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&ATTACHMENT_PLAN_MAGIC);
        encoded.push(ATTACHMENT_WIRE_VERSION);
        encoded.push(0);
        encoded.extend_from_slice(&chunk_count.to_be_bytes());
        encoded.extend_from_slice(&self.object_id.0);
        encoded.extend_from_slice(&self.cancellation_commitment);
        encoded.extend_from_slice(&self.total_ciphertext_bytes.to_be_bytes());
        for descriptor in &self.chunks {
            encoded.extend_from_slice(&descriptor.ciphertext_bytes.to_be_bytes());
            encoded.extend_from_slice(&descriptor.ciphertext_sha256);
        }
        debug_assert_eq!(encoded.len(), self.encoded_len());
        Ok(encoded)
    }

    /// Decodes exactly one canonical attachment plan and rejects trailing data.
    ///
    /// # Errors
    ///
    /// Returns a structural, version, bounds, or exact-length error.
    pub fn decode(encoded: &[u8]) -> Result<Self, AttachmentWireError> {
        require_prefix(encoded, ATTACHMENT_PLAN_MAGIC, ATTACHMENT_PLAN_HEADER_BYTES)?;
        if encoded[5] != 0 {
            return Err(AttachmentWireError::ReservedBitsSet);
        }
        let chunk_count = usize::from(u16::from_be_bytes(read_array(encoded, 6)?));
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(AttachmentWireError::InvalidChunkCount(chunk_count));
        }
        let expected = ATTACHMENT_PLAN_HEADER_BYTES
            .checked_add(
                chunk_count
                    .checked_mul(ATTACHMENT_CHUNK_DESCRIPTOR_BYTES)
                    .ok_or(AttachmentWireError::LengthOverflow)?,
            )
            .ok_or(AttachmentWireError::LengthOverflow)?;
        require_exact_length(encoded, expected)?;

        let mut chunks = Vec::with_capacity(chunk_count);
        let mut offset = ATTACHMENT_PLAN_HEADER_BYTES;
        for _ in 0..chunk_count {
            chunks.push(AttachmentChunkDescriptor {
                ciphertext_bytes: u32::from_be_bytes(read_array(encoded, offset)?),
                ciphertext_sha256: read_array(encoded, offset + 4)?,
            });
            offset += ATTACHMENT_CHUNK_DESCRIPTOR_BYTES;
        }
        let plan = Self {
            object_id: MessageId(read_array(encoded, 8)?),
            cancellation_commitment: read_array(encoded, 24)?,
            total_ciphertext_bytes: u64::from_be_bytes(read_array(encoded, 56)?),
            chunks,
        };
        plan.validate()?;
        Ok(plan)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentChunkRecord {
    pub object_id: MessageId,
    pub chunk_index: u16,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext_sha256: [u8; SHA256_BYTES],
    pub ciphertext: Vec<u8>,
}

impl AttachmentChunkRecord {
    /// Validates record-local bounds. Plan and digest matching occur in custody state.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range index or ciphertext length.
    pub fn validate(&self) -> Result<(), AttachmentWireError> {
        if usize::from(self.chunk_index) >= MAX_CHUNKS {
            return Err(AttachmentWireError::InvalidChunkIndex(self.chunk_index));
        }
        if !(MIN_CHUNK_CIPHERTEXT_BYTES..=MAX_CHUNK_CIPHERTEXT_BYTES)
            .contains(&self.ciphertext.len())
        {
            return Err(AttachmentWireError::InvalidChunkLength(
                self.ciphertext.len(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        ATTACHMENT_CHUNK_HEADER_BYTES + self.ciphertext.len()
    }

    /// Encodes one exact opaque chunk record.
    ///
    /// # Errors
    ///
    /// Returns a local validation error before output allocation.
    pub fn encode(&self) -> Result<Vec<u8>, AttachmentWireError> {
        self.validate()?;
        let ciphertext_bytes = u32::try_from(self.ciphertext.len())
            .map_err(|_| AttachmentWireError::InvalidChunkLength(self.ciphertext.len()))?;
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&ATTACHMENT_CHUNK_MAGIC);
        encoded.push(ATTACHMENT_WIRE_VERSION);
        encoded.push(0);
        encoded.extend_from_slice(&self.chunk_index.to_be_bytes());
        encoded.extend_from_slice(&self.object_id.0);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&ciphertext_bytes.to_be_bytes());
        encoded.extend_from_slice(&self.ciphertext_sha256);
        encoded.extend_from_slice(&self.ciphertext);
        debug_assert_eq!(encoded.len(), self.encoded_len());
        Ok(encoded)
    }

    /// Decodes exactly one bounded opaque chunk record.
    ///
    /// # Errors
    ///
    /// Returns a structural, version, bounds, or exact-length error.
    pub fn decode(encoded: &[u8]) -> Result<Self, AttachmentWireError> {
        require_prefix(
            encoded,
            ATTACHMENT_CHUNK_MAGIC,
            ATTACHMENT_CHUNK_HEADER_BYTES,
        )?;
        if encoded[5] != 0 {
            return Err(AttachmentWireError::ReservedBitsSet);
        }
        let ciphertext_bytes = usize::try_from(u32::from_be_bytes(read_array(encoded, 36)?))
            .map_err(|_| AttachmentWireError::LengthOverflow)?;
        if !(MIN_CHUNK_CIPHERTEXT_BYTES..=MAX_CHUNK_CIPHERTEXT_BYTES).contains(&ciphertext_bytes) {
            return Err(AttachmentWireError::InvalidChunkLength(ciphertext_bytes));
        }
        let expected = ATTACHMENT_CHUNK_HEADER_BYTES
            .checked_add(ciphertext_bytes)
            .ok_or(AttachmentWireError::LengthOverflow)?;
        require_exact_length(encoded, expected)?;
        let record = Self {
            object_id: MessageId(read_array(encoded, 8)?),
            chunk_index: u16::from_be_bytes(read_array(encoded, 6)?),
            nonce: read_array(encoded, 24)?,
            ciphertext_sha256: read_array(encoded, 40)?,
            ciphertext: encoded[ATTACHMENT_CHUNK_HEADER_BYTES..].to_vec(),
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentCustodyRecord {
    pub object_id: MessageId,
    pub plan_sha256: [u8; SHA256_BYTES],
    pub plan_committed: bool,
    pub chunk_count: u16,
    pub chunk_bitmap: Vec<u8>,
}

impl AttachmentCustodyRecord {
    /// Validates exact bitmap length and canonical unused bits.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid count, bitmap, or custody-before-plan state.
    pub fn validate(&self) -> Result<(), AttachmentWireError> {
        let chunk_count = usize::from(self.chunk_count);
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(AttachmentWireError::InvalidChunkCount(chunk_count));
        }
        let expected = bitmap_bytes(chunk_count);
        if self.chunk_bitmap.len() != expected {
            return Err(AttachmentWireError::InvalidBitmapLength {
                declared: self.chunk_bitmap.len(),
                expected,
            });
        }
        let used_bits = chunk_count % 8;
        if used_bits != 0 {
            let unused_mask = !((1_u8 << used_bits) - 1);
            if self
                .chunk_bitmap
                .last()
                .is_some_and(|byte| byte & unused_mask != 0)
            {
                return Err(AttachmentWireError::NonCanonicalBitmap);
            }
        }
        if !self.plan_committed && self.chunk_bitmap.iter().any(|byte| *byte != 0) {
            return Err(AttachmentWireError::CustodyBeforePlan);
        }
        Ok(())
    }

    #[must_use]
    pub fn has_chunk(&self, index: u16) -> bool {
        if index >= self.chunk_count {
            return false;
        }
        let index = usize::from(index);
        self.chunk_bitmap[index / 8] & (1 << (index % 8)) != 0
    }

    #[must_use]
    pub fn missing_chunks(&self) -> Vec<u16> {
        (0..self.chunk_count)
            .filter(|index| !self.has_chunk(*index))
            .collect()
    }

    /// Encodes one hop-authenticated custody bitmap. This is never delivery.
    ///
    /// # Errors
    ///
    /// Returns a canonical bitmap validation error.
    pub fn encode(&self) -> Result<Vec<u8>, AttachmentWireError> {
        self.validate()?;
        let bitmap_len = u16::try_from(self.chunk_bitmap.len()).map_err(|_| {
            AttachmentWireError::InvalidBitmapLength {
                declared: self.chunk_bitmap.len(),
                expected: bitmap_bytes(usize::from(self.chunk_count)),
            }
        })?;
        let mut encoded =
            Vec::with_capacity(ATTACHMENT_CUSTODY_HEADER_BYTES + self.chunk_bitmap.len());
        encoded.extend_from_slice(&ATTACHMENT_CUSTODY_MAGIC);
        encoded.push(ATTACHMENT_WIRE_VERSION);
        encoded.push(u8::from(self.plan_committed));
        encoded.extend_from_slice(&self.chunk_count.to_be_bytes());
        encoded.extend_from_slice(&self.object_id.0);
        encoded.extend_from_slice(&self.plan_sha256);
        encoded.extend_from_slice(&bitmap_len.to_be_bytes());
        encoded.extend_from_slice(&self.chunk_bitmap);
        Ok(encoded)
    }

    /// Decodes exactly one canonical custody bitmap.
    ///
    /// # Errors
    ///
    /// Returns a structural, version, bounds, or bitmap error.
    pub fn decode(encoded: &[u8]) -> Result<Self, AttachmentWireError> {
        require_prefix(
            encoded,
            ATTACHMENT_CUSTODY_MAGIC,
            ATTACHMENT_CUSTODY_HEADER_BYTES,
        )?;
        if encoded[5] & !1 != 0 {
            return Err(AttachmentWireError::ReservedBitsSet);
        }
        let chunk_count = u16::from_be_bytes(read_array(encoded, 6)?);
        let bitmap_len = usize::from(u16::from_be_bytes(read_array(encoded, 56)?));
        let expected = ATTACHMENT_CUSTODY_HEADER_BYTES
            .checked_add(bitmap_len)
            .ok_or(AttachmentWireError::LengthOverflow)?;
        require_exact_length(encoded, expected)?;
        let record = Self {
            object_id: MessageId(read_array(encoded, 8)?),
            plan_sha256: read_array(encoded, 24)?,
            plan_committed: encoded[5] & 1 != 0,
            chunk_count,
            chunk_bitmap: encoded[ATTACHMENT_CUSTODY_HEADER_BYTES..].to_vec(),
        };
        record.validate()?;
        Ok(record)
    }
}

#[must_use]
pub const fn bitmap_bytes(chunk_count: usize) -> usize {
    chunk_count.div_ceil(8)
}

fn require_prefix(
    encoded: &[u8],
    magic: [u8; 4],
    minimum: usize,
) -> Result<(), AttachmentWireError> {
    if encoded.len() < minimum {
        return Err(AttachmentWireError::Truncated);
    }
    if encoded[..4] != magic {
        return Err(AttachmentWireError::InvalidMagic);
    }
    if encoded[4] != ATTACHMENT_WIRE_VERSION {
        return Err(AttachmentWireError::UnsupportedVersion(encoded[4]));
    }
    Ok(())
}

const fn require_exact_length(encoded: &[u8], expected: usize) -> Result<(), AttachmentWireError> {
    if encoded.len() != expected {
        return Err(AttachmentWireError::LengthMismatch {
            declared: expected,
            actual: encoded.len(),
        });
    }
    Ok(())
}

fn read_array<const SIZE: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], AttachmentWireError> {
    encoded
        .get(offset..offset + SIZE)
        .ok_or(AttachmentWireError::Truncated)?
        .try_into()
        .map_err(|_| AttachmentWireError::Truncated)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentWireError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    ReservedBitsSet,
    InvalidChunkCount(usize),
    InvalidChunkIndex(u16),
    InvalidChunkLength(usize),
    ShortIntermediateChunk { index: usize, length: usize },
    TotalCiphertextMismatch { declared: u64, actual: u64 },
    AttachmentTooLarge(u64),
    InvalidBitmapLength { declared: usize, expected: usize },
    NonCanonicalBitmap,
    CustodyBeforePlan,
    LengthOverflow,
    LengthMismatch { declared: usize, actual: usize },
}

impl fmt::Display for AttachmentWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AttachmentWireError {}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    fn two_chunk_plan() -> AttachmentPlan {
        AttachmentPlan {
            object_id: MessageId([0x11; 16]),
            cancellation_commitment: [0x22; 32],
            total_ciphertext_bytes: 0x0003_0031,
            chunks: vec![
                AttachmentChunkDescriptor {
                    ciphertext_bytes: u32::try_from(MAX_CHUNK_CIPHERTEXT_BYTES).expect("bound"),
                    ciphertext_sha256: [0x33; 32],
                },
                AttachmentChunkDescriptor {
                    ciphertext_bytes: 33,
                    ciphertext_sha256: [0x44; 32],
                },
            ],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    #[test]
    fn plan_has_stable_golden_encoding() {
        let plan = two_chunk_plan();
        let encoded = plan.encode().expect("valid plan");
        assert_eq!(
            encoded.len(),
            ATTACHMENT_PLAN_HEADER_BYTES + 2 * ATTACHMENT_CHUNK_DESCRIPTOR_BYTES
        );
        assert_eq!(
            hex(&encoded),
            concat!(
                "4841503101000002",
                "11111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "0000000000030031",
                "00030010",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "00000021",
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        );
        assert_eq!(AttachmentPlan::decode(&encoded), Ok(plan));
    }

    #[test]
    fn plan_rejects_noncanonical_lengths_and_trailing_data() {
        let mut short_first = two_chunk_plan();
        short_first.chunks[0].ciphertext_bytes -= 1;
        short_first.total_ciphertext_bytes -= 1;
        assert!(matches!(
            short_first.validate(),
            Err(AttachmentWireError::ShortIntermediateChunk { .. })
        ));

        let mut trailing = two_chunk_plan().encode().expect("valid plan");
        trailing.push(0);
        assert!(matches!(
            AttachmentPlan::decode(&trailing),
            Err(AttachmentWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn maximum_plan_and_chunk_record_round_trip_at_exact_limits() {
        let descriptor = AttachmentChunkDescriptor {
            ciphertext_bytes: u32::try_from(MAX_CHUNK_CIPHERTEXT_BYTES).expect("bound"),
            ciphertext_sha256: [0x5a; SHA256_BYTES],
        };
        let plan = AttachmentPlan {
            object_id: MessageId([0x6b; 16]),
            cancellation_commitment: [0x7c; SHA256_BYTES],
            total_ciphertext_bytes: MAX_ATTACHMENT_CIPHERTEXT_BYTES,
            chunks: vec![descriptor; MAX_CHUNKS],
        };
        let encoded_plan = plan.encode().expect("maximum plan");
        assert_eq!(encoded_plan.len(), MAX_ATTACHMENT_PLAN_BYTES);
        assert_eq!(AttachmentPlan::decode(&encoded_plan), Ok(plan));

        let chunk = AttachmentChunkRecord {
            object_id: MessageId([0x6b; 16]),
            chunk_index: u16::try_from(MAX_CHUNKS - 1).expect("bound"),
            nonce: [0x8d; NONCE_BYTES],
            ciphertext_sha256: [0x5a; SHA256_BYTES],
            ciphertext: vec![0xa5; MAX_CHUNK_CIPHERTEXT_BYTES],
        };
        let encoded_chunk = chunk.encode().expect("maximum chunk");
        assert_eq!(
            encoded_chunk.len(),
            ATTACHMENT_CHUNK_HEADER_BYTES + MAX_CHUNK_CIPHERTEXT_BYTES
        );
        assert_eq!(AttachmentChunkRecord::decode(&encoded_chunk), Ok(chunk));
    }

    #[test]
    fn plan_rejects_truncation_unknown_version_and_reserved_bits() {
        let encoded = two_chunk_plan().encode().expect("valid plan");
        assert_eq!(
            AttachmentPlan::decode(&encoded[..ATTACHMENT_PLAN_HEADER_BYTES - 1]),
            Err(AttachmentWireError::Truncated)
        );

        let mut unknown_version = encoded.clone();
        unknown_version[4] = 2;
        assert_eq!(
            AttachmentPlan::decode(&unknown_version),
            Err(AttachmentWireError::UnsupportedVersion(2))
        );

        let mut reserved = encoded;
        reserved[5] = 1;
        assert_eq!(
            AttachmentPlan::decode(&reserved),
            Err(AttachmentWireError::ReservedBitsSet)
        );
    }

    #[test]
    fn chunk_record_is_exact_and_bounded() {
        let record = AttachmentChunkRecord {
            object_id: MessageId([7; 16]),
            chunk_index: 1,
            nonce: [8; NONCE_BYTES],
            ciphertext_sha256: [9; SHA256_BYTES],
            ciphertext: vec![5; MIN_CHUNK_CIPHERTEXT_BYTES],
        };
        let encoded = record.encode().expect("valid chunk");
        assert_eq!(AttachmentChunkRecord::decode(&encoded), Ok(record));

        let mut reserved = encoded;
        reserved[5] = 1;
        assert_eq!(
            AttachmentChunkRecord::decode(&reserved),
            Err(AttachmentWireError::ReservedBitsSet)
        );
    }

    #[test]
    fn custody_bitmap_is_canonical_and_never_implies_delivery() {
        let custody = AttachmentCustodyRecord {
            object_id: MessageId([1; 16]),
            plan_sha256: [2; SHA256_BYTES],
            plan_committed: true,
            chunk_count: 10,
            chunk_bitmap: vec![0b0101_0101, 0b0000_0010],
        };
        let encoded = custody.encode().expect("canonical custody");
        assert_eq!(
            AttachmentCustodyRecord::decode(&encoded),
            Ok(custody.clone())
        );
        assert!(custody.has_chunk(9));
        assert_eq!(custody.missing_chunks(), vec![1, 3, 5, 7, 8]);

        let mut noncanonical = custody;
        noncanonical.chunk_bitmap[1] |= 0b1000_0000;
        assert_eq!(
            noncanonical.validate(),
            Err(AttachmentWireError::NonCanonicalBitmap)
        );

        let custody_before_plan = AttachmentCustodyRecord {
            object_id: MessageId([1; 16]),
            plan_sha256: [2; SHA256_BYTES],
            plan_committed: false,
            chunk_count: 1,
            chunk_bitmap: vec![1],
        };
        assert_eq!(
            custody_before_plan.validate(),
            Err(AttachmentWireError::CustodyBeforePlan)
        );
    }

    #[test]
    fn object_priorities_keep_text_and_receipts_ahead_of_bulk() {
        assert!(ObjectClass::RecipientReceipt.priority() < ObjectClass::Text.priority());
        assert!(ObjectClass::Text.priority() < ObjectClass::AttachmentManifest.priority());
        assert!(
            ObjectClass::AttachmentManifest.priority() < ObjectClass::AttachmentChunk.priority()
        );
    }
}
