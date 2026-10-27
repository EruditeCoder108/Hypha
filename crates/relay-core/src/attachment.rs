//! Deterministic attachment custody state, independent of Android transports.

use core::fmt;

use relay_wire::attachment::{
    ATTACHMENT_CHUNK_HEADER_BYTES, AttachmentChunkRecord, AttachmentCustodyRecord, AttachmentPlan,
    AttachmentWireError, bitmap_bytes,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableChunkOutcome {
    Stored,
    Duplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentCustodyState {
    plan: AttachmentPlan,
    plan_sha256: [u8; 32],
    chunk_bitmap: Vec<u8>,
    committed_storage_bytes: u64,
}

impl AttachmentCustodyState {
    /// Starts custody after the canonical plan is durably committed.
    ///
    /// The quota check conservatively includes the plan, every chunk record header,
    /// and all ciphertext before any chunk is accepted.
    ///
    /// # Errors
    ///
    /// Returns an invalid-plan, arithmetic, or quota error.
    pub fn from_durable_plan(
        plan: AttachmentPlan,
        available_quota_bytes: u64,
    ) -> Result<Self, AttachmentCustodyError> {
        let encoded = plan.encode().map_err(AttachmentCustodyError::InvalidPlan)?;
        let chunk_headers = u64::try_from(plan.chunks.len())
            .ok()
            .and_then(|count| count.checked_mul(ATTACHMENT_CHUNK_HEADER_BYTES as u64))
            .ok_or(AttachmentCustodyError::LengthOverflow)?;
        let required = u64::try_from(encoded.len())
            .ok()
            .and_then(|plan_bytes| plan_bytes.checked_add(chunk_headers))
            .and_then(|with_headers| with_headers.checked_add(plan.total_ciphertext_bytes))
            .ok_or(AttachmentCustodyError::LengthOverflow)?;
        if required > available_quota_bytes {
            return Err(AttachmentCustodyError::QuotaExceeded {
                required,
                available: available_quota_bytes,
            });
        }
        let plan_sha256 = sha256(&encoded);
        let chunk_bitmap = vec![0; bitmap_bytes(plan.chunks.len())];
        Ok(Self {
            plan,
            plan_sha256,
            chunk_bitmap,
            committed_storage_bytes: u64::try_from(encoded.len())
                .map_err(|_| AttachmentCustodyError::LengthOverflow)?,
        })
    }

    #[must_use]
    pub const fn plan(&self) -> &AttachmentPlan {
        &self.plan
    }

    #[must_use]
    pub const fn plan_sha256(&self) -> [u8; 32] {
        self.plan_sha256
    }

    #[must_use]
    pub const fn committed_storage_bytes(&self) -> u64 {
        self.committed_storage_bytes
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.chunk_bitmap
            .iter()
            .enumerate()
            .all(|(byte_index, byte)| {
                let chunks_left = self.plan.chunks.len().saturating_sub(byte_index * 8);
                let expected = if chunks_left >= 8 {
                    u8::MAX
                } else {
                    (1_u8 << chunks_left) - 1
                };
                *byte == expected
            })
    }

    /// Records a chunk only after its bytes and metadata are durably committed.
    ///
    /// This transition validates object ID, index, plan descriptor, and the SHA-256
    /// of the opaque ciphertext. It returns custody state, never recipient delivery.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, mismatched, or corrupted chunk data.
    pub fn record_durable_chunk(
        &mut self,
        record: &AttachmentChunkRecord,
    ) -> Result<DurableChunkOutcome, AttachmentCustodyError> {
        record
            .validate()
            .map_err(AttachmentCustodyError::InvalidChunk)?;
        if record.object_id != self.plan.object_id {
            return Err(AttachmentCustodyError::WrongObject);
        }
        let index = usize::from(record.chunk_index);
        let descriptor = self
            .plan
            .chunks
            .get(index)
            .ok_or(AttachmentCustodyError::ChunkOutOfRange(record.chunk_index))?;
        let record_length = u32::try_from(record.ciphertext.len())
            .map_err(|_| AttachmentCustodyError::LengthOverflow)?;
        if descriptor.ciphertext_bytes != record_length
            || descriptor.ciphertext_sha256 != record.ciphertext_sha256
        {
            return Err(AttachmentCustodyError::DescriptorMismatch(
                record.chunk_index,
            ));
        }
        if sha256(&record.ciphertext) != descriptor.ciphertext_sha256 {
            return Err(AttachmentCustodyError::DigestMismatch(record.chunk_index));
        }
        let mask = 1_u8 << (index % 8);
        let byte = &mut self.chunk_bitmap[index / 8];
        if *byte & mask != 0 {
            return Ok(DurableChunkOutcome::Duplicate);
        }
        *byte |= mask;
        self.committed_storage_bytes = self
            .committed_storage_bytes
            .checked_add(ATTACHMENT_CHUNK_HEADER_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(u64::from(record_length)))
            .ok_or(AttachmentCustodyError::LengthOverflow)?;
        Ok(DurableChunkOutcome::Stored)
    }

    /// Returns the exact hop-custody bitmap. This type cannot be confused with a
    /// recipient receipt at compile time or on the wire.
    ///
    /// # Errors
    ///
    /// Returns an error only if internal state violates canonical bitmap rules.
    pub fn custody_record(&self) -> Result<AttachmentCustodyRecord, AttachmentCustodyError> {
        let chunk_count = u16::try_from(self.plan.chunks.len())
            .map_err(|_| AttachmentCustodyError::LengthOverflow)?;
        let record = AttachmentCustodyRecord {
            object_id: self.plan.object_id,
            plan_sha256: self.plan_sha256,
            plan_committed: true,
            chunk_count,
            chunk_bitmap: self.chunk_bitmap.clone(),
        };
        record
            .validate()
            .map_err(AttachmentCustodyError::InvalidCustody)?;
        Ok(record)
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentCustodyError {
    InvalidPlan(AttachmentWireError),
    InvalidChunk(AttachmentWireError),
    InvalidCustody(AttachmentWireError),
    QuotaExceeded { required: u64, available: u64 },
    WrongObject,
    ChunkOutOfRange(u16),
    DescriptorMismatch(u16),
    DigestMismatch(u16),
    LengthOverflow,
}

impl fmt::Display for AttachmentCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AttachmentCustodyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_wire::{
        MessageId,
        attachment::{AttachmentChunkDescriptor, MAX_CHUNK_CIPHERTEXT_BYTES, NONCE_BYTES},
    };

    fn record(object_id: MessageId, index: u16, ciphertext: Vec<u8>) -> AttachmentChunkRecord {
        AttachmentChunkRecord {
            object_id,
            chunk_index: index,
            nonce: [u8::try_from(index).expect("test index"); NONCE_BYTES],
            ciphertext_sha256: sha256(&ciphertext),
            ciphertext,
        }
    }

    fn plan_and_records() -> (AttachmentPlan, AttachmentChunkRecord, AttachmentChunkRecord) {
        let object_id = MessageId([7; 16]);
        let first = record(object_id, 0, vec![1; MAX_CHUNK_CIPHERTEXT_BYTES]);
        let second = record(object_id, 1, vec![2; 33]);
        let plan = AttachmentPlan {
            object_id,
            cancellation_commitment: [9; 32],
            total_ciphertext_bytes: u64::try_from(first.ciphertext.len() + second.ciphertext.len())
                .expect("test total"),
            chunks: vec![
                AttachmentChunkDescriptor {
                    ciphertext_bytes: u32::try_from(first.ciphertext.len()).expect("test length"),
                    ciphertext_sha256: first.ciphertext_sha256,
                },
                AttachmentChunkDescriptor {
                    ciphertext_bytes: u32::try_from(second.ciphertext.len()).expect("test length"),
                    ciphertext_sha256: second.ciphertext_sha256,
                },
            ],
        };
        (plan, first, second)
    }

    #[test]
    fn quota_is_checked_before_any_chunk_state_exists() {
        let (plan, _, _) = plan_and_records();
        assert!(matches!(
            AttachmentCustodyState::from_durable_plan(plan, 1),
            Err(AttachmentCustodyError::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn durable_chunks_are_idempotent_and_resume_exactly() {
        let (plan, first, second) = plan_and_records();
        let mut state =
            AttachmentCustodyState::from_durable_plan(plan, 1_000_000).expect("quota available");
        assert_eq!(
            state.record_durable_chunk(&second),
            Ok(DurableChunkOutcome::Stored)
        );
        assert_eq!(
            state.record_durable_chunk(&second),
            Ok(DurableChunkOutcome::Duplicate)
        );
        let custody = state.custody_record().expect("custody");
        assert!(custody.plan_committed);
        assert_eq!(custody.missing_chunks(), vec![0]);
        assert!(!state.is_complete());

        assert_eq!(
            state.record_durable_chunk(&first),
            Ok(DurableChunkOutcome::Stored)
        );
        assert!(state.is_complete());
        assert!(
            state
                .custody_record()
                .expect("custody")
                .missing_chunks()
                .is_empty()
        );
    }

    #[test]
    fn corrupt_or_wrong_object_chunks_fail_closed() {
        let (plan, first, _) = plan_and_records();
        let mut state =
            AttachmentCustodyState::from_durable_plan(plan, 1_000_000).expect("quota available");
        let mut corrupt = first.clone();
        corrupt.ciphertext[0] ^= 1;
        assert_eq!(
            state.record_durable_chunk(&corrupt),
            Err(AttachmentCustodyError::DigestMismatch(0))
        );

        let mut wrong_object = first;
        wrong_object.object_id = MessageId([8; 16]);
        assert_eq!(
            state.record_durable_chunk(&wrong_object),
            Err(AttachmentCustodyError::WrongObject)
        );
        assert_eq!(
            state.custody_record().expect("custody").missing_chunks(),
            vec![0, 1]
        );
    }
}
