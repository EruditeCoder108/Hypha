//! Recipient-private attachment metadata and authenticated completion receipts.

use core::fmt;

use relay_wire::MessageId;

pub const ATTACHMENT_CONTENT_VERSION: u8 = 1;
pub const PRIVATE_MANIFEST_MAGIC: [u8; 4] = *b"HAM1";
pub const RECIPIENT_RECEIPT_MAGIC: [u8; 4] = *b"HAR1";
pub const PRIVATE_MANIFEST_HEADER_BYTES: usize = 132;
pub const RECIPIENT_RECEIPT_BYTES: usize = 56;
pub const MAX_FILE_NAME_BYTES: usize = 128;
pub const MAX_MIME_TYPE_BYTES: usize = 96;
pub const MAX_IMAGE_BYTES: u64 = 25 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 96 * 1024 * 1024;
pub const SHA256_BYTES: usize = 32;
pub const CONTENT_KEY_BYTES: usize = 32;
const COMPLETE_STATUS: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttachmentKind {
    Image = 1,
    File = 2,
}

impl AttachmentKind {
    #[must_use]
    pub const fn maximum_bytes(self) -> u64 {
        match self {
            Self::Image => MAX_IMAGE_BYTES,
            Self::File => MAX_FILE_BYTES,
        }
    }
}

impl TryFrom<u8> for AttachmentKind {
    type Error = AttachmentContentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Image),
            2 => Ok(Self::File),
            other => Err(AttachmentContentError::UnsupportedKind(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientAttachmentManifest {
    pub object_id: MessageId,
    pub kind: AttachmentKind,
    pub courier_plan_sha256: [u8; SHA256_BYTES],
    pub content_key: [u8; CONTENT_KEY_BYTES],
    pub plaintext_bytes: u64,
    pub plaintext_sha256: [u8; SHA256_BYTES],
    pub mime_type: String,
    pub file_name: String,
}

impl RecipientAttachmentManifest {
    /// Validates all recipient-private fields before encryption or presentation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid sizes, MIME syntax, or an unsafe filename.
    pub fn validate(&self) -> Result<(), AttachmentContentError> {
        if self.plaintext_bytes == 0 || self.plaintext_bytes > self.kind.maximum_bytes() {
            return Err(AttachmentContentError::InvalidPlaintextLength(
                self.plaintext_bytes,
            ));
        }
        if !valid_mime_type(&self.mime_type) {
            return Err(AttachmentContentError::InvalidMimeType);
        }
        if !valid_file_name(&self.file_name) {
            return Err(AttachmentContentError::InvalidFileName);
        }
        Ok(())
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        PRIVATE_MANIFEST_HEADER_BYTES + self.mime_type.len() + self.file_name.len()
    }

    /// Encodes endpoint-only attachment metadata for signed recipient encryption.
    ///
    /// # Errors
    ///
    /// Returns a validation error before output allocation.
    pub fn encode(&self) -> Result<Vec<u8>, AttachmentContentError> {
        self.validate()?;
        let mime_length = u16::try_from(self.mime_type.len())
            .map_err(|_| AttachmentContentError::InvalidMimeType)?;
        let name_length = u16::try_from(self.file_name.len())
            .map_err(|_| AttachmentContentError::InvalidFileName)?;
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&PRIVATE_MANIFEST_MAGIC);
        encoded.push(ATTACHMENT_CONTENT_VERSION);
        encoded.push(self.kind as u8);
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&self.object_id.0);
        encoded.extend_from_slice(&self.courier_plan_sha256);
        encoded.extend_from_slice(&self.content_key);
        encoded.extend_from_slice(&self.plaintext_bytes.to_be_bytes());
        encoded.extend_from_slice(&self.plaintext_sha256);
        encoded.extend_from_slice(&mime_length.to_be_bytes());
        encoded.extend_from_slice(&name_length.to_be_bytes());
        encoded.extend_from_slice(self.mime_type.as_bytes());
        encoded.extend_from_slice(self.file_name.as_bytes());
        debug_assert_eq!(encoded.len(), self.encoded_len());
        Ok(encoded)
    }

    /// Decodes exactly one endpoint-only attachment manifest.
    ///
    /// # Errors
    ///
    /// Returns a structural, version, bounds, UTF-8, or exact-length error.
    pub fn decode(encoded: &[u8]) -> Result<Self, AttachmentContentError> {
        if encoded.len() < PRIVATE_MANIFEST_HEADER_BYTES {
            return Err(AttachmentContentError::Truncated);
        }
        require_prefix(encoded, PRIVATE_MANIFEST_MAGIC)?;
        let kind = AttachmentKind::try_from(encoded[5])?;
        if encoded[6..8] != [0, 0] {
            return Err(AttachmentContentError::ReservedBitsSet);
        }
        let mime_length = usize::from(u16::from_be_bytes(read_array(encoded, 128)?));
        let name_length = usize::from(u16::from_be_bytes(read_array(encoded, 130)?));
        if !(3..=MAX_MIME_TYPE_BYTES).contains(&mime_length) {
            return Err(AttachmentContentError::InvalidMimeType);
        }
        if !(1..=MAX_FILE_NAME_BYTES).contains(&name_length) {
            return Err(AttachmentContentError::InvalidFileName);
        }
        let expected = PRIVATE_MANIFEST_HEADER_BYTES
            .checked_add(mime_length)
            .and_then(|value| value.checked_add(name_length))
            .ok_or(AttachmentContentError::LengthOverflow)?;
        if encoded.len() != expected {
            return Err(AttachmentContentError::LengthMismatch {
                declared: expected,
                actual: encoded.len(),
            });
        }
        let mime_end = PRIVATE_MANIFEST_HEADER_BYTES + mime_length;
        let mime_type = core::str::from_utf8(&encoded[PRIVATE_MANIFEST_HEADER_BYTES..mime_end])
            .map_err(|_| AttachmentContentError::InvalidUtf8)?
            .to_owned();
        let file_name = core::str::from_utf8(&encoded[mime_end..])
            .map_err(|_| AttachmentContentError::InvalidUtf8)?
            .to_owned();
        let manifest = Self {
            object_id: MessageId(read_array(encoded, 8)?),
            kind,
            courier_plan_sha256: read_array(encoded, 24)?,
            content_key: read_array(encoded, 56)?,
            plaintext_bytes: u64::from_be_bytes(read_array(encoded, 88)?),
            plaintext_sha256: read_array(encoded, 96)?,
            mime_type,
            file_name,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientAttachmentReceipt {
    pub object_id: MessageId,
    pub courier_plan_sha256: [u8; SHA256_BYTES],
}

impl RecipientAttachmentReceipt {
    #[must_use]
    pub fn encode(self) -> [u8; RECIPIENT_RECEIPT_BYTES] {
        let mut encoded = [0_u8; RECIPIENT_RECEIPT_BYTES];
        encoded[..4].copy_from_slice(&RECIPIENT_RECEIPT_MAGIC);
        encoded[4] = ATTACHMENT_CONTENT_VERSION;
        encoded[5] = COMPLETE_STATUS;
        encoded[8..24].copy_from_slice(&self.object_id.0);
        encoded[24..56].copy_from_slice(&self.courier_plan_sha256);
        encoded
    }

    #[must_use]
    pub fn confirms(self, object_id: MessageId, courier_plan_sha256: [u8; SHA256_BYTES]) -> bool {
        self.object_id.0 == object_id.0 && self.courier_plan_sha256 == courier_plan_sha256
    }

    /// Decodes one exact recipient-authenticated attachment completion record.
    ///
    /// # Errors
    ///
    /// Returns an error for an incorrect length, prefix, status, or reserved bits.
    pub fn decode(encoded: &[u8]) -> Result<Self, AttachmentContentError> {
        if encoded.len() != RECIPIENT_RECEIPT_BYTES {
            return Err(AttachmentContentError::InvalidReceiptLength(encoded.len()));
        }
        require_prefix(encoded, RECIPIENT_RECEIPT_MAGIC)?;
        if encoded[5] != COMPLETE_STATUS {
            return Err(AttachmentContentError::UnsupportedStatus(encoded[5]));
        }
        if encoded[6..8] != [0, 0] {
            return Err(AttachmentContentError::ReservedBitsSet);
        }
        Ok(Self {
            object_id: MessageId(read_array(encoded, 8)?),
            courier_plan_sha256: read_array(encoded, 24)?,
        })
    }
}

fn valid_mime_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(3..=MAX_MIME_TYPE_BYTES).contains(&bytes.len()) || !value.is_ascii() {
        return false;
    }
    let mut slash = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'/' {
            if slash.replace(index).is_some() {
                return false;
            }
        } else if !matches!(
            byte,
            b'a'..=b'z'
                | b'0'..=b'9'
                | b'!'
                | b'#'
                | b'$'
                | b'&'
                | b'^'
                | b'_'
                | b'.'
                | b'+'
                | b'-'
        ) {
            return false;
        }
    }
    slash.is_some_and(|index| index > 0 && index + 1 < bytes.len())
}

fn valid_file_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_FILE_NAME_BYTES
        && value.trim() == value
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .chars()
            .all(|character| !character.is_control() && !matches!(character, '/' | '\\'))
}

fn require_prefix(encoded: &[u8], magic: [u8; 4]) -> Result<(), AttachmentContentError> {
    if encoded.len() < 5 {
        return Err(AttachmentContentError::Truncated);
    }
    if encoded[..4] != magic {
        return Err(AttachmentContentError::InvalidMagic);
    }
    if encoded[4] != ATTACHMENT_CONTENT_VERSION {
        return Err(AttachmentContentError::UnsupportedVersion(encoded[4]));
    }
    Ok(())
}

fn read_array<const SIZE: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], AttachmentContentError> {
    encoded
        .get(offset..offset + SIZE)
        .ok_or(AttachmentContentError::Truncated)?
        .try_into()
        .map_err(|_| AttachmentContentError::Truncated)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentContentError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedKind(u8),
    UnsupportedStatus(u8),
    ReservedBitsSet,
    InvalidPlaintextLength(u64),
    InvalidMimeType,
    InvalidFileName,
    InvalidUtf8,
    LengthOverflow,
    LengthMismatch { declared: usize, actual: usize },
    InvalidReceiptLength(usize),
}

impl fmt::Display for AttachmentContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AttachmentContentError {}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    fn manifest() -> RecipientAttachmentManifest {
        RecipientAttachmentManifest {
            object_id: MessageId([0x11; 16]),
            kind: AttachmentKind::File,
            courier_plan_sha256: [0x22; SHA256_BYTES],
            content_key: [0x33; CONTENT_KEY_BYTES],
            plaintext_bytes: 42,
            plaintext_sha256: [0x44; SHA256_BYTES],
            mime_type: "application/octet-stream".to_owned(),
            file_name: "note.txt".to_owned(),
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
    fn private_manifest_has_stable_golden_encoding() {
        let manifest = manifest();
        let encoded = manifest.encode().expect("valid manifest");
        assert_eq!(
            hex(&encoded),
            concat!(
                "48414d3101020000",
                "11111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "000000000000002a",
                "4444444444444444444444444444444444444444444444444444444444444444",
                "00180008",
                "6170706c69636174696f6e2f6f637465742d73747265616d",
                "6e6f74652e747874",
            ),
        );
        assert_eq!(RecipientAttachmentManifest::decode(&encoded), Ok(manifest));
    }

    #[test]
    fn private_manifest_rejects_unsafe_metadata_and_trailing_data() {
        let mut unsafe_name = manifest();
        unsafe_name.file_name = "../note.txt".to_owned();
        assert_eq!(
            unsafe_name.validate(),
            Err(AttachmentContentError::InvalidFileName)
        );

        let mut uppercase_mime = manifest();
        uppercase_mime.mime_type = "Application/octet-stream".to_owned();
        assert_eq!(
            uppercase_mime.validate(),
            Err(AttachmentContentError::InvalidMimeType)
        );

        let mut trailing = manifest().encode().expect("valid manifest");
        trailing.push(0);
        assert!(matches!(
            RecipientAttachmentManifest::decode(&trailing),
            Err(AttachmentContentError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn private_manifest_accepts_exact_maximum_fields_and_rejects_version_skew() {
        let mut maximum = manifest();
        maximum.plaintext_bytes = MAX_FILE_BYTES;
        maximum.file_name = "n".repeat(MAX_FILE_NAME_BYTES);
        maximum.mime_type = format!("a/{}", "b".repeat(MAX_MIME_TYPE_BYTES - 2));
        let encoded = maximum.encode().expect("maximum private fields");
        assert_eq!(RecipientAttachmentManifest::decode(&encoded), Ok(maximum));

        let mut unknown_version = encoded.clone();
        unknown_version[4] = 2;
        assert_eq!(
            RecipientAttachmentManifest::decode(&unknown_version),
            Err(AttachmentContentError::UnsupportedVersion(2))
        );

        let mut reserved = encoded;
        reserved[6] = 1;
        assert_eq!(
            RecipientAttachmentManifest::decode(&reserved),
            Err(AttachmentContentError::ReservedBitsSet)
        );

        let mut oversized_image = manifest();
        oversized_image.kind = AttachmentKind::Image;
        oversized_image.plaintext_bytes = MAX_IMAGE_BYTES + 1;
        assert_eq!(
            oversized_image.validate(),
            Err(AttachmentContentError::InvalidPlaintextLength(
                MAX_IMAGE_BYTES + 1
            ))
        );
    }

    #[test]
    fn recipient_receipt_binds_object_and_plan() {
        let receipt = RecipientAttachmentReceipt {
            object_id: MessageId([7; 16]),
            courier_plan_sha256: [8; SHA256_BYTES],
        };
        let encoded = receipt.encode();
        assert_eq!(RecipientAttachmentReceipt::decode(&encoded), Ok(receipt));
        assert!(receipt.confirms(MessageId([7; 16]), [8; SHA256_BYTES]));
        assert!(!receipt.confirms(MessageId([7; 16]), [9; SHA256_BYTES]));
        assert!(!receipt.confirms(MessageId([6; 16]), [8; SHA256_BYTES]));

        let mut wrong_status = encoded;
        wrong_status[5] = 2;
        assert_eq!(
            RecipientAttachmentReceipt::decode(&wrong_status),
            Err(AttachmentContentError::UnsupportedStatus(2))
        );
    }
}
