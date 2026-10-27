//! Bounded application payloads carried only inside authenticated encryption.

pub mod attachment;

use core::fmt;

use relay_wire::MessageId;

pub const MESSAGE_MAGIC: [u8; 4] = *b"RMSG";
pub const RECEIPT_MAGIC: [u8; 4] = *b"RACK";
pub const CONTENT_VERSION: u8 = 1;
pub const REPLY_CONTENT_VERSION: u8 = 2;
pub const DIRECT_TEXT_TYPE: u8 = 1;
pub const DELIVERED_STATUS: u8 = 1;
pub const MESSAGE_HEADER_LEN: usize = 26;
pub const REPLY_MESSAGE_HEADER_LEN: usize = 44;
pub const RECEIPT_LEN: usize = 24;
pub const MAX_TEXT_BYTES: usize = 2_048;
pub const MAX_REPLY_PREVIEW_BYTES: usize = 256;
pub const MAX_DIRECT_TEXT_ENCODED_BYTES: usize =
    REPLY_MESSAGE_HEADER_LEN + MAX_REPLY_PREVIEW_BYTES + MAX_TEXT_BYTES;
pub const WIFI_UPGRADE_OFFER_MAGIC: [u8; 4] = *b"RWUO";
pub const WIFI_UPGRADE_ACK_MAGIC: [u8; 4] = *b"RWUA";
pub const WIFI_UPGRADE_OFFER_LEN: usize = 72;
pub const WIFI_UPGRADE_ACK_LEN: usize = 40;
pub const OFFER_ID_BYTES: usize = 16;
pub const UPGRADE_PSK_BYTES: usize = 32;
pub const WIFI_TOKEN_BYTES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectText {
    pub id: MessageId,
    pub text: String,
    pub reply: Option<ReplyReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyReference {
    pub message_id: MessageId,
    pub preview: String,
}

impl DirectText {
    /// Encodes one exact, bounded UTF-8 text record.
    ///
    /// # Errors
    ///
    /// Returns an error for empty text or text exceeding [`MAX_TEXT_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let text = self.text.as_bytes();
        if text.is_empty() {
            return Err(MessageError::EmptyText);
        }
        if text.len() > MAX_TEXT_BYTES {
            return Err(MessageError::TextTooLarge(text.len()));
        }
        let text_len =
            u16::try_from(text.len()).map_err(|_| MessageError::TextTooLarge(text.len()))?;
        let Some(reply) = &self.reply else {
            let mut encoded = Vec::with_capacity(MESSAGE_HEADER_LEN + text.len());
            encoded.extend_from_slice(&MESSAGE_MAGIC);
            encoded.push(CONTENT_VERSION);
            encoded.push(DIRECT_TEXT_TYPE);
            encoded.extend_from_slice(&[0, 0]);
            encoded.extend_from_slice(&self.id.0);
            encoded.extend_from_slice(&text_len.to_be_bytes());
            encoded.extend_from_slice(text);
            return Ok(encoded);
        };
        if reply.message_id == self.id {
            return Err(MessageError::SelfReply);
        }
        let preview = reply.preview.as_bytes();
        if preview.is_empty() {
            return Err(MessageError::EmptyReplyPreview);
        }
        if preview.len() > MAX_REPLY_PREVIEW_BYTES {
            return Err(MessageError::ReplyPreviewTooLarge(preview.len()));
        }
        let preview_len = u16::try_from(preview.len())
            .map_err(|_| MessageError::ReplyPreviewTooLarge(preview.len()))?;
        let mut encoded = Vec::with_capacity(REPLY_MESSAGE_HEADER_LEN + preview.len() + text.len());
        encoded.extend_from_slice(&MESSAGE_MAGIC);
        encoded.push(REPLY_CONTENT_VERSION);
        encoded.push(DIRECT_TEXT_TYPE);
        encoded.extend_from_slice(&[1, 0]);
        encoded.extend_from_slice(&self.id.0);
        encoded.extend_from_slice(&text_len.to_be_bytes());
        encoded.extend_from_slice(&reply.message_id.0);
        encoded.extend_from_slice(&preview_len.to_be_bytes());
        encoded.extend_from_slice(preview);
        encoded.extend_from_slice(text);
        Ok(encoded)
    }

    /// Decodes exactly one bounded UTF-8 text record and rejects trailing data.
    ///
    /// # Errors
    ///
    /// Returns a structural, bounds, version, or UTF-8 error.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageError> {
        if encoded.len() < MESSAGE_HEADER_LEN {
            return Err(MessageError::Truncated);
        }
        if encoded[..4] != MESSAGE_MAGIC {
            return Err(MessageError::InvalidMagic);
        }
        if encoded[5] != DIRECT_TEXT_TYPE {
            return Err(MessageError::UnsupportedType(encoded[5]));
        }
        let id = MessageId(
            encoded[8..24]
                .try_into()
                .map_err(|_| MessageError::Truncated)?,
        );
        let text_len = usize::from(u16::from_be_bytes(
            encoded[24..26]
                .try_into()
                .map_err(|_| MessageError::Truncated)?,
        ));
        if text_len == 0 {
            return Err(MessageError::EmptyText);
        }
        if text_len > MAX_TEXT_BYTES {
            return Err(MessageError::TextTooLarge(text_len));
        }
        match encoded[4] {
            CONTENT_VERSION => decode_plain_text(encoded, id, text_len),
            REPLY_CONTENT_VERSION => decode_reply(encoded, id, text_len),
            version => Err(MessageError::UnsupportedVersion(version)),
        }
    }
}

fn decode_plain_text(
    encoded: &[u8],
    id: MessageId,
    text_len: usize,
) -> Result<DirectText, MessageError> {
    if encoded[6..8] != [0, 0] {
        return Err(MessageError::ReservedBitsSet);
    }
    require_exact_len(encoded, MESSAGE_HEADER_LEN, text_len)?;
    let text = core::str::from_utf8(&encoded[MESSAGE_HEADER_LEN..])
        .map_err(|_| MessageError::InvalidUtf8)?
        .to_owned();
    Ok(DirectText {
        id,
        text,
        reply: None,
    })
}

fn decode_reply(
    encoded: &[u8],
    id: MessageId,
    text_len: usize,
) -> Result<DirectText, MessageError> {
    if encoded.len() < REPLY_MESSAGE_HEADER_LEN {
        return Err(MessageError::Truncated);
    }
    if encoded[6..8] != [1, 0] {
        return Err(MessageError::InvalidReplyFlags);
    }
    let reply_id = MessageId(
        encoded[26..42]
            .try_into()
            .map_err(|_| MessageError::Truncated)?,
    );
    if reply_id == id {
        return Err(MessageError::SelfReply);
    }
    let preview_len = usize::from(u16::from_be_bytes(
        encoded[42..44]
            .try_into()
            .map_err(|_| MessageError::Truncated)?,
    ));
    if preview_len == 0 {
        return Err(MessageError::EmptyReplyPreview);
    }
    if preview_len > MAX_REPLY_PREVIEW_BYTES {
        return Err(MessageError::ReplyPreviewTooLarge(preview_len));
    }
    require_exact_len(encoded, REPLY_MESSAGE_HEADER_LEN, preview_len + text_len)?;
    let preview_end = REPLY_MESSAGE_HEADER_LEN + preview_len;
    let preview = core::str::from_utf8(&encoded[REPLY_MESSAGE_HEADER_LEN..preview_end])
        .map_err(|_| MessageError::InvalidUtf8)?
        .to_owned();
    let text = core::str::from_utf8(&encoded[preview_end..])
        .map_err(|_| MessageError::InvalidUtf8)?
        .to_owned();
    Ok(DirectText {
        id,
        text,
        reply: Some(ReplyReference {
            message_id: reply_id,
            preview,
        }),
    })
}

fn require_exact_len(
    encoded: &[u8],
    header_len: usize,
    content_len: usize,
) -> Result<(), MessageError> {
    let expected = header_len
        .checked_add(content_len)
        .ok_or(MessageError::LengthOverflow)?;
    if encoded.len() != expected {
        return Err(MessageError::LengthMismatch {
            declared: expected,
            actual: encoded.len(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    pub id: MessageId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiUpgradeOffer {
    pub offer_id: [u8; OFFER_ID_BYTES],
    pub psk: [u8; UPGRADE_PSK_BYTES],
    pub initiator_token: [u8; WIFI_TOKEN_BYTES],
    pub responder_token: [u8; WIFI_TOKEN_BYTES],
}

impl WifiUpgradeOffer {
    #[must_use]
    pub fn encode(self) -> [u8; WIFI_UPGRADE_OFFER_LEN] {
        let mut encoded = [0_u8; WIFI_UPGRADE_OFFER_LEN];
        encoded[..4].copy_from_slice(&WIFI_UPGRADE_OFFER_MAGIC);
        encoded[4] = CONTENT_VERSION;
        encoded[8..24].copy_from_slice(&self.offer_id);
        encoded[24..56].copy_from_slice(&self.psk);
        encoded[56..64].copy_from_slice(&self.initiator_token);
        encoded[64..72].copy_from_slice(&self.responder_token);
        encoded
    }

    /// Decodes one exact Wi-Fi upgrade capability.
    ///
    /// # Errors
    ///
    /// Returns an error for an incorrect length, magic, version, or reserved bits.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageError> {
        validate_fixed_prefix(encoded, WIFI_UPGRADE_OFFER_LEN, WIFI_UPGRADE_OFFER_MAGIC)?;
        Ok(Self {
            offer_id: read_fixed(encoded, 8)?,
            psk: read_fixed(encoded, 24)?,
            initiator_token: read_fixed(encoded, 56)?,
            responder_token: read_fixed(encoded, 64)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiUpgradeAck {
    pub offer_id: [u8; OFFER_ID_BYTES],
    pub initiator_token: [u8; WIFI_TOKEN_BYTES],
    pub responder_token: [u8; WIFI_TOKEN_BYTES],
}

impl WifiUpgradeAck {
    #[must_use]
    pub fn encode(self) -> [u8; WIFI_UPGRADE_ACK_LEN] {
        let mut encoded = [0_u8; WIFI_UPGRADE_ACK_LEN];
        encoded[..4].copy_from_slice(&WIFI_UPGRADE_ACK_MAGIC);
        encoded[4] = CONTENT_VERSION;
        encoded[8..24].copy_from_slice(&self.offer_id);
        encoded[24..32].copy_from_slice(&self.initiator_token);
        encoded[32..40].copy_from_slice(&self.responder_token);
        encoded
    }

    /// Decodes one exact Wi-Fi upgrade acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error for an incorrect length, magic, version, or reserved bits.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageError> {
        validate_fixed_prefix(encoded, WIFI_UPGRADE_ACK_LEN, WIFI_UPGRADE_ACK_MAGIC)?;
        Ok(Self {
            offer_id: read_fixed(encoded, 8)?,
            initiator_token: read_fixed(encoded, 24)?,
            responder_token: read_fixed(encoded, 32)?,
        })
    }
}

fn validate_fixed_prefix(
    encoded: &[u8],
    expected_len: usize,
    magic: [u8; 4],
) -> Result<(), MessageError> {
    if encoded.len() != expected_len {
        return Err(MessageError::InvalidControlLength(encoded.len()));
    }
    if encoded[..4] != magic {
        return Err(MessageError::InvalidMagic);
    }
    if encoded[4] != CONTENT_VERSION {
        return Err(MessageError::UnsupportedVersion(encoded[4]));
    }
    if encoded[5..8] != [0, 0, 0] {
        return Err(MessageError::ReservedBitsSet);
    }
    Ok(())
}

fn read_fixed<const SIZE: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], MessageError> {
    encoded
        .get(offset..offset + SIZE)
        .ok_or(MessageError::Truncated)?
        .try_into()
        .map_err(|_| MessageError::Truncated)
}

impl DeliveryReceipt {
    #[must_use]
    pub fn encode(self) -> [u8; RECEIPT_LEN] {
        let mut encoded = [0_u8; RECEIPT_LEN];
        encoded[..4].copy_from_slice(&RECEIPT_MAGIC);
        encoded[4] = CONTENT_VERSION;
        encoded[5] = DELIVERED_STATUS;
        encoded[8..24].copy_from_slice(&self.id.0);
        encoded
    }

    /// Decodes one exact delivered receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for incorrect length, magic, version, status, or reserved bits.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageError> {
        if encoded.len() != RECEIPT_LEN {
            return Err(MessageError::InvalidReceiptLength(encoded.len()));
        }
        if encoded[..4] != RECEIPT_MAGIC {
            return Err(MessageError::InvalidMagic);
        }
        if encoded[4] != CONTENT_VERSION {
            return Err(MessageError::UnsupportedVersion(encoded[4]));
        }
        if encoded[5] != DELIVERED_STATUS {
            return Err(MessageError::UnsupportedStatus(encoded[5]));
        }
        if encoded[6..8] != [0, 0] {
            return Err(MessageError::ReservedBitsSet);
        }
        Ok(Self {
            id: MessageId(
                encoded[8..24]
                    .try_into()
                    .map_err(|_| MessageError::Truncated)?,
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedType(u8),
    UnsupportedStatus(u8),
    ReservedBitsSet,
    EmptyText,
    TextTooLarge(usize),
    EmptyReplyPreview,
    ReplyPreviewTooLarge(usize),
    InvalidReplyFlags,
    SelfReply,
    InvalidUtf8,
    LengthOverflow,
    LengthMismatch { declared: usize, actual: usize },
    InvalidReceiptLength(usize),
    InvalidControlLength(usize),
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MessageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip_preserves_unicode_exactly() {
        let message = DirectText {
            id: MessageId([7; 16]),
            text: "hello offline 🌍 नमस्ते".to_owned(),
            reply: None,
        };
        let encoded = message.encode().expect("encode");
        assert_eq!(DirectText::decode(&encoded), Ok(message));
    }

    #[test]
    fn text_bounds_and_trailing_data_are_rejected() {
        let empty = DirectText {
            id: MessageId([1; 16]),
            text: String::new(),
            reply: None,
        };
        assert_eq!(empty.encode(), Err(MessageError::EmptyText));
        let oversized = DirectText {
            id: MessageId([1; 16]),
            text: "x".repeat(MAX_TEXT_BYTES + 1),
            reply: None,
        };
        assert_eq!(
            oversized.encode(),
            Err(MessageError::TextTooLarge(MAX_TEXT_BYTES + 1))
        );
        let mut encoded = DirectText {
            id: MessageId([2; 16]),
            text: "bounded".to_owned(),
            reply: None,
        }
        .encode()
        .expect("encode");
        encoded.push(0);
        assert!(matches!(
            DirectText::decode(&encoded),
            Err(MessageError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn malformed_utf8_is_rejected() {
        let mut encoded = DirectText {
            id: MessageId([3; 16]),
            text: "a".to_owned(),
            reply: None,
        }
        .encode()
        .expect("encode");
        encoded[MESSAGE_HEADER_LEN] = 0xFF;
        assert_eq!(DirectText::decode(&encoded), Err(MessageError::InvalidUtf8));
    }

    #[test]
    fn reply_round_trip_binds_original_id_preview_and_body() {
        let message = DirectText {
            id: MessageId([4; 16]),
            text: "I am at the east gate".to_owned(),
            reply: Some(ReplyReference {
                message_id: MessageId([5; 16]),
                preview: "Where are you?".to_owned(),
            }),
        };
        let encoded = message.encode().expect("encode reply");
        assert_eq!(encoded[4], REPLY_CONTENT_VERSION);
        assert_eq!(DirectText::decode(&encoded), Ok(message));
    }

    #[test]
    fn reply_bounds_and_flags_are_rejected() {
        let message = DirectText {
            id: MessageId([4; 16]),
            text: "body".to_owned(),
            reply: Some(ReplyReference {
                message_id: MessageId([5; 16]),
                preview: "p".repeat(MAX_REPLY_PREVIEW_BYTES),
            }),
        };
        let mut encoded = message.encode().expect("encode maximum reply preview");
        encoded[6] = 3;
        assert_eq!(
            DirectText::decode(&encoded),
            Err(MessageError::InvalidReplyFlags),
        );

        let oversized = DirectText {
            id: MessageId([6; 16]),
            text: "body".to_owned(),
            reply: Some(ReplyReference {
                message_id: MessageId([7; 16]),
                preview: "p".repeat(MAX_REPLY_PREVIEW_BYTES + 1),
            }),
        };
        assert_eq!(
            oversized.encode(),
            Err(MessageError::ReplyPreviewTooLarge(
                MAX_REPLY_PREVIEW_BYTES + 1,
            )),
        );
    }

    #[test]
    fn delivery_receipt_is_exact_and_bound_to_message_id() {
        let receipt = DeliveryReceipt {
            id: MessageId([9; 16]),
        };
        let encoded = receipt.encode();
        assert_eq!(DeliveryReceipt::decode(&encoded), Ok(receipt));
        let mut wrong_status = encoded;
        wrong_status[5] = 2;
        assert_eq!(
            DeliveryReceipt::decode(&wrong_status),
            Err(MessageError::UnsupportedStatus(2))
        );
    }

    #[test]
    fn wifi_upgrade_capability_and_ack_are_exact() {
        let offer = WifiUpgradeOffer {
            offer_id: [1; OFFER_ID_BYTES],
            psk: [2; UPGRADE_PSK_BYTES],
            initiator_token: [3; WIFI_TOKEN_BYTES],
            responder_token: [4; WIFI_TOKEN_BYTES],
        };
        let encoded = offer.encode();
        assert_eq!(WifiUpgradeOffer::decode(&encoded), Ok(offer));
        let ack = WifiUpgradeAck {
            offer_id: offer.offer_id,
            initiator_token: offer.initiator_token,
            responder_token: offer.responder_token,
        };
        assert_eq!(WifiUpgradeAck::decode(&ack.encode()), Ok(ack));
        assert_eq!(
            WifiUpgradeOffer::decode(&encoded[..encoded.len() - 1]),
            Err(MessageError::InvalidControlLength(encoded.len() - 1))
        );
    }
}
