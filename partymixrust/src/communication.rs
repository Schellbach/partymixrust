//! Encrypted, metadata-minimal off-chain communication (Section 6.1).
//!
//! Recommended transports: Nostr DMs (NIP-04/44), Signal, or MLS groups.
//! This module defines the payload format only — transport is pluggable.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::shielded_csv::{Coin, Commitment};

/// Encrypted envelope — ciphertext is opaque to the mixer infrastructure.
///
/// Transport layer must not leak sender/recipient metadata beyond what the
/// chosen channel inherently exposes (Section 6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Opaque AEAD ciphertext (e.g. XChaCha20-Poly1305).
    pub ciphertext: Vec<u8>,
    /// Ephemeral or long-lived recipient key fingerprint (not identity).
    pub recipient_key_id: [u8; 32],
    /// Optional nonce / header for the AEAD scheme.
    pub nonce: Vec<u8>,
    /// Protocol version for forward compatibility.
    pub version: u8,
}

/// Plaintext payloads — encrypted before transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "body")]
pub enum MixerPayload {
    /// User → mixer: deposit coin + proof.
    Deposit(DepositPayload),
    /// User → mixer: withdrawal request with fresh destination address.
    WithdrawalRequest(WithdrawalRequestPayload),
    /// Mixer → user: withdrawal delivery.
    WithdrawalDelivery(WithdrawalDeliveryPayload),
    /// Mixer → user: deposit acknowledgement.
    DepositAck(DepositAckPayload),
    /// Mixer → user: error (no sensitive details).
    Error(ErrorPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositPayload {
    pub session_id: Uuid,
    pub coin: Coin,
    pub coin_proof: Vec<u8>,
    /// Opening randomness for user's address commitment (shared out-of-band).
    pub address_opening_rand: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequestPayload {
    pub session_id: Uuid,
    pub amount: u64,
    /// Fresh address commitment — user generates new account per withdrawal.
    pub destination_address: Commitment,
    pub destination_opening_rand: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalDeliveryPayload {
    pub session_id: Uuid,
    pub coin: Coin,
    pub coin_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAckPayload {
    pub session_id: Uuid,
    pub deposit_id: Uuid,
    pub credited_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub session_id: Uuid,
    pub code: ErrorCode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidProof,
    InsufficientBalance,
    RateLimited,
    BatchingDisabled,
    InternalError,
}

/// Recommended channel identifiers for documentation / client config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RecommendedChannel {
    /// Nostr encrypted DM (NIP-04 legacy or NIP-44 v2).
    NostrDm,
    /// Signal private message.
    Signal,
    /// Messaging Layer Security group (multi-party).
    Mls,
}

/// Trait for transport backends — implement per channel.
pub trait SecureChannel: Send + Sync {
    fn send(&self, msg: &EncryptedMessage) -> Result<(), ChannelError>;
    fn receive(&self) -> Result<EncryptedMessage, ChannelError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel error: {0}")]
    Failed(String),
}

/// Serialize payload → encrypt → wrap in `EncryptedMessage`.
///
/// Actual encryption is delegated to the caller's AEAD implementation.
pub fn wrap_payload(payload: &MixerPayload, encrypt: impl FnOnce(&[u8]) -> Vec<u8>) -> EncryptedMessage {
    let plaintext = serde_json::to_vec(payload).expect("payload serializes");
    EncryptedMessage {
        ciphertext: encrypt(&plaintext),
        recipient_key_id: [0u8; 32],
        nonce: vec![],
        version: 1,
    }
}

pub fn unwrap_payload(
    msg: &EncryptedMessage,
    decrypt: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Option<MixerPayload> {
    let plaintext = decrypt(&msg.ciphertext)?;
    serde_json::from_slice(&plaintext).ok()
}
