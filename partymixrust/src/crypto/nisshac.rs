//! NISSHAC signature backend (Section 4.1).

use secp256k1::Message;

use crate::shielded_csv::{PublicKey, SigCommitment, Signature};

/// Non-interactive Schnorr Signature Half-Aggregation with Commitments.
pub trait NisshacBackend: Send + Sync {
    type SecretKey;
    type Signature: Clone;

    fn keygen(&self) -> (Self::SecretKey, PublicKey);

    fn sign_to_contract(
        &self,
        sk: &Self::SecretKey,
        message: &Message,
        tx_hash: &[u8; 32],
    ) -> Result<(Self::Signature, SigCommitment, [u8; 32]), NisshacError>;

    fn aggregate(
        &self,
        signatures: &[(Self::Signature, PublicKey, Message)],
    ) -> Result<Signature, NisshacError>;

    fn verify_aggregate(
        &self,
        sig: &Signature,
        pks_and_msgs: Vec<(PublicKey, Message)>,
    ) -> Result<bool, NisshacError>;

    fn commit_retrieve(&self, sig: &Signature, index: usize) -> SigCommitment;

    fn commit_verify(
        &self,
        comm: SigCommitment,
        tx_hash: &[u8; 32],
        pk: &PublicKey,
    ) -> Result<bool, NisshacError>;
}

#[derive(Debug, thiserror::Error)]
pub enum NisshacError {
    #[error("NISSHAC error: {0}")]
    Failed(String),
}

/// Fixed NISSHAC message (Section 4.2).
pub fn state_update_message() -> Message {
    Message::from_digest_slice(b"Shielded CSV: state update").expect("valid message length")
}
