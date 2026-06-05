//! PCD proving/verification trait (Section 3.7).

use crate::shielded_csv::{EdgeLabel, LocalInput};

/// Backend-agnostic PCD interface.
///
/// Implementations must provide efficient (history-independent) proving and
/// statistical zero-knowledge (Section 3.7, 6.4).
pub trait PcdBackend: Send + Sync {
    type ProvKey;
    type VerKey;

    fn keygen(&self) -> (Self::ProvKey, Self::VerKey);

    fn prove(
        &self,
        prk: &Self::ProvKey,
        z: &EdgeLabel,
        w_loc: &LocalInput,
        z_in: &[EdgeLabel],
        proofs_in: &[Vec<u8>],
    ) -> Result<Vec<u8>, PcdError>;

    fn verify(&self, vk: &Self::VerKey, z: &EdgeLabel, proof: &[u8]) -> Result<bool, PcdError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PcdError {
    #[error("proving failed: {0}")]
    ProveFailed(String),
    #[error("verification failed: {0}")]
    VerifyFailed(String),
}
