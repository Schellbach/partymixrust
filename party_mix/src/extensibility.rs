//! Extensibility hooks for future protocol features (Appendix A.1).

use crate::shielded_csv::{AcctStateEssence, CoinEssence, PublicKey, ToSAccValue};

/// t-of-n shared account spending (Section 5.1, MuSig2/FROST + sign-to-contract).
pub trait SharedAccountPolicy: Send + Sync {
    type SigningSession;

    fn threshold(&self) -> u32;
    fn total_owners(&self) -> u32;

    fn begin_signing_session(&self, tx_hash: &[u8; 32]) -> Self::SigningSession;
    fn contribute_signature(&self, session: &mut Self::SigningSession, partial: Vec<u8>) -> bool;
    fn finalize_signature(&self, session: &Self::SigningSession) -> Option<Vec<u8>>;
}

/// Time-locked transactions (Appendix A.1.1).
pub trait TimelockPolicy: Send + Sync {
    fn unlock_height(&self) -> u64;
    fn is_unlocked(&self, current_height: u64) -> bool;
}

/// Atomic swap coordination (Appendix A.1.2).
pub trait AtomicSwapCoordinator: Send + Sync {
    fn initiate_swap(
        &self,
        our_coin: &CoinEssence,
        their_nullifier_pk: PublicKey,
        timeout_nav: ToSAccValue,
    ) -> Result<SwapSession, SwapError>;

    fn complete_swap(&self, session: &SwapSession) -> Result<(), SwapError>;
}

#[derive(Debug, Clone)]
pub struct SwapSession {
    pub session_id: [u8; 32],
    pub conditional_nav: ToSAccValue,
}

#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    #[error("swap failed: {0}")]
    Failed(String),
}

/// Multi-asset support (Appendix A.1.3).
pub trait AssetId: Copy + Eq + std::hash::Hash + Send + Sync + 'static {
    fn zero() -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BtcAsset;

impl AssetId for BtcAsset {
    fn zero() -> Self {
        BtcAsset
    }
}

/// Asset-tagged coin essence for future multi-asset pools.
#[derive(Debug, Clone)]
pub struct MultiAssetCoinEssence<A: AssetId> {
    pub asset: A,
    pub essence: CoinEssence,
}

/// Multi-operator pool governance placeholder.
pub trait PoolGovernance: Send + Sync {
    fn authorize_withdrawal(&self, operator_id: &[u8; 32], amount: u64) -> bool;
    fn authorize_consolidation(&self, operator_id: &[u8; 32]) -> bool;
}

/// No-op shared account stub.
#[derive(Debug, Default)]
pub struct SingleOperatorPolicy;

impl SharedAccountPolicy for SingleOperatorPolicy {
    type SigningSession = Vec<u8>;

    fn threshold(&self) -> u32 {
        1
    }

    fn total_owners(&self) -> u32 {
        1
    }

    fn begin_signing_session(&self, _tx_hash: &[u8; 32]) -> Self::SigningSession {
        vec![]
    }

    fn contribute_signature(&self, _session: &mut Self::SigningSession, _partial: Vec<u8>) -> bool {
        true
    }

    fn finalize_signature(&self, _session: &Self::SigningSession) -> Option<Vec<u8>> {
        Some(vec![])
    }
}

/// Placeholder timelock — always unlocked.
#[derive(Debug, Default)]
pub struct NoTimelock;

impl TimelockPolicy for NoTimelock {
    fn unlock_height(&self) -> u64 {
        0
    }

    fn is_unlocked(&self, _current_height: u64) -> bool {
        true
    }
}

/// Pool account metadata for shared-operator setups.
#[derive(Debug, Clone)]
pub struct SharedPoolAccountMeta {
    pub essence: AcctStateEssence,
    pub threshold: u32,
    pub owner_pks: Vec<PublicKey>,
}
