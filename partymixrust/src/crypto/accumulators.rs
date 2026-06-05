//! Accumulator backend traits (Section 3.5, 3.6).

use crate::shielded_csv::{
    AccValue, BlockchainLocation, Commitment, PublicKey, SigCommitment, ToSAccSetElement,
    ToSAccValue,
};

/// Per-account spent accumulator (Section 3.5).
pub trait SpentAccumulatorBackend: Send + Sync {
    type ManagerState: Clone;
    type Proof: AsRef<[u8]>;

    fn new_manager(&self) -> Self::ManagerState;
    fn value(&self, state: &Self::ManagerState) -> AccValue;

    fn prove_non_membership_and_insert(
        &self,
        state: &Self::ManagerState,
        coin_on_chain_ids: Vec<[u8; 8]>,
    ) -> Result<(Self::ManagerState, Self::Proof), AccumulatorError>;

    fn verify_non_membership_and_insert(
        &self,
        old: &AccValue,
        new: &AccValue,
        coin_on_chain_ids: Vec<[u8; 8]>,
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError>;
}

/// Global nullifier ToS-accumulator (Section 3.6).
pub trait NullifierAccumulatorBackend: Send + Sync {
    type ManagerState: Clone;
    type Proof: AsRef<[u8]>;

    fn new_manager(&self) -> Self::ManagerState;
    fn value(&self, state: &Self::ManagerState) -> ToSAccValue;

    fn append_set(
        &self,
        state: &Self::ManagerState,
        set: Vec<ToSAccSetElement>,
    ) -> Self::ManagerState;

    /// `ToSAccMRemoveSet` — reorg handling (Section 4.2).
    fn remove_set(&self, state: &Self::ManagerState) -> Self::ManagerState;

    fn prove_union_membership(
        &self,
        state: &Self::ManagerState,
        element: ToSAccSetElement,
    ) -> Result<Self::Proof, AccumulatorError>;

    fn prove_is_prefix(
        &self,
        states: &[Self::ManagerState],
        target: &Self::ManagerState,
    ) -> Result<Self::Proof, AccumulatorError>;

    fn prove_distinct_element(
        &self,
        a: &Self::ManagerState,
        b: &Self::ManagerState,
    ) -> Result<Self::Proof, AccumulatorError>;

    fn verify_union_membership(
        &self,
        value: &ToSAccValue,
        element: (PublicKey, SigCommitment, BlockchainLocation, Commitment),
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError>;

    fn verify_is_prefix(
        &self,
        values: &[ToSAccValue],
        target: &ToSAccValue,
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError>;

    fn verify_distinct_element(
        &self,
        a: &ToSAccValue,
        b: &ToSAccValue,
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AccumulatorError {
    #[error("accumulator operation failed: {0}")]
    OperationFailed(String),
}
