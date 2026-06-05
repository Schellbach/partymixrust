//! Mock cryptographic backends for development and testing.

use secp256k1::Message;

use super::accumulators::{AccumulatorError, NullifierAccumulatorBackend, SpentAccumulatorBackend};
use super::nisshac::{NisshacBackend, NisshacError};
use super::pcd::{PcdBackend, PcdError};
use crate::shielded_csv::{
    AccValue, BlockchainLocation, Commitment, EdgeLabel, LocalInput, PublicKey, SigCommitment,
    Signature, ToSAccSetElement, ToSAccValue,
};

const MOCK_PCD_PREFIX: &[u8] = b"MOCK_PCD_PROOF";

#[derive(Debug, Default, Clone)]
pub struct MockPcd;

impl PcdBackend for MockPcd {
    type ProvKey = ();
    type VerKey = ();

    fn keygen(&self) -> (Self::ProvKey, Self::VerKey) {
        ((), ())
    }

    fn prove(
        &self,
        _prk: &Self::ProvKey,
        _z: &EdgeLabel,
        _w_loc: &LocalInput,
        _z_in: &[EdgeLabel],
        _proofs_in: &[Vec<u8>],
    ) -> Result<Vec<u8>, PcdError> {
        Ok(MOCK_PCD_PREFIX.to_vec())
    }

    fn verify(&self, _vk: &Self::VerKey, _z: &EdgeLabel, proof: &[u8]) -> Result<bool, PcdError> {
        Ok(proof.starts_with(MOCK_PCD_PREFIX))
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockSpentAccumulator;

#[derive(Debug, Clone)]
pub struct MockSpentState {
    pub value: AccValue,
    pub inserted: Vec<[u8; 8]>,
}

impl SpentAccumulatorBackend for MockSpentAccumulator {
    type ManagerState = MockSpentState;
    type Proof = Vec<u8>;

    fn new_manager(&self) -> Self::ManagerState {
        MockSpentState {
            value: AccValue([0u8; 32]),
            inserted: vec![],
        }
    }

    fn value(&self, state: &Self::ManagerState) -> AccValue {
        state.value
    }

    fn prove_non_membership_and_insert(
        &self,
        state: &Self::ManagerState,
        coin_on_chain_ids: Vec<[u8; 8]>,
    ) -> Result<(Self::ManagerState, Self::Proof), AccumulatorError> {
        let mut next = state.clone();
        next.inserted.extend(coin_on_chain_ids);
        next.value = AccValue(crate::shielded_csv::hash(&format!("{:?}", next.inserted).into_bytes()));
        Ok((next, b"mock_snmi".to_vec()))
    }

    fn verify_non_membership_and_insert(
        &self,
        _old: &AccValue,
        _new: &AccValue,
        _coin_on_chain_ids: Vec<[u8; 8]>,
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError> {
        Ok(proof == b"mock_snmi")
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockNullifierAccumulator;

#[derive(Debug, Clone)]
pub struct MockNullifierState {
    pub value: ToSAccValue,
    pub sets: Vec<Vec<ToSAccSetElement>>,
}

impl NullifierAccumulatorBackend for MockNullifierAccumulator {
    type ManagerState = MockNullifierState;
    type Proof = Vec<u8>;

    fn new_manager(&self) -> Self::ManagerState {
        MockNullifierState {
            value: ToSAccValue([0u8; 32]),
            sets: vec![],
        }
    }

    fn value(&self, state: &Self::ManagerState) -> ToSAccValue {
        state.value
    }

    fn append_set(
        &self,
        state: &Self::ManagerState,
        set: Vec<ToSAccSetElement>,
    ) -> Self::ManagerState {
        let mut next = state.clone();
        next.sets.push(set);
        next.value = ToSAccValue(crate::shielded_csv::hash(
            &format!("{:?}", next.sets.len()).into_bytes(),
        ));
        next
    }

    fn remove_set(&self, state: &Self::ManagerState) -> Self::ManagerState {
        let mut next = state.clone();
        next.sets.pop();
        next.value = ToSAccValue(crate::shielded_csv::hash(
            &format!("{:?}", next.sets.len()).into_bytes(),
        ));
        next
    }

    fn prove_union_membership(
        &self,
        _state: &Self::ManagerState,
        _element: ToSAccSetElement,
    ) -> Result<Self::Proof, AccumulatorError> {
        Ok(b"mock_nm".to_vec())
    }

    fn prove_is_prefix(
        &self,
        _states: &[Self::ManagerState],
        _target: &Self::ManagerState,
    ) -> Result<Self::Proof, AccumulatorError> {
        Ok(b"mock_nap".to_vec())
    }

    fn prove_distinct_element(
        &self,
        _a: &Self::ManagerState,
        _b: &Self::ManagerState,
    ) -> Result<Self::Proof, AccumulatorError> {
        Ok(b"mock_distinct".to_vec())
    }

    fn verify_union_membership(
        &self,
        _value: &ToSAccValue,
        _element: (PublicKey, SigCommitment, BlockchainLocation, Commitment),
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError> {
        Ok(proof == b"mock_nm")
    }

    fn verify_is_prefix(
        &self,
        _values: &[ToSAccValue],
        _target: &ToSAccValue,
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError> {
        Ok(proof == b"mock_nap")
    }

    fn verify_distinct_element(
        &self,
        _a: &ToSAccValue,
        _b: &ToSAccValue,
        proof: &Self::Proof,
    ) -> Result<bool, AccumulatorError> {
        Ok(proof == b"mock_distinct")
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockNisshac;

impl NisshacBackend for MockNisshac {
    type SecretKey = [u8; 32];
    type Signature = Vec<u8>;

    fn keygen(&self) -> (Self::SecretKey, PublicKey) {
        let sk = [1u8; 32];
        let pk = crate::shielded_csv::Signature::keygen_pub(
            &secp256k1::SecretKey::from_slice(&sk).unwrap(),
        );
        (sk, pk)
    }

    fn sign_to_contract(
        &self,
        _sk: &Self::SecretKey,
        _message: &Message,
        tx_hash: &[u8; 32],
    ) -> Result<(Self::Signature, SigCommitment, [u8; 32]), NisshacError> {
        Ok((
            b"mock_sig".to_vec(),
            SigCommitment(*tx_hash),
            [2u8; 32],
        ))
    }

    fn aggregate(
        &self,
        signatures: &[(Self::Signature, PublicKey, Message)],
    ) -> Result<Signature, NisshacError> {
        let _ = signatures;
        Ok(Signature(b"mock_agg_sig".to_vec()))
    }

    fn verify_aggregate(
        &self,
        sig: &Signature,
        _pks_and_msgs: Vec<(PublicKey, Message)>,
    ) -> Result<bool, NisshacError> {
        Ok(sig.0 == b"mock_agg_sig")
    }

    fn commit_retrieve(&self, _sig: &Signature, _index: usize) -> SigCommitment {
        SigCommitment([3u8; 32])
    }

    fn commit_verify(
        &self,
        _comm: SigCommitment,
        _tx_hash: &[u8; 32],
        _pk: &PublicKey,
    ) -> Result<bool, NisshacError> {
        Ok(true)
    }
}
