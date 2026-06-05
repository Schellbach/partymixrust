//! Cryptographic primitives from Shielded CSV Section 3.
//!
//! Concrete backends are abstracted behind traits in [`crate::crypto`].

use secp256k1::{Keypair, SecretKey as Secp256k1SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::shielded_csv::protocol::{BlockchainLocation, EdgeLabel, LocalInput};

pub type PublicKey = XOnlyPublicKey;
pub type SecretKey = Secp256k1SecretKey;

pub fn hash(data: &[u8]) -> [u8; 32] {
    // TODO: replace with domain-separated hash (paper uses implicit pp)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    let v = h.finish();
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// Binding + hiding commitment (Pedersen, Section 4.2).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    pub fn commit(msg: &[u8; 32], rand: &[u8; 32]) -> Self {
        // TODO: Pedersen commitment over secp256k1
        Self(hash(&[msg.as_slice(), rand.as_slice()].concat()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// NISSHAC aggregate signature (Section 4.1).
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

/// Sign-to-contract commitment R_i (Section 4.1).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct SigCommitment(pub [u8; 32]);

impl SigCommitment {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Signature {
    pub fn keygen_pub(sk: &SecretKey) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, sk);
        XOnlyPublicKey::from_keypair(&keypair).0
    }

    pub fn agg_verify(_sig: &Signature, _pm_aggd: Vec<(PublicKey, secp256k1::Message)>) -> bool {
        // TODO: NISSHAC SigAggregateVerify (Section 4.1)
        true
    }

    pub fn commit_retrieve(_sig: &Signature, _i: usize) -> SigCommitment {
        // TODO: SigCommRetrieve
        SigCommitment([0u8; 32])
    }

    pub fn commit_verify(_comm: SigCommitment, _msg: &[u8; 32], _pk: &PublicKey) -> bool {
        // TODO: SigCommVerify
        true
    }
}

/// Spent accumulator value (Section 3.5, per-account).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct AccValue(pub [u8; 32]);

/// Spent accumulator manager state.
pub struct AccM {
    value: AccValue,
}

impl AccM {
    pub fn new() -> Self {
        Self {
            value: AccValue([0u8; 32]),
        }
    }

    pub fn value(state: &AccM) -> AccValue {
        state.value
    }

    pub fn prove_non_membership_and_insert(
        state: &AccM,
        elements: Vec<[u8; 8]>,
    ) -> (AccM, Vec<u8>) {
        // TODO: AccMProveNonMembershipAndInsert (Section 3.5)
        let _ = elements;
        (state.clone(), vec![])
    }
}

impl Clone for AccM {
    fn clone(&self) -> Self {
        Self { value: self.value }
    }
}

pub struct AccV;

impl AccV {
    pub fn new() -> AccValue {
        AccValue([0u8; 32])
    }

    pub fn verify_non_membership_and_insert(
        _v: &AccValue,
        _v_prime: &AccValue,
        _elements: Vec<[u8; 8]>,
        _proof: &[u8],
    ) -> bool {
        // TODO: AccVVerifyNonMembershipAndInsert
        true
    }
}

/// ToS-accumulator element: (nullifier_pk, tx_comm, blockchain_loc, fee_acct_comm).
pub type ToSAccSetElement = (PublicKey, SigCommitment, BlockchainLocation, Commitment);

/// Nullifier accumulator value (Section 3.6).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct ToSAccValue(pub [u8; 32]);

pub struct ToSAccM {
    value: ToSAccValue,
    depth: u32,
}

impl ToSAccM {
    pub fn new() -> Self {
        Self {
            value: ToSAccValue([0u8; 32]),
            depth: 0,
        }
    }

    pub fn value(state: &ToSAccM) -> ToSAccValue {
        state.value
    }

    /// Append a block's nullifier set (Section 4.2 `process_block`).
    pub fn append_set(
        state: &ToSAccM,
        set: Vec<ToSAccSetElement>,
    ) -> Self {
        // TODO: ToSAccMAppendSet
        let _ = set;
        Self {
            value: ToSAccValue(hash(&state.value.0)),
            depth: state.depth + 1,
        }
    }

    /// Remove last appended set — used during reorg (Section 4.2).
    pub fn remove_set(state: &ToSAccM) -> Self {
        // TODO: ToSAccMRemoveSet
        Self {
            value: state.value,
            depth: state.depth.saturating_sub(1),
        }
    }

    pub fn prove_union_membership(_state: &ToSAccM, _element: ToSAccSetElement) -> Vec<u8> {
        vec![]
    }

    pub fn prove_is_prefix(_states: &[ToSAccM], _state_prime: &ToSAccM) -> Vec<u8> {
        vec![]
    }

    pub fn prove_distinct_element(_state: &ToSAccM, _state_prime: &ToSAccM) -> Vec<u8> {
        vec![]
    }
}

impl Clone for ToSAccM {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            depth: self.depth,
        }
    }
}

pub struct ToSAccV;

impl ToSAccV {
    pub fn verify_union_membership(
        _v: &ToSAccValue,
        _element: ToSAccSetElement,
        _proof: &[u8],
    ) -> bool {
        true
    }

    pub fn verify_is_prefix(
        _v: &[ToSAccValue],
        _v_prime: &ToSAccValue,
        _proof: &[u8],
    ) -> bool {
        true
    }

    pub fn verify_distinct_element(
        _v: &ToSAccValue,
        _v_prime: &ToSAccValue,
        _proof: &[u8],
    ) -> bool {
        true
    }
}

/// PCD proving/verification (Section 3.7).
pub struct PCD;
pub struct PCDProvKey;
pub struct PCDVerKey;

impl PCD {
    pub fn keygen() -> (PCDProvKey, PCDVerKey) {
        (PCDProvKey, PCDVerKey)
    }

    pub fn prove(
        _prk: &PCDProvKey,
        _z: EdgeLabel,
        _w_loc: LocalInput,
        _z_in: &[EdgeLabel],
        _proofs_in: &[Vec<u8>],
    ) -> Vec<u8> {
        // TODO: recursive STARK / folding backend
        b"MOCK_PCD_PROOF".to_vec()
    }

    pub fn verify(_vk: &PCDVerKey, _z: EdgeLabel, proof: &[u8]) -> bool {
        proof.starts_with(b"MOCK_PCD_PROOF")
    }
}
