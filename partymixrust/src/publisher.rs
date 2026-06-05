//! Publisher service — aggregate nullifier construction (Section 4.2).
//!
//! Uses `PaymentInitOutputFee` + `payment_finalize_fee` so the mixer earns
//! the protocol-native publisher fee when first to post a nullifier.

use tracing::info;

use crate::crypto::nisshac::{state_update_message, NisshacBackend};
use crate::shielded_csv::{
    AggregateNullifier, Commitment, PaymentInitOutputFee, PublicKey, Signature,
};
use crate::types::MixerConfig;

#[derive(Debug, thiserror::Error)]
pub enum PublisherError {
    #[error("invalid fee output proof")]
    InvalidFeeProof,
    #[error("aggregation failed: {0}")]
    AggregationFailed(String),
    #[error("fee mismatch: expected {expected}, got {actual}")]
    FeeMismatch { expected: u64, actual: u64 },
}

/// Pending nullifier awaiting aggregation and broadcast.
#[derive(Debug, Clone)]
pub struct PendingNullifier<N: NisshacBackend> {
    pub nullifier_pk: PublicKey,
    pub signature: N::Signature,
    pub fee_output: PaymentInitOutputFee,
    pub fee_proof: Vec<u8>,
}

/// Mixer-as-publisher: collects nullifiers, half-aggregates NISSHAC sigs.
pub struct Publisher<N: NisshacBackend> {
    nisshac: N,
    config: MixerConfig,
    pending: Vec<PendingNullifier<N>>,
    fee_address: Commitment,
}

impl<N: NisshacBackend> Publisher<N> {
    pub fn new(nisshac: N, config: MixerConfig, fee_address: Commitment) -> Self {
        Self {
            nisshac,
            config,
            pending: Vec::new(),
            fee_address,
        }
    }

    /// Collect `PaymentInitOutputFee` from a payment_init step (Section 4.2).
    pub fn submit_nullifier(
        &mut self,
        pending: PendingNullifier<N>,
    ) -> Result<(), PublisherError> {
        if pending.fee_output.fee < self.config.publisher_fee {
            return Err(PublisherError::FeeMismatch {
                expected: self.config.publisher_fee,
                actual: pending.fee_output.fee,
            });
        }
        // TODO: PCDVerify fee_output + fee_proof
        self.pending.push(pending);
        Ok(())
    }

    /// Build aggregate nullifier with half-aggregated NISSHAC (Section 4.1).
    pub fn build_aggregate_nullifier(&self) -> Result<AggregateNullifier, PublisherError> {
        if self.pending.is_empty() {
            return Err(PublisherError::AggregationFailed("no pending nullifiers".into()));
        }

        let msg = state_update_message();
        let sigs: Vec<(N::Signature, PublicKey, secp256k1::Message)> = self
            .pending
            .iter()
            .map(|p| (p.signature.clone(), p.nullifier_pk, msg))
            .collect();

        let agg = self
            .nisshac
            .aggregate(&sigs)
            .map_err(|e| PublisherError::AggregationFailed(e.to_string()))?;

        let pks: Vec<PublicKey> = self.pending.iter().map(|p| p.nullifier_pk).collect();

        info!(count = pks.len(), "built aggregate nullifier");

        Ok(AggregateNullifier {
            pks,
            sig: agg,
            fee_acct_comm: self.fee_address,
        })
    }

    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Verify an incoming aggregate nullifier (as a node would in `process_block`).
pub fn verify_aggregate_nullifier(agg: &AggregateNullifier) -> bool {
    let msg = state_update_message();
    let pm_aggd: Vec<(PublicKey, secp256k1::Message)> = agg
        .pks
        .iter()
        .map(|pk| (*pk, msg))
        .collect();
    Signature::agg_verify(&agg.sig, pm_aggd)
}
