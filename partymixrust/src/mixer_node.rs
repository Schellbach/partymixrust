//! `MixerNode` — extends Shielded CSV `Node` with mixer operations.
//!
//! Implements `process_block`, `accept_payment`, and reorg handling via
//! conditional NAV + `ToSAccMRemoveSet` (Section 4.2).

use std::collections::HashMap;

use tracing::{info, warn};

use crate::crypto::pcd::PcdBackend;
use crate::shielded_csv::{
    AggregateNullifier, BlockchainLocation, Coin, Commitment, EdgeLabel, PublicKey,
    SigCommitment, Signature, ToSAccM, ToSAccValue,
};
use crate::types::{AuditEventType, MixerConfig, PrivacyAuditEvent};
use crate::wallet_state::{NullifierKvEntry, WalletState};

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("invalid aggregate nullifier signature")]
    InvalidAggregateNullifier,
    #[error("payment rejected: invalid proof or accumulator")]
    PaymentRejected,
    #[error("reorg deeper than tracked history")]
    ReorgTooDeep,
}

/// Shielded CSV node extended for mixer operation.
pub struct MixerNode<P: PcdBackend> {
    pub config: MixerConfig,
    pub wallet: WalletState,
    pub nullifier_accum: ToSAccM,
    pub pcd: P,
    pub pcd_vk: P::VerKey,
    /// Current chain tip height.
    pub chain_height: u64,
}

impl<P: PcdBackend> MixerNode<P> {
    pub fn new(config: MixerConfig, wallet: WalletState, pcd: P) -> Self {
        let (_, vk) = pcd.keygen();
        Self {
            config,
            wallet,
            nullifier_accum: ToSAccM::new(),
            pcd,
            pcd_vk: vk,
            chain_height: 0,
        }
    }

    /// Scan block for aggregate nullifiers; update ToS-accumulator + KV store.
    ///
    /// See Section 4.2 `process_block`. Duplicate nullifier PKs are ignored
    /// to prevent double-nullification attacks.
    pub fn process_block(
        &mut self,
        block_height: u64,
        aggregate_nullifiers: Vec<AggregateNullifier>,
    ) -> Result<(), NodeError> {
        let msg = secp256k1::Message::from_digest_slice(b"Shielded CSV: state update")
            .expect("valid message");

        let mut loc = block_height * 2u64.pow(24);
        let mut block_nullifiers: Vec<(
            PublicKey,
            SigCommitment,
            BlockchainLocation,
            Commitment,
        )> = Vec::new();

        for aggregate_nullifier in aggregate_nullifiers {
            let pm_aggd: Vec<(PublicKey, secp256k1::Message)> = aggregate_nullifier
                .pks
                .iter()
                .map(|pk| (*pk, msg))
                .collect();

            if !Signature::agg_verify(&aggregate_nullifier.sig, pm_aggd) {
                warn!(block_height, "skipping invalid aggregate nullifier");
                continue;
            }

            for (i, pk) in aggregate_nullifier.pks.into_iter().enumerate() {
                if self.wallet.nullifier_kv.contains_key(&pk) {
                    // Critical: ignore duplicate PKs (Section 4.2).
                    continue;
                }

                let blockchain_loc: BlockchainLocation =
                    loc.to_be_bytes()[..6].try_into().unwrap();
                let sig_comm = Signature::commit_retrieve(&aggregate_nullifier.sig, i);

                self.wallet.nullifier_kv.insert(
                    pk,
                    NullifierKvEntry {
                        sig_comm,
                        blockchain_loc,
                        fee_acct_comm: aggregate_nullifier.fee_acct_comm,
                    },
                );

                loc += 1;
                block_nullifiers.push((
                    pk,
                    sig_comm,
                    blockchain_loc,
                    aggregate_nullifier.fee_acct_comm,
                ));
            }
        }

        self.nullifier_accum = ToSAccM::append_set(&self.nullifier_accum, block_nullifiers);
        let nav = ToSAccM::value(&self.nullifier_accum);
        self.wallet.record_nullifier_accum(nav);
        self.chain_height = block_height;

        info!(
            block_height,
            new_nullifiers = loc.saturating_sub(block_height * 2u64.pow(24)),
            "processed block"
        );
        Ok(())
    }

    /// Full PCD verification + historic nullifier accumulator check.
    ///
    /// See Section 4.2 `accept_payment`.
    pub fn accept_payment(
        &self,
        coin: Coin,
        coin_proof: &[u8],
        acct_id_bytes: &[u8; 32],
        pk_commit_rand: &[u8; 32],
    ) -> Result<u64, NodeError> {
        if coin.essence.address != Commitment::commit(acct_id_bytes, pk_commit_rand) {
            return Err(NodeError::PaymentRejected);
        }

        let received_ids: Vec<[u8; 8]> = self
            .wallet
            .unspent_coins
            .iter()
            .map(|c| c.coin.on_chain_id())
            .collect();
        if received_ids.contains(&coin.on_chain_id()) {
            return Err(NodeError::PaymentRejected);
        }

        if !self.wallet.nullifier_accum_history.contains(&coin.nullifier_accum) {
            return Err(NodeError::PaymentRejected);
        }

        if !self
            .pcd
            .verify(
                &self.pcd_vk,
                &EdgeLabel::Coin(coin),
                coin_proof,
            )
            .unwrap_or(false)
        {
            return Err(NodeError::PaymentRejected);
        }

        Ok(coin.essence.amount)
    }

    /// Handle blockchain reorg: `ToSAccMRemoveSet` + trim history (Section 4.2).
    pub fn handle_reorg(&mut self, disconnected_blocks: u32) -> Result<(), NodeError> {
        if disconnected_blocks as usize > self.wallet.nullifier_accum_history.len() {
            return Err(NodeError::ReorgTooDeep);
        }

        for _ in 0..disconnected_blocks {
            self.nullifier_accum = ToSAccM::remove_set(&self.nullifier_accum);
        }

        let trim_to = self
            .wallet
            .nullifier_accum_history
            .len()
            .saturating_sub(disconnected_blocks as usize);
        self.wallet.trim_nullifier_history(trim_to);

        // TODO: remove affected nullifiers from nullifier_kv by blockchain_loc
        info!(disconnected_blocks, "handled blockchain reorg");
        self.log_audit(AuditEventType::ReorgHandled);
        Ok(())
    }

    /// Current nullifier accumulator value for conditional NAV construction.
    pub fn current_nav(&self) -> ToSAccValue {
        ToSAccM::value(&self.nullifier_accum)
    }

    fn log_audit(&self, event_type: AuditEventType) {
        let _event = PrivacyAuditEvent {
            timestamp: chrono::Utc::now(),
            event_type,
            correlation_id: uuid::Uuid::new_v4(),
        };
        // Privacy: log event type only, never coin/proof/account data.
        info!(?event_type, "privacy audit event");
    }
}

/// Legacy-compatible nullifier KV view.
pub type NullifierKvStore = HashMap<PublicKey, (SigCommitment, BlockchainLocation, Commitment)>;
