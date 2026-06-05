//! Withdrawal flow: spend pool account, create fresh coin for user.
//!
//! Default: one withdrawal per transaction (Section 6.3 Coin Linkability).
//! Batched withdrawals require `MixerConfig.allow_batched_withdrawals`.

use tracing::{info, warn};
use uuid::Uuid;

use crate::communication::{MixerPayload, WithdrawalDeliveryPayload, WithdrawalRequestPayload};
use std::marker::PhantomData;

use crate::crypto::pcd::PcdBackend;
use crate::mixer_node::MixerNode;
use crate::pool::PoolManager;
use crate::shielded_csv::{CoinEssence, EdgeLabel, PaymentInitLocalInput};
use crate::types::{MixerConfig, MixerWithdrawalRequest, WithdrawalDelivery, WithdrawalStatus};
use crate::wallet_state::WalletState;

#[derive(Debug, thiserror::Error)]
pub enum WithdrawalError {
    #[error("insufficient user balance")]
    InsufficientBalance,
    #[error("batching disabled — see Section 6.3 Coin Linkability")]
    BatchingDisabled,
    #[error("batch size {0} exceeds maximum {1}")]
    BatchTooLarge(usize, usize),
    #[error("pool error: {0}")]
    Pool(#[from] crate::pool::PoolError),
    #[error("withdrawal processing failed: {0}")]
    ProcessingFailed(String),
}

/// Handles user withdrawals with linkability-aware batching policy.
pub struct WithdrawalHandler<P: PcdBackend> {
    pool: PoolManager,
    _pcd: PhantomData<P>,
}

impl<P: PcdBackend> WithdrawalHandler<P> {
    pub fn new(pool: PoolManager) -> Self {
        Self {
            pool,
            _pcd: PhantomData,
        }
    }

    /// Queue a withdrawal request (off-chain).
    pub fn queue_withdrawal(
        &self,
        wallet: &mut WalletState,
        user_id_hash: [u8; 32],
        request: WithdrawalRequestPayload,
    ) -> Result<MixerWithdrawalRequest, WithdrawalError> {
        let service_fee = self.pool.config().withdrawal_service_fee;
        self.pool
            .reserve_withdrawal(wallet, user_id_hash, request.amount, service_fee)?;

        let wr = MixerWithdrawalRequest {
            id: Uuid::new_v4(),
            user_id_hash,
            amount: request.amount,
            destination_address: request.destination_address,
            service_fee,
            requested_at: chrono::Utc::now(),
            status: WithdrawalStatus::Queued,
        };

        info!(withdrawal_id = %wr.id, amount = wr.amount, "withdrawal queued");
        Ok(wr)
    }

    /// Process a single withdrawal — one output per transaction (default).
    ///
    /// ```text
    /// Mixer: payment_init from pool account
    ///         → publish nullifier (earn publisher fee)
    ///         → payment_finalize → fresh Coin + PCD proof
    /// Mixer --[encrypted: Coin + proof]--> User
    /// ```
    pub fn process_single_withdrawal(
        &self,
        node: &MixerNode<P>,
        wallet: &mut WalletState,
        request: &MixerWithdrawalRequest,
    ) -> Result<WithdrawalDelivery, WithdrawalError> {
        let pool_account = self.pool.primary_account(wallet)?;

        // Section 6.3: exactly one user output coin per transaction.
        let output_coin = CoinEssence {
            address: request.destination_address,
            amount: request.amount,
            idx: [0u8, 1], // single output at index 1 (index 0 reserved internally)
        };

        let conditional_nav = node.current_nav();

        // TODO: Select pool coins / balance to fund withdrawal
        // TODO: Insert spent coins into pool spent_accum (AccMProveNonMembershipAndInsert)
        // TODO: NISSHAC sign-to-contract over transaction hash
        // TODO: payment_init → PaymentInitOutput + PaymentInitOutputFee
        // TODO: PCDProve payment_init; submit to Publisher
        // TODO: After block confirmation: payment_finalize
        // TODO: PCDProve output coin for user

        let w_loc = PaymentInitLocalInput {
            acct_id: pool_account.acct_id,
            acct_comm_rands: vec![],
            new_coins: vec![output_coin],
            fee: self.pool.config().publisher_fee,
            new_spent_accum: pool_account.state.spent_accum,
            snmi_proof: vec![],
            new_nullifier_pk: pool_account.acct_id, // TODO: fresh nullifier keypair
            conditional_nav,
            tx_hash_randomness: rand::random(),
            nullifier_tx_comm_pk: pool_account.acct_id,
            nullifier_tx_comm: crate::shielded_csv::SigCommitment([0u8; 32]),
            nullifier_accum: conditional_nav,
            nap_proof: vec![],
        };

        let tx_hash = crate::shielded_csv::Transaction {
            conditional_nav,
            prev_state: pool_account.state.essence,
            prev_coins: vec![],
            new_state: pool_account.state.essence,
            new_coins: vec![output_coin],
        }
        .hash(w_loc.tx_hash_randomness);

        let mock_coin = crate::shielded_csv::Coin {
            essence: output_coin,
            tx_hash,
            blockchain_loc: [0u8; 6],
            nullifier_accum: conditional_nav,
        };

        let coin_proof = node
            .pcd
            .prove(
                &node.pcd.keygen().0,
                &EdgeLabel::Coin(mock_coin),
                &crate::shielded_csv::LocalInput::PaymentInit(w_loc),
                &[EdgeLabel::AcctState(pool_account.state)],
                &[pool_account.state_proof.clone()],
            )
            .map_err(|e| WithdrawalError::ProcessingFailed(e.to_string()))?;

        info!(
            withdrawal_id = %request.id,
            "single withdrawal processed (mock proof)"
        );

        Ok(WithdrawalDelivery {
            request_id: request.id,
            coin: mock_coin,
            coin_proof,
            tx_hash,
        })
    }

    /// Optional batched withdrawals — operator must explicitly enable.
    ///
    /// **Privacy warning (Section 6.3):** coins created in the same transaction
    /// are linkable if recipients communicate.
    pub fn process_batched_withdrawals(
        &self,
        node: &MixerNode<P>,
        wallet: &mut WalletState,
        requests: &[MixerWithdrawalRequest],
        config: &MixerConfig,
    ) -> Result<Vec<WithdrawalDelivery>, WithdrawalError> {
        if !config.allow_batched_withdrawals {
            return Err(WithdrawalError::BatchingDisabled);
        }
        if requests.len() > config.max_batch_size {
            return Err(WithdrawalError::BatchTooLarge(
                requests.len(),
                config.max_batch_size,
            ));
        }

        warn!(
            count = requests.len(),
            "processing batched withdrawals — Section 6.3 linkability applies"
        );

        let mut deliveries = Vec::new();
        for request in requests {
            deliveries.push(self.process_single_withdrawal(node, wallet, request)?);
        }
        // TODO: merge into single Transaction with multiple CoinEssences
        Ok(deliveries)
    }

    pub fn build_delivery_payload(delivery: &WithdrawalDelivery, session_id: Uuid) -> MixerPayload {
        MixerPayload::WithdrawalDelivery(WithdrawalDeliveryPayload {
            session_id,
            coin: delivery.coin,
            coin_proof: delivery.coin_proof.clone(),
        })
    }

    pub fn decode_request(payload: &MixerPayload) -> Option<WithdrawalRequestPayload> {
        match payload {
            MixerPayload::WithdrawalRequest(r) => Some(r.clone()),
            _ => None,
        }
    }
}
