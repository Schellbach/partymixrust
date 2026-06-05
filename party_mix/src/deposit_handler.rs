//! Deposit flow: receive coin + proof, verify, credit, optionally consolidate.

use tracing::info;
use uuid::Uuid;

use crate::communication::{DepositPayload, MixerPayload};
use std::marker::PhantomData;

use crate::crypto::pcd::PcdBackend;
use crate::mixer_node::MixerNode;
use crate::pool::PoolManager;
use crate::shielded_csv::{EdgeLabel, PaymentInitLocalInput};
use crate::types::{DepositReceipt, DepositStatus, MixerDeposit};
use crate::wallet_state::WalletState;

#[derive(Debug, thiserror::Error)]
pub enum DepositError {
    #[error("invalid coin proof")]
    InvalidProof,
    #[error("payment rejected by node")]
    PaymentRejected,
    #[error("pool error: {0}")]
    Pool(#[from] crate::pool::PoolError),
}

/// Handles user deposits over encrypted channels.
pub struct DepositHandler<P: PcdBackend> {
    pool: PoolManager,
    /// Mixer's deposit-receiving account ID bytes.
    mixer_acct_id: [u8; 32],
    mixer_address_rand: [u8; 32],
    _pcd: PhantomData<P>,
}

impl<P: PcdBackend> DepositHandler<P> {
    pub fn new(pool: PoolManager, mixer_acct_id: [u8; 32], mixer_address_rand: [u8; 32]) -> Self {
        Self {
            pool,
            mixer_acct_id,
            mixer_address_rand,
            _pcd: PhantomData,
        }
    }

    /// Step 1: Receive deposit — verify proof, credit internal balance.
    ///
    /// ```text
    /// User --[encrypted: Coin + proof]--> Mixer
    /// Mixer: accept_payment → credit liability ledger
    /// ```
    pub fn receive_deposit(
        &self,
        node: &MixerNode<P>,
        wallet: &mut WalletState,
        user_id_hash: [u8; 32],
        payload: DepositPayload,
    ) -> Result<DepositReceipt, DepositError> {
        let amount = node
            .accept_payment(
                payload.coin,
                &payload.coin_proof,
                &self.mixer_acct_id,
                &self.mixer_address_rand,
            )
            .map_err(|_| DepositError::PaymentRejected)?;

        self.pool.credit_deposit(wallet, user_id_hash, amount);

        wallet.add_unspent_coin(crate::types::PoolCoin {
            coin: payload.coin,
            proof: payload.coin_proof,
            pool_account_id: Uuid::nil(), // not yet consolidated
        });

        let deposit = MixerDeposit {
            id: Uuid::new_v4(),
            user_id_hash,
            amount,
            credited_at: chrono::Utc::now(),
            source_coin_on_chain_id: Some(payload.coin.on_chain_id()),
            status: DepositStatus::PendingConsolidation,
        };

        info!(
            deposit_id = %deposit.id,
            amount,
            "deposit received and credited"
        );

        Ok(DepositReceipt {
            deposit_id: deposit.id,
            credited_amount: amount,
            status: deposit.status,
        })
    }

    /// Step 2: Consolidate received coin into main pool account.
    ///
    /// Uses `payment_init` + `payment_finalize` with two-step fee mechanism
    /// (Section 4.2) so mixer earns publisher fees when self-publishing.
    pub fn consolidate_into_pool(
        &self,
        node: &MixerNode<P>,
        wallet: &mut WalletState,
        deposit_coin_on_chain_id: [u8; 8],
    ) -> Result<(), DepositError> {
        let pool_coin = wallet
            .remove_unspent_coin(deposit_coin_on_chain_id)
            .ok_or(DepositError::InvalidProof)?;

        let pool_account = self.pool.primary_account(wallet)?;

        // TODO: Build PaymentInitLocalInput spending pool_coin into pool_account
        // TODO: Run payment_init → produce PaymentInitOutput + PaymentInitOutputFee
        // TODO: PCDProve for payment_init vertex
        // TODO: Self-publish via Publisher or external publisher
        // TODO: After nullifier confirmed: payment_finalize → update pool AcctState

        let _conditional_nav = node.current_nav();
        let _w_loc = PaymentInitLocalInput {
            acct_id: pool_account.acct_id,
            acct_comm_rands: vec![[0u8; 32]],
            new_coins: vec![],
            fee: self.pool.config().publisher_fee,
            new_spent_accum: pool_account.state.spent_accum,
            snmi_proof: vec![],
            new_nullifier_pk: pool_account.acct_id,
            conditional_nav: _conditional_nav,
            tx_hash_randomness: [0u8; 32],
            nullifier_tx_comm_pk: pool_account.acct_id,
            nullifier_tx_comm: crate::shielded_csv::SigCommitment([0u8; 32]),
            nullifier_accum: _conditional_nav,
            nap_proof: vec![],
        };

        let _coin = pool_coin.coin;
        let _proof = pool_coin.proof;
        let _ = node.pcd.prove(
            &node.pcd.keygen().0,
            &EdgeLabel::Coin(_coin),
            &crate::shielded_csv::LocalInput::PaymentInit(_w_loc),
            &[],
            &[_proof],
        );

        info!("consolidation payment_init prepared (TODO: finalize)");
        Ok(())
    }

    /// Decode encrypted deposit payload.
    pub fn decode_payload(payload: &MixerPayload) -> Option<DepositPayload> {
        match payload {
            MixerPayload::Deposit(p) => Some(p.clone()),
            _ => None,
        }
    }
}
