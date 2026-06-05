//! Internal shielded liquidity management.
//!
//! The mixer maintains long-lived `AcctState` pool accounts. Off-chain
//! liabilities track user balances; actual value lives in Shielded CSV coins.

use tracing::{info, warn};
use uuid::Uuid;

use crate::shielded_csv::{AcctState, AcctStateEssence, AccV, PublicKey};
use crate::types::{LiabilityEntry, MixerConfig, PoolAccount};
use crate::wallet_state::WalletState;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("no primary pool account configured")]
    NoPrimaryAccount,
    #[error("insufficient pool liquidity: need {needed}, have {available}")]
    InsufficientLiquidity { needed: u64, available: u64 },
    #[error("accounting mismatch: liabilities {liabilities} vs pool {pool}")]
    AccountingMismatch { liabilities: u64, pool: u64 },
}

/// Manages pool accounts and internal accounting.
#[derive(Debug, Clone)]
pub struct PoolManager {
    config: MixerConfig,
}

impl PoolManager {
    pub fn new(config: MixerConfig) -> Self {
        Self { config }
    }

    /// Create a new pool account (first nullifier_pk = acct_id, Section 4.2).
    pub fn create_pool_account(
        &self,
        wallet: &mut WalletState,
        acct_id: PublicKey,
        label: impl Into<String>,
        is_primary: bool,
    ) -> PoolAccount {
        let state = AcctState {
            essence: AcctStateEssence {
                id: acct_id,
                nullifier_pk: acct_id,
                balance: 0,
            },
            spent_accum: AccV::new(),
            nullifier_accum: wallet
                .nullifier_accum_history
                .last()
                .copied()
                .unwrap_or_default(),
        };

        let account = PoolAccount {
            id: Uuid::new_v4(),
            label: label.into(),
            acct_id,
            state,
            state_proof: vec![],
            is_primary,
        };

        if is_primary {
            for existing in wallet.pool_accounts.values_mut() {
                existing.is_primary = false;
            }
        }

        wallet.update_pool_account(account.clone());
        info!(account_id = %account.id, "pool account created");
        account
    }

    pub fn credit_deposit(
        &self,
        wallet: &mut WalletState,
        user_id_hash: [u8; 32],
        amount: u64,
    ) {
        wallet.credit_user(user_id_hash, amount);
        info!(
            user_id_prefix = %hex::encode(&user_id_hash[..4]),
            amount,
            "deposit credited to internal ledger"
        );
    }

    pub fn reserve_withdrawal(
        &self,
        wallet: &mut WalletState,
        user_id_hash: [u8; 32],
        amount: u64,
        service_fee: u64,
    ) -> Result<(), PoolError> {
        let total = amount.saturating_add(service_fee);
        if !wallet.debit_user(user_id_hash, total) {
            return Err(PoolError::InsufficientLiquidity {
                needed: total,
                available: wallet
                    .liabilities
                    .get(&user_id_hash)
                    .map(LiabilityEntry::available)
                    .unwrap_or(0),
            });
        }
        Ok(())
    }

    pub fn check_solvency(&self, wallet: &WalletState) -> Result<(), PoolError> {
        let liabilities = wallet.total_liabilities();
        let pool = wallet.total_unspent_pool_value();
        if liabilities > pool {
            warn!(liabilities, pool, "pool accounting mismatch detected");
            return Err(PoolError::AccountingMismatch { liabilities, pool });
        }
        Ok(())
    }

    pub fn primary_account<'a>(&self, wallet: &'a WalletState) -> Result<&'a PoolAccount, PoolError> {
        wallet
            .primary_pool_account()
            .ok_or(PoolError::NoPrimaryAccount)
    }

    pub fn config(&self) -> &MixerConfig {
        &self.config
    }
}
