//! Prunable, secure wallet storage (Section 6.2).
//!
//! Stores pool account states, unspent coins, spent accumulator subtrees,
//! and historic nullifier accumulator values.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::shielded_csv::{
    AccValue, Coin, PublicKey, SigCommitment, ToSAccValue, PCDVerKey,
};
use crate::types::{LiabilityEntry, PoolAccount, PoolCoin};

/// Pruning horizon for spent accumulator subtrees (Section 6.2, footnote 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Forget spent-accumulator subtrees older than this block height.
    pub spent_accum_prune_before: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierKvEntry {
    pub sig_comm: SigCommitment,
    pub blockchain_loc: [u8; 6],
    pub fee_acct_comm: crate::shielded_csv::Commitment,
}

/// Mixer wallet state — extends Section 6.2 with pool-specific bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    pub pool_accounts: HashMap<Uuid, PoolAccount>,
    pub unspent_coins: Vec<PoolCoin>,
    pub liabilities: HashMap<[u8; 32], LiabilityEntry>,
    pub nullifier_kv: HashMap<PublicKey, NullifierKvEntry>,
    pub nullifier_accum_history: Vec<ToSAccValue>,
    pub spent_accum_snapshots: HashMap<PublicKey, AccValue>,
    pub pcd_verification_key: Option<Vec<u8>>,
    pub pruning: PruningConfig,
}

impl WalletState {
    pub fn new() -> Self {
        Self {
            pool_accounts: HashMap::new(),
            unspent_coins: Vec::new(),
            liabilities: HashMap::new(),
            nullifier_kv: HashMap::new(),
            nullifier_accum_history: vec![ToSAccValue([0u8; 32])],
            spent_accum_snapshots: HashMap::new(),
            pcd_verification_key: None,
            pruning: PruningConfig {
                spent_accum_prune_before: None,
            },
        }
    }

    pub fn primary_pool_account(&self) -> Option<&PoolAccount> {
        self.pool_accounts.values().find(|a| a.is_primary)
    }

    pub fn credit_user(&mut self, user_id_hash: [u8; 32], amount: u64) {
        let entry = self
            .liabilities
            .entry(user_id_hash)
            .or_insert(LiabilityEntry {
                user_id_hash,
                credited: 0,
                withdrawn: 0,
            });
        entry.credited = entry.credited.saturating_add(amount);
    }

    pub fn debit_user(&mut self, user_id_hash: [u8; 32], amount: u64) -> bool {
        let entry = match self.liabilities.get_mut(&user_id_hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.available() < amount {
            return false;
        }
        entry.withdrawn = entry.withdrawn.saturating_add(amount);
        true
    }

    pub fn add_unspent_coin(&mut self, pool_coin: PoolCoin) {
        self.unspent_coins.push(pool_coin);
    }

    pub fn remove_unspent_coin(&mut self, on_chain_id: [u8; 8]) -> Option<PoolCoin> {
        if let Some(pos) = self
            .unspent_coins
            .iter()
            .position(|c| c.coin.on_chain_id() == on_chain_id)
        {
            Some(self.unspent_coins.remove(pos))
        } else {
            None
        }
    }

    pub fn update_pool_account(&mut self, account: PoolAccount) {
        self.pool_accounts.insert(account.id, account);
    }

    pub fn record_nullifier_accum(&mut self, value: ToSAccValue) {
        if self.nullifier_accum_history.last() != Some(&value) {
            self.nullifier_accum_history.push(value);
        }
    }

    /// Trim historic NAV values after reorg (Section 4.2).
    pub fn trim_nullifier_history(&mut self, keep_from: usize) {
        if keep_from < self.nullifier_accum_history.len() {
            self.nullifier_accum_history.drain(0..keep_from);
        }
    }

    /// Prune old spent-accumulator data (Section 6.2).
    pub fn prune_spent_accumulators(&mut self, before_block: u64) {
        let _ = before_block;
        // TODO: drop subtrees in spent_accum_snapshots below pruning horizon
    }

    pub fn total_liabilities(&self) -> u64 {
        self.liabilities.values().map(|e| e.available()).sum()
    }

    pub fn total_unspent_pool_value(&self) -> u64 {
        self.unspent_coins
            .iter()
            .map(|c| c.coin.essence.amount)
            .sum::<u64>()
            + self
                .pool_accounts
                .values()
                .map(|a| a.state.essence.balance)
                .sum::<u64>()
    }
}

/// In-memory spent-coin tracking for `accept_payment` duplicate detection.
pub fn already_received_ids(wallet: &WalletState) -> Vec<[u8; 8]> {
    wallet
        .unspent_coins
        .iter()
        .map(|c| c.coin.on_chain_id())
        .collect()
}

/// Verify coin proof against stored verification key.
pub fn verify_coin_proof(_vk: &PCDVerKey, _coin: &Coin, proof: &[u8]) -> bool {
    crate::shielded_csv::PCD::verify(&crate::shielded_csv::PCDVerKey, crate::shielded_csv::EdgeLabel::Coin(*_coin), proof)
}
