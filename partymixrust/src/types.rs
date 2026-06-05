//! Mixer-specific data models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::shielded_csv::{AcctState, Coin, Commitment, PublicKey};

/// Internal deposit credit — off-chain liability, not a Shielded CSV coin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixerDeposit {
    pub id: Uuid,
    pub user_id_hash: [u8; 32],
    pub amount: u64,
    pub credited_at: DateTime<Utc>,
    /// On-chain coin ID of the received deposit coin (for consolidation tracking).
    pub source_coin_on_chain_id: Option<[u8; 8]>,
    pub status: DepositStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    /// Proof verified, balance credited, coin held separately.
    PendingConsolidation,
    /// Moved into main pool account via payment_init/finalize.
    Consolidated,
    /// Deposit rejected (invalid proof, double-spend, etc.).
    Rejected,
}

/// User withdrawal request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixerWithdrawalRequest {
    pub id: Uuid,
    pub user_id_hash: [u8; 32],
    pub amount: u64,
    /// Receiver address: hiding commitment to account ID (Section 4.2).
    pub destination_address: Commitment,
    /// Service fee charged by mixer (separate from publisher fee).
    pub service_fee: u64,
    pub requested_at: DateTime<Utc>,
    pub status: WithdrawalStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    Queued,
    Processing,
    /// Coin + proof delivered over encrypted channel.
    Completed,
    Failed,
}

/// Long-lived shielded pool account managed by the mixer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolAccount {
    pub id: Uuid,
    pub label: String,
    pub acct_id: PublicKey,
    pub state: AcctState,
    /// PCD proof for current account state.
    pub state_proof: Vec<u8>,
    pub is_primary: bool,
}

/// Unspent coin held by the mixer with its proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolCoin {
    pub coin: Coin,
    pub proof: Vec<u8>,
    pub pool_account_id: Uuid,
}

/// Off-chain accounting ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiabilityEntry {
    pub user_id_hash: [u8; 32],
    pub credited: u64,
    pub withdrawn: u64,
}

impl LiabilityEntry {
    pub fn available(&self) -> u64 {
        self.credited.saturating_sub(self.withdrawn)
    }
}

/// Operator configuration affecting privacy trade-offs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixerConfig {
    /// Minimum confirmations before accepting deposit coins.
    pub deposit_confirmations: u32,
    /// Service fee in satoshis (or asset base units).
    pub withdrawal_service_fee: u64,
    /// Publisher fee offered per nullifier (Section 4.2 two-step mechanism).
    pub publisher_fee: u64,
    /// Conditional NAV depth — blocks to wait before spending (reorg safety).
    pub conditional_nav_depth: u32,

    /// Default `false`. See Section 6.3 Coin Linkability.
    ///
    /// When `true`, multiple withdrawal outputs may share one transaction.
    /// Recipients who communicate can link coins from the same tx.
    pub allow_batched_withdrawals: bool,

    /// Max outputs per batched withdrawal when enabled.
    pub max_batch_size: usize,
}

impl Default for MixerConfig {
    fn default() -> Self {
        Self {
            deposit_confirmations: 6,
            withdrawal_service_fee: 1000,
            publisher_fee: 500,
            conditional_nav_depth: 6,
            allow_batched_withdrawals: false,
            max_batch_size: 1,
        }
    }
}

/// Result of a completed withdrawal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalDelivery {
    pub request_id: Uuid,
    pub coin: Coin,
    pub coin_proof: Vec<u8>,
    pub tx_hash: [u8; 32],
}

/// Result of deposit acceptance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositReceipt {
    pub deposit_id: Uuid,
    pub credited_amount: u64,
    pub status: DepositStatus,
}

/// Privacy-safe audit event (no sensitive payloads).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub correlation_id: Uuid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditEventType {
    DepositReceived,
    DepositVerified,
    DepositRejected,
    ConsolidationStarted,
    ConsolidationCompleted,
    WithdrawalQueued,
    WithdrawalCompleted,
    WithdrawalBatched,
    NullifierPublished,
    ReorgHandled,
}
