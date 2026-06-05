//! API request/response types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{DepositReceipt, MixerConfig, WithdrawalDelivery};

/// Off-chain encrypted transfer format (recommended over HTTP for coin data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffChainTransferEnvelope {
    pub session_id: Uuid,
    /// Base64-encoded `EncryptedMessage` JSON.
    pub encrypted_payload_b64: String,
    /// Recommended transport hint.
    pub channel: String,
}

/// `POST /v1/sessions` — initiate mixer session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    /// Hash of user identity — never send raw identity to mixer.
    pub user_id_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: Uuid,
    pub mixer_deposit_address_commitment: String,
    pub config_summary: ConfigSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub withdrawal_service_fee: u64,
    pub allow_batched_withdrawals: bool,
    pub linkability_warning: Option<String>,
}

impl From<&MixerConfig> for ConfigSummary {
    fn from(c: &MixerConfig) -> Self {
        Self {
            withdrawal_service_fee: c.withdrawal_service_fee,
            allow_batched_withdrawals: c.allow_batched_withdrawals,
            linkability_warning: if c.allow_batched_withdrawals {
                Some(
                    "Batched withdrawals enabled: coins from the same transaction \
                     are linkable if recipients communicate (Section 6.3)."
                        .into(),
                )
            } else {
                None
            },
        }
    }
}

/// `POST /v1/sessions/{id}/deposit` — register encrypted deposit envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitDepositRequest {
    pub envelope: OffChainTransferEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitDepositResponse {
    pub receipt: DepositReceipt,
}

/// `POST /v1/sessions/{id}/withdraw` — register encrypted withdrawal request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitWithdrawalRequest {
    pub envelope: OffChainTransferEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitWithdrawalResponse {
    pub withdrawal_id: Uuid,
    pub status: String,
}

/// `GET /v1/sessions/{id}/withdrawal/{wid}` — poll withdrawal status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalStatusResponse {
    pub withdrawal_id: Uuid,
    pub status: String,
    /// Encrypted delivery envelope when complete.
    pub delivery_envelope: Option<OffChainTransferEnvelope>,
}

/// `GET /v1/health`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub chain_height: u64,
    pub pool_solvency_ok: bool,
}

/// `GET /v1/metrics` — privacy-safe operational metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub pending_deposits: u64,
    pub pending_withdrawals: u64,
    pub total_liabilities: u64,
    pub pool_value: u64,
}

/// Internal service state snapshot for API handlers.
#[derive(Debug, Default)]
pub struct ApiState {
    pub sessions: std::collections::HashMap<Uuid, SessionRecord>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub user_id_hash: [u8; 32],
    pub deposits: Vec<DepositReceipt>,
    pub withdrawals: Vec<WithdrawalDelivery>,
}
