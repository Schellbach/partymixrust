//! Axum HTTP server — session management and status endpoints.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use tokio::sync::RwLock;
use tracing::info;

use super::messages::*;
use crate::types::MixerConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: MixerConfig,
    pub api: Arc<RwLock<ApiState>>,
    pub chain_height: Arc<RwLock<u64>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/metrics", get(metrics))
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/{id}/deposit", post(submit_deposit))
        .route("/v1/sessions/{id}/withdraw", post(submit_withdrawal))
        .with_state(state)
}

pub async fn serve(addr: &str, state: AppState) -> Result<(), std::io::Error> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "mixer HTTP API listening");
    axum::serve(listener, app).await
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let height = *state.chain_height.read().await;
    Json(HealthResponse {
        status: "ok".into(),
        chain_height: height,
        pool_solvency_ok: true,
    })
}

async fn metrics(State(state): State<AppState>) -> Json<MetricsResponse> {
    let api = state.api.read().await;
    Json(MetricsResponse {
        pending_deposits: api.sessions.values().map(|s| s.deposits.len() as u64).sum(),
        pending_withdrawals: 0,
        total_liabilities: 0,
        pool_value: 0,
    })
}

async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    let user_hash = hex::decode(&req.user_id_hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    if user_hash.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&user_hash);

    let session_id = uuid::Uuid::new_v4();
    state.api.write().await.sessions.insert(
        session_id,
        SessionRecord {
            user_id_hash: hash,
            deposits: vec![],
            withdrawals: vec![],
        },
    );

    Ok(Json(CreateSessionResponse {
        session_id,
        mixer_deposit_address_commitment: hex::encode([0u8; 32]),
        config_summary: ConfigSummary::from(&state.config),
    }))
}

async fn submit_deposit(
    State(state): State<AppState>,
    Path(session_id): Path<uuid::Uuid>,
    Json(_req): Json<SubmitDepositRequest>,
) -> Result<Json<SubmitDepositResponse>, StatusCode> {
    let _ = state;
    let _ = session_id;
    // TODO: decrypt envelope, run DepositHandler::receive_deposit
    Err(StatusCode::NOT_IMPLEMENTED)
}

async fn submit_withdrawal(
    State(state): State<AppState>,
    Path(session_id): Path<uuid::Uuid>,
    Json(_req): Json<SubmitWithdrawalRequest>,
) -> Result<Json<SubmitWithdrawalResponse>, StatusCode> {
    let _ = state;
    let _ = session_id;
    // TODO: decrypt envelope, run WithdrawalHandler::queue_withdrawal
    Err(StatusCode::NOT_IMPLEMENTED)
}
