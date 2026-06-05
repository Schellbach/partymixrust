//! Party Mix mixer node binary.

use std::sync::Arc;

use party_mix::api::{serve, ApiState, AppState};
use party_mix::crypto::MockPcd;
use party_mix::mixer_node::MixerNode;
use party_mix::pool::PoolManager;
use party_mix::types::MixerConfig;
use party_mix::wallet_state::WalletState;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = MixerConfig::default();
    let wallet = WalletState::new();
    let pcd = MockPcd;
    let node = MixerNode::new(config.clone(), wallet, pcd);
    let pool = PoolManager::new(config.clone());

    let _node = node;
    let _pool = pool;

    let state = AppState {
        config,
        api: Arc::new(RwLock::new(ApiState::default())),
        chain_height: Arc::new(RwLock::new(0)),
    };

    serve("127.0.0.1:8787", state).await?;
    Ok(())
}
