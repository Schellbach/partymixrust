//! Party Mix mixer node binary.

use std::sync::Arc;

use partymixrust::api::{serve, ApiState, AppState};
use partymixrust::crypto::MockPcd;
use partymixrust::mixer_node::MixerNode;
use partymixrust::pool::PoolManager;
use partymixrust::types::MixerConfig;
use partymixrust::wallet_state::WalletState;
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
