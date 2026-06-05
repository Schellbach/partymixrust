//! # Party Mix — Shielded CSV Mixer
//!
//! A high-privacy, efficient shielded liquidity pool / mixing service built on
//! [Shielded CSV](https://eprint.iacr.org/2025/068) (Nick, Eagen, Linus, 2024).
//!
//! ## Privacy model
//!
//! Coin proofs reveal only validity and creation time. History, balances, account
//! IDs, and output counts stay hidden from recipients (paper Section 1.1).
//!
//! ## Coin linkability (Section 6.3)
//!
//! Coins created in the same transaction are linkable if recipients communicate.
//! Withdrawals default to **one output per transaction**; batched withdrawals
//! require explicit operator opt-in.

pub mod api;
pub mod communication;
pub mod crypto;
pub mod deposit_handler;
pub mod extensibility;
pub mod mixer_node;
pub mod pool;
pub mod publisher;
pub mod shielded_csv;
pub mod types;
pub mod wallet_state;
pub mod withdrawal_handler;

pub use deposit_handler::DepositHandler;
pub use mixer_node::MixerNode;
pub use pool::PoolManager;
pub use publisher::Publisher;
pub use types::*;
pub use wallet_state::WalletState;
pub use withdrawal_handler::WithdrawalHandler;
