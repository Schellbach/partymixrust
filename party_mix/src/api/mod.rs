//! HTTP API surface for the mixer service.
//!
//! Coin + proof transfer uses `EncryptedMessage` off-chain (Section 6.1).
//! This API handles session management and status queries only.

pub mod http;
pub mod messages;

pub use http::{serve, AppState};
pub use messages::*;
