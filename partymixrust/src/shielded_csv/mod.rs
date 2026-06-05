//! Shielded CSV protocol types and predicates.
//!
//! Mirrors the reference pseudocode at
//! <https://github.com/ShieldedCSV/ShieldedCSV> (paper Section 4.2).

mod primitives;
mod protocol;

pub use primitives::*;
pub use protocol::*;
