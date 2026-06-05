//! Cryptographic backend traits.
//!
//! Concrete PCD (recursive STARK / folding), accumulator, and NISSHAC
//! implementations plug in here. Initial release uses mock proofs.

pub mod accumulators;
pub mod mock;
pub mod nisshac;
pub mod pcd;

pub use accumulators::*;
pub use mock::*;
pub use nisshac::*;
pub use pcd::*;
