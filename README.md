# Party Mix Rust

High-privacy Shielded CSV liquidity pool / mixing service in Rust.

Built on [Shielded CSV: Private and Efficient Client-Side Validation](https://eprint.iacr.org/2025/068) (Nick, Eagen, Linus, 2024) and the [reference implementation](https://github.com/ShieldedCSV/ShieldedCSV).

> **Status:** Skeleton / research implementation. PCD, accumulators, and NISSHAC use mock backends. Not production-ready.

## Features

- **Protocol fidelity** — `payment_init`, `payment_finalize`, `payment_finalize_fee`, conditional NAV, ToS-accumulator, NISSHAC aggregate nullifiers
- **Mixer node** — `process_block`, `accept_payment`, reorg via `ToSAccMRemoveSet`
- **Pool accounting** — off-chain liabilities + on-chain Shielded CSV coins
- **Privacy defaults** — sequential withdrawals (Section 6.3 linkability caveat)
- **Encrypted off-chain channel** — `EncryptedMessage` + Nostr/Signal/MLS recommendations
- **Pluggable crypto** — trait boundaries for PCD, accumulators, NISSHAC

## Quick Start

```bash
cd party-mix-rust
cargo build
cargo test
cargo run --bin party-mix   # HTTP API on 127.0.0.1:8787
```

## Documentation

- [Architecture & flows](docs/ARCHITECTURE.md)

## Crate Layout

| Module | Role |
|--------|------|
| `mixer_node` | Chain scanning, payment acceptance, reorg |
| `pool` | Pool accounts + liability ledger |
| `deposit_handler` | Receive deposits, consolidate to pool |
| `withdrawal_handler` | Queue + process withdrawals |
| `publisher` | Aggregate nullifiers, claim publisher fees |
| `wallet_state` | Prunable secure storage |
| `communication` | Encrypted off-chain message format |
| `shielded_csv` | Protocol types + compliance predicates |
| `crypto` | Backend traits + mocks |
| `extensibility` | Shared accounts, timelocks, swaps, multi-asset |

## Privacy Warning

Coins created in the **same transaction are linkable** if recipients communicate (Section 6.3). Withdrawals default to **one coin per transaction**. Enable `MixerConfig.allow_batched_withdrawals` only with explicit operator consent.

## License

MIT
