# Party Mix Rust — Architecture

Shielded CSV liquidity pool / mixer built on [Shielded CSV](https://eprint.iacr.org/2025/068) (Nick, Eagen, Linus, Sept 2024).

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OFF-CHAIN (encrypted)                              │
│  User ◄──── EncryptedMessage (Coin + PCD proof) ────► Mixer Operator        │
│         Nostr DM / Signal / MLS — no metadata leakage (Section 6.1)           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PARTY MIX RUST NODE                                  │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────────┐  ┌────────────┐ │
│  │  MixerNode   │  │    Pool     │  │ DepositHandler   │  │ Withdrawal │ │
│  │ process_block│  │  AcctStates │  │ verify + credit  │  │ Handler    │ │
│  │ accept_payment│ │ liabilities │  │ consolidate      │  │ 1 tx/out    │ │
│  │ reorg/NAV    │  │ spent accum │  │ payment_init     │  │ Section6.3 │ │
│  └──────┬───────┘  └──────┬──────┘  └────────┬─────────┘  └─────┬──────┘ │
│         │                 │                   │                   │        │
│  ┌──────┴─────────────────┴───────────────────┴───────────────────┴──────┐ │
│  │                        WalletState (Section 6.2)                       │ │
│  │  pool accounts │ unspent coins │ nullifier KV │ NAV history │ proofs  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│  ┌──────────────┐  ┌─────────────────────────────────────────────────────┐ │
│  │  Publisher   │  │ crypto/ — PcdBackend, NisshacBackend, Accumulators  │ │
│  │ NISSHAC agg  │  │ mock impl now; Plonky2/folding backends later      │ │
│  │ fee finalize │  └─────────────────────────────────────────────────────┘ │
│  └──────────────┘                                                            │
│  ┌──────────────┐                                                            │
│  │  HTTP API    │  sessions, status, metrics — NOT raw coin transfer        │
│  └──────────────┘                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BITCOIN / BULLETIN BOARD                             │
│  AggregateNullifier = (nullifier_pks, NISSHAC sig, publisher fee address)   │
│  ~64 bytes per nullified account (Section 4.1)                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Module Layout

```
partymixrust/
├── Cargo.toml                 # workspace
├── partymixrust/
│   ├── src/
│   │   ├── lib.rs
│   │   ├── mixer_node.rs      # Node + reorg + accept_payment
│   │   ├── pool.rs            # liquidity + liabilities
│   │   ├── deposit_handler.rs
│   │   ├── withdrawal_handler.rs
│   │   ├── publisher.rs       # NISSHAC aggregation + fees
│   │   ├── wallet_state.rs
│   │   ├── communication.rs   # EncryptedMessage + payloads
│   │   ├── types.rs           # MixerDeposit, PoolAccount, etc.
│   │   ├── extensibility.rs   # shared accounts, timelocks, swaps
│   │   ├── shielded_csv/      # protocol types + predicates
│   │   ├── crypto/            # trait boundaries + mocks
│   │   └── api/               # HTTP session API
│   └── tests/integration.rs
└── docs/ARCHITECTURE.md
```

## Data Models

| Type | Purpose |
|------|---------|
| `MixerDeposit` | Off-chain credit after verified coin receipt |
| `MixerWithdrawalRequest` | User liability debit + destination address |
| `PoolAccount` | Long-lived `AcctState` + PCD proof |
| `PoolCoin` | Unspent coin held pending consolidation/spend |
| `LiabilityEntry` | Per-user credited vs withdrawn accounting |
| `EncryptedMessage` | AEAD wrapper for off-chain coin transfer |
| `MixerConfig` | Fees, NAV depth, **batching policy (Section 6.3)** |

## API Surface

### HTTP (session management only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Liveness + chain height |
| `GET` | `/v1/metrics` | Privacy-safe pool metrics |
| `POST` | `/v1/sessions` | Create session, return deposit address commitment |
| `POST` | `/v1/sessions/{id}/deposit` | Submit encrypted deposit envelope |
| `POST` | `/v1/sessions/{id}/withdraw` | Submit encrypted withdrawal request |
| `GET` | `/v1/sessions/{id}/withdrawal/{wid}` | Poll status; delivery envelope when done |

### Off-chain transfer format (`EncryptedMessage`)

```json
{
  "ciphertext": "<AEAD bytes>",
  "recipient_key_id": "<32-byte fingerprint>",
  "nonce": "<nonce>",
  "version": 1
}
```

Plaintext payloads (`MixerPayload`):

- `Deposit` — `{ coin, coin_proof, address_opening_rand }`
- `WithdrawalRequest` — `{ amount, destination_address, ... }`
- `WithdrawalDelivery` — `{ coin, coin_proof }`

**Recommended channels:** Nostr DM (NIP-44), Signal, MLS (Section 6.1).

## Flow Diagrams

### User Deposit

```
1. User obtains mixer deposit address commitment (out-of-band or via POST /v1/sessions)
2. User builds Shielded CSV payment to mixer address (external wallet)
3. User encrypts DepositPayload → EncryptedMessage
4. User sends via Signal/Nostr/MLS (NOT HTTP body with raw coin if avoidable)

Mixer:
5. DepositHandler::receive_deposit
   a. MixerNode::accept_payment — PCD verify + historic NAV check (Section 4.2)
   b. PoolManager::credit_deposit — internal liability
   c. WalletState::add_unspent_coin — hold coin + proof
6. Return DepositReceipt (deposit_id, amount, PendingConsolidation)
```

### Internal Consolidation into Pool

```
1. Operator triggers consolidate (or automatic background job)
2. DepositHandler::consolidate_into_pool
   a. Remove coin from unspent set
   b. Build Transaction with conditional_nav = current NAV (reorg safety)
   c. payment_init — spend user coin into pool AcctState (Section 4.2, Fig. 3)
   d. PCDProve payment_init vertex
   e. Publisher::submit_nullifier(PaymentInitOutputFee)
   f. Publisher::build_aggregate_nullifier — NISSHAC half-aggregate (Section 4.1)
   g. Broadcast aggregate nullifier → process_block
   h. payment_finalize — enrich AcctState + pool coins
   i. Publisher earns fee via payment_finalize_fee (Section 4.2)
3. Update PoolAccount state + proof in WalletState
```

### User Withdrawal (single tx — default)

```
1. User generates FRESH account ID + address commitment (unlinkability)
2. User encrypts WithdrawalRequestPayload → secure channel

Mixer:
3. WithdrawalHandler::queue_withdrawal
   a. Reserve liability (amount + service_fee)
4. WithdrawalHandler::process_single_withdrawal  [ONE output coin — Section 6.3]
   a. Select pool AcctState + funding
   b. Build Transaction: conditional_nav, single CoinEssence for user
   c. payment_init from pool account
   d. Self-publish or external publisher (earn publisher_fee)
   e. payment_finalize after block inclusion
   f. PCDProve output Coin for user
5. Encrypt WithdrawalDelivery → secure channel to user

User:
6. accept_payment with fresh coin proof — spend freely
```

### Reorg Handling

```
1. Chain reorg disconnects n blocks
2. MixerNode::handle_reorg(n)
   a. ToSAccMRemoveSet × n (Section 3.6)
   b. Trim nullifier_accum_history
   c. Purge affected nullifier_kv entries
3. Conditional NAV allows no-op proofs for affected txs (Section 4.2)
```

## Privacy Decisions

| Decision | Rationale | Reference |
|----------|-----------|-----------|
| One withdrawal per tx (default) | Coins in same tx are linkable | Section 6.3 |
| Encrypted off-chain coin transfer | Minimize metadata leakage | Section 6.1 |
| Historic NAV list in accept_payment | Bind coins to observed chain state | Section 4.2 |
| Conditional NAV on all mixer txs | Reorg safety without burning balance | Section 4.2 |
| Mock PCD initially | Pluggable recursive STARK/folding backend | Section 6.4 |

## Extensibility Hooks (`extensibility.rs`)

- `SharedAccountPolicy` — t-of-n operators (Section 5.1)
- `TimelockPolicy` — Appendix A.1.1
- `AtomicSwapCoordinator` — Appendix A.1.2
- `AssetId` / `MultiAssetCoinEssence` — Appendix A.1.3

## Fee Model

1. **Service fee** — `MixerConfig.withdrawal_service_fee` (operator revenue)
2. **Publisher fee** — `PaymentInitOutputFee` + `payment_finalize_fee` (protocol-native, Section 4.2)
