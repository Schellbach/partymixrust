//! Shielded CSV protocol data structures and compliance predicates (Section 4.2).
//!
//! Includes `payment_init`, `payment_finalize`, and `payment_finalize_fee`
//! from the two-step publisher fee mechanism (Section 4.2, Fig. 3).

use serde::{Deserialize, Serialize};

use super::primitives::*;

/// Aggregate nullifiers posted to the blockchain by publishers (Section 4.2).
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AggregateNullifier {
    /// Schnorr public keys — each nullifies one account state update.
    pub pks: Vec<PublicKey>,
    /// Half-aggregated NISSHAC signature; R-parts commit to tx hashes.
    pub sig: Signature,
    /// Commitment to publisher fee-receiver account ID.
    pub fee_acct_comm: Commitment,
}

/// Coin essence — address, amount, index (Section 4.2).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct CoinEssence {
    pub address: Commitment,
    pub amount: u64,
    pub idx: [u8; 2],
}

impl CoinEssence {
    /// Fee coin index (Section 4.2).
    pub const FEE_IDX: [u8; 2] = [0xff, 0xff];
}

pub type CoinId = [u8; 34];
pub type CoinIdOnChain = [u8; 8];

/// 21-bit block height + 22-bit index within block.
pub type BlockchainLocation = [u8; 6];

/// Full coin with blockchain context (Section 4.2).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Coin {
    pub essence: CoinEssence,
    pub tx_hash: [u8; 32],
    pub blockchain_loc: BlockchainLocation,
    pub nullifier_accum: ToSAccValue,
}

impl Coin {
    pub fn id(&self) -> CoinId {
        [self.tx_hash.as_slice(), self.essence.idx.as_slice()]
            .concat()
            .try_into()
            .unwrap()
    }

    pub fn on_chain_id(&self) -> CoinIdOnChain {
        [self.blockchain_loc.as_slice(), self.essence.idx.as_slice()]
            .concat()
            .try_into()
            .unwrap()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct AcctStateEssence {
    pub id: PublicKey,
    pub balance: u64,
    pub nullifier_pk: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct AcctState {
    pub essence: AcctStateEssence,
    pub spent_accum: AccValue,
    pub nullifier_accum: ToSAccValue,
}

/// Transaction with conditional NAV for reorg safety (Section 4.2).
#[derive(Debug, PartialEq, Clone)]
pub struct Transaction {
    pub conditional_nav: ToSAccValue,
    pub prev_state: AcctStateEssence,
    pub prev_coins: Vec<CoinId>,
    pub new_state: AcctStateEssence,
    pub new_coins: Vec<CoinEssence>,
}

impl Transaction {
    pub fn hash(&self, randomness: [u8; 32]) -> [u8; 32] {
        let tx: Vec<u8> = format!(
            "{randomness:?} {:?} {:?} {:?} {:?} {:?}",
            self.conditional_nav,
            self.prev_state,
            self.prev_coins,
            self.new_state,
            self.new_coins
        )
        .into_bytes();
        hash(&tx)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PaymentInitLocalInput {
    pub acct_id: PublicKey,
    pub acct_comm_rands: Vec<[u8; 32]>,
    pub new_coins: Vec<CoinEssence>,
    pub fee: u64,
    pub new_spent_accum: AccValue,
    pub snmi_proof: Vec<u8>,
    pub new_nullifier_pk: PublicKey,
    pub conditional_nav: ToSAccValue,
    pub tx_hash_randomness: [u8; 32],
    pub nullifier_tx_comm_pk: PublicKey,
    pub nullifier_tx_comm: SigCommitment,
    pub nullifier_accum: ToSAccValue,
    pub nap_proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct PaymentInitOutputPartial {
    pub tx_hash: [u8; 32],
    pub nullifier_pk: PublicKey,
    pub nullifier_tx_comm: SigCommitment,
    pub nullifier_accum: ToSAccValue,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PaymentInitOutput {
    pub partial_output: PaymentInitOutputPartial,
    pub acct_state_essence: AcctStateEssence,
    pub spent_accum: AccValue,
    pub coin_essences: Vec<CoinEssence>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PaymentInitOutputFee {
    pub partial_output: PaymentInitOutputPartial,
    pub fee: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PaymentFinalizeLocalInput {
    pub fee_acct_comm: Commitment,
    pub blockchain_loc: BlockchainLocation,
    pub nullifier_accum: ToSAccValue,
    pub nm_proof: Vec<u8>,
    pub nap_proof: Vec<u8>,
}

/// `payment_init` predicate (Section 4.2, Fig. 3).
pub fn payment_init(
    prev_state: AcctState,
    prev_coins: &[Coin],
    w_loc: PaymentInitLocalInput,
) -> Option<(PaymentInitOutput, PaymentInitOutputFee)> {
    for (prev_coin, acct_comm_rand) in prev_coins.iter().zip(w_loc.acct_comm_rands.iter()) {
        if prev_coin.essence.address
            != Commitment::commit(&prev_state.essence.id.serialize(), acct_comm_rand)
        {
            return None;
        }
    }

    let mut coins_sum = 0u64;
    for coin in &w_loc.new_coins {
        coins_sum = coins_sum.checked_add(coin.amount)?;
    }
    coins_sum = coins_sum.checked_sub(w_loc.fee)?;

    let prev_coins_sum: u64 = prev_coins.iter().map(|x| x.essence.amount).sum();
    let new_balance = (prev_state.essence.balance + prev_coins_sum).checked_sub(coins_sum)?;

    let prev_coin_ids: Vec<CoinIdOnChain> = prev_coins.iter().map(|x| x.on_chain_id()).collect();
    if !AccV::verify_non_membership_and_insert(
        &prev_state.spent_accum,
        &w_loc.new_spent_accum,
        prev_coin_ids,
        &w_loc.snmi_proof,
    ) {
        return None;
    }

    let new_coin_idcs: Vec<[u8; 2]> = w_loc.new_coins.iter().map(|x| x.idx).collect();
    for i in 1..new_coin_idcs.len() {
        let idx = new_coin_idcs[i];
        if idx <= new_coin_idcs[i - 1] || idx == CoinEssence::FEE_IDX {
            return None;
        }
    }

    let acct_state_essence = AcctStateEssence {
        id: prev_state.essence.id,
        nullifier_pk: w_loc.new_nullifier_pk,
        balance: new_balance,
    };

    let tx = Transaction {
        conditional_nav: w_loc.conditional_nav,
        prev_state: prev_state.essence,
        prev_coins: prev_coins.iter().map(|x| x.id()).collect(),
        new_state: acct_state_essence,
        new_coins: w_loc.new_coins.clone(),
    };
    let tx_hash = tx.hash(w_loc.tx_hash_randomness);
    if !Signature::commit_verify(w_loc.nullifier_tx_comm, &tx_hash, &w_loc.nullifier_tx_comm_pk) {
        return None;
    }

    let partial_output = PaymentInitOutputPartial {
        tx_hash,
        nullifier_pk: prev_state.essence.nullifier_pk,
        nullifier_tx_comm: w_loc.nullifier_tx_comm,
        nullifier_accum: w_loc.nullifier_accum,
    };

    // Conditional NAV: no-op path on reorg (Section 4.2).
    if ToSAccV::verify_distinct_element(
        &tx.conditional_nav,
        &w_loc.nullifier_accum,
        &w_loc.nap_proof,
    ) {
        let noop_state = AcctStateEssence {
            id: acct_state_essence.id,
            nullifier_pk: acct_state_essence.nullifier_pk,
            balance: prev_state.essence.balance,
        };
        Some((
            PaymentInitOutput {
                partial_output,
                acct_state_essence: noop_state,
                spent_accum: prev_state.spent_accum,
                coin_essences: Vec::new(),
            },
            PaymentInitOutputFee {
                partial_output,
                fee: 0,
            },
        ))
    } else {
        let mut nullifier_accums: Vec<ToSAccValue> =
            prev_coins.iter().map(|x| x.nullifier_accum).collect();
        nullifier_accums.push(prev_state.nullifier_accum);
        nullifier_accums.push(tx.conditional_nav);
        if !ToSAccV::verify_is_prefix(&nullifier_accums, &w_loc.nullifier_accum, &w_loc.nap_proof) {
            return None;
        }
        Some((
            PaymentInitOutput {
                partial_output,
                acct_state_essence,
                spent_accum: w_loc.new_spent_accum,
                coin_essences: w_loc.new_coins[1..].to_vec(),
            },
            PaymentInitOutputFee {
                partial_output,
                fee: w_loc.fee,
            },
        ))
    }
}

pub fn payment_init_newacct(
    prev_coins: &[Coin],
    w_loc: PaymentInitLocalInput,
) -> Option<(PaymentInitOutput, PaymentInitOutputFee)> {
    let newacct = AcctState {
        essence: AcctStateEssence {
            id: w_loc.acct_id,
            nullifier_pk: w_loc.acct_id,
            balance: 0,
        },
        spent_accum: AccV::new(),
        nullifier_accum: w_loc.nullifier_accum,
    };
    payment_init(newacct, prev_coins, w_loc)
}

fn payment_finalize_internal(
    pay_init_output: &PaymentInitOutputPartial,
    w_loc: &PaymentFinalizeLocalInput,
) -> bool {
    if !ToSAccV::verify_is_prefix(
        &[pay_init_output.nullifier_accum],
        &w_loc.nullifier_accum,
        &w_loc.nap_proof,
    ) {
        return false;
    }
    ToSAccV::verify_union_membership(
        &w_loc.nullifier_accum,
        (
            pay_init_output.nullifier_pk,
            pay_init_output.nullifier_tx_comm,
            w_loc.blockchain_loc,
            w_loc.fee_acct_comm,
        ),
        &w_loc.nm_proof,
    )
}

/// `payment_finalize_fee` — publisher claims fee coin (Section 4.2).
pub fn payment_finalize_fee(
    pay_init: &PaymentInitOutputFee,
    w_loc: PaymentFinalizeLocalInput,
) -> Option<Coin> {
    if !payment_finalize_internal(&pay_init.partial_output, &w_loc) {
        return None;
    }
    Some(Coin {
        essence: CoinEssence {
            address: w_loc.fee_acct_comm,
            amount: pay_init.fee,
            idx: CoinEssence::FEE_IDX,
        },
        tx_hash: pay_init.partial_output.tx_hash,
        nullifier_accum: w_loc.nullifier_accum,
        blockchain_loc: w_loc.blockchain_loc,
    })
}

/// `payment_finalize` — sender/recipient obtains updated state + coins.
pub fn payment_finalize(
    pay_init: &PaymentInitOutput,
    w_loc: PaymentFinalizeLocalInput,
) -> Option<(AcctState, Vec<Coin>)> {
    if !payment_finalize_internal(&pay_init.partial_output, &w_loc) {
        return None;
    }
    let coins = pay_init
        .coin_essences
        .iter()
        .map(|x| Coin {
            essence: *x,
            tx_hash: pay_init.partial_output.tx_hash,
            nullifier_accum: w_loc.nullifier_accum,
            blockchain_loc: w_loc.blockchain_loc,
        })
        .collect();
    Some((
        AcctState {
            essence: pay_init.acct_state_essence,
            spent_accum: pay_init.spent_accum,
            nullifier_accum: w_loc.nullifier_accum,
        },
        coins,
    ))
}

#[derive(Debug, PartialEq, Clone)]
pub struct IssuanceProof;

pub fn issuance(_w_loc: IssuanceProof) -> Option<Coin> {
    None
}

#[derive(Debug, PartialEq, Clone)]
pub enum LocalInput {
    Issuance(IssuanceProof),
    PaymentInit(PaymentInitLocalInput),
    PaymentFinalize(PaymentFinalizeLocalInput),
}

#[derive(Debug, PartialEq, Clone)]
pub enum EdgeLabel {
    AcctState(AcctState),
    Coin(Coin),
    PaymentInitOutput(PaymentInitOutput),
    PaymentInitOutputFee(PaymentInitOutputFee),
}

pub fn compliance_predicate_pay_init(
    z_out: EdgeLabel,
    w_loc: LocalInput,
    acct_state: Option<AcctState>,
    z_in: &[EdgeLabel],
) -> bool {
    let w_loc = match w_loc {
        LocalInput::PaymentInit(w) => w,
        _ => return false,
    };

    let prev_coins: Result<Vec<Coin>, ()> = z_in.iter().try_fold(Vec::new(), |mut acc, x| {
        if let EdgeLabel::Coin(coin) = x {
            acc.push(*coin);
            Ok(acc)
        } else {
            Err(())
        }
    });
    let prev_coins = match prev_coins {
        Ok(c) => c,
        Err(()) => return false,
    };

    let output = if let Some(acct_state) = acct_state {
        payment_init(acct_state, &prev_coins, w_loc)
    } else {
        payment_init_newacct(&prev_coins, w_loc)
    };

    match output {
        None => false,
        Some(output) => match z_out {
            EdgeLabel::PaymentInitOutput(ref z_out) => output.0 == *z_out,
            EdgeLabel::PaymentInitOutputFee(ref z_out) => output.1 == *z_out,
            _ => false,
        },
    }
}

pub fn compliance_predicate_pay_finalize(
    z_out: EdgeLabel,
    w_loc: LocalInput,
    z_in: &[EdgeLabel],
) -> bool {
    if z_in.len() != 1 {
        return false;
    }
    let w_loc = match w_loc {
        LocalInput::PaymentFinalize(w) => w,
        _ => return false,
    };
    match &z_in[0] {
        EdgeLabel::PaymentInitOutput(output) => match payment_finalize(output, w_loc) {
            None => false,
            Some((acct_state, coins)) => {
                z_out == EdgeLabel::AcctState(acct_state)
                    || coins.iter().any(|x| z_out == EdgeLabel::Coin(*x))
            }
        },
        EdgeLabel::PaymentInitOutputFee(output) => payment_finalize_fee(output, w_loc)
            .map(|coin| EdgeLabel::Coin(coin) == z_out)
            .unwrap_or(false),
        _ => false,
    }
}

pub fn compliance_predicate(z_out: EdgeLabel, w_loc: LocalInput, z_in: &[EdgeLabel]) -> bool {
    if z_in.is_empty() {
        if let LocalInput::Issuance(w_loc) = w_loc {
            if let Some(coin) = issuance(w_loc) {
                return z_out == EdgeLabel::Coin(coin);
            }
        }
        return false;
    }

    match &z_in[0] {
        EdgeLabel::AcctState(acct_state) => {
            compliance_predicate_pay_init(z_out, w_loc, Some(*acct_state), &z_in[1..])
        }
        EdgeLabel::Coin(_) => compliance_predicate_pay_init(z_out, w_loc, None, z_in),
        EdgeLabel::PaymentInitOutput(_) | EdgeLabel::PaymentInitOutputFee(_) => {
            compliance_predicate_pay_finalize(z_out, w_loc, z_in)
        }
    }
}
