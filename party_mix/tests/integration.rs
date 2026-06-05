use party_mix::crypto::{MockPcd, PcdBackend};
use party_mix::deposit_handler::DepositHandler;
use party_mix::mixer_node::MixerNode;
use party_mix::pool::PoolManager;
use party_mix::shielded_csv::{Coin, CoinEssence, EdgeLabel, ToSAccValue};
use party_mix::types::MixerConfig;
use party_mix::wallet_state::WalletState;
use party_mix::withdrawal_handler::WithdrawalHandler;

#[test]
fn deposit_and_withdrawal_skeleton_flow() {
    let config = MixerConfig::default();
    let wallet = WalletState::new();
    let pcd = MockPcd;
    let node = MixerNode::new(config.clone(), wallet, pcd);
    let pool = PoolManager::new(config.clone());

    let deposit_handler = DepositHandler::new(pool.clone(), [9u8; 32], [8u8; 32]);
    let withdrawal_handler = WithdrawalHandler::new(pool.clone());

    let mut wallet = WalletState::new();
    let sk = secp256k1::SecretKey::from_slice(&[4u8; 32]).unwrap();
    let acct_id = party_mix::shielded_csv::Signature::keygen_pub(&sk);
    pool.create_pool_account(&mut wallet, acct_id, "primary", true);
    let user_hash = [7u8; 32];

    let coin = Coin {
        essence: CoinEssence {
            address: party_mix::shielded_csv::Commitment::commit(&[9u8; 32], &[8u8; 32]),
            amount: 100_000,
            idx: [0, 1],
        },
        tx_hash: [1u8; 32],
        blockchain_loc: [2u8; 6],
        nullifier_accum: ToSAccValue([0u8; 32]),
    };

    wallet.record_nullifier_accum(coin.nullifier_accum);

    let proof = node
        .pcd
        .prove(
            &node.pcd.keygen().0,
            &EdgeLabel::Coin(coin),
            &party_mix::shielded_csv::LocalInput::Issuance(
                party_mix::shielded_csv::IssuanceProof,
            ),
            &[],
            &[],
        )
        .unwrap();

    let payload = party_mix::communication::DepositPayload {
        session_id: uuid::Uuid::new_v4(),
        coin,
        coin_proof: proof,
        address_opening_rand: [8u8; 32],
    };

    let receipt = deposit_handler
        .receive_deposit(&node, &mut wallet, user_hash, payload)
        .expect("deposit should succeed");

    assert_eq!(receipt.credited_amount, 100_000);

    let wr = withdrawal_handler
        .queue_withdrawal(
            &mut wallet,
            user_hash,
            party_mix::communication::WithdrawalRequestPayload {
                session_id: uuid::Uuid::new_v4(),
                amount: 50_000,
                destination_address: party_mix::shielded_csv::Commitment::commit(
                    &[5u8; 32],
                    &[6u8; 32],
                ),
                destination_opening_rand: [6u8; 32],
            },
        )
        .expect("withdrawal should queue");

    let delivery = withdrawal_handler
        .process_single_withdrawal(&node, &mut wallet, &wr)
        .expect("withdrawal should process");

    assert_eq!(delivery.coin.essence.amount, 50_000);
}
