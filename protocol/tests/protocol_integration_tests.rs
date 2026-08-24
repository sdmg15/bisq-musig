use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::Client as ElectrumClient;
use bdk_wallet::bitcoin;
use bdk_wallet::rusqlite::Connection;
use bitcoin::key::{Keypair, Secp256k1, TapTweak as _, TweakedKeypair, TweakedPublicKey};
use bitcoin::secp256k1::Message;
use bitcoin::{Amount, FeeRate, Network, TapSighashType, XOnlyPublicKey};
use bmp_tracing::tracing;
use musig2::KeyAggContext;
use musig2::secp::{Point, Scalar};
use protocol::protocol_musig_adaptor::{BMPContext, BMPProtocol, BoxedTradeWallet, ProtocolRole};
use protocol::script_paths::{deposit_payout_descriptor, deposit_payout_tap_tree};
use protocol::transaction::{CustomPayoutTxBuilder, TransactionExt as _};
use testenv::TestEnv;
use tokio::runtime::Runtime;
use wallet::bmp_wallet::{BMPWallet, WalletApi as _};
use wallet::protocol_wallet_api::{MemWallet, ProtocolWalletApi};

#[test]
fn test_initial_tx_creation() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;
    let (_, _) = initial_tx_creation(&mut env)?;
    Ok(())
}

/// Single entry point used by every test below to obtain a funded trade wallet. The concrete
/// backend (`MemWallet` vs `BMPWallet<Connection>`) is selected by the `WALLET_BACKEND`
/// environment variable (`mem` or `bmp`); it defaults to `bmp` when unset. Both implement
/// [`wallet::protocol_wallet_api::ProtocolWalletApi`] and are interchangeable from the protocol's
/// point of view.
pub fn funded_wallet(env: &mut TestEnv) -> BoxedTradeWallet {
    // TODO need to abstract sync(), so we can simplify this.
    match std::env::var("WALLET_BACKEND")
        .unwrap_or_else(|_| "bmp".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "mem" => Box::new(funded_mem_wallet(env)),
        "bmp" => Box::new(funded_bmp_wallet(env)),
        other => panic!("unknown WALLET_BACKEND={other:?}, expected `mem` or `bmp`"),
    }
}

fn funded_bmp_wallet(env: &mut TestEnv) -> BMPWallet<Connection> {
    let mut wallet =
        BMPWallet::<Connection>::new(env.new_temp_path(), "", Network::Regtest).unwrap();

    let address = wallet.get_new_address().unwrap();
    let txid = env
        .fund_address(&address.address, Amount::from_btc(10f64).unwrap())
        .unwrap();
    env.mine_block().unwrap();
    env.wait_for_tx(txid).unwrap();

    let chain = env.new_testchain().unwrap();
    let rt = Runtime::new().expect("create runtime");
    rt.block_on(async { wallet.sync_all(&chain).await })
        .unwrap();
    wallet
}

fn funded_mem_wallet(env: &mut TestEnv) -> MemWallet {
    let client = BdkElectrumClient::new(ElectrumClient::new(&env.electrum_url()).unwrap());
    let mut wallet = MemWallet::new(client).unwrap();
    let address = wallet.next_unused_address();
    let txid = env
        .fund_address(&address.address, Amount::from_btc(10f64).unwrap())
        .unwrap();
    env.mine_block().unwrap();
    env.wait_for_tx(txid).unwrap();
    wallet.sync().unwrap();
    wallet
}

fn initial_tx_creation(env: &mut TestEnv) -> anyhow::Result<(BMPProtocol, BMPProtocol)> {
    tracing::debug!(
        "running with wallet backend: {}",
        std::env::var("WALLET_BACKEND").unwrap_or_else(|_| "bmp (default)".to_owned())
    );

    let alice_funds = funded_wallet(env);
    let bob_funds = funded_wallet(env);

    let alice_client = Box::new(env.new_testchain()?);
    let bob_client = Box::new(env.new_testchain()?);

    let seller_amount = Amount::from_btc(1.4)?;
    let buyer_amount = Amount::from_btc(0.2)?;


    // up to here this was the preparation for the protocol, the code from now on needs to be called from outside API
    let alice_context = BMPContext::new(
        alice_client,
        alice_funds,
        ProtocolRole::Seller,
        seller_amount,
        buyer_amount,
    )?;

    let mut alice = BMPProtocol::new(alice_context)?;
    let bob_context = BMPContext::new(
        bob_client,
        bob_funds,
        ProtocolRole::Buyer,
        seller_amount,
        buyer_amount,
    )?;
    let mut bob = BMPProtocol::new(bob_context)?;
    env.mine_block()?;

    // Round 1--------
    let alice_response = alice.round1()?;
    let bob_response = bob.round1()?;

    // Round2 -------
    let alice_r2 = alice.round2(bob_response)?;
    let bob_r2 = bob.round2(alice_response)?;

    // Round 3 ----------
    let alice_r3 = alice.round3(bob_r2)?;
    let bob_r3 = bob.round3(alice_r2)?;

    assert_eq!(alice_r3.deposit_txid, bob_r3.deposit_txid);

    // Round 4 ---------------------------
    let alice_r4 = alice.round4(bob_r3)?;
    let bob_r4 = bob.round4(alice_r3)?;

    // Round 5 all is ok, broadcasting deposit-tx ---------------------------
    alice.round5(bob_r4)?;
    bob.round5(alice_r4)?;

    // done -----------------------------
    env.mine_block()?;
    Ok((alice, bob))
}

#[test]
fn test_swap() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;

    // create all transaction and Broadcast DepositTx already
    let (mut alice, mut bob) = initial_tx_creation(&mut env)?;
    dbg!(alice.swap_tx.unsigned_tx()?);
    dbg!(bob.swap_tx.unsigned_tx()?);

    // alice broadcasts SwapTx
    let alice_swap = alice.swap_tx.sign(&alice.p_tik)?;
    dbg!(alice.swap_tx.broadcast(&alice.ctx)?);
    env.mine_block()?;
    // bob must find the transaction and retrieve P_a from it and then spend DepositTx-Output0 to his wallet.
    // TODO need to read the transaction from blockchain looking for bob.swap_tx.txid
    // cheating and using the transaction from alice directly
    bob.swap_tx.reveal(&alice_swap, &mut bob.p_tik)?;
    assert!(bob.p_tik.aggregated_key()?.prv_key().is_ok(),
        "We should have the aggregated secret key now");
    assert_eq!(bob.p_tik.peers_key_share()?.prv_key()?, alice.p_tik.my_key_share()?.prv_key()?,
        "Bob should have Alice secret key for p_tik");
    // TODO now make a arbitrary transaction with the key into own wallet.

    Ok(())
}

// TODO write a test where Bob does not sign DepositTx but Alice has it already. Bob needs to
//  remove the funds from the INPUT OF DepositTx.

#[test]
fn test_warning() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;

    // create all transaction and Broadcast DepositTx already
    let (alice, _bob) = initial_tx_creation(&mut env)?;
    dbg!(alice.warning_tx_me.signed_tx()?);
    // alice broadcasts WarningTx
    dbg!(alice.warning_tx_me.broadcast(&alice.ctx)?);
    env.mine_block()?;
    Ok(())
}

#[test]
fn test_penalty() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    let (mut alice, bob) = initial_tx_creation(&mut env)?;
    // Trade is cooperatively closed. Alice learns Bob's key on her payout and uses it to
    // preemptively sign her PenaltyTx.
    alice.penalty_tx.sign(&bob.q_tik)?;
    // Now suppose that Bob broadcasts his WarningTx, hoping to fraudulently claim after some delay.
    bob.warning_tx_me.broadcast(&bob.ctx)?;
    env.mine_block()?;
    // Alice notices and broadcasts her PenaltyTx, sending all funds to her.
    alice.penalty_tx.broadcast(&alice.ctx)?;
    env.mine_block()?;
    Ok(())
}

#[test]
fn test_claim() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;

    // create all transaction and Broadcast DepositTx already
    let (alice, _bob) = initial_tx_creation(&mut env)?;
    // alice broadcasts WarningTx
    alice.warning_tx_me.broadcast(&alice.ctx)?;
    env.mine_block()?;
    env.mine_block()?; // we have set time-delay t2 to 2 Blocks
    dbg!(alice.claim_tx_me.signed_tx()?);

    // according to BIP-68 min time to wait is 512sec
    // let mut remaining_time = 532;
    // while remaining_time > 0 {
    //     println!("Remaining time: {} seconds", remaining_time);
    //     thread::sleep(Duration::from_secs(10));
    //     remaining_time -= 10;
    // }
    // thread::sleep(Duration::from_secs(512)); //otherwise non-BIP68-final error

    let tx = alice.claim_tx_me.broadcast(&alice.ctx)?;

    tracing::info!("http://localhost:5000/tx/{tx}");
    env.mine_block()?;
    Ok(())
}

#[test]
fn test_claim_too_early() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;

    // create all transaction and Broadcast DepositTx already
    let (alice, _bob) = initial_tx_creation(&mut env)?;
    alice.warning_tx_me.broadcast(&alice.ctx)?;
    // env.mine_block()?;
    env.mine_block()?; // we have set time-delay t2 to 2 Blocks

    let rtx = alice.claim_tx_me.broadcast(&alice.ctx);
    match rtx {
        Ok(_) => panic!("ClaimTx should not go through, because it's been broadcast too early.
            HINT: Do not run this test in parallel with other tests, use --test-threads=1"),
        Err(e) => {
            let error_message = format!("{e:?}");
            // println!("{}", error_message);
            assert!(error_message.contains("non-BIP68-final"),
                "Wrong error message: {error_message}");
        }
    }
    env.mine_block()?;
    Ok(())
}

#[test]
fn test_redirect() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;

    // create all transaction and Broadcast DepositTx already
    let (alice, bob) = initial_tx_creation(&mut env)?;
    // alice broadcasts WarningTx
    let bob_warn_id = bob.warning_tx_me.broadcast(&bob.ctx)?;
    env.mine_block()?;
    dbg!(bob_warn_id);

    let tx = alice.redirect_tx_me.broadcast(&alice.ctx)?;
    dbg!(tx);
    env.mine_block()?;
    Ok(())
}

#[test]
fn test_custom_payout() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    let (mut alice, mut bob) = initial_tx_creation(&mut env)?;
    let mut builder = CustomPayoutTxBuilder::default();
    builder
        .set_buyer_input(alice.deposit_tx.builder.buyer_payout()?.clone())
        .set_seller_input(alice.deposit_tx.builder.seller_payout()?.clone())
        .set_buyer_input_descriptor(alice.deposit_tx.p_descriptor.clone().unwrap())
        .set_seller_input_descriptor(alice.deposit_tx.q_descriptor.clone().unwrap())
        .set_buyer_payout_address(bob.claim_tx_me.builder.payout_address()?.clone())
        .set_seller_payout_address(alice.claim_tx_me.builder.payout_address()?.clone())
        .set_seller_payout_amount_excluding_fee(Amount::from_sat(30_000_000))
        .set_fee_rate(FeeRate::from_sat_per_vb_u32(15))
        .compute_unsigned_tx()?
        .sign_partial(&mut *alice.ctx.funds)?
        .sign_partial(&mut *bob.ctx.funds)?;
    let tx = builder.signed_tx()?;

    dbg!(alice.ctx.chain.transaction_broadcast(&tx)?);
    env.mine_block()?;
    Ok(())
}

#[test]
fn test_q_tik() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    // env.start_explorer_in_container()?;

    // create all transaction and Broadcast DepositTx already
    let (mut alice, bob) = initial_tx_creation(&mut env)?;

    // message
    let sighash = bob.swap_tx.builder.input_sighash()?;
    let msg = Message::from(sighash);

    // path 1: secp sig  -----------------------------

    // let grab the keys and produce new sig
    let q_tik = &mut alice.q_tik;
    q_tik.set_peers_prv_key(*bob.q_tik.my_key_share()?.prv_key()?)?;
    let agg_sec = *q_tik.aggregate_prv_key_shares()?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &agg_sec.serialize())?;
    let merkle_root = alice.deposit_tx.merkle_root;
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, merkle_root);
    // let sig1 = secp.sign_schnorr(&msg, &keypair); // will end up in Bad Signature
    let sig1 = secp.sign_schnorr(&msg, &tweaked.to_keypair());
    // Update the witness stack.
    let sighash_type = TapSighashType::Default;
    let signature_secp = bitcoin::taproot::Signature { signature: sig1, sighash_type };
    let path1_pub_point = Point::from_slice(&keypair.public_key().serialize())?;
    let path1_tweak_point = Point::from_slice(&tweaked.to_keypair().public_key().serialize())?;

    // KeyAgg with merkle root copied from `alice.deposit_tx` -------
    let d: TweakedPublicKey = q_tik.with_taproot_tweak(merkle_root.as_ref())?.tweaked_public_key();
    // How to do the signature with Point d and secure key?

    // AggKey ----------------------------------------------
    let agg_key = *q_tik.aggregated_key()?.pub_key();

    // recalculate ---------------------------
    let ac = [q_tik.my_key_share()?, q_tik.peers_key_share()?].map(|p| *p.pub_key());
    let pks = if ac[0] < ac[1] { [ac[0], ac[1]] } else { [ac[1], ac[0]] };
    let new_ctx = KeyAggContext::new(pks)?;
    dbg!(&new_ctx, &ac, &pks);
    let new_agg_key: Point = new_ctx.aggregated_pubkey();
    let new_ctx2 = new_ctx.with_unspendable_taproot_tweak()?;
    let new_tweaked: Point = new_ctx2.aggregated_pubkey();

    assert_eq!(new_agg_key, new_ctx2.aggregated_pubkey_untweaked(), "new_agg_key not equal");

    // verify ------------------------------------------
    dbg!(&path1_pub_point, &path1_tweak_point, &d, &agg_key, &new_tweaked, &new_agg_key);

    assert_eq!(d.serialize(), tweaked.to_keypair().x_only_public_key().0.serialize(), "pubkey not equal");

    // use signature and broadcast ------------------------------------------

    // Get the signed transaction.
    let tx = bob.swap_tx.unsigned_tx()?.clone()
        .with_key_spend_witness(0, &signature_secp);

    let txid = alice.ctx.chain.transaction_broadcast(&tx)?;
    dbg!(txid);
    env.mine_block()?;
    Ok(())
}

/// The bridge the protocol needs at trade closure: import the aggregated payout secret
/// together with `deposit_payout_tap_tree(..)` and the wallet ends up watching/signing exactly
/// the deposit payout output's script pubkey.
#[test]
fn imported_payout_key_matches_deposit_payout_descriptor() {
    let agg_secret = Scalar::from_slice(&[0x42; 32]).unwrap();
    let internal_key: XOnlyPublicKey =
        XOnlyPublicKey::from_slice(&agg_secret.base_point_mul().serialize_xonly()).unwrap();
    let buyer_pub_key = &"0000000000000000000000000000000000000000000000000000000000000002"
        .parse()
        .unwrap();
    let seller_pub_key = &"0000000000000000000000000000000000000000000000000000000000000003"
        .parse()
        .unwrap();

    let dir = std::env::temp_dir().join(format!("bmp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut w = BMPWallet::<Connection>::new(&dir, "", Network::Regtest).unwrap();
    let trade_wallet: &mut dyn ProtocolWalletApi = &mut w;
    trade_wallet
        .import_private_key(
            agg_secret,
            Some(deposit_payout_tap_tree(buyer_pub_key, seller_pub_key).unwrap()),
        )
        .unwrap();

    let desc = deposit_payout_descriptor(&internal_key, buyer_pub_key, seller_pub_key).unwrap();
    assert_eq!(w.imported_keys()[0].script_pubkey(), desc.script_pubkey());
    std::fs::remove_dir_all(&dir).unwrap();
}
