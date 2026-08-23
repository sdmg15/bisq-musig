use std::str::FromStr as _;

use bdk_kyoto::bip157::tokio;
use bdk_kyoto::{FeeRate, TrustedPeer};
use bdk_wallet::bitcoin::{Address, Amount, Network};
use bdk_wallet::psbt::PsbtUtils as _;
use bdk_wallet::{KeychainKind, SignOptions};
use chain::CBFScanner;
use rand::RngCore as _;
use secp::Scalar;
use testenv::TestEnv;
use wallet::bmp_wallet::*;

fn new_private_key() -> Scalar {
    let mut seed: [u8; 32] = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    Scalar::from_slice(&seed).unwrap()
}

#[tokio::test]
async fn init_test() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    let chain = env.new_testchain()?;

    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest)?;
    let receive_amount = Amount::from_sat(100_000);

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(&chain).await?;

    assert_eq!(wallet.balance(), receive_amount);
    Ok(())
}

#[tokio::test]
async fn test_sync_with_imported_keys() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    let chain = env.new_testchain()?;

    let prv_key = new_private_key();

    let receive_amount = Amount::from_sat(100_000);

    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest)?;
    wallet.import_private_key(prv_key, None);

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(&chain).await?;
    assert_eq!(wallet.balance(), receive_amount + receive_amount);

    Ok(())
}

#[tokio::test]
async fn test_broadcast_transaction() -> anyhow::Result<()> {
    // This test broadcast a transaction created from main wallet balance only
    let mut env = TestEnv::new()?;
    let chain = env.new_testchain()?;

    let prv_key = new_private_key();

    // Bind the dir once: `env.get_tmp_path()` allocates a fresh `TempDir` on every call,
    // so calling it twice (here and at `load_wallet` below) would point to two different
    // directories. `.to_path_buf()` ends the `&mut env` borrow immediately so the rest of
    // the test can keep mutating `env`.
    let dir = env.new_temp_path().to_path_buf();
    let mut wallet = BMPWallet::new(&dir, "", Network::Regtest)?;
    wallet.import_private_key(prv_key, None);

    let receive_amount = Amount::from_sat(100_000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(&chain).await?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(1_000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();
    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(&chain).await?;

    let new_balance = receive_amount - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let enc_wallet = BMPWallet::load_wallet(&dir, Network::Regtest, "")?;
    assert_eq!(enc_wallet.balance(), new_balance);

    Ok(())
}

#[tokio::test]
async fn test_broadcast_transaction_two() -> anyhow::Result<()> {
    // This test broadcast a transaction created from imported wallets only
    let mut env = TestEnv::new()?;
    let chain = env.new_testchain()?;

    let prv_key = new_private_key();

    // See note in `test_broadcast_transaction` re: binding the temp dir once.
    let dir = env.new_temp_path().to_path_buf();
    let mut wallet = BMPWallet::new(&dir, "", Network::Regtest)?;
    wallet.import_private_key(prv_key, None);

    let receive_amount = Amount::from_sat(100_000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(&chain).await?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(1_000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();
    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(&chain).await?;

    let new_balance = receive_amount - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let enc_wallet = BMPWallet::load_wallet(&dir, Network::Regtest, "")?;
    assert_eq!(enc_wallet.balance(), new_balance);

    Ok(())
}

#[tokio::test]
async fn test_broadcast_transaction_three() -> anyhow::Result<()> {
    // This test will attempt send a transaction created from both main wallet and imported keys
    // balance
    let mut env = TestEnv::new()?;
    let chain = env.new_testchain()?;

    let prv_key = new_private_key();

    // See note in `test_broadcast_transaction` re: binding the temp dir once.
    let dir = env.new_temp_path().to_path_buf();
    let mut wallet = BMPWallet::new(&dir, "", Network::Regtest)?;
    wallet.import_private_key(prv_key, None);

    let main_wallet_addr = wallet.next_unused_address(KeychainKind::External);

    let receive_amount = Amount::from_sat(100_000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.fund_address(&main_wallet_addr, receive_amount)?;

    env.mine_block()?;

    wallet.sync_all(&chain).await?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(100_000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();

    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(&chain).await?;

    let new_balance = (receive_amount + receive_amount) - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let mut enc_wallet = BMPWallet::load_wallet(&dir, Network::Regtest, "")?;

    env.fund_address(&main_wallet_addr, Amount::from_sat(10_000))?;
    env.mine_block()?;
    enc_wallet.sync_all(&chain).await?;
    assert_eq!(enc_wallet.balance(), new_balance + Amount::from_sat(10_000));

    Ok(())
}

#[tokio::test]
async fn test_cbf_main_wallet() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    env.mine_blocks(2)?;
    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);
    env.fund_address(&addr, Amount::from_sat(100_000))?;

    assert_eq!(wallet.balance(), Amount::from_sat(0));

    env.mine_blocks(4)?;

    let peers = [TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];
    wallet.sync_all(&CBFScanner::new(peers.to_vec())).await?;
    assert_eq!(wallet.balance(), Amount::from_sat(100_000));
    Ok(())
}

#[tokio::test]
async fn test_cbf_imported() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;
    env.mine_block()?;

    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest)?;

    let prv_keys = [new_private_key(), new_private_key(), new_private_key()];
    for e in &prv_keys {
        wallet.import_private_key(*e, None);
    }
    for e in &prv_keys {
        env.fund_from_prv_key(e, Amount::from_sat(10_000)).unwrap();
    }

    assert_eq!(wallet.balance(), Amount::from_sat(0));

    env.mine_blocks(4)?;
    let peers = vec![TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];

    wallet.sync_all(&CBFScanner::new(peers)).await?;
    assert_eq!(wallet.balance(), Amount::from_sat(30_000));
    Ok(())
}

#[tokio::test]
async fn test_cbf_imported_and_main() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    env.mine_block()?;

    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);
    env.fund_address(&addr, Amount::from_sat(100_000))?;

    let prv_keys = [new_private_key(), new_private_key(), new_private_key()];
    for e in &prv_keys {
        wallet.import_private_key(*e, None);
    }
    for e in &prv_keys {
        env.fund_from_prv_key(e, Amount::from_sat(10_000)).unwrap();
    }

    assert_eq!(wallet.balance(), Amount::from_sat(0));

    env.mine_blocks(4)?;
    let peers = vec![TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];

    wallet.sync_all(&CBFScanner::new(peers)).await?;

    assert_eq!(wallet.balance(), Amount::from_sat(130_000));

    Ok(())
}

#[tokio::test]
async fn test_cbf_persistence() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    env.mine_block()?;

    // See note in `test_broadcast_transaction` re: binding the temp dir once.
    let dir = env.new_temp_path().to_path_buf();
    let mut wallet = BMPWallet::new(&dir, "", Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);
    env.fund_address(&addr, Amount::from_sat(230_000))?;

    let peers = [TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];
    env.mine_block()?;

    let cbf = CBFScanner::new(peers.to_vec());
    wallet.sync_all(&cbf).await?;
    assert_eq!(wallet.balance(), Amount::from_sat(230_000));

    // Reload the wallet from persisted state
    let mut loaded_wallet = BMPWallet::load_wallet(&dir, Network::Regtest, "")?;
    assert_eq!(loaded_wallet.balance(), Amount::from_sat(230_000));

    env.fund_address(&addr, Amount::from_sat(70_000))?;
    env.mine_block()?;
    loaded_wallet.sync_all(&cbf).await?;
    assert_eq!(loaded_wallet.balance(), Amount::from_sat(300_000));

    // Create a transaction and broadcast it to the connected peer
    let receiving_addr =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;
    let mut tx_builder = loaded_wallet.build_tx();
    tx_builder.add_recipient(receiving_addr.assume_checked(), Amount::from_sat(70_000));

    let mut psbt = tx_builder.finish()?;

    loaded_wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();

    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    loaded_wallet.sync_all(&cbf).await?;
    assert_eq!(loaded_wallet.balance(), Amount::from_sat(230_000) - fee);

    Ok(())
}

#[tokio::test]
async fn test_drain_wallet_with_main_balance() -> anyhow::Result<()> {
    // This test will attempt to drain the imported wallets UTXOs
    // With the main wallet having some balance it won't be touched.
    let mut env = TestEnv::new()?;
    let chain = env.new_testchain()?;

    env.mine_block()?;

    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);

    let amount_to_send_main_wallet = Amount::from_sat(100_000);
    let amount_to_send_imported = Amount::from_sat(10_000);
    env.fund_address(&addr, amount_to_send_main_wallet)?;

    let prv_keys = [new_private_key(), new_private_key()];
    for e in &prv_keys {
        wallet.import_private_key(*e, None);
    }
    for e in &prv_keys {
        env.fund_from_prv_key(e, amount_to_send_imported).unwrap();
    }

    env.mine_block()?;
    wallet.sync_all(&chain).await?;

    // Doing *2 because we have two imported keys with the same amount received 10_000
    let current_balance = amount_to_send_main_wallet + amount_to_send_imported * 2;
    assert_eq!(wallet.balance(), current_balance);

    let mut psbt = wallet.drain_imported_balance(FeeRate::from_sat_per_vb(10).unwrap())?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let drained_amount = amount_to_send_imported * 2 - psbt.fee()?;

    let tx = psbt.extract_tx()?;

    env.broadcast(&tx)?;
    env.mine_block()?;

    wallet.sync_all(&chain).await?;

    let main_wallet_balance = drained_amount + amount_to_send_main_wallet;

    assert_eq!(wallet.balance(), main_wallet_balance);

    Ok(())
}

#[tokio::test]
#[should_panic(expected = "value: Output below the dust limit: 0")]
async fn test_drain_wallet_no_balance() {
    // In this test drain is called but the wallet doesn't have any imported key
    // insuffucient balance should be thrown
    let mut env = TestEnv::new().unwrap();

    env.mine_block().unwrap();

    let mut wallet = BMPWallet::new(env.new_temp_path(), "", Network::Regtest).unwrap();
    let addr = wallet.next_unused_address(KeychainKind::External);

    let amount_to_send_main_wallet = Amount::from_sat(100_000);

    env.fund_address(&addr, amount_to_send_main_wallet).unwrap();
    env.mine_block().unwrap();

    wallet
        .drain_imported_balance(FeeRate::from_sat_per_vb(10).unwrap())
        .unwrap();
}
