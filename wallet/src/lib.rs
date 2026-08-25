mod coin_selection;
mod utils;

pub mod bmp_wallet;
pub mod chain_data_source;
pub mod protocol_wallet_api;
#[cfg(test)]
pub mod test_utils;

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bdk_kyoto::FeeRate;
    use bdk_kyoto::bip157::{ScriptBuf, tokio};
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::bitcoin::key::{Secp256k1, TapTweak as _};
    use bdk_wallet::bitcoin::secp256k1::Message;
    use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
    use bdk_wallet::bitcoin::{
        Address, AddressType, Amount, BlockHash, Network, OutPoint, TxOut, Weight, XOnlyPublicKey,
        psbt, taproot,
    };
    use bdk_wallet::chain::{self, BlockId};
    use bdk_wallet::miniscript::Descriptor;
    use bdk_wallet::miniscript::descriptor::TapTree;
    use bdk_wallet::test_utils::{ReceiveTo, receive_output_to_address};
    use bdk_wallet::{AddressInfo, KeychainKind, SignOptions};
    use bmp_tracing::tracing;
    use rand::RngCore as _;
    use secp::Scalar;
    use tempfile::{TempDir, tempdir};

    use crate::bmp_wallet::{BMPWallet, STOP_GAP, WalletApi as _};
    use crate::test_utils::{MockedBDKElectrum, derive_public_key, load_imported_wallet};

    fn get_dir() -> TempDir {
        tempdir().unwrap()
    }

    fn new_private_key() -> Scalar {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Scalar::from_slice(&seed).unwrap()
    }

    /// Single-leaf tap tree `and_v(v:pk(a),pk(b))`, the shape of the protocol's deposit payouts.
    fn sample_tap_tree(a: &XOnlyPublicKey, b: &XOnlyPublicKey) -> TapTree<XOnlyPublicKey> {
        let Descriptor::Tr(tr) = format!("tr({a},and_v(v:pk({a}),pk({b})))")
            .parse::<Descriptor<XOnlyPublicKey>>()
            .unwrap()
        else {
            unreachable!()
        };
        tr.tap_tree().clone().unwrap()
    }

    #[test]
    fn test_create_wallet() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert_eq!(bmp_wallet.imported_keys().len(), 0);
        assert_eq!(bmp_wallet.balance(), Amount::from_sat(0));

        let seed = bmp_wallet.get_seed_phrase()?;

        tracing::info!("Generated mnemonic {} ", seed);
        assert!(!seed.is_empty());

        let receiving_addr = bmp_wallet.get_new_address()?;

        assert_eq!(receiving_addr.address_type(), Some(AddressType::P2tr));

        tracing::info!("Generated address {:?}", receiving_addr);

        // Mark address as used and make sure next address will be different.
        assert!(bmp_wallet.mark_used(KeychainKind::External, receiving_addr.index));

        let new_receiving_addr = bmp_wallet.get_new_address()?;

        assert_ne!(
            bmp_wallet.next_derivation_index(KeychainKind::External),
            new_receiving_addr.index
        );

        assert_ne!(new_receiving_addr, receiving_addr);
        Ok(())
    }

    #[test]
    fn test_load_wallet() -> anyhow::Result<()> {
        let stored_seed: String;
        let stored_balance: Amount;
        let last_generated_addr: AddressInfo;
        let dir = get_dir();
        {
            let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
            assert_eq!(wallet.imported_keys().len(), 0);
            stored_balance = wallet.balance();
            stored_seed = wallet.get_seed_phrase().unwrap();
            last_generated_addr = wallet.get_new_address()?;

            receive_output_to_address(
                &mut wallet,
                last_generated_addr.address.clone(),
                Amount::ONE_BTC * 2,
                ReceiveTo::Block(chain::ConfirmationBlockTime {
                    block_id: BlockId {
                        height: 2,
                        hash: BlockHash::all_zeros(),
                    },
                    confirmation_time: 2,
                }),
            );

            wallet.persist()?;
        }

        let mut wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
        let loaded_seed = wallet.get_seed_phrase()?;

        let new_receiving_addr = wallet.get_new_address()?;

        assert_eq!(wallet.imported_keys().len(), 0);
        assert_eq!(wallet.balance(), stored_balance);
        assert_eq!(loaded_seed, stored_seed);

        // After reloading with previously used address make sure the next generated one is
        // different
        assert_ne!(new_receiving_addr, last_generated_addr);
        Ok(())
    }

    #[test]
    fn test_imported_keys() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let pk1 = new_private_key();
        let pk2 = new_private_key();

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys().len(), 2);

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
        assert_eq!(loaded_wallet.imported_keys(), bmp_wallet.imported_keys());
        Ok(())
    }

    #[test]
    fn test_imported_keys_with_tap_tree() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let pk = new_private_key();

        // A tap tree like the protocol's deposit payout: and_v(v:pk(A),pk(B))
        let (a, b) = (
            derive_public_key(&new_private_key()),
            derive_public_key(&new_private_key()),
        );
        let tap_tree = sample_tap_tree(&a, &b);

        bmp_wallet.import_private_key(pk, Some(tap_tree.clone()))?;

        assert_eq!(bmp_wallet.imported_keys().len(), 1);
        let merkle_root = bmp_wallet.imported_keys()[0]
            .merkle_root()
            .expect("merkle root should be present");

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;

        assert_eq!(loaded_wallet.imported_keys().len(), 1);

        let loaded = &loaded_wallet.imported_keys()[0];
        assert_eq!(loaded.secret(), pk);
        assert_eq!(loaded.internal_key(), derive_public_key(&pk));
        assert_eq!(loaded.tap_tree(), Some(&tap_tree));
        assert_eq!(loaded.merkle_root(), Some(merkle_root));
        assert_eq!(loaded_wallet.imported_keys(), bmp_wallet.imported_keys());

        Ok(())
    }

    #[tokio::test]
    async fn test_sync() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(1));

        tracing::info!("Wallet balance after syncing {}", bmp_wallet.balance());

        tracing::info!("{:#?}", bmp_wallet.tx_graph());
        Ok(())
    }

    #[tokio::test]
    async fn test_sync_with_imported_keys() -> anyhow::Result<()> {
        let pk1 = new_private_key();
        let pk2 = new_private_key();
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys().len(), 2);

        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        tracing::info!("Wallet balance after syncing {}", bmp_wallet.balance());
        Ok(())
    }

    #[tokio::test]
    async fn sign_inputs_main_wallet_only() -> anyhow::Result<()> {
        let client = MockedBDKElectrum {};
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(1));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_sat(100_000);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_inputs_main_and_imported_keys() -> anyhow::Result<()> {
        let client = MockedBDKElectrum {};
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let keys_to_import = [new_private_key(), new_private_key()];
        for k in &keys_to_import {
            bmp_wallet.import_private_key(*k, None)?;
        }

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let first_key_wallet = load_imported_wallet(dir.path(), &keys_to_import[0])?;
        let second_key_wallet = load_imported_wallet(dir.path(), &keys_to_import[1])?;

        let first_key_unspents = first_key_wallet.list_unspent().collect::<Vec<_>>();
        let second_key_unspents = second_key_wallet.list_unspent().collect::<Vec<_>>();

        assert_eq!(first_key_unspents.len(), 1);
        assert_eq!(second_key_unspents.len(), 1);

        for i in &first_key_unspents {
            let psbt_input = psbt::Input {
                witness_utxo: Some(i.txout.clone()),
                tap_internal_key: Some(derive_public_key(&keys_to_import[0])),
                ..Default::default()
            };
            tx_builder
                .add_foreign_utxo(i.outpoint, psbt_input, Weight::from_wu(66))
                .unwrap();
        }

        for i in &second_key_unspents {
            let psbt_input = psbt::Input {
                witness_utxo: Some(i.txout.clone()),
                tap_internal_key: Some(derive_public_key(&keys_to_import[1])),
                ..Default::default()
            };
            tx_builder
                .add_foreign_utxo(i.outpoint, psbt_input, Weight::from_wu(66))
                .unwrap();
        }

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_imported_key_tap_tree() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let pk = new_private_key();
        let (a, b) = (
            derive_public_key(&new_private_key()),
            derive_public_key(&new_private_key()),
        );
        let tap_tree = sample_tap_tree(&a, &b);

        // Import private key with tap tree
        bmp_wallet.import_private_key(pk, Some(tap_tree))?;
        let imported = bmp_wallet.imported_keys()[0].clone();
        let merkle_root = imported
            .merkle_root()
            .expect("merkle root should be present");

        // The output the key controls is tr(P, tap_tree), *not* tr(P)
        let secp = Secp256k1::new();
        let xonly = derive_public_key(&pk);
        assert_eq!(
            imported.script_pubkey(),
            ScriptBuf::new_p2tr(&secp, xonly, Some(merkle_root))
        );

        // Put a utxo paying to tr(P, tap_tree) into the wallet's graph, the way `sync_all` does,
        // and let the wallet's own `build_tx` path (imported_utxos) prepare the PSBT input.
        let outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001:0",
        )?;
        let txout = TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: imported.script_pubkey(),
        };
        bmp_wallet.insert_txout(outpoint, txout);

        let mut tx_builder = bmp_wallet.build_tx();

        // Add a recipient so transaction can be built
        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        tx_builder.add_recipient(to_address, Amount::from_sat(100_000));

        let mut res_psbt = tx_builder.finish()?;

        assert_eq!(res_psbt.inputs.len(), 1);
        assert_eq!(res_psbt.inputs[0].tap_internal_key, Some(xonly));
        assert_eq!(res_psbt.inputs[0].tap_merkle_root, Some(merkle_root));

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        // The key-path signature must verify against the *tweaked* output key
        let witness = res_psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(
            witness.len(),
            1,
            "key-path spend has a single witness element"
        );
        let sig = taproot::Signature::from_slice(&witness[0])?;
        let output_key = xonly
            .tap_tweak(&secp, Some(merkle_root))
            .0
            .to_x_only_public_key();
        let sighash = {
            let prevouts = [res_psbt.inputs[0].witness_utxo.clone().unwrap()];
            let mut cache = SighashCache::new(&res_psbt.unsigned_tx);
            cache.taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                sig.sighash_type,
            )?
        };
        secp.verify_schnorr(&sig.signature, &Message::from(sighash), &output_key)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_selection_with_main_and_imported() -> anyhow::Result<()> {
        let client = MockedBDKElectrum {};
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let pk1: [u8; 32] = [
            180, 143, 139, 78, 9, 248, 73, 139, 169, 173, 99, 191, 248, 54, 50, 207, 137, 222, 85,
            70, 228, 53, 252, 227, 191, 26, 160, 101, 121, 195, 74, 212,
        ];

        let pk2: [u8; 32] = [
            78, 212, 125, 103, 117, 115, 156, 113, 203, 95, 207, 59, 190, 106, 63, 162, 225, 131,
            186, 216, 94, 123, 55, 23, 125, 232, 214, 160, 33, 172, 124, 61,
        ];

        bmp_wallet.import_private_key(Scalar::from_slice(&pk1).unwrap(), None)?;
        bmp_wallet.import_private_key(Scalar::from_slice(&pk2).unwrap(), None)?;

        bmp_wallet.sync_all(&client).await?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let mut tx_builder = bmp_wallet.build_tx();

        tx_builder.add_recipient(to_address, to_spend);

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        Ok(())
    }

    #[test]
    #[should_panic = "file is not a database"]
    fn encrypted_wallet() {
        let dir = get_dir();
        let bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest).unwrap();
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Try loading the wallet with wrong decryption key should panic
        let lw = BMPWallet::load_wallet(dir.path(), Network::Regtest, "secret123").unwrap();
        lw.get_seed_phrase().unwrap();
    }

    #[test]
    fn encrypted_wallet_with_decryption() -> anyhow::Result<()> {
        let dir = get_dir();
        let bmp_wallet = BMPWallet::new(dir.path(), "secret123", Network::Regtest)?;
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Load the wallet with right decryption key
        let lw = BMPWallet::load_wallet(dir.path(), Network::Regtest, "secret123").unwrap();
        assert_eq!(lw.get_seed_phrase().unwrap(), seed);
        Ok(())
    }

    #[tokio::test]
    async fn drain_wallet() -> anyhow::Result<()> {
        let pk1 = new_private_key();
        let pk2 = new_private_key();
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys().len(), 2);

        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));
        assert_eq!(
            bmp_wallet.imported_balance().trusted_spendable(),
            Amount::from_int_btc(2)
        );

        // Now attempt to drain the 2 BTC from the imported wallets
        let psbt = bmp_wallet.drain_imported_balance(FeeRate::from_sat_per_kwu(25_000))?;
        let tx = psbt.extract_tx()?;
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_str("1.99983150 BTC")?);

        Ok(())
    }

    #[tokio::test]
    async fn test_wallet_with_path_creation() -> anyhow::Result<()> {
        let dir_one = get_dir();
        let dir_two = get_dir();

        let client = MockedBDKElectrum {};

        tracing::debug!("Wallet path {:?}", dir_one);
        tracing::debug!("Wallet 2 path {:?}", dir_two);

        let mut w1 = BMPWallet::new(dir_one.path(), "", Network::Regtest)?;
        let w2 = BMPWallet::new(dir_two.path(), "", Network::Regtest)?;

        tracing::debug!("Wallet one balance before syncing {}", w1.balance());
        assert_eq!(w1.balance(), Amount::from_int_btc(0));
        w1.sync_all(&client).await?;

        assert_eq!(w1.balance(), Amount::from_int_btc(1));
        assert_eq!(w2.balance(), Amount::ZERO);
        Ok(())
    }

    #[test]
    fn test_address_generation() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let mut add_vec: Vec<AddressInfo> = vec![];

        loop {
            add_vec.push(wallet.next_address(KeychainKind::External)?);
            if add_vec.len() >= STOP_GAP {
                break;
            }
        }

        // Since we reached STOP_GAP, next_address should return one address from the add_vec list
        let new_addr = wallet.next_address(KeychainKind::External)?;
        assert!(add_vec.contains(&new_addr));

        // Returned next address should be different from previous one but still exist in the list
        let new_addr2 = wallet.next_address(KeychainKind::External)?;
        assert!(add_vec.contains(&new_addr2) && new_addr != new_addr2);

        Ok(())
    }

    #[test]
    fn test_list_unused_addresses_since_last_used() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        // Reveal a handful of addresses (indices 0..=4).
        let revealed: Vec<AddressInfo> = (0..5)
            .map(|_| wallet.reveal_next_address(KeychainKind::External))
            .collect();
        let revealed_indices: Vec<u32> = revealed.iter().map(|a| a.index).collect();
        assert_eq!(revealed_indices, vec![0, 1, 2, 3, 4]);

        // With no on-chain activity, the new method returns the same set
        // as list_unused_addresses.
        let baseline: Vec<u32> = wallet
            .list_unused_addresses(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        assert_eq!(since_last, baseline);
        assert_eq!(since_last, vec![0, 1, 2, 3, 4]);

        // Receive an output on the address at index 2. The "last used" index
        // is now 2, so list_unused_addresses_since_last_used must exclude
        // indices 0 and 1 (gap addresses) even though list_unused_addresses
        // still includes them.
        receive_output_to_address(
            &mut wallet,
            revealed[2].address.clone(),
            Amount::ONE_BTC,
            ReceiveTo::Block(chain::ConfirmationBlockTime {
                block_id: BlockId {
                    height: 2,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 2,
            }),
        );

        let baseline: Vec<u32> = wallet
            .list_unused_addresses(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        // The unfiltered list still surfaces the gap indices 0 and 1.
        assert_eq!(baseline, vec![0, 1, 3, 4]);

        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        // Filtered list drops everything at or below the last used index.
        assert_eq!(since_last, vec![3, 4]);

        // Receive on the highest revealed index (4). No unused address with
        // a greater index exists yet, so the iterator should be empty —
        // confirming the threshold tracks the *maximum* used index.
        receive_output_to_address(
            &mut wallet,
            revealed[4].address.clone(),
            Amount::ONE_BTC,
            ReceiveTo::Block(chain::ConfirmationBlockTime {
                block_id: BlockId {
                    height: 3,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 3,
            }),
        );

        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        assert!(
            since_last.is_empty(),
            "expected no unused addresses past the highest used index, got {since_last:?}"
        );

        // Reveal one more address; it should now be the sole result.
        let new_addr = wallet.reveal_next_address(KeychainKind::External);
        assert_eq!(new_addr.index, 5);

        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        assert_eq!(since_last, vec![5]);

        // The internal keychain has had no on-chain activity at all, so the
        // method must fall back to "all revealed unused" for that keychain.
        let internal_addr = wallet.reveal_next_address(KeychainKind::Internal);
        let internal_since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::Internal)
            .map(|a| a.index)
            .collect();
        assert!(internal_since_last.contains(&internal_addr.index));

        Ok(())
    }
}
