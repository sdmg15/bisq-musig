mod coin_selection;
pub mod utils;

pub mod bmp_wallet;
pub mod chain_data_source;
pub mod password;
pub mod error;
pub mod persisted;
pub mod protocol_wallet_api;
#[cfg(test)]
pub mod test_utils;
pub mod wallet_info;

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bdk_kyoto::FeeRate;
    use bdk_kyoto::bip157::{ScriptBuf, tokio};
    use bdk_wallet::bitcoin::bip32::Xpriv;
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::bitcoin::hex::DisplayHex as _;
    use bdk_wallet::bitcoin::key::{Secp256k1, TapTweak as _};
    use bdk_wallet::bitcoin::secp256k1::Message;
    use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
    use bdk_wallet::bitcoin::{
        Address, AddressType, Amount, BlockHash, Network, OutPoint, Transaction, TxOut, Weight,
        XOnlyPublicKey, absolute, psbt, taproot, transaction,
    };
    use bdk_wallet::chain::{self, BlockId};
    use bdk_wallet::keys::bip39::Mnemonic;
    use bdk_wallet::miniscript::Descriptor;
    use bdk_wallet::miniscript::descriptor::TapTree;
    use bdk_wallet::rusqlite::Connection;
    use bdk_wallet::template::{Bip86, DescriptorTemplate as _};
    use bdk_wallet::test_utils::{ReceiveTo, receive_output_to_address};
    use bdk_wallet::{AddressInfo, KeychainKind, SignOptions};
    use bmp_tracing::tracing;
    use rand::RngCore as _;
    use secp::Scalar;

    use crate::bmp_wallet::{BMPWallet, ImportedKey, STOP_GAP, WalletApi as _};
    use crate::error::WalletErrorKind;
    use crate::password::Password;
    use crate::persisted::{BMPWalletPersister as _, DBStorage};
    use crate::protocol_wallet_api::ProtocolWalletApi as _;
    use crate::test_utils::{MemDbHandle, MockedBDKElectrum, derive_public_key, test_password};
    use crate::utils::derive_key_from_password;

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
        let mem_storage = DBStorage::Memory("bmp_wallet".to_owned());

        let mut bmp_wallet = BMPWallet::new(mem_storage, &test_password(), Network::Regtest)?;
        assert_eq!(bmp_wallet.imported_keys().len(), 0);
        assert_eq!(bmp_wallet.balance(), Amount::from_sat(0));

        let seed = bmp_wallet.get_seed_phrase()?;

        tracing::info!("Generated mnemonic {} ", seed);
        assert_ne!(seed, "");

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
    fn new_wallet_matches_standard_bip39_restore() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        let seed_phrase = wallet.get_seed_phrase()?;
        let wallet_address = wallet.get_new_address()?.address;

        let mnemonic = Mnemonic::parse_normalized(&seed_phrase)?;
        let bip39_seed = mnemonic.to_seed("");
        let xprv = Xpriv::new_master(Network::Regtest, &bip39_seed)?;
        let (descriptor, _, _) =
            Bip86(xprv, KeychainKind::External).build(Network::Regtest.into())?;
        let expected_address = descriptor
            .at_derivation_index(0)?
            .address(Network::Regtest)?;

        assert_eq!(wallet_address, expected_address);
        Ok(())
    }

    #[test]
    fn signing_rejects_seed_descriptor_mismatch() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let storage = mem_storage.store.clone();

        let wallet = BMPWallet::new(storage.clone(), &test_password(), Network::Regtest)?;
        drop(wallet);

        let salt = storage.load_salt(BMPWallet::DB_NAME)?;
        let mut db = storage.open(BMPWallet::DB_NAME)?;
        let key = derive_key_from_password(&test_password(), &salt)?;
        db.pragma_update(None, "key", key.as_str())?;
        db.execute(&format!("DELETE FROM {}", BMPWallet::SEEDS_TABLE_NAME), [])?;
        Connection::persist_seed_phrase(
            &mut db,
            BMPWallet::SEEDS_TABLE_NAME,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )?;
        drop(db);

        let mut wallet = BMPWallet::load_wallet(storage, Network::Regtest, &test_password())?;
        let mut psbt = psbt::Psbt::from_unsigned_tx(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        })?;
        let error = wallet.sign(&mut psbt, SignOptions::default()).unwrap_err();

        assert!(matches!(error, WalletErrorKind::SeedDescriptorMismatch));
        Ok(())
    }

    #[test]
    fn test_load_wallet() -> anyhow::Result<()> {
        let stored_seed: String;
        let stored_balance: Amount;
        let last_generated_addr: AddressInfo;
        let mem_storage = MemDbHandle::new()?;

        {
            let mut wallet = BMPWallet::new(
                mem_storage.store.clone(),
                &test_password(),
                Network::Regtest,
            )?;
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

        let mut wallet =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password())?;
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
    fn load_recreates_wallet_when_seed_is_present() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let storage = mem_storage.store.clone();
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut db = storage.open(BMPWallet::DB_NAME)?;
        let salt = storage.persist_salt(BMPWallet::DB_NAME)?;
        let key = derive_key_from_password(&test_password(), &salt)?;
        db.pragma_update(None, "key", key.as_str())?;
        Connection::init(
            &mut db,
            Some(BMPWallet::IMPORTED_KEYS_TABLE_NAME),
            Some(BMPWallet::SEEDS_TABLE_NAME),
        )?;
        Connection::persist_seed_phrase(&mut db, BMPWallet::SEEDS_TABLE_NAME, seed_phrase)?;
        drop(db);

        let mut wallet = BMPWallet::load_wallet(storage, Network::Regtest, &test_password())?;
        assert_eq!(wallet.imported_keys().len(), 0);
        assert_eq!(wallet.get_seed_phrase()?, seed_phrase);
        assert_eq!(
            wallet.get_new_address()?.address.address_type(),
            Some(AddressType::P2tr)
        );
        Ok(())
    }

    #[test]
    fn test_imported_keys() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut bmp_wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        let pk1 = new_private_key();
        let pk2 = new_private_key();

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys().len(), 2);

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password())?;
        assert_eq!(loaded_wallet.imported_keys(), bmp_wallet.imported_keys());
        Ok(())
    }

    #[test]
    fn load_rejects_duplicate_imported_internal_key() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        let pk = new_private_key();

        wallet.import_private_key(pk, None)?;
        wallet.persist()?;

        let descriptor = wallet.imported_keys()[0].descriptor().to_string();
        let negated_pk = -pk;
        assert_eq!(derive_public_key(&pk), derive_public_key(&negated_pk));

        let db = mem_storage.store.open(BMPWallet::DB_NAME)?;
        db.execute(
            &format!(
                "INSERT INTO {} (key, descriptor) VALUES (?1, ?2)",
                BMPWallet::IMPORTED_KEYS_TABLE_NAME
            ),
            bdk_wallet::rusqlite::params![negated_pk.serialize().to_lower_hex_string(), descriptor],
        )?;
        drop(db);

        let result = BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password());
        assert!(matches!(result, Err(WalletErrorKind::DuplicateKey)));
        Ok(())
    }

    #[test]
    fn test_duplicate_key_import() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut bmp_wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        let pk1 = new_private_key();

        bmp_wallet.import_private_key(pk1, None)?;
        assert_eq!(bmp_wallet.imported_keys().len(), 1);

        let res = bmp_wallet.import_private_key(pk1, None);
        assert!(matches!(res, Err(WalletErrorKind::DuplicateKey)));
        assert_eq!(bmp_wallet.imported_keys().len(), 1);

        let (a, b) = (
            derive_public_key(&new_private_key()),
            derive_public_key(&new_private_key()),
        );
        let tap_tree = sample_tap_tree(&a, &b);
        let res = bmp_wallet.import_private_key(pk1, Some(tap_tree));
        assert!(matches!(res, Err(WalletErrorKind::DuplicateKey)));
        assert_eq!(bmp_wallet.imported_keys().len(), 1);
        Ok(())
    }

    #[test]
    fn test_imported_keys_with_tap_tree() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
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
        let loaded_wallet = BMPWallet::load_wallet(
            mem_storage.store.clone(),
            Network::Regtest,
            &test_password(),
        )?;

        assert_eq!(loaded_wallet.imported_keys().len(), 1);

        let loaded_keys = loaded_wallet.imported_keys();
        let loaded = &loaded_keys[0];
        assert_eq!(loaded.secret(), pk);
        assert_eq!(loaded.internal_key(), derive_public_key(&pk));
        assert_eq!(loaded.tap_tree(), Some(&tap_tree));
        assert_eq!(loaded.merkle_root(), Some(merkle_root));
        assert_eq!(loaded_wallet.imported_keys(), bmp_wallet.imported_keys());

        Ok(())
    }

    #[test]
    fn persist_reports_a_failed_imported_key_write() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        wallet.import_private_key(new_private_key(), None)?;
        let address = wallet.reveal_next_address(KeychainKind::External);

        // Make only the imported-key write fail. BDK's own tables stay writable.
        let db = mem_storage.store.open(BMPWallet::DB_NAME)?;
        db.execute_batch(&format!(
            "CREATE TRIGGER fail_import BEFORE INSERT ON {} \
             BEGIN SELECT RAISE(ABORT, 'imported key write failed'); END",
            BMPWallet::IMPORTED_KEYS_TABLE_NAME
        ))?;

        assert!(wallet.persist().is_err());
        assert!(
            wallet.staged().is_some(),
            "unsaved BDK changes must be kept for a retry"
        );

        db.execute_batch("DROP TRIGGER fail_import")?;
        drop(db);
        assert!(wallet.persist()?);
        drop(wallet);

        let reloaded =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password())?;
        assert_eq!(reloaded.imported_keys().len(), 1);
        assert_eq!(
            reloaded.derivation_index(KeychainKind::External),
            Some(address.index)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_sync() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
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

        let mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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
        let mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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
        let mut mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;

        let keys_to_import = [new_private_key(), new_private_key()];

        for k in &keys_to_import {
            bmp_wallet.import_private_key(*k, None)?;
        }

        // Anchor the connections of the imported keys
        for key in &bmp_wallet.imported_keys() {
            mem_storage.anchor_imported_key(key)?;
        }

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let keys = keys_to_import
            .iter()
            .map(|k| ImportedKey::new(*k, None).unwrap())
            .collect::<Vec<_>>();
        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let imported_wallets =
            BMPWallet::load_imported_wallets(&keys, &mem_storage.store, Network::Regtest)?;
        let first_key_unspents = imported_wallets[0].0.list_unspent().collect::<Vec<_>>();
        let second_key_unspents = imported_wallets[1].0.list_unspent().collect::<Vec<_>>();

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
        let mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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
        let mem_storage = MemDbHandle::new()?;

        let mut bmp_wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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

    #[tokio::test]
    async fn locked_imported_utxo_is_not_selected() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let locked_imported = wallet
            .list_utxos()
            .into_iter()
            .find(|utxo| utxo.imported)
            .expect("sync should provide an imported UTXO");
        let locked_outpoint = OutPoint::new(locked_imported.tx_id, locked_imported.vout);
        wallet.lock_utxo(locked_outpoint)?;

        assert!(wallet.is_utxo_locked(locked_outpoint));

        let mut builder = wallet.build_tx();
        builder
            .fee_rate(FeeRate::from_sat_per_kwu(250))
            .add_recipient(ScriptBuf::default(), Amount::from_sat(50_000_000));
        let psbt = builder.finish()?;

        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_ne!(
            psbt.unsigned_tx.input[0].previous_output, locked_outpoint,
            "locked imported UTXO must not be selected"
        );

        Ok(())
    }

    #[tokio::test]
    async fn locked_wallet_utxo_is_not_selected_without_imported_utxos() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let own_utxo = wallet
            .list_utxos()
            .into_iter()
            .find(|utxo| !utxo.imported)
            .expect("sync should provide a wallet-owned UTXO");
        let locked_outpoint = OutPoint::new(own_utxo.tx_id, own_utxo.vout);
        wallet.lock_utxo(locked_outpoint)?;

        let mut builder = wallet.build_tx();
        builder
            .fee_rate(FeeRate::from_sat_per_kwu(250))
            .add_recipient(ScriptBuf::default(), Amount::from_sat(50_000_000));
        let err = builder
            .finish()
            .expect_err("the only wallet UTXO is locked");

        assert!(err.to_string().contains("Insufficient funds"), "got: {err}");

        Ok(())
    }

    #[tokio::test]
    async fn locked_utxos_remain_locked_after_wallet_reload() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let utxos = wallet.list_utxos();
        let imported = utxos
            .iter()
            .find(|utxo| utxo.imported)
            .expect("sync should provide an imported UTXO");
        let owned = utxos
            .iter()
            .find(|utxo| !utxo.imported)
            .expect("sync should provide a wallet-owned UTXO");
        let imported_outpoint = OutPoint::new(imported.tx_id, imported.vout);
        let owned_outpoint = OutPoint::new(owned.tx_id, owned.vout);

        wallet.lock_utxo(imported_outpoint)?;
        wallet.lock_utxo(owned_outpoint)?;
        drop(wallet);

        let mut reloaded = BMPWallet::load_wallet(
            mem_storage.store.clone(),
            Network::Regtest,
            &test_password(),
        )?;

        assert!(reloaded.is_utxo_locked(imported_outpoint));
        assert!(reloaded.is_utxo_locked(owned_outpoint));

        let reloaded_utxos = reloaded.list_utxos();
        assert!(
            reloaded_utxos
                .iter()
                .find(|utxo| OutPoint::new(utxo.tx_id, utxo.vout) == imported_outpoint)
                .is_some_and(|utxo| utxo.is_locked)
        );
        assert!(
            reloaded_utxos
                .iter()
                .find(|utxo| OutPoint::new(utxo.tx_id, utxo.vout) == owned_outpoint)
                .is_some_and(|utxo| utxo.is_locked)
        );

        // Unlocking immediately makes the imported outpoint eligible for coin selection again.
        reloaded.unlock_utxo(imported_outpoint)?;
        assert!(!reloaded.is_utxo_locked(imported_outpoint));

        let mut builder = reloaded.build_tx();
        builder
            .fee_rate(FeeRate::from_sat_per_kwu(250))
            .add_recipient(ScriptBuf::default(), Amount::from_sat(50_000_000));
        let psbt = builder.finish()?;
        assert!(
            psbt.unsigned_tx
                .input
                .iter()
                .any(|input| input.previous_output == imported_outpoint)
        );

        // Persist both unlocks, reload, and verify the unlocked state and selection behavior.
        reloaded.unlock_utxo(owned_outpoint)?;
        drop(reloaded);

        let mut reloaded =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password())?;
        assert!(!reloaded.is_utxo_locked(imported_outpoint));
        assert!(!reloaded.is_utxo_locked(owned_outpoint));

        let mut builder = reloaded.build_tx();
        builder
            .fee_rate(FeeRate::from_sat_per_kwu(250))
            .add_recipient(ScriptBuf::default(), Amount::from_sat(50_000_000));
        let psbt = builder.finish()?;
        assert!(
            psbt.unsigned_tx
                .input
                .iter()
                .any(|input| input.previous_output == imported_outpoint)
        );

        // The owned outpoint is selectable too when the imported one is locked.
        reloaded.lock_utxo(imported_outpoint)?;
        let mut builder = reloaded.build_tx();
        builder
            .fee_rate(FeeRate::from_sat_per_kwu(250))
            .add_recipient(ScriptBuf::default(), Amount::from_sat(50_000_000));
        let psbt = builder.finish()?;
        assert!(
            psbt.unsigned_tx
                .input
                .iter()
                .any(|input| input.previous_output == owned_outpoint)
        );

        Ok(())
    }

    #[test]
    fn load_wallet_with_the_right_password() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let bmp_wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert_ne!(seed, "");
        assert_eq!(seed.split_whitespace().count(), 24);

        let lw =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password()).unwrap();
        assert_eq!(lw.get_seed_phrase().unwrap(), seed);
        Ok(())
    }

    #[tokio::test]
    async fn drain_wallet() -> anyhow::Result<()> {
        let pk1 = new_private_key();
        let pk2 = new_private_key();

        let mem_storage = MemDbHandle::new()?;
        let mut bmp_wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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
    async fn drain_imported_balance_preserves_locked_imported_coins() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let locked = wallet
            .list_utxos()
            .into_iter()
            .find(|utxo| utxo.imported)
            .expect("sync should provide an imported UTXO");
        let locked_outpoint = OutPoint::new(locked.tx_id, locked.vout);
        wallet.lock_utxo(locked_outpoint)?;

        let psbt = wallet.drain_imported_balance(FeeRate::from_sat_per_kwu(25_000))?;

        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert!(
            psbt.unsigned_tx
                .input
                .iter()
                .all(|input| input.previous_output != locked_outpoint)
        );
        assert_eq!(wallet.imported_balance().trusted_spendable(), locked.amount);

        Ok(())
    }

    #[tokio::test]
    async fn test_wallet_with_path_creation() -> anyhow::Result<()> {
        let mem_storage_one = MemDbHandle::new()?;

        let mem_storage_two = MemDbHandle::new()?;

        let client = MockedBDKElectrum {};

        let mut w1 = BMPWallet::new(mem_storage_one.store, &test_password(), Network::Regtest)?;
        let w2 = BMPWallet::new(mem_storage_two.store, &test_password(), Network::Regtest)?;

        tracing::debug!("Wallet one balance before syncing {}", w1.balance());
        assert_eq!(w1.balance(), Amount::from_int_btc(0));
        w1.sync_all(&client).await?;

        assert_eq!(w1.balance(), Amount::from_int_btc(1));
        assert_eq!(w2.balance(), Amount::ZERO);
        Ok(())
    }

    #[test]
    fn test_address_generation() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

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

    // --- the GUI-facing query/mutation surface ---------------------------------------------

    #[tokio::test]
    async fn list_transactions_describes_an_incoming_payment() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        assert!(
            wallet.list_transactions().is_empty(),
            "nothing before syncing"
        );

        // MockedBDKElectrum confirms 1 BTC to the wallet in the latest block.
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let txs = wallet.list_transactions();
        assert_eq!(txs.len(), 1);
        let tx = &txs[0];

        assert!(tx.incoming, "a received payment must be flagged incoming");
        assert_eq!(
            tx.amount,
            Amount::ONE_BTC,
            "amount is the net effect on the wallet"
        );
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, Amount::ONE_BTC);
        assert!(
            tx.outputs[0].address.is_some(),
            "a P2TR output must decode to an address"
        );
        assert_eq!(tx.lock_time, 0);

        // Confirmed in the tip block, so exactly one confirmation, with a real timestamp.
        assert!(
            tx.block_height.is_some(),
            "expected a confirmed tx, got {:?}",
            tx.block_height
        );
        assert_eq!(tx.num_confirmations, 1);
        assert!(tx.timestamp.is_some());
        // bisq2 decodes this with Instant.ofEpochSecond; a millisecond value would be absurd.
        assert!(
            tx.timestamp.unwrap() < 4_000_000_000,
            "timestamp must be in seconds"
        );

        Ok(())
    }

    #[tokio::test]
    async fn list_transactions_reports_an_outgoing_payment() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        let tx = wallet.send_to_address(
            &to_address,
            Amount::from_sat(100_000),
            FeeRate::from_sat_per_kwu(250),
        )?;

        let spend = wallet
            .list_transactions()
            .into_iter()
            .find(|info| info.tx_id == tx.compute_txid())
            .expect("the spend must show up in the transaction list");

        assert!(!spend.incoming, "a spend must not be flagged incoming");
        // Net effect = payment + fee, i.e. everything that left the wallet after change.
        assert!(
            spend.amount >= Amount::from_sat(100_000),
            "outgoing amount {} must cover the payment",
            spend.amount
        );
        assert!(
            spend.amount < Amount::ONE_BTC,
            "change must not be counted as spent"
        );
        assert_eq!(
            spend.num_confirmations, 0,
            "a freshly built tx is unconfirmed"
        );
        assert_eq!(spend.block_height, None);
        assert_eq!(spend.timestamp, None);
        assert!(!spend.inputs.is_empty(), "a spend must have inputs");
        assert!(
            spend.inputs.iter().all(|input| !input.witness.is_empty()),
            "signed inputs must carry a witness"
        );

        Ok(())
    }

    /// A payment must count as spent the moment it is handed out, not once it confirms —
    /// otherwise the next payment re-selects the same coin and (RBF) replaces the first one.
    #[tokio::test]
    async fn send_to_address_marks_its_inputs_spent() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;
        assert_eq!(wallet.balance(), Amount::ONE_BTC, "one coin to spend from");

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        let amount = Amount::from_sat(60_000_000);
        let fee_rate = FeeRate::from_sat_per_kwu(250);

        let first = wallet.send_to_address(&to_address, amount, fee_rate)?;
        let spent: Vec<OutPoint> = first.input.iter().map(|i| i.previous_output).collect();

        // The coin just spent is gone from the unspent set right away, and the balance drops
        // to the (unconfirmed) change.
        assert!(
            wallet.list_unspent().all(|u| !spent.contains(&u.outpoint)),
            "inputs of an unconfirmed payment must not be listed as unspent"
        );
        assert!(
            wallet.balance() < Amount::ONE_BTC - amount,
            "balance {} must exclude the payment",
            wallet.balance()
        );

        // Only ~0.4 BTC of change is left, so a second 0.6 BTC payment has to fail. Before the
        // spend was recorded it would instead "succeed" by re-selecting the 1 BTC input — a
        // replacement of the first payment.
        let err = wallet
            .send_to_address(&to_address, amount, fee_rate)
            .expect_err("must not re-spend the inputs of an unconfirmed payment");
        assert!(err.to_string().contains("Insufficient funds"), "got: {err}");

        // The spend is persisted, not merely staged: it survives a reload.
        drop(wallet);
        let reloaded =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password())?;
        assert!(
            reloaded
                .list_unspent()
                .all(|u| !spent.contains(&u.outpoint)),
            "a reloaded wallet must still know about the spend"
        );
        assert!(reloaded.balance() < Amount::ONE_BTC - amount);

        Ok(())
    }

    #[tokio::test]
    async fn list_utxos_covers_own_and_imported_outputs() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;

        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        assert!(wallet.list_utxos().is_empty(), "nothing before syncing");

        wallet.import_private_key(new_private_key(), None)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let utxos = wallet.list_utxos();
        assert_eq!(utxos.len(), 3, "1 own + 2 imported: {utxos:#?}");

        let own: Vec<_> = utxos.iter().filter(|u| !u.imported).collect();
        let imported: Vec<_> = utxos.iter().filter(|u| u.imported).collect();
        assert_eq!(own.len(), 1);
        assert_eq!(imported.len(), 2);

        assert_eq!(own[0].amount, Amount::ONE_BTC);
        assert_eq!(own[0].num_confirmations, 1);
        assert!(own[0].address.is_some());

        for utxo in imported {
            assert_eq!(utxo.amount, Amount::ONE_BTC);
            assert!(
                utxo.address.is_some(),
                "imported P2TR outputs must decode to an address"
            );
        }

        // The total must agree with what the balance reports, or the GUI contradicts itself.
        let utxo_total: Amount = utxos.iter().map(|u| u.amount).sum();
        assert_eq!(utxo_total, wallet.full_balance().trusted_spendable());

        Ok(())
    }

    #[tokio::test]
    async fn list_utxos_drops_spent_imported_outputs() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;

        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let imported = |w: &BMPWallet| w.list_utxos().iter().filter(|u| u.imported).count();
        assert_eq!(imported(&wallet), 1, "the imported coin starts out unspent");

        // Sweep the imported coin, then let the wallet see the spending transaction. Imported
        // outputs are floating txouts with no chain position, so the only way to know they are
        // gone is that something in the graph spends them.
        let psbt = wallet.drain_imported_balance(FeeRate::from_sat_per_kwu(25_000))?;
        let spend = psbt.extract_tx()?;
        bdk_wallet::test_utils::insert_tx(&mut wallet, spend);

        assert_eq!(
            imported(&wallet),
            0,
            "a spent imported output must not still be listed as unspent"
        );

        Ok(())
    }

    #[tokio::test]
    async fn full_balance_includes_imported_keys() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        assert_eq!(wallet.full_balance().total(), Amount::ZERO);

        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let balance = wallet.full_balance();
        assert_eq!(
            balance.total(),
            Amount::from_int_btc(2),
            "1 own + 1 imported"
        );
        assert_eq!(balance.confirmed, Amount::from_int_btc(2));
        assert_eq!(balance.untrusted_pending, Amount::ZERO);
        // The flattened `WalletApi::balance` must stay consistent with the breakdown.
        assert_eq!(wallet.balance(), balance.trusted_spendable());

        Ok(())
    }

    #[test]
    fn list_wallet_addresses_covers_both_keychains() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        assert!(
            wallet.list_wallet_addresses().is_empty(),
            "nothing revealed yet"
        );

        let external = wallet.get_new_address()?;
        let internal = wallet.get_change_address()?;

        let addresses = wallet.list_wallet_addresses();
        assert!(
            addresses.iter().any(|info| info.address == external.address),
            "missing external address"
        );
        assert!(
            addresses.iter().any(|info| info.address == internal.address),
            "missing change address"
        );
        assert_eq!(addresses.len(), 2, "one per keychain so far: {addresses:?}");

        // Revealing more must extend the list rather than replace it.
        let another = wallet.get_new_address()?;
        let addresses = wallet.list_wallet_addresses();
        assert_eq!(addresses.len(), 3);
        assert!(addresses.iter().any(|info| info.address == another.address));

        Ok(())
    }

    #[tokio::test]
    async fn send_to_address_builds_a_fully_signed_tx() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        let to_spend = Amount::from_sat(100_000);

        let tx = wallet.send_to_address(&to_address, to_spend, FeeRate::from_sat_per_kwu(250))?;

        assert!(
            tx.input.iter().all(|input| !input.witness.is_empty()),
            "extract_tx must only succeed on a fully signed tx"
        );
        assert!(
            tx.output
                .iter()
                .any(|output| output.script_pubkey == to_address.script_pubkey()
                    && output.value == to_spend),
            "the payment output must be present with the requested amount"
        );

        Ok(())
    }

    #[tokio::test]
    async fn send_to_address_rejects_an_unaffordable_payment() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;
        let mut wallet = BMPWallet::new(mem_storage.store, &test_password(), Network::Regtest)?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        // Nothing synced, so there is nothing to spend.
        let result = wallet.send_to_address(
            &to_address,
            Amount::from_sat(100_000),
            FeeRate::from_sat_per_kwu(250),
        );
        assert!(result.is_err(), "spending from an empty wallet must fail");

        Ok(())
    }

    /// Re-keying requires proof of the current password, so a caller who cannot present it must
    /// not be able to rotate the key and lock the owner out.
    #[test]
    fn change_password_refuses_a_wrong_old_password() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;

        let mut wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        let seed = wallet.get_seed_phrase()?;

        let attacker: Password = "Attacker#9".parse()?;
        let Err(err) = wallet.change_password(&attacker, &attacker) else {
            panic!("re-keying without the current password must fail");
        };
        assert!(
            matches!(err, WalletErrorKind::InvalidPassword),
            "unexpected error: {err:?}"
        );
        assert!(
            wallet.check_password(&test_password())?,
            "the original password must still be the one in force"
        );
        assert!(
            !wallet.check_password(&attacker)?,
            "the rejected password must not have taken effect"
        );
        drop(wallet);

        // ...and that survives a reload, i.e. nothing reached disk.
        let reloaded =
            BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &test_password())?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }

    /// Replacing one password with another happens in a single authenticated step.
    #[test]
    fn change_password_replaces_the_password_in_one_step() -> anyhow::Result<()> {
        let mem_storage = MemDbHandle::new()?;

        let mut wallet = BMPWallet::new(
            mem_storage.store.clone(),
            &test_password(),
            Network::Regtest,
        )?;
        let seed = wallet.get_seed_phrase()?;

        let fresh: Password = "Fresh#2024".parse()?;
        wallet.change_password(&test_password(), &fresh)?;

        assert!(wallet.check_password(&fresh)?);
        assert!(
            !wallet.check_password(&test_password())?,
            "old password must stop verifying"
        );
        drop(wallet);

        let reloaded = BMPWallet::load_wallet(mem_storage.store, Network::Regtest, &fresh)?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }
}
