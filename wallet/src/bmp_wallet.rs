use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::str::FromStr as _;
use std::{fs, vec};

use base64::Engine as _;
use base64::engine::general_purpose;
use bdk_electrum::bdk_core::bitcoin::{Address, FeeRate, OutPoint};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hex::DisplayHex as _;
use bdk_wallet::bitcoin::{
    Amount, Network, PrivateKey, Psbt, ScriptBuf, Sequence, TapNodeHash, Weight, XOnlyPublicKey,
    psbt,
};
use bdk_wallet::chain::Merge as _;
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::miniscript::psbt::PsbtExt as _;
use bdk_wallet::rusqlite::{self, Connection, named_params};
use bdk_wallet::signer::{InputSigner as _, SignerContext, SignerError, SignerWrapper};
use bdk_wallet::template::{Bip86, DescriptorTemplate as _};
use bdk_wallet::{
    AddressInfo, Balance, ChangeSet, KeychainKind, PersistedWallet, SignOptions, TxBuilder, Utxo,
    Wallet, WalletPersister, WeightedUtxo,
};
use hex::ToHex as _;
use rand::RngCore as _;
use secp::Scalar;

use crate::chain_data_source::ChainDataSource;
use crate::coin_selection::{AlwaysSpendImportedFirst, SpendImportedOnly};
use crate::protocol_wallet_api::{
    ProtocolWalletApi, WalletErrorKind, WalletExt, finish_standard_psbt, internal_key_at_index,
    sign_selected_inputs_with,
};
use crate::utils::{derive_key_from_password, get_salt};

pub trait BMPWalletPersister: WalletPersister {
    type DB;

    fn new(db_path: &str) -> anyhow::Result<Self::DB, <Self as WalletPersister>::Error>;

    fn init(
        db: &mut Self::DB,
        imported_keys_table: Option<&str>,
        seeds_table_name: Option<&str>,
    ) -> anyhow::Result<()>;

    fn persist_seed_phrase(
        db: &mut Self::DB,
        seeds_table_name: &str,
        seed_phrase: &str,
    ) -> anyhow::Result<()>;

    fn load_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
    ) -> anyhow::Result<Vec<(Scalar, Option<TapNodeHash>)>>;

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[(Scalar, Option<TapNodeHash>)],
    ) -> anyhow::Result<()>;

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String>;

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error>;
}

impl BMPWalletPersister for Connection {
    type DB = Self;

    fn new(db_path: &str) -> Result<Self::DB, rusqlite::Error> {
        let db = Self::open(db_path)?;
        Ok(db)
    }

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error> {
        Self::persist(db, cs)
    }

    fn init(
        db: &mut Self::DB,
        imported_keys_table: Option<&str>,
        seeds_table_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let create_imported_keys_table = format!(
            "CREATE TABLE {} ( \
                    key TEXT PRIMARY KEY NOT NULL,
                    merkle_root TEXT
                ) STRICT",
            imported_keys_table.unwrap(),
        );

        let create_seeds_table = format!(
            "CREATE TABLE {} ( \
                    seed TEXT PRIMARY KEY NOT NULL
                ) STRICT",
            seeds_table_name.unwrap(),
        );

        let query = format!("{create_imported_keys_table}; {create_seeds_table}");

        let trx = db.transaction()?;

        trx.execute_batch(&query)?;
        trx.commit()?;
        Ok(())
    }

    fn persist_seed_phrase(
        db: &mut Self::DB,
        seeds_table_name: &str,
        seed_phrase: &str,
    ) -> anyhow::Result<()> {
        let trx = db.transaction()?;
        {
            let mut stmt = trx.prepare(&format!(
                "INSERT INTO {seeds_table_name}(seed) VALUES(:seed)"
            ))?;

            stmt.execute(named_params! {
                ":seed": seed_phrase
            })?;
        }

        trx.commit()?;
        Ok(())
    }

    fn load_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
    ) -> anyhow::Result<Vec<(Scalar, Option<TapNodeHash>)>> {
        let mut imported_keys: Vec<(Scalar, Option<TapNodeHash>)> = vec![];

        let mut statement =
            db.prepare(&format!("SELECT key, merkle_root FROM {keys_table_name}"))?;

        let row_iter = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>("key")?,
                row.get::<_, Option<String>>("merkle_root")?,
            ))
        })?;

        for row in row_iter {
            let (key_str, merkle_opt) = row?;
            let secret = Scalar::from_hex(&key_str)?;

            match merkle_opt {
                Some(ref s) if !s.is_empty() => {
                    let tph = TapNodeHash::from_str(s)?;
                    imported_keys.push((secret, Some(tph)));
                }
                _ => {
                    imported_keys.push((secret, None));
                }
            }
        }

        Ok(imported_keys)
    }

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[(Scalar, Option<TapNodeHash>)],
    ) -> anyhow::Result<()> {
        let db_trx = db.transaction()?;
        {
            let mut statement = db_trx.prepare_cached(&format!(
                "INSERT OR IGNORE INTO {keys_table_name} (key, merkle_root) VALUES (:key, :m_root)"
            ))?;

            for key in keys {
                let root = if let Some(h) = key.1 {
                    h.encode_hex()
                } else {
                    String::new()
                };
                statement.execute(named_params! {
                    ":key": key.0.serialize().to_lower_hex_string(),
                    ":m_root": root,
                })?;
            }
        }

        db_trx.commit()?;
        Ok(())
    }

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String> {
        let mnemonic = db.query_row(
            &format!("SELECT seed FROM {seeds_table_name}"),
            (),
            |row| row.get::<_, String>("seed"),
        )?;

        Ok(mnemonic)
    }
}

const STOP_GAP: usize = 50;

pub struct BMPWallet<P: BMPWalletPersister> {
    wallet: PersistedWallet<P>,
    imported_keys: Vec<(Scalar, Option<TapNodeHash>)>,
    imported_balance: Balance,
    signers_loaded: bool,
    db: P,
    last_unused_address: Option<String>,
}

impl BMPWallet<Connection> {
    pub fn list_unused_addresses_since_last_used(
        &self,
        key_chain: KeychainKind,
    ) -> impl Iterator<Item = AddressInfo> + '_ {
        let last_used = self.spk_index().last_used_index(key_chain);
        self.list_unused_addresses(key_chain)
            .filter(move |info| last_used.is_none_or(|idx| info.index > idx))
    }

    pub fn next_address(&mut self, key_chain: KeychainKind) -> anyhow::Result<AddressInfo> {
        let unused = self.list_unused_addresses_since_last_used(key_chain).collect::<Vec<_>>();

        let addr = if unused.len() >= STOP_GAP {
            // Find the position of the last returned address, or start at the beginning
            let next_index = if let Some(last_addr) = &self.last_unused_address {
                // Search for the last address in the current unused list
                unused.iter().position(|info| info.address.to_string() == *last_addr)
                    .map_or(0, |idx| (idx + 1) % unused.len())
            } else {
                // No previous address, start with the first one
                0
            };

            let selected = unused[next_index].clone();

            // Update index to track the address just given out
            self.last_unused_address = Some(selected.address.to_string());

            selected
        } else {
            let addr = self.reveal_next_address(key_chain);
            self.persist()?;
            // Reset the index since we've generated new addresses
            self.last_unused_address = None;
            addr
        };

        Ok(addr)
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    pub fn import_private_key(&mut self, pk: Scalar, merkle_root: Option<TapNodeHash>) {
        self.imported_keys.push((pk, merkle_root));
    }

    fn imported_utxos(&self) -> Vec<WeightedUtxo> {
        let secp: &bdk_wallet::bitcoin::key::Secp256k1<bdk_wallet::bitcoin::secp256k1::All> =
            self.secp_ctx();
        self.tx_graph()
            .floating_txouts()
            .map(|utxo| {
                let output_script_pubkey = &utxo.1.script_pubkey;

                let tap_internal_key = self
                    .imported_keys
                    .iter()
                    .map(|scalar| {
                        let pbk = scalar.0.base_point_mul().serialize_xonly();
                        XOnlyPublicKey::from_slice(&pbk).expect("Should be valid xonly pubkey")
                    })
                    .find(|pubkey| {
                        let script = ScriptBuf::new_p2tr(secp, *pubkey, None);
                        script == *output_script_pubkey
                    });

                WeightedUtxo {
                    utxo: Utxo::Foreign {
                        outpoint: utxo.0,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        psbt_input: Box::new(psbt::Input {
                            witness_utxo: Some(utxo.1.clone()),
                            tap_internal_key,
                            ..Default::default()
                        }),
                    },
                    satisfaction_weight: Weight::from_wu_usize(65),
                }
            })
            .collect::<Vec<_>>()
    }

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst> {
        let imported_weighted_utxos = self.imported_utxos();
        let coin_selection = AlwaysSpendImportedFirst(imported_weighted_utxos);
        self.wallet.build_tx().coin_selection(coin_selection)
    }
}

impl WalletExt for BMPWallet<Connection> {
    fn update_psbt_with_derivation_paths(&self, psbt: &mut Psbt) {
        self.wallet.update_psbt_with_derivation_paths(psbt);
    }
}

impl ProtocolWalletApi for BMPWallet<Connection> {
    fn network(&self) -> Network {
        self.wallet.network()
    }

    fn new_address(&mut self) -> Result<Address, WalletErrorKind> {
        Ok(self.next_address(KeychainKind::External)?.address)
    }

    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey, WalletErrorKind> {
        // Use `next_address` (gap-filling) rather than `reveal_next_address` directly so
        // that the internal key's index stays in step with what `new_address` would yield.
        let index = self.next_address(KeychainKind::External)?.index;
        internal_key_at_index(self, index)
    }

    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt, WalletErrorKind> {
        finish_standard_psbt(self.build_tx(), recipients, fee_rate)
    }

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> Result<(), WalletErrorKind> {
        // TODO unify signing
        sign_selected_inputs_with(self, psbt, is_selected, |w, p, opts| {
            <Self as WalletApi>::sign(w, p, opts).map_err(Into::into)
        })
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    fn import_private_key(&mut self, pk: Scalar, merkle_root: Option<TapNodeHash>) {
        self.import_private_key(pk, merkle_root);
    }
}

#[trait_variant::make(Send)]
pub trait WalletApi {
    const DB_NAME: &str;
    const SEEDS_TABLE_NAME: &'static str;
    const IMPORTED_KEYS_TABLE_NAME: &'static str;

    fn new(path: &Path, password: &str, network: Network) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn load_wallet(path: &Path, network: Network, password: &str) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo>;
    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo>;

    fn get_seed_phrase(&self) -> anyhow::Result<String>;

    fn balance(&self) -> Amount;

    fn persist(&mut self) -> anyhow::Result<bool>;

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst>;

    fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> anyhow::Result<(), SignerError>;

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> anyhow::Result<()>;

    fn drain_imported_balance(&mut self, fee_rate: FeeRate) -> anyhow::Result<Psbt>;
}

pub fn get_imported_wallets(
    imported_keys: &Vec<(Scalar, Option<TapNodeHash>)>,
    db: &Connection,
    network: Network,
    db_name: &str,
) -> anyhow::Result<Vec<(PersistedWallet<Connection>, Connection)>> {
    let mut res = vec![];
    for key in imported_keys {
        let pubk = key.0.base_point_mul();
        let pubk = pubk.serialize_xonly().to_lower_hex_string();
        let path_str = db
            .path()
            .expect("DB path should not be empty")
            .replace(db_name, "");
        let db_path = Path::new(&path_str).join(format!("bmp_{pubk}.db3"));

        let mut db = Connection::open(db_path)?;
        let imported_wallet_opt = Wallet::load()
            .check_network(network)
            .extract_keys()
            .load_wallet(&mut db)?;

        let imported_wallet = if let Some(wallet) = imported_wallet_opt { wallet } else {
            let descriptor = format!("tr({pubk})");

            Wallet::create_single(descriptor)
                .network(network)
                .create_wallet(&mut db)?
        };
        res.push((imported_wallet, db));
    }
    Ok(res)
}

impl WalletApi for BMPWallet<Connection> {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";
    const DB_NAME: &str = "bmp_bdk_wallet.db3";

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> Result<(), anyhow::Error> {
        let network = self.network();
        let mut vec = vec![&mut self.wallet];
        let mut imported =
            get_imported_wallets(&self.imported_keys, &self.db, network, Self::DB_NAME)?;

        vec.extend(
            imported
                .iter_mut()
                .map(|persister_wallet| &mut persister_wallet.0),
        );

        s.sync(vec).await?;

        let mut final_imported_balance = Balance::default();

        // For having accurate Wallet::calculate_fee and Wallet::calculate_fee_rate
        // This is also at same time a way to have to UTXOs of the imported merged
        // into the main wallet, allowing easy manipulation during coinselection
        for (w, _) in &imported {
            for utxo in w.list_unspent() {
                self.insert_txout(utxo.outpoint, utxo.txout);
            }
            final_imported_balance = final_imported_balance + w.balance();
        }

        self.imported_balance = final_imported_balance;

        // Persist changes from imported keys
        for (w, db) in &mut imported {
            w.persist(db)?;
        }

        self.persist()?;
        Ok(())
    }

    fn new(path: &Path, password: &str, network: Network) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        // TODO: Make the word size configurable?
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let xprv = Xpriv::new_master(network, &seed)?;

        let (descriptor, external_map, _) =
            Bip86(xprv, KeychainKind::External).build(network.into())?;
        let (change_descriptor, internal_map, _) =
            Bip86(xprv, KeychainKind::Internal).build(network.into())?;

        let db_path = path.join(Self::DB_NAME);
        let db_path = db_path.to_str().expect("Should get path value");

        let mut db = Connection::new(db_path)?;

        // Derive encryption key
        let salt_path = format!("{db_path}.salt");
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        fs::write(&salt_path, general_purpose::STANDARD.encode(salt))?;
        let enc_key = derive_key_from_password(password, &salt)?;
        db.pragma_update(None, "key", enc_key)?;

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet(&mut db)?;

        Connection::init(
            &mut db,
            Some(Self::IMPORTED_KEYS_TABLE_NAME),
            Some(Self::SEEDS_TABLE_NAME),
        )?;

        let mnemonic = Mnemonic::from_entropy(&seed)?;
        let words = mnemonic.to_string();
        Connection::persist_seed_phrase(&mut db, Self::SEEDS_TABLE_NAME, &words)?;

        Ok(Self {
            wallet,
            imported_keys: vec![],
            imported_balance: Balance::default(),
            signers_loaded: true,
            db,
            last_unused_address: None,
        })
    }

    fn persist(&mut self) -> anyhow::Result<bool> {
        // Persist imported keys and then persist staged changes from ChangeSet
        let _ = Connection::persist_imported_keys(
            &mut self.db,
            Self::IMPORTED_KEYS_TABLE_NAME,
            &self.imported_keys,
        );

        match self.wallet.staged_mut() {
            Some(stage) => {
                Connection::persist_staged_changes(&mut self.db, &*stage)?;
                let _ = stage.take();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> anyhow::Result<(), SignerError> {
        //// @TODO performance: cache the public keys derivation
        let secp = self.secp_ctx();
        let is_mine = |input_script: &ScriptBuf| {
            for key in &self.imported_keys {
                let xonly_pubkey = key.0.base_point_mul().serialize_xonly();
                let xonly_pubkey = XOnlyPublicKey::from_slice(&xonly_pubkey)
                    .expect("Should be valid xonly pubkey");
                let script = ScriptBuf::new_p2tr(secp, xonly_pubkey, key.1);

                if script == *input_script {
                    return Some(*key);
                }
            }
            None
        };

        for (input_index, input_details) in psbt.inputs.clone().iter().enumerate() {
            let txout = input_details.witness_utxo.as_ref().unwrap();

            if let Some(signing_key) = is_mine(&txout.script_pubkey) {
                let signer = PrivateKey::from_slice(&signing_key.0.serialize(), self.network())
                    .map_err(|_e| SignerError::External("Invalid signing key".to_owned()))?;

                let sw = SignerWrapper::new(
                    signer,
                    SignerContext::Tap {
                        is_internal_key: true,
                    },
                );

                sw.sign_input(psbt, input_index, &sign_options, secp)?;
                psbt.finalize_inp_mut(secp, input_index)
                    .map_err(|_e| SignerError::External("Unable to finalized input".to_owned()))?;
            }
        }

        // Check whether the signing keys were loaded if not load them into the wallet
        if !self.signers_loaded {
            tracing::info!("Loading the signers into the wallet");
            let recovery_phrase = self
                .get_seed_phrase()
                .map_err(|_| SignerError::External("Unable to load keys.".to_owned()))?;
            let mnemonic = Mnemonic::parse_normalized(&recovery_phrase)
                .map_err(|_| SignerError::External("Unable to parse recovery phrase".to_owned()))?;

            let xprv = Xpriv::new_master(self.network(), &mnemonic.to_entropy())
                .map_err(|_| SignerError::External("Unable to load keys".to_owned()))?;

            let (_, external_map, _) = Bip86(xprv, KeychainKind::External)
                .build(self.network().into())
                .map_err(|_| SignerError::External("BIP 86 derivation failed".to_owned()))?;

            let (_, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
                .build(self.network().into())
                .map_err(|_| SignerError::External("BIP 86 derivation failed".to_owned()))?;

            self.wallet.set_keymap(KeychainKind::External, external_map);
            self.wallet.set_keymap(KeychainKind::Internal, internal_map);
            self.signers_loaded = true;
        }

        // BDK returns `true` only when every input of the PSBT got finalized. Partial-sign use
        // cases (e.g. the trade protocol's half-deposit PSBTs that also carry the peer's still-
        // unsigned inputs) legitimately leave inputs un-finalized, so we don't assert here.
        let _finalized = self.wallet.sign(psbt, sign_options)?;

        Ok(())
    }

    // For already created wallets this will load stored data
    // This will also load the imported keys
    fn load_wallet(path: &Path, network: Network, password: &str) -> anyhow::Result<Self> {
        let (salt, mut db) = {
            let p = path.join(Self::DB_NAME);
            (
                get_salt(p.to_str().expect("Path must not be empty"))?,
                Connection::open(p)?,
            )
        };

        let decrypt_key = derive_key_from_password(password, &salt)?;
        db.pragma_update(None, "key", decrypt_key)?;

        let wallet_opt = Wallet::load().check_network(network).load_wallet(&mut db)?;

        if let Some(wallet) = wallet_opt {
            let imported_keys =
                Connection::load_imported_keys(&mut db, Self::IMPORTED_KEYS_TABLE_NAME)?;

            return Ok(Self {
                wallet,
                imported_keys,
                imported_balance: Balance::default(),
                signers_loaded: false,
                db,
                last_unused_address: None,
            });
        }

        Err(anyhow::anyhow!("Unable to load wallet"))
    }

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst> {
        self.build_tx()
    }

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo> {
        self.next_address(KeychainKind::External)
    }

    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo> {
        self.next_address(KeychainKind::Internal)
    }

    fn balance(&self) -> Amount {
        (self.imported_balance.clone() + self.wallet.balance()).trusted_spendable()
    }

    fn get_seed_phrase(&self) -> anyhow::Result<String> {
        Connection::get_seed_phrase(&self.db, Self::SEEDS_TABLE_NAME)
    }

    fn drain_imported_balance(&mut self, fee_rate: FeeRate) -> anyhow::Result<Psbt> {
        let drain_to_address = self.next_address(KeychainKind::Internal)?;
        let imported_balance = self.imported_balance.trusted_spendable();

        let imported_utxos = self.imported_utxos();
        let cs = SpendImportedOnly(imported_utxos.clone());

        let mut tx_builder = self.build_tx().coin_selection(cs);

        tx_builder
            .fee_rate(fee_rate)
            .add_recipient(drain_to_address.script_pubkey(), imported_balance);

        match tx_builder.finish() {
            Err(e) => match e {
                bdk_wallet::error::CreateTxError::CoinSelection(insufficient_funds) => {
                    let cs = SpendImportedOnly(imported_utxos);
                    let fees = insufficient_funds.needed - insufficient_funds.available;
                    let amount_to_send = imported_balance - fees;
                    let mut new_builder = self.build_tx().coin_selection(cs);
                    new_builder
                        .fee_rate(fee_rate)
                        .add_recipient(drain_to_address.script_pubkey(), amount_to_send);

                    let psbt = new_builder.finish()?;
                    self.imported_balance = Balance::default();

                    tracing::debug!(
                        "AMOUNT TO SEND {amount_to_send}, fees {fees}, imported balance {}",
                        self.imported_balance
                    );

                    Ok(psbt)
                }
                _ => Err(e.into()),
            },
            Ok(psbt) => Ok(psbt),
        }
    }
}

impl Deref for BMPWallet<Connection> {
    type Target = PersistedWallet<Connection>;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for BMPWallet<Connection> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bdk_kyoto::FeeRate;
    use bdk_kyoto::bip157::{ScriptBuf, tokio};
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::bitcoin::key::Secp256k1;
    use bdk_wallet::bitcoin::{
        Address, AddressType, Amount, BlockHash, Network, OutPoint, TapNodeHash, TxOut, Weight,
        psbt,
    };
    use bdk_wallet::chain::{self, BlockId};
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

    #[test]
    fn test_create_wallet() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert_eq!(bmp_wallet.imported_keys.len(), 0);
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
            assert_eq!(wallet.imported_keys.len(), 0);
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

        assert_eq!(wallet.imported_keys.len(), 0);
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

        bmp_wallet.import_private_key(pk1, None);
        bmp_wallet.import_private_key(pk2, None);

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
        assert_eq!(loaded_wallet.imported_keys, bmp_wallet.imported_keys);
        Ok(())
    }

    #[test]
    fn test_imported_keys_with_merkle_root() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let pk = new_private_key();

        // Create a sample merkle root (32 bytes hex)
        let merkle_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let merkle = TapNodeHash::from_str(merkle_hex)?;

        bmp_wallet.import_private_key(pk, Some(merkle));

        assert_eq!(bmp_wallet.imported_keys.len(), 1);

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;

        assert_eq!(loaded_wallet.imported_keys.len(), 1);

        let (loaded_pk, loaded_merkle_opt) = &loaded_wallet.imported_keys[0];
        assert_eq!(loaded_pk, &pk);
        let loaded_merkle = loaded_merkle_opt
            .as_ref()
            .expect("merkle root should be present");
        assert_eq!(loaded_merkle.to_string(), merkle_hex);

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

        bmp_wallet.import_private_key(pk1, None);
        bmp_wallet.import_private_key(pk2, None);

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

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
            bmp_wallet.import_private_key(*k, None);
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
    async fn sign_with_imported_key_merkle_root() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let pk = new_private_key();

        // Example merkle root hex (32 bytes)
        let merkle_hex = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let merkle = TapNodeHash::from_str(merkle_hex)?;

        // Import private key with merkle root
        bmp_wallet.import_private_key(pk, Some(merkle));

        // Build a tx consuming a foreign utxo that pays to tr(pubkey, merkle_root)
        let secp = Secp256k1::new();
        let xonly = derive_public_key(&pk);

        let outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001:0",
        )?;

        let txout = TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, Some(merkle)),
        };

        let mut psbt_input = psbt::Input {
            witness_utxo: Some(txout.clone()),
            tap_internal_key: Some(xonly),
            ..Default::default()
        };
        psbt_input.tap_merkle_root = Some(merkle);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder
            .add_foreign_utxo(outpoint, psbt_input, Weight::from_wu(66))
            .unwrap();

        // Add a recipient so transaction can be built
        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        tx_builder.add_recipient(to_address, Amount::from_sat(100_000));

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

        bmp_wallet.import_private_key(Scalar::from_slice(&pk1).unwrap(), None);
        bmp_wallet.import_private_key(Scalar::from_slice(&pk2).unwrap(), None);

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

        bmp_wallet.import_private_key(pk1, None);
        bmp_wallet.import_private_key(pk2, None);

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));
        assert_eq!(
            bmp_wallet.imported_balance.trusted_spendable(),
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
