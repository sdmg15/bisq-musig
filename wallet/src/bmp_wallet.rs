use std::ops::{Deref, DerefMut};
use std::vec;

use bdk_electrum::bdk_core::bitcoin::{Address, FeeRate, OutPoint};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{
    Amount, Network, PrivateKey, Psbt, ScriptBuf, Sequence, TapNodeHash, Weight, XOnlyPublicKey,
    psbt,
};
use bdk_wallet::chain::Merge as _;
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::miniscript::descriptor::{TapTree, Tr};
use bdk_wallet::miniscript::psbt::PsbtExt as _;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::signer::{InputSigner as _, SignerContext, SignerError, SignerWrapper};
use bdk_wallet::template::{Bip86, DescriptorTemplate as _};
use bdk_wallet::{
    AddressInfo, Balance, KeychainKind, PersistedWallet, SignOptions, TxBuilder, Utxo, Wallet,
    WeightedUtxo,
};
use rand::RngCore as _;
use secp::Scalar;

use crate::chain_data_source::ChainDataSource;
use crate::coin_selection::{AlwaysSpendImportedFirst, SpendImportedOnly};
use crate::persisted::{BMPDatabase, BMPWalletPersister, DBStorage};
use crate::protocol_wallet_api::{
    ProtocolWalletApi, WalletErrorKind, WalletExt, finish_standard_psbt, internal_key_at_index,
    sign_selected_inputs_with,
};
use crate::utils::derive_key_from_password;

/// An external (non-HD) private key imported into the wallet, together with the Taproot output
/// template it controls: `tr(P, tap_tree)` where `P` is the (untweaked) internal key derived from
/// `secret`. A missing tap tree means a key-path-only output (`tr(P)`, as in BIP86).
///
/// The full descriptor is kept (rather than just the merkle root) because BDK wallets are
/// descriptor-driven: it is what lets the per-key sub-wallet in [`load_imported_wallets`] watch
/// the right script pubkey, and what [`BMPWallet::imported_utxos`] and [`WalletApi::sign`] use
/// to recognise and tweak-sign the output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedKey {
    secret: Scalar,
    descriptor: Tr<XOnlyPublicKey>,
}

impl ImportedKey {
    pub fn new(secret: Scalar, tap_tree: Option<TapTree<XOnlyPublicKey>>) -> anyhow::Result<Self> {
        let descriptor = Tr::new(Self::internal_key_of(&secret), tap_tree)?;
        Ok(Self { secret, descriptor })
    }

    /// Rebuild from the persisted `tr(..)` descriptor string; checks that it belongs to `secret`.
    pub(crate) fn from_descriptor_str(secret: Scalar, descriptor: &str) -> anyhow::Result<Self> {
        let descriptor: Tr<XOnlyPublicKey> = descriptor.parse()?;
        anyhow::ensure!(
            *descriptor.internal_key() == Self::internal_key_of(&secret),
            "imported key descriptor does not match its secret key"
        );
        Ok(Self { secret, descriptor })
    }

    fn internal_key_of(secret: &Scalar) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&secret.base_point_mul().serialize_xonly())
            .expect("Should be valid xonly pubkey")
    }

    pub const fn secret(&self) -> Scalar {
        self.secret
    }

    pub fn internal_key(&self) -> XOnlyPublicKey {
        *self.descriptor.internal_key()
    }

    pub fn tap_tree(&self) -> Option<&TapTree<XOnlyPublicKey>> {
        self.descriptor.tap_tree().as_ref()
    }

    pub const fn descriptor(&self) -> &Tr<XOnlyPublicKey> {
        &self.descriptor
    }

    pub fn merkle_root(&self) -> Option<TapNodeHash> {
        self.descriptor.spend_info().merkle_root()
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.descriptor.script_pubkey()
    }
}

pub(crate) const STOP_GAP: usize = 50;

pub struct BMPWallet<P: BMPWalletPersister> {
    wallet: PersistedWallet<P>,
    imported_keys: Vec<ImportedKey>,
    imported_balance: Balance,
    signers_loaded: bool,
    db: BMPDatabase<P>,
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

    /// Import an external private key (i.e. one not derived from the HD wallet) controlling a
    /// `tr(P, tap_tree)` output, `P` being the untweaked internal key of `pk`. `None` means a
    /// key-path-only `tr(P)` output. After importing, a rescan should be triggered.
    pub fn import_private_key(
        &mut self,
        pk: Scalar,
        tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind> {
        self.imported_keys.push(ImportedKey::new(pk, tap_tree)?);
        Ok(())
    }

    /// Test-only introspection of the imported keys; enable the `test-utils` feature to use it
    /// from tests in downstream crates.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn imported_keys(&self) -> &[ImportedKey] {
        &self.imported_keys
    }

    pub const fn imported_balance(&self) -> &Balance {
        &self.imported_balance
    }

    fn imported_utxos(&self) -> Vec<WeightedUtxo> {
        self.tx_graph()
            .floating_txouts()
            .map(|utxo| {
                let output_script_pubkey = &utxo.1.script_pubkey;

                let (tap_internal_key, tap_merkle_root) = self
                    .imported_keys
                    .iter()
                    .find(|key| key.script_pubkey() == *output_script_pubkey)
                    .map_or((None, None), |key| {
                        (Some(key.internal_key()), key.merkle_root())
                    });

                WeightedUtxo {
                    utxo: Utxo::Foreign {
                        outpoint: utxo.0,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        psbt_input: Box::new(psbt::Input {
                            witness_utxo: Some(utxo.1.clone()),
                            tap_internal_key,
                            tap_merkle_root,
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

    fn load_imported_wallets(
        imported_keys: &[ImportedKey],
        storage: &DBStorage,
        network: Network,
    ) -> anyhow::Result<Vec<(PersistedWallet<Connection>, Connection)>> {
        let mut res = vec![];
        for key in imported_keys {
            let pubk = key.internal_key();
            // One sub-wallet DB per output template: the same internal key may back a key-path-only
            // output and a `tr(P, tree)` output, which have different script pubkeys.
            let db_file = match key.merkle_root() {
                None => format!("bmp_{pubk}.db3"),
                Some(root) => format!("bmp_{pubk}_{root}.db3"),
            };

            let imported_storage = storage.sibling(&db_file);
            let mut db = imported_storage.open(&db_file)?;
            let descriptor = key.descriptor().to_string();

            let imported_wallet_opt = Wallet::load()
                .descriptor(KeychainKind::External, Some(descriptor.clone()))
                .check_network(network)
                .extract_keys()
                .load_wallet(&mut db)?;

            let imported_wallet = if let Some(wallet) = imported_wallet_opt {
                wallet
            } else {
                Wallet::create_single(descriptor)
                    .network(network)
                    .create_wallet(&mut db)?
            };
            res.push((imported_wallet, db));
        }
        Ok(res)
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

    fn import_private_key(
        &mut self,
        pk: Scalar,
        tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind> {
        self.import_private_key(pk, tap_tree)
    }
}

#[trait_variant::make(Send)]
pub trait WalletApi {
    const DB_NAME: &str;
    const SEEDS_TABLE_NAME: &'static str;
    const IMPORTED_KEYS_TABLE_NAME: &'static str;

    fn new(storage: DBStorage, password: &str, network: Network) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn load_wallet(storage: DBStorage, network: Network, password: &str) -> anyhow::Result<Self>
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

impl WalletApi for BMPWallet<Connection> {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";
    const DB_NAME: &str = "bmp_bdk_wallet.db3";

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> Result<(), anyhow::Error> {
        let network = self.network();
        let mut vec = vec![&mut self.wallet];
        let mut imported =
            Self::load_imported_wallets(&self.imported_keys, self.db.location(), network)?;

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

    fn new(storage: DBStorage, password: &str, network: Network) -> anyhow::Result<Self>
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

        let mut db = storage.open(Self::DB_NAME)?;
        let salt = storage.persist_salt(Self::DB_NAME)?;

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
            db: BMPDatabase::new(storage,db),
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
            self.imported_keys
                .iter()
                .find(|key| key.script_pubkey() == *input_script)
        };

        for (input_index, input_details) in psbt.inputs.clone().iter().enumerate() {
            let txout = input_details.witness_utxo.as_ref().unwrap();

            if let Some(signing_key) = is_mine(&txout.script_pubkey) {
                let signer =
                    PrivateKey::from_slice(&signing_key.secret().serialize(), self.network())
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
    fn load_wallet(storage: DBStorage, network: Network, password: &str) -> anyhow::Result<Self> {
        let salt = storage.load_salt(Self::DB_NAME)?;
        let mut db = storage.open(Self::DB_NAME)?;

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
                db: BMPDatabase::new(storage, db),
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
