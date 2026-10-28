use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ops::{Deref, DerefMut};
use std::time::UNIX_EPOCH;
use std::vec;

use bdk_electrum::bdk_core::bitcoin::{Address, FeeRate, OutPoint};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hex::DisplayHex as _;
use bdk_wallet::bitcoin::{
    Amount, Network, PrivateKey, Psbt, ScriptBuf, Sequence, TapNodeHash, Transaction, Weight,
    XOnlyPublicKey, consensus, psbt,
};
use bdk_wallet::chain::{ChainPosition, Merge as _};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::miniscript::descriptor::{KeyMap, TapTree, Tr};
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
use crate::error::{Result, WalletErrorKind};
use crate::password::Password;
use crate::persisted::{BMPDatabase, BMPWalletPersister as _, DBStorage, PersistenceError};
use crate::protocol_wallet_api::{
    ProtocolWalletApi, WalletExt, finish_standard_psbt, internal_key_at_index,
    sign_selected_inputs_with,
};
use crate::utils::{derive_key_from_password, key_verifier};
use crate::wallet_info::{PubAddressInfo, TxInfo, TxInputInfo, TxOutputInfo, UtxoInfo};
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
    pub fn new(secret: Scalar, tap_tree: Option<TapTree<XOnlyPublicKey>>) -> Result<Self> {
        let descriptor = Tr::new(Self::internal_key_of(&secret), tap_tree)?;
        Ok(Self { secret, descriptor })
    }

    /// Rebuild from the persisted `tr(..)` descriptor string; checks that it belongs to `secret`.
    pub(crate) fn from_descriptor_str(secret: Scalar, descriptor: &str) -> Result<Self> {
        let descriptor: Tr<XOnlyPublicKey> = descriptor.parse()?;
        if *descriptor.internal_key() != Self::internal_key_of(&secret) {
            return Err(WalletErrorKind::MismatchedDescriptor);
        }
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

pub struct BMPWallet {
    wallet: PersistedWallet<Connection>,
    imported_keys: HashMap<ScriptBuf, ImportedKey>,
    imported_balance: Balance,
    signers_loaded: bool,
    db: BMPDatabase<Connection>,
    last_unused_address: Option<String>,
    /// Argon2 salt backing the current database key, mirrored on disk as `<db_path>.salt`.
    salt: Vec<u8>,
    /// SHA-256 fingerprint of the `SQLCipher` key currently in force. Retained so a caller-
    /// supplied password can be *verified* (re-derive, fingerprint, compare) without keeping the
    /// plaintext password — or the key itself — in memory: the derived key only exists
    /// transiently, for `PRAGMA key`/`rekey`, and is zeroized right after use.
    key_verifier: [u8; 32],
}

struct Bip86Keys {
    external: (ExtendedDescriptor, KeyMap),
    internal: (ExtendedDescriptor, KeyMap),
}

impl BMPWallet {
    fn bip86_keys_from_seed_phrase(network: Network, seed_phrase: &str) -> Result<Bip86Keys> {
        let mnemonic = Mnemonic::parse_normalized(seed_phrase)?;
        let seed = mnemonic.to_seed("");
        let xprv = Xpriv::new_master(network, &seed)?;

        let (external, external_map, _) =
            Bip86(xprv, KeychainKind::External).build(network.into())?;
        let (internal, internal_map, _) =
            Bip86(xprv, KeychainKind::Internal).build(network.into())?;

        Ok(Bip86Keys {
            external: (external, external_map),
            internal: (internal, internal_map),
        })
    }

    fn create_wallet_from_seed(
        db: &mut Connection,
        network: Network,
        seed_phrase: &str,
    ) -> Result<PersistedWallet<Connection>> {
        let Bip86Keys {
            external: (descriptor, external_map),
            internal: (change_descriptor, internal_map),
        } = Self::bip86_keys_from_seed_phrase(network, seed_phrase)?;

        Ok(Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet(db)?)
    }

    pub fn list_unused_addresses_since_last_used(
        &self,
        key_chain: KeychainKind,
    ) -> impl Iterator<Item = AddressInfo> + '_ {
        let last_used = self.spk_index().last_used_index(key_chain);
        self.list_unused_addresses(key_chain)
            .filter(move |info| last_used.is_none_or(|idx| info.index > idx))
    }

    pub fn next_address(&mut self, key_chain: KeychainKind) -> Result<AddressInfo> {
        let unused = self
            .list_unused_addresses_since_last_used(key_chain)
            .collect::<Vec<_>>();

        let addr = if unused.len() >= STOP_GAP {
            // Find the position of the last returned address, or start at the beginning
            let next_index = if let Some(last_addr) = &self.last_unused_address {
                // Search for the last address in the current unused list
                unused
                    .iter()
                    .position(|info| info.address.to_string() == *last_addr)
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
    ) -> Result<()> {
        let key_to_import = ImportedKey::new(pk, tap_tree)?;
        Self::insert_imported_key(&mut self.imported_keys, key_to_import)
    }

    /// Test-only introspection of the imported keys; enable the `test-utils` feature to use it
    /// from tests in downstream crates.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn imported_keys(&self) -> Vec<ImportedKey> {
        let mut keys = self.imported_keys.values().cloned().collect::<Vec<_>>();
        keys.sort_by(|left, right| {
            left.script_pubkey()
                .as_bytes()
                .cmp(right.script_pubkey().as_bytes())
        });
        keys
    }

    pub const fn imported_balance(&self) -> &Balance {
        &self.imported_balance
    }

    fn imported_utxos(&self) -> Vec<WeightedUtxo> {
        self.tx_graph()
            .floating_txouts()
            .filter(|utxo| !self.is_utxo_locked(utxo.0))
            .map(|utxo| {
                let output_script_pubkey = &utxo.1.script_pubkey;

                let (tap_internal_key, tap_merkle_root) = self
                    .imported_keys
                    .get(output_script_pubkey)
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

    /// The full balance breakdown, combining the HD wallet with any imported keys.
    ///
    /// [`WalletApi::balance`] flattens this to a single spendable [`Amount`]; callers that need
    /// to distinguish confirmed from pending funds should use this instead.
    pub fn full_balance(&self) -> Balance {
        self.imported_balance.clone() + self.wallet.balance()
    }

    /// Every address revealed so far on either keychain, external first.
    pub fn list_wallet_addresses(&self) -> Vec<PubAddressInfo> {
        [KeychainKind::External, KeychainKind::Internal]
            .into_iter()
            .flat_map(|kind| {
                // `derivation_index` is `None` until the keychain has revealed anything, in
                // which case the inner range is skipped entirely.
                self.wallet
                    .derivation_index(kind)
                    .into_iter()
                    .flat_map(move |last_revealed| {
                        (0..=last_revealed).map(move |index| PubAddressInfo {
                            address: self.wallet.peek_address(kind, index).address,
                        })
                    })
            })
            .collect()
    }

    /// The imported key controlling `script_pubkey`, if any.
    fn imported_key_for_script(&self, script_pubkey: &ScriptBuf) -> Option<&ImportedKey> {
        self.imported_keys.get(script_pubkey)
    }

    fn insert_imported_key(
        imported_keys: &mut HashMap<ScriptBuf, ImportedKey>,
        key: ImportedKey,
    ) -> Result<()> {
        if imported_keys
            .values()
            .any(|existing| existing.internal_key() == key.internal_key())
        {
            return Err(WalletErrorKind::DuplicateKey);
        }

        match imported_keys.entry(key.script_pubkey()) {
            Entry::Occupied(_) => Err(WalletErrorKind::DuplicateKey),
            Entry::Vacant(entry) => {
                entry.insert(key);
                Ok(())
            }
        }
    }

    /// Renders `script_pubkey` as an address, or `None` if it isn't a standard one.
    fn address_for_script(&self, script_pubkey: &ScriptBuf) -> Option<PubAddressInfo> {
        Address::from_script(script_pubkey, self.wallet.network())
            .ok()
            .map(|address| PubAddressInfo { address })
    }

    /// Confirmation count for a chain position: `0` while unconfirmed.
    fn num_confirmations(&self, block_height: Option<u32>) -> u32 {
        let next_height = self.wallet.latest_checkpoint().height() + 1;
        block_height.map_or(0, |height| next_height.saturating_sub(height))
    }

    /// All unspent outputs, both the HD wallet's own and those held by imported keys.
    ///
    /// Imported outputs live in the tx graph as *floating* txouts (inserted by
    /// [`WalletApi::sync_all`] so that fee calculation works), which carry no chain position —
    /// they are therefore always reported with `num_confirmations == 0`. Ones the graph already
    /// knows to be spent are dropped, so this stays consistent with [`Self::full_balance`].
    pub fn list_utxos(&self) -> Vec<UtxoInfo> {
        let own = self.list_unspent().map(|utxo| {
            let block_height = match utxo.chain_position {
                ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.height),
                ChainPosition::Unconfirmed { .. } => None,
            };
            UtxoInfo {
                tx_id: utxo.outpoint.txid,
                vout: utxo.outpoint.vout,
                amount: utxo.txout.value,
                address: self.address_for_script(&utxo.txout.script_pubkey),
                num_confirmations: self.num_confirmations(block_height),
                imported: false,
                is_locked: self.is_outpoint_locked(utxo.outpoint),
            }
        });

        let imported = self
            .tx_graph()
            .floating_txouts()
            .filter(|(outpoint, _)| self.tx_graph().outspends(*outpoint).is_empty())
            .filter(|(_, txout)| self.imported_key_for_script(&txout.script_pubkey).is_some())
            .map(|(outpoint, txout)| UtxoInfo {
                tx_id: outpoint.txid,
                vout: outpoint.vout,
                amount: txout.value,
                address: self.address_for_script(&txout.script_pubkey),
                num_confirmations: 0,
                imported: true,
                is_locked: self.is_outpoint_locked(outpoint)
            });

        own.chain(imported).collect()
    }

    /// Every wallet-relevant transaction, flattened for display.
    pub fn list_transactions(&self) -> Vec<TxInfo> {
        self.wallet
            .transactions()
            .map(|wallet_tx| {
                let tx = wallet_tx.tx_node.tx.as_ref();
                let (sent, received) = self.wallet.sent_and_received(tx);
                // `sent` counts every input we own and `received` every output we own (change
                // included), so the difference is the true net effect on the wallet.
                let incoming = received >= sent;
                let amount = if incoming {
                    received - sent
                } else {
                    sent - received
                };

                let (block_height, timestamp) = match &wallet_tx.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        (Some(anchor.block_id.height), Some(anchor.confirmation_time))
                    }
                    ChainPosition::Unconfirmed { .. } => (None, None),
                };

                TxInfo {
                    tx_id: wallet_tx.tx_node.txid,
                    inputs: tx
                        .input
                        .iter()
                        .map(|txin| TxInputInfo {
                            prev_out_tx_id: txin.previous_output.txid,
                            prev_out_index: txin.previous_output.vout,
                            sequence: txin.sequence.to_consensus_u32(),
                            script_sig: txin.script_sig.clone(),
                            witness: consensus::serialize(&txin.witness).to_lower_hex_string(),
                        })
                        .collect(),
                    outputs: tx
                        .output
                        .iter()
                        .map(|txout| TxOutputInfo {
                            value: txout.value,
                            address: self.address_for_script(&txout.script_pubkey),
                            script_pubkey: txout.script_pubkey.clone(),
                        })
                        .collect(),
                    lock_time: tx.lock_time.to_consensus_u32(),
                    block_height,
                    timestamp,
                    num_confirmations: self.num_confirmations(block_height),
                    amount,
                    incoming,
                }
            })
            .collect()
    }

    /// Checks `password` against the key currently protecting the database, without needing the
    /// plaintext password (or the key itself) to have been retained: the freshly derived key is
    /// compared by its one-way fingerprint and dropped again.
    pub fn check_password(&self, password: &Password) -> Result<bool> {
        let key = derive_key_from_password(password, &self.salt)?;
        Ok(key_verifier(&key) == self.key_verifier)
    }

    /// Re-keys the database to `new_password`, rotating the Argon2 salt at the same time.
    ///
    /// The rotation is staged so that the database is at no point keyed by a salt that exists
    /// nowhere on disk (a crash then would make the wallet permanently unopenable): the new salt
    /// is written to `<db_path>.salt.new` *before* the re-key, and renamed over `<db_path>.salt`
    /// after it. A crash in between is healed on the next [`WalletApi::load_wallet`], which
    /// falls back to the staged salt and completes the rename.
    ///
    /// This is the raw primitive and authenticates nobody: `old_password` is only used to undo
    /// the re-key when committing the new salt fails. Every caller must verify it first — see
    /// [`Self::change_password`].
    fn rekey(&mut self, old_password: &Password, new_password: &Password) -> Result<()> {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let new_key = derive_key_from_password(new_password, &salt)?;

        self.db.storage().write_staged_salt(Self::DB_NAME, &salt)?;

        if let Err(e) = self.db.pragma_update(None, "rekey", new_key.as_str()) {
            self.db.storage().remove_staged_salt(Self::DB_NAME);
            return Err(PersistenceError::Database(e).into());
        }

        // Commit the rotated salt. If that fails, undo the re-key with a key re-derived from
        // the (just verified) old password, rather than leave database and salt out of step.
        if let Err(e) = self.db.storage().commit_staged_salt(Self::DB_NAME) {
            let old_key = derive_key_from_password(old_password, &self.salt)?;
            self.db.pragma_update(None, "rekey", old_key.as_str())?;
            self.db.storage().remove_staged_salt(Self::DB_NAME);
            return Err(e.into());
        }

        self.salt = salt.to_vec();
        self.key_verifier = key_verifier(&new_key);
        Ok(())
    }

    /// Changes the wallet password from `old_password` to `new_password`, re-keying the
    /// database and rotating the Argon2 salt.
    ///
    /// `old_password` must be the password currently in force, so nobody who cannot present it
    /// can rotate the key and lock the owner out. The wallet is always password-protected: a
    /// password can only be replaced, never removed, and `new_password` follows the password rules
    /// by construction (see [`Password`]).
    pub fn change_password(
        &mut self,
        old_password: &Password,
        new_password: &Password,
    ) -> Result<()> {
        if !self.check_password(old_password)? {
            return Err(WalletErrorKind::InvalidPassword);
        }
        self.rekey(old_password, new_password)
    }

    /// Builds, signs and persists a payment to `address`. The caller is responsible for
    /// broadcasting the returned transaction.
    ///
    /// The signed transaction is recorded in the wallet as unconfirmed before it is returned,
    /// so its inputs count as spent from here on. The wallet cannot rely on the chain to tell
    /// it: compact block filter sync only ever reports confirmed transactions, so until the
    /// payment was mined the spent coins would still look unspent, and a second payment would
    /// happily pick the same inputs — and, since BDK opts into RBF, could replace the first one
    /// in the mempool. Treating a signed-and-handed-out transaction as spent is the safe
    /// direction: a payment that never made it to the network leaves coins looking locked
    /// (recoverable) rather than double-spent (not).
    pub fn send_to_address(
        &mut self,
        address: &Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Transaction> {
        let mut builder = self.build_tx();
        builder
            .fee_rate(fee_rate)
            .add_recipient(address.script_pubkey(), amount);
        let mut psbt = builder.finish()?;

        <Self as WalletApi>::sign(self, &mut psbt, SignOptions::default())?;
        let tx = psbt.extract_tx()?;

        let last_seen = UNIX_EPOCH
            .elapsed()
            .map_err(WalletErrorKind::generic)?
            .as_secs();
        self.wallet.apply_unconfirmed_txs([(tx.clone(), last_seen)]);
        <Self as WalletApi>::persist(self)?;

        Ok(tx)
    }

    pub(crate) fn load_imported_wallets<'a>(
        imported_keys: impl IntoIterator<Item = &'a ImportedKey>,
        storage: &DBStorage,
        network: Network,
    ) -> Result<Vec<(PersistedWallet<Connection>, Connection)>> {
        let mut res = vec![];
        for key in imported_keys {
            let pubk = key.internal_key();
            let db_file = format!("bmp_{pubk}.db3");

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

    /// Opens the wallet database at `db_path` with the key derived from `password` and `salt`.
    ///
    /// Factored out of [`WalletApi::load_wallet`] so that it can be retried with the *staged* salt
    /// when recovering from an interrupted password change (see [`BMPWallet::rekey`]).
    fn load_with_salt(
        storage: DBStorage,
        salt: Vec<u8>,
        network: Network,
        password: &Password,
    ) -> Result<Self> {
        let mut db = storage.open(Self::DB_NAME)?;
        let key = derive_key_from_password(password, &salt)?;
        db.pragma_update(None, "key", key.as_str())?;

        let wallet_opt = Wallet::load()
            .check_network(network)
            .load_wallet(&mut db)
            .map_err(|e| match e {
                bdk_wallet::LoadWithPersistError::Persist(rusqlite::Error::SqliteFailure(
                    sqlite_err,
                    _,
                )) if sqlite_err.code == rusqlite::ErrorCode::NotADatabase => {
                    WalletErrorKind::InvalidPassword
                }
                // SQLCipher uses `NotADatabase` for a wrong key; permission failures remain
                // persistence errors so clients do not mistake filesystem access for a password.
                other => other.into(),
            })?;

        let wallet = if let Some(wallet) = wallet_opt {
            wallet
        } else if Connection::has_seed_phrase(&db, Self::SEEDS_TABLE_NAME)? {
            tracing::warn!("No wallet found, but seed phrase exists; creating wallet from seed");
            let seed_phrase = Connection::get_seed_phrase(&db, Self::SEEDS_TABLE_NAME)?;
            Self::create_wallet_from_seed(&mut db, network, &seed_phrase)?
        } else {
            return Err(WalletErrorKind::NoWallet);
        };

        let mut imported_keys = HashMap::new();
        for (key_hex, descriptor) in
            Connection::load_imported_key_rows(&mut db, Self::IMPORTED_KEYS_TABLE_NAME)?
        {
            let secret = Scalar::from_hex(&key_hex).map_err(WalletErrorKind::generic)?;
            let key = ImportedKey::from_descriptor_str(secret, &descriptor)?;
            Self::insert_imported_key(&mut imported_keys, key)?;
        }

        Ok(Self {
            wallet,
            imported_keys,
            imported_balance: Balance::default(),
            signers_loaded: false,
            db: BMPDatabase::new(storage, db),
            last_unused_address: None,
            salt,
            key_verifier: key_verifier(&key),
        })
    }
}

impl WalletExt for BMPWallet {
    fn update_psbt_with_derivation_paths(&self, psbt: &mut Psbt) {
        self.wallet.update_psbt_with_derivation_paths(psbt);
    }
}

impl ProtocolWalletApi for BMPWallet {
    fn network(&self) -> Network {
        self.wallet.network()
    }

    fn new_address(&mut self) -> Result<Address> {
        Ok(self.next_address(KeychainKind::External)?.address)
    }

    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey> {
        // Use `next_address` (gap-filling) rather than `reveal_next_address` directly so
        // that the internal key's index stays in step with what `new_address` would yield.
        let index = self.next_address(KeychainKind::External)?.index;
        internal_key_at_index(self, index)
    }

    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt> {
        finish_standard_psbt(self.build_tx(), recipients, fee_rate)
    }

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> Result<()> {
        // TODO unify signing
        sign_selected_inputs_with(self, psbt, is_selected, |w, p, opts| {
            <Self as WalletApi>::sign(w, p, opts)
        })
    }

    fn import_private_key(
        &mut self,
        pk: Scalar,
        tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<()> {
        self.import_private_key(pk, tap_tree)
    }

    fn list_locked_utxos(&self) -> Vec<OutPoint> {
        self.wallet.list_locked_outpoints().collect()
    }

    fn lock_utxo(&mut self, utxo: OutPoint) -> Result<()> {
        self.lock_outpoint(utxo);
        self.persist()?;
        Ok(())
    }

    fn unlock_utxo(&mut self, utxo: OutPoint) -> Result<()> {
        self.unlock_outpoint(utxo);
        self.persist()?;
        Ok(())
    }

    fn is_utxo_locked(&self, utxo: OutPoint) -> bool {
        self.is_outpoint_locked(utxo)
    }
}

#[trait_variant::make(Send)]
pub trait WalletApi {
    const DB_NAME: &str;
    const SEEDS_TABLE_NAME: &'static str;
    const IMPORTED_KEYS_TABLE_NAME: &'static str;

    /// Creates a fresh wallet in `storage`, protected by `password`.
    fn new(storage: DBStorage, password: &Password, network: Network) -> Result<Self>
    where
        Self: Sized;

    /// Opens the wallet in `storage`; a wrong `password` fails with
    /// [`WalletErrorKind::InvalidPassword`].
    fn load_wallet(storage: DBStorage, network: Network, password: &Password) -> Result<Self>
    where
        Self: Sized;

    fn get_new_address(&mut self) -> Result<AddressInfo>;
    fn get_change_address(&mut self) -> Result<AddressInfo>;

    fn get_seed_phrase(&self) -> Result<String>;

    fn balance(&self) -> Amount;

    fn persist(&mut self) -> Result<bool>;

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst>;

    fn sign(&mut self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<()>;

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> Result<()>;

    fn drain_imported_balance(&mut self, fee_rate: FeeRate) -> Result<Psbt>;
}

impl WalletApi for BMPWallet {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";
    const DB_NAME: &str = "bmp_bdk_wallet.db3";

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> Result<()> {
        let network = self.network();
        let mut vec = vec![&mut self.wallet];
        let mut imported =
            Self::load_imported_wallets(self.imported_keys.values(), self.db.storage(), network)?;

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

    fn new(storage: DBStorage, password: &Password, network: Network) -> Result<Self>
    where
        Self: Sized,
    {
        // TODO: Make the word size configurable?
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        // Never create over an existing wallet.
        if storage.db_exists(Self::DB_NAME) {
            return Err(WalletErrorKind::WalletAlreadyExists);
        }

        let mut db = storage.open(Self::DB_NAME)?;
        let salt = storage.persist_salt(Self::DB_NAME)?;

        let key = derive_key_from_password(password, &salt)?;
        db.pragma_update(None, "key", key.as_str())?;

        Connection::init(
            &mut db,
            Some(Self::IMPORTED_KEYS_TABLE_NAME),
            Some(Self::SEEDS_TABLE_NAME),
        )?;

        let mnemonic = Mnemonic::from_entropy(&seed)?;
        let words = mnemonic.to_string();
        Connection::persist_seed_phrase(&mut db, Self::SEEDS_TABLE_NAME, &words)?;

        let wallet = Self::create_wallet_from_seed(&mut db, network, &words)?;

        Ok(Self {
            wallet,
            imported_keys: HashMap::new(),
            imported_balance: Balance::default(),
            signers_loaded: true,
            db: BMPDatabase::new(storage, db),
            last_unused_address: None,
            salt,
            key_verifier: key_verifier(&key),
        })
    }

    fn persist(&mut self) -> Result<bool> {
        // Persist imported keys and then persist staged changes from ChangeSet
        let imported_keys = self.imported_keys.values().collect::<Vec<_>>();
        Connection::persist_imported_keys(
            &mut self.db,
            Self::IMPORTED_KEYS_TABLE_NAME,
            &imported_keys,
        )?;

        match self.wallet.staged_mut() {
            Some(stage) => {
                Connection::persist_staged_changes(&mut self.db, &*stage)?;
                let _ = stage.take();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn sign(&mut self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<()> {
        let secp = self.secp_ctx();
        for (input_index, input_details) in psbt.inputs.clone().iter().enumerate() {
            let txout = input_details.witness_utxo.as_ref().unwrap();

            if let Some(signing_key) = self.imported_keys.get(&txout.script_pubkey) {
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
            let Bip86Keys {
                external: (external_descriptor, external_map),
                internal: (internal_descriptor, internal_map),
            } = Self::bip86_keys_from_seed_phrase(self.network(), &recovery_phrase)
                .map_err(|_| SignerError::External("Unable to load keys".to_owned()))?;

            if &external_descriptor != self.wallet.public_descriptor(KeychainKind::External)
                || &internal_descriptor != self.wallet.public_descriptor(KeychainKind::Internal)
            {
                return Err(WalletErrorKind::SeedDescriptorMismatch);
            }

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
    fn load_wallet(storage: DBStorage, network: Network, password: &Password) -> Result<Self> {
        if let Some(p) = storage.base_path() {
            tracing::debug!(path = %p.display(), "Loading wallet database.");
        } else {
            tracing::debug!("Loading in-memory wallet database.");
        }

        let salt = storage.load_salt(Self::DB_NAME)?;
        match Self::load_with_salt(storage.clone(), salt, network, password) {
            Ok(wallet) => {
                storage.remove_staged_salt(Self::DB_NAME);
                Ok(wallet)
            }
            Err(primary_error) => {
                let staged_salt = storage.read_staged_salt(Self::DB_NAME);
                let Some(staged_salt) = staged_salt else {
                    return Err(primary_error);
                };

                let wallet = Self::load_with_salt(storage.clone(), staged_salt, network, password)
                    .map_err(|_| primary_error)?;

                storage.commit_staged_salt(Self::DB_NAME)?;
                tracing::warn!(
                    "Completed a password change that was interrupted before its rotated salt was committed."
                );
                Ok(wallet)
            }
        }
    }

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst> {
        self.build_tx()
    }

    fn get_new_address(&mut self) -> Result<AddressInfo> {
        self.next_address(KeychainKind::External)
    }

    fn get_change_address(&mut self) -> Result<AddressInfo> {
        self.next_address(KeychainKind::Internal)
    }

    fn balance(&self) -> Amount {
        (self.imported_balance.clone() + self.wallet.balance()).trusted_spendable()
    }

    fn get_seed_phrase(&self) -> Result<String> {
        Ok(Connection::get_seed_phrase(
            &self.db,
            Self::SEEDS_TABLE_NAME,
        )?)
    }

    fn drain_imported_balance(&mut self, fee_rate: FeeRate) -> Result<Psbt> {
        let drain_to_address = self.next_address(KeychainKind::Internal)?;
        let imported_utxos = self.imported_utxos();
        let imported_amount: Amount = imported_utxos
            .iter()
            .map(|utxo| utxo.utxo.txout().value)
            .sum();
        let cs = SpendImportedOnly(imported_utxos.clone());

        let mut tx_builder = self.build_tx().coin_selection(cs);

        tx_builder
            .fee_rate(fee_rate)
            .add_recipient(drain_to_address.script_pubkey(), imported_amount);

        let psbt = match tx_builder.finish() {
            Err(bdk_wallet::error::CreateTxError::CoinSelection(insufficient_funds)) => {
                let cs = SpendImportedOnly(imported_utxos);
                let fees = insufficient_funds.needed - insufficient_funds.available;
                let amount_to_send = imported_amount - fees;
                let mut new_builder = self.build_tx().coin_selection(cs);
                new_builder
                    .fee_rate(fee_rate)
                    .add_recipient(drain_to_address.script_pubkey(), amount_to_send);
                new_builder.finish()?
            }
            Err(e) => return Err(e.into()),
            Ok(psbt) => psbt,
        };

        let spent_amount: Amount = psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .expect("drain PSBT inputs must include witness UTXOs")
                    .value
            })
            .sum();
        self.imported_balance.confirmed -= spent_amount;

        tracing::debug!(
            "spent imported amount {}, remaining imported balance {}",
            spent_amount,
            self.imported_balance
        );

        Ok(psbt)
    }
}

impl Deref for BMPWallet {
    type Target = PersistedWallet<Connection>;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for BMPWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
