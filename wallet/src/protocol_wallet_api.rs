use std::io::Write as _;
use std::mem;
use std::sync::LazyLock;

use bdk_electrum::BdkElectrumClient;
use bdk_electrum::bdk_core::bitcoin::bip32::Xpriv;
use bdk_electrum::electrum_client::Client;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, XOnlyPublicKey, absolute,
    secp256k1,
};
use bdk_wallet::coin_selection::CoinSelectionAlgorithm;
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor};
use bdk_wallet::miniscript::ToPublicKey as _;
use bdk_wallet::miniscript::descriptor::TapTree;
use bdk_wallet::miniscript::psbt::PsbtExt as _;
use bdk_wallet::template::{Bip86, DescriptorTemplate as _};
use bdk_wallet::{AddressInfo, KeychainKind, SignOptions, TxBuilder, TxOrdering, Wallet};
use rand::RngCore as _;
use secp::Scalar;
use thiserror::Error;

/// The Protocol Wallet API is used by the protocol to create and sign transactions.
/// It's the part of functionality being exposed only to the protocol.
/// The protocol will see `protocol_wallet_api` and the GUI will see `WalletApi`, both are
/// implemented in the `BMPWallet`.
pub trait ProtocolWalletApi {
    fn network(&self) -> Network;

    fn new_address(&mut self) -> Result<Address>;

    /// Reveal a fresh external-keychain Taproot internal key. The returned X-only key shall
    /// correspond to a P2TR address that this wallet would otherwise have produced via
    /// [`Self::new_address`] — the two methods are intentionally tied together so that
    /// callers can use either flavour interchangeably and rely on the wallet to keep its
    /// keychain cursor / gap-fill state consistent.
    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey>;

    /// This creates a PSBT for use with the depositTx (but not limited to). You specify the
    /// recipients, consisting of the deposit- (and trade-)amount and spk, and the
    /// `trade_fee_outputs`. This method returns a PSBT with added inputs sufficient to pay the
    /// outputs and an optional change output. NOTE: There might be no change output, if not
    /// needed. The method guarantees that it won't reorder the outputs.
    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt>;

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> Result<()>;

    /// Import an external private key (i.e. one not derived from the HD wallet) controlling a
    /// `tr(P, tap_tree)` output, where `P` is the untweaked internal key of `pk`. `None` means a
    /// key-path-only `tr(P)` output. After importing, a rescan should be triggered.
    fn import_private_key(
        &mut self,
        pk: Scalar,
        tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind>;
}

pub struct MemWallet {
    wallet: Wallet,
    client: BdkElectrumClient<Client>,
}

// TODO think about stop_gap and batch_size
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

pub(crate) static LIBSECP256K1_CTX: LazyLock<secp256k1::Secp256k1<secp256k1::All>> =
    LazyLock::new(secp256k1::Secp256k1::new);

impl MemWallet {
    pub fn public_descriptor(&self, chain: KeychainKind) -> &ExtendedDescriptor {
        self.wallet.public_descriptor(chain)
    }

    pub fn new(client: BdkElectrumClient<Client>) -> anyhow::Result<Self> {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let network: Network = Network::Regtest;
        let xprv: Xpriv = Xpriv::new_master(network, &seed)?;

        let (descriptor, external_map, _) = Bip86(xprv, KeychainKind::External)
            .build(network.into())
            .expect("Failed to build external descriptor");

        let (change_descriptor, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
            .build(network.into())
            .expect("Failed to build internal descriptor");

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet_no_persist()?;

        Ok(Self { wallet, client })
    }

    pub fn sync(&mut self) -> anyhow::Result<()> {
        // Populate the electrum client's transaction cache so it doesn't re-download transaction we
        // already have.
        self.client
            .populate_tx_cache(self.wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

        let request = self.wallet.start_full_scan().inspect({
            let mut stdout = std::io::stdout();
            // let mut once = HashSet::<KeychainKind>::new();
            move |_k, _spk_i, _| {
                stdout.flush().expect("must flush");
            }
        });
        tracing::info!("requesting update...");
        let update = self
            .client
            .full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
        self.wallet.apply_update(update)?;
        Ok(())
    }

    pub fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    pub fn reveal_next_address(&mut self) -> AddressInfo {
        self.wallet.reveal_next_address(KeychainKind::External)
    }

    pub fn next_unused_address(&mut self) -> AddressInfo {
        self.wallet.next_unused_address(KeychainKind::External)
    }
}

pub(crate) trait WalletExt {
    fn update_psbt_with_derivation_paths(&self, psbt: &mut Psbt);
}

impl WalletExt for Wallet {
    fn update_psbt_with_derivation_paths(&self, psbt: &mut Psbt) {
        for input in &mut psbt.inputs {
            for key in input.tap_key_origins.keys() {
                let spk = ScriptBuf::new_p2tr(&*LIBSECP256K1_CTX, *key, None);
                if let Some((keychain, index)) = self.derivation_of_spk(spk) {
                    let desc = self
                        .public_descriptor(keychain)
                        .at_derivation_index(index)
                        .expect("child can't be hardened");
                    if let Descriptor::Tr(tr) = desc {
                        let ik = tr.internal_key();
                        let pub_key = ik.to_public_key().inner;
                        let key_source = (
                            ik.master_fingerprint(),
                            ik.full_derivation_path().expect("descriptor is definite"),
                        );
                        input.bip32_derivation.insert(pub_key, key_source);
                    }
                }
            }
        }
    }
}

impl WalletExt for MemWallet {
    fn update_psbt_with_derivation_paths(&self, psbt: &mut Psbt) {
        self.wallet.update_psbt_with_derivation_paths(psbt);
    }
}

impl ProtocolWalletApi for MemWallet {
    fn network(&self) -> Network {
        self.wallet.network()
    }

    fn new_address(&mut self) -> Result<Address> {
        self.wallet.new_address()
    }

    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey> {
        self.wallet.new_internal_key()
    }

    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt> {
        self.wallet.create_psbt(recipients, fee_rate)
    }

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> Result<()> {
        self.wallet.sign_selected_inputs(psbt, is_selected)
    }

    fn import_private_key(
        &mut self,
        _pk: Scalar,
        _tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind> {
        // `MemWallet` is an in-memory wallet that doesn't currently support imported keys.
        // If/when this is needed, mirror the `BMPWallet` implementation.
        todo!("MemWallet does not yet support importing private keys")
    }
}

impl ProtocolWalletApi for Wallet {
    fn network(&self) -> Network {
        self.network()
    }

    fn new_address(&mut self) -> Result<Address> {
        // For privacy, always get fresh addresses for the trade protocol.
        // FIXME: Need to find a way to prevent gaps of unused addresses from growing too large.
        Ok(self.reveal_next_address(KeychainKind::External).address)
    }

    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey> {
        let index = self.reveal_next_address(KeychainKind::External).index;
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
            Self::sign(w, p, opts)?;
            Ok(())
        })
    }

    fn import_private_key(
        &mut self,
        _pk: Scalar,
        _tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind> {
        unimplemented!(
            "bdk_wallet::Wallet does not support importing external private keys; \
            use BMPWallet for that"
        )
    }
}

/// Sign the wallet-owned inputs of `psbt` using the supplied `sign` closure, then transfer the
/// resulting signatures and witness data for any input matched by `is_selected` back into the
/// caller's PSBT — finalizing any selected input that BDK left only partially signed (e.g. a
/// multi-sig Taproot script-path spend) via the `miniscript` library.
///
/// The signing step is delegated to a closure so each `ProtocolWalletApi` flavour can plug in
/// its own primitive (`Wallet::sign`, `BMPWallet::sign`, etc.) while the surrounding
/// PSBT-clone / derivation-path-update / signature-transfer / finalize boilerplate stays in
/// one place. Mirrors how `internal_key_at_index` is shared.
pub(crate) fn sign_selected_inputs_with<W, F>(
    wallet: &mut W,
    psbt: &mut Psbt,
    is_selected: &dyn Fn(&OutPoint) -> bool,
    sign: F,
) -> Result<()>
where
    W: WalletExt + ?Sized,
    F: FnOnce(&mut W, &mut Psbt, SignOptions) -> anyhow::Result<()>,
{
    if !is_well_formed_psbt(psbt) {
        return Err(WalletErrorKind::MalformedPsbt);
    }
    let mut psbt_copy = psbt.clone();
    // Populate the BIP32 derivation paths before BDK can finalize the inputs we own. Also
    // tell BDK to trust the witness UTXO since the full previous transactions are not
    // carried in the PSBT.
    wallet.update_psbt_with_derivation_paths(&mut psbt_copy);
    sign(
        wallet,
        &mut psbt_copy,
        SignOptions {
            trust_witness_utxo: true,
            ..SignOptions::default()
        },
    )?;
    for i in 0..psbt.inputs.len() {
        if is_selected(&psbt.unsigned_tx.input[i].previous_output) {
            psbt.inputs[i].final_script_sig = psbt_copy.inputs[i].final_script_sig.take();
            psbt.inputs[i].final_script_witness = psbt_copy.inputs[i].final_script_witness.take();
            psbt.inputs[i].tap_script_sigs = mem::take(&mut psbt_copy.inputs[i].tap_script_sigs);

            if !psbt.inputs[i].tap_script_sigs.is_empty() {
                // BDK couldn't finalize the selected input (e.g. a multi-sig Taproot script
                // path). Try to finalize it ourselves using the `miniscript` lib, ignoring
                // any errors that might occur.
                let _ = psbt.finalize_inp_mut(&*LIBSECP256K1_CTX, i);
            }
        }
    }
    Ok(())
}

/// Apply the standard PSBT-builder configuration used by the trade protocol — untouched output
/// ordering, zero locktime, given fee rate, given recipients — and finish the builder. Generic
/// over the coin-selection algorithm so the same helper serves `Wallet`, `MemWallet`, and
/// `BMPWallet`.
pub(crate) fn finish_standard_psbt<Cs: CoinSelectionAlgorithm>(
    mut builder: TxBuilder<'_, Cs>,
    recipients: Vec<(ScriptBuf, Amount)>,
    fee_rate: FeeRate,
) -> Result<Psbt> {
    builder
        .ordering(TxOrdering::Untouched)
        .nlocktime(absolute::LockTime::ZERO)
        .fee_rate(fee_rate)
        .set_recipients(recipients);
    Ok(builder.finish()?)
}

/// Derive the X-only Taproot internal public key at the given external-keychain derivation
/// index, from the wallet's external descriptor. Shared by every `ProtocolWalletApi`
/// implementation so that the descriptor-walking logic isn't repeated per wallet flavour;
/// each implementor only needs to decide *which* index to feed in (e.g. via
/// `reveal_next_address` or a gap-filling `next_address`).
pub(crate) fn internal_key_at_index(
    wallet: &Wallet,
    index: u32,
) -> Result<XOnlyPublicKey, WalletErrorKind> {
    if let Descriptor::Tr(tr) = wallet.public_descriptor(KeychainKind::External) {
        let ik = tr.internal_key().clone();
        return Ok(ik
            .at_derivation_index(index)?
            .derive_public_key(&*LIBSECP256K1_CTX)?
            .to_x_only_pubkey());
    }
    Err(WalletErrorKind::NotTaprootAddress)
}

/// PSBT well-formedness predicate used as a precondition for signing. Mirrors the check
/// previously performed by the protocol crate's adapter implementations.
fn is_well_formed_psbt(psbt: &Psbt) -> bool {
    psbt.inputs.len() == psbt.unsigned_tx.input.len()
        && psbt.outputs.len() == psbt.unsigned_tx.output.len()
        && psbt
            .unsigned_tx
            .input
            .iter()
            .all(|i| i.script_sig.is_empty() && i.witness.is_empty())
}

type Result<T, E = WalletErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum WalletErrorKind {
    #[error("not a Taproot address")]
    NotTaprootAddress,
    #[error("malformed PSBT")]
    MalformedPsbt,
    ConversionError(#[from] bdk_wallet::miniscript::descriptor::ConversionError),
    CreateTx(#[from] bdk_wallet::error::CreateTxError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
