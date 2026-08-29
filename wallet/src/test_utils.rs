use std::str::FromStr as _;

use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::hex::DisplayHex as _;
use bdk_wallet::bitcoin::key::{Keypair, Secp256k1, TapTweak as _};
use bdk_wallet::bitcoin::secp256k1::{Message, schnorr};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_wallet::bitcoin::{
    Amount, BlockHash, OutPoint, PrivateKey, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxOut, Weight, Witness, XOnlyPublicKey, psbt,
};
use bdk_wallet::chain::{BlockId, ChainPosition, ConfirmationBlockTime};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
use bdk_wallet::{KeychainKind, LocalOutput, PersistedWallet, Utxo, WeightedUtxo};
use rand::RngCore as _;
use secp::Scalar;

use crate::bmp_wallet::ImportedKey;
use crate::chain_data_source::ChainDataSource;
use crate::persisted::{BMPWalletPersister, DBStorage};

pub struct MockedBDKElectrum;

impl ChainDataSource for MockedBDKElectrum {
    const RECOVERY_HEIGHT: usize = 10;
    const BATCH_SIZE: usize = 10;
    const STOP_GAP: usize = 10;

    async fn sync(
        &self,
        persister: Vec<&mut PersistedWallet<impl BMPWalletPersister>>,
    ) -> anyhow::Result<()> {
        for w in persister {
            insert_checkpoint(
                w,
                BlockId {
                    height: 42,
                    hash: BlockHash::all_zeros(),
                },
            );
            insert_checkpoint(
                w,
                BlockId {
                    height: 1_000,
                    hash: BlockHash::all_zeros(),
                },
            );
            insert_checkpoint(
                w,
                BlockId {
                    height: 2_000,
                    hash: BlockHash::all_zeros(),
                },
            );
            receive_output_in_latest_block(w, Amount::ONE_BTC);
        }
        Ok(())
    }
}

pub fn verify_signature(
    signing_key: &PrivateKey,
    witness: &Witness,
    unsigned_tx: &Transaction,
    prev_outputs: &[TxOut],
) -> anyhow::Result<()> {
    // To verify, we need the signature, message, and pubkey
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &signing_key.inner);
    let signature = schnorr::Signature::from_slice(witness.iter().next().unwrap())?;

    let prevouts = Prevouts::All(prev_outputs);
    let input_index = 0;
    let mut sighash_cache = SighashCache::new(unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
        .unwrap();

    let message = Message::from(sighash);

    // add tweak. this was taken from `signer::sign_psbt_schnorr`
    let keypair = keypair.tap_tweak(&secp, None).to_keypair();
    let xonly_pubkey = XOnlyPublicKey::from_keypair(&keypair).0; // ignoring the parity

    // Must verify if we used the correct key to sign
    let verify_res = secp.verify_schnorr(&signature, &message, &xonly_pubkey);
    assert!(verify_res.is_ok(), "The wrong internal key was used");
    Ok(())
}


pub fn derive_public_key(key: &Scalar) -> XOnlyPublicKey {
    let xonly_pubkey = key.base_point_mul().serialize_xonly();
    XOnlyPublicKey::from_slice(&xonly_pubkey).expect("Should be valid xonly pubkey")
}

pub fn foreign_utxo(value: Amount, index: u32) -> WeightedUtxo {
    assert!(index < 10);
    let outpoint = OutPoint::from_str(&format!(
        "000000000000000000000000000000000000000000000000000000000000000{index}:0"
    ))
    .unwrap();
    WeightedUtxo {
        utxo: Utxo::Foreign {
            outpoint,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            psbt_input: Box::new(psbt::Input {
                witness_utxo: Some(TxOut {
                    value,
                    script_pubkey: ScriptBuf::from_bytes(vec![0, 0, 1]),
                }),
                non_witness_utxo: None,
                ..Default::default()
            }),
        },
        satisfaction_weight: Weight::from_wu_usize(107),
    }
}

pub fn confirmed_utxo(
    value: Amount,
    index: u32,
    confirmation_height: u32,
    confirmation_time: u64,
) -> WeightedUtxo {
    local_utxo(
        value,
        index,
        ChainPosition::Confirmed {
            anchor: ConfirmationBlockTime {
                block_id: BlockId {
                    height: confirmation_height,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time,
            },
            transitively: None,
        },
    )
}

pub fn local_utxo(
    value: Amount,
    index: u32,
    chain_position: ChainPosition<ConfirmationBlockTime>,
) -> WeightedUtxo {
    assert!(index < 10);
    let outpoint = OutPoint::from_str(&format!(
        "000000000000000000000000000000000000000000000000000000000000000{index}:0"
    ))
    .unwrap();
    WeightedUtxo {
        satisfaction_weight: Weight::from_wu_usize(107),
        utxo: Utxo::Local(LocalOutput {
            outpoint,
            txout: TxOut {
                value,
                script_pubkey: ScriptBuf::from_bytes(vec![0, 0, 2]),
            },
            keychain: KeychainKind::External,
            is_spent: false,
            derivation_index: 42,
            chain_position,
        }),
    }
}

pub struct MemDbHandle {
    pub store: DBStorage,
    anchors: Vec<Connection>, // keeps every shared-cache DB (main + imported-key siblings) alive
}

impl MemDbHandle {
    pub fn new() -> anyhow::Result<Self> {
        let mut seed = [0u8; 10];
        rand::rng().fill_bytes(&mut seed);
        let name = format!("bmp_test_{}", seed.to_lower_hex_string());
        let store = DBStorage::Memory(name.clone());
        let anchor = store.open(&name)?;
        Ok(Self { store, anchors: vec![anchor] })
    }
    
    /// Pin the shared-cache DB for an imported key's sub-wallet so it
    /// survives connections opening/closing around it.
    pub fn anchor_imported_key(&mut self, key: &ImportedKey) -> anyhow::Result<()> {
        let db_file = match key.merkle_root() {
                None => format!("bmp_{}.db3", key.internal_key()),
                Some(root) => format!("bmp_{}_{}.db3", key.internal_key(), root),
        };

        let sibling_location = self.store.sibling(&db_file);
        self.anchors.push(sibling_location.open(&db_file)?);
        Ok(())
    }
}

