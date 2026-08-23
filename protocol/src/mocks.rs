use std::collections::BTreeMap;

use bdk_wallet::bitcoin::taproot::Signature;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Sequence, TapNodeHash,
    TapSighashType, Transaction, TxIn, TxOut, VarInt, Weight, Witness, XOnlyPublicKey, absolute,
    psbt,
};
use musig2::secp::Scalar;
use wallet::protocol_wallet_api::{ProtocolWalletApi, WalletErrorKind};

use crate::mocks::WalletErrorKind::Other;
use crate::psbt::Redact as _;
use crate::transaction::{TransactionErrorKind, TxOutput};

struct MockTradeWallet<Cs: Iterator<Item = TxOutput>, As: Iterator<Item = Address>> {
    funding_coins: Cs,
    new_addresses: As,
    signature_map: BTreeMap<OutPoint, Signature>,
    internal_key: Option<XOnlyPublicKey>,
    script_sigs: BTreeMap<XOnlyPublicKey, Vec<Signature>>,
}

impl<Cs: Iterator<Item = TxOutput>, As: Iterator<Item = Address>> ProtocolWalletApi
    for MockTradeWallet<Cs, As>
{
    fn network(&self) -> Network { Network::Regtest }

    fn new_address(&mut self) -> Result<Address, WalletErrorKind> {
        self.new_addresses.next().ok_or_else(|| Other(TransactionErrorKind::MissingAddress.into()))
    }

    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey, WalletErrorKind> {
        self.internal_key.take().ok_or_else(|| Other(TransactionErrorKind::MissingAddress.into()))
    }

    fn create_psbt(
        &mut self,
        mut recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt, WalletErrorKind> {
        let fee_cost_msat = |weight: Weight|
            fee_rate.to_sat_per_kwu().checked_mul(weight.to_wu())
                .ok_or(Other(TransactionErrorKind::Overflow.into()));

        // Provisionally add a change recipient of zero value. We should never normally use
        // `new_address()` for change outputs, but this is just a mock.
        recipients.push((self.new_address()?.script_pubkey(), Amount::ZERO));

        let base_weight = Weight::from_wu_usize(38 + 4 * VarInt::from(recipients.len()).size());
        let mut output = Vec::with_capacity(recipients.len());
        let mut cost_msat = fee_cost_msat(base_weight)?;

        for (script_pubkey, value) in recipients {
            let tx_out = TxOut { value, script_pubkey };
            cost_msat = (|| cost_msat
                .checked_add(value.to_sat().checked_mul(1000)?)?
                .checked_add(fee_cost_msat(tx_out.weight()).ok()?))()
                .ok_or(Other(TransactionErrorKind::Overflow.into()))?;
            output.push(tx_out);
        }

        let mut input = Vec::new();
        let mut inputs = Vec::new();
        let mut funds = Amount::ZERO;

        while funds < Amount::from_sat(cost_msat.div_ceil(1000)) {
            let new_coin = self.funding_coins.next()
                .ok_or(Other(TransactionErrorKind::MissingTxOutput.into()))?;
            let new_coin_weight = new_coin.estimated_input_weight()
                .ok_or(Other(TransactionErrorKind::InvalidPsbt.into()))?;
            funds = funds.checked_add(new_coin.prevout.value)
                .ok_or(Other(TransactionErrorKind::Overflow.into()))?;
            cost_msat = cost_msat.checked_add(fee_cost_msat(new_coin_weight)?)
                .ok_or(Other(TransactionErrorKind::Overflow.into()))?;
            input.push(TxIn {
                previous_output: new_coin.outpoint,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            });
            inputs.push(psbt::Input {
                witness_utxo: Some(new_coin.prevout),
                ..psbt::Input::default()
            });
        }

        let change_output = output.last_mut().expect("tx has a provisional change output");
        change_output.value = funds - Amount::from_sat(cost_msat.div_ceil(1000));
        if change_output.value < change_output.script_pubkey.minimal_non_dust() {
            output.pop();
        }

        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        Ok(Psbt { inputs, ..Psbt::from_unsigned_tx(unsigned_tx).expect("tx is unsigned by construction") })
    }

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> Result<(), WalletErrorKind> {
        let mut script_sigs = self.script_sigs.clone();

        for (input, TxIn { previous_output, .. })
        in psbt.inputs.iter_mut().zip(&psbt.unsigned_tx.input)
        {
            if is_selected(previous_output) {
                for (key, (leaf_hashes, _)) in &input.tap_key_origins {
                    if let Some(sig) = script_sigs.get_mut(key).and_then(Vec::pop) {
                        for leaf_hash in leaf_hashes {
                            input.tap_script_sigs.insert((*key, *leaf_hash), sig);
                        }
                    }
                }
                if let Some(signature) = self.signature_map.get(previous_output) {
                    // Mock keyspend:
                    input.final_script_witness = Some(Witness::p2tr_key_spend(signature));
                    input.redact_sensitive_fields();
                } else if input.tap_key_origins.len() == input.tap_script_sigs.len() + 1 {
                    // Mock script spend (assumes only one path):
                    if let Some((control_block, (script, _))) = input.tap_scripts.first_key_value()
                    {
                        let mut wit = Witness::new();
                        // For the purpose of the mock, assume that (pubkey, leaf-hash) -> signature
                        // mappings occur in the opposite order that the signatures need to be added
                        // to the witness. This won't be true in general.
                        for sig in input.tap_script_sigs.values().rev() {
                            wit.push(sig.serialize());
                        }
                        wit.push(script.as_bytes());
                        wit.push(control_block.serialize());
                        input.final_script_witness = Some(wit);
                        input.redact_sensitive_fields();
                    }
                }
            }
        }
        Ok(())
    }

    fn import_private_key(&mut self, _pk: Scalar, _mr: Option<TapNodeHash>) {
        unimplemented!("MockTradeWallet does not support importing private keys")
    }
}

//noinspection SpellCheckingInspection
pub fn mock_buyer_trade_wallet() -> impl ProtocolWalletApi {
    let funding_coins = [
        "658654575bbbeb46e965bd9eb37fd3be550a7e0fa2d64bc5f218763155602300:0",
    ].map(TxOutput::mock_1_btc_coin).into_iter();
    let signature_map = signature_map(funding_coins.as_slice(), &[
        "f631ae99b4743315b237af9c48ae1f9bb87b6c5404e84d8e3907269218d1bba5\
         4c397158aa233fd3f2227f4dc46922ef62eb8cc39a06b7a339b33e2401d512c1",
    ]);
    let new_addresses = [
        "bcrt1pgsj9aw0wvs5h6zj780djnu267v6jazmfekwm4g4q4s6ax3w3t0lseqqnjc",
        "bcrt1pkar3gerekw8f9gef9vn9xz0qypytgacp9wa5saelpksdgct33qdqan7c89",
        "bcrt1pv537m7m6w0gdrcdn3mqqdpgrk3j400yrdrjwf5c9whyl2f8f4p6q9dn3l9",
        "bcrt1pzvynlely05x82u40cts3znctmvyskue74xa5zwy0t5ueuv92726szpgpaa",
    ].map(|a| a.parse::<Address<_>>()
        .expect("hardcoded addresses should be valid").assume_checked()).into_iter();
    let internal_key =
        "51494dc22e24a32fe9dcfbd7e85faf345fa1df296fb49d156e859ef345201295".parse().ok();
    let script_sigs = script_sigs(internal_key.as_slice(), &[
        "5564448d3c5f024eaf2c65024a0c6e7a9066eb0390f8ffaeee2feacde310fabf\
         87f3a8d8ad7fb125d7a6f68a282cfab8cd3178262a1fd0c2d06a598c8c454af8",
        "652d0abaa3b4f8c7dd85ac9d523d44f768c8e1541aded79165c3cdfb3ba35d62\
         eef114e89becb490a80cfdab946d2d91748ccea501ceb4f08655dcc2868c0463",
    ]);

    MockTradeWallet { funding_coins, new_addresses, signature_map, internal_key, script_sigs }
}

//noinspection SpellCheckingInspection
pub fn mock_seller_trade_wallet() -> impl ProtocolWalletApi {
    let funding_coins = [
        "4a5ecc72ec8db78f11c6785f560a13f6f32eac66d160a8157d30956695ccf523:0",
        "373b3ca0b9135e9649672772d4659bb5597d06b4694f1fbdbece285823fde0a3:1",
    ].map(TxOutput::mock_1_btc_coin).into_iter();
    let signature_map = signature_map(funding_coins.as_slice(), &[
        "2376111ed79dac9ff6f2d85dfe57d142f6075f4df9381aeab87a941477425224\
         7555f791ddf82354a3d73fa24955f6c5330ae44b2b238fa74be2eee9a46fcb72",
        "637f4a624bfc46bdb52e01b923d157a97148210f1a2669716815d3249c615673\
         17d543868698f30130e0aaf693ce265c544e3db5eda568bffb6ccd03d25a31df",
    ]);
    let new_addresses = [
        "bcrt1p80xu5f0nqjarfnechsmlt488jf3tykx8cva9zeeczlsu4c7x557qr499gz",
        "bcrt1pt5xd4aqe9whmvlz78mt39rvdlgpp6hujs5ggwan5285zjnsf73rq20k456",
        "bcrt1pwxlp4v9v7v03nx0e7vunlc87d4936wnyqegw0fuahudypan64wysefpqzy",
        "bcrt1pw4s5zvfm665fq9u6uwn9g7gwna658s939dvvf9wg63yede8kvyms5pmalx",
        "bcrt1pe3kcs085e8qej9aqqx6qryv2qsfxzywy9xd8pryzwemv2dghdqgscylr69",
    ].map(|a| a.parse::<Address<_>>()
        .expect("hardcoded addresses should be valid").assume_checked()).into_iter();
    let internal_key =
        "fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f".parse().ok();
    let script_sigs = script_sigs(internal_key.as_slice(), &[
        "87790f7eb3e98eb1b4dadc55ff5762275c4e3c02c6491abb26c8eabfada55b4b\
         3f2627f627919d667be8f191a1b275b01549ab24e5eeda0019f83c658840500e",
        "52fe2e44a4789a0f9bc406da144dcacca2621d2c1286e2d8f9913425c9927288\
         13d658a3334a4070ce585cb907a67604fc74578e84e714c38c6547377fac133e",
    ]);

    MockTradeWallet { funding_coins, new_addresses, signature_map, internal_key, script_sigs }
}

fn signature_vec(signatures: &[&'static str]) -> Vec<Signature> {
    signatures.iter().map(|s| Signature {
        signature: s.parse().expect("hardcoded signatures should be valid"),
        sighash_type: TapSighashType::Default,
    }).collect()
}

fn signature_map(funding_coins: &[TxOutput], signatures: &[&'static str]) -> BTreeMap<OutPoint, Signature> {
    funding_coins.iter().map(|o| o.outpoint).zip(signature_vec(signatures)).collect()
}

fn script_sigs(iks: &[XOnlyPublicKey], signatures: &[&'static str]) -> BTreeMap<XOnlyPublicKey, Vec<Signature>> {
    iks.iter().map(|k| (*k, signature_vec(signatures))).collect()
}
