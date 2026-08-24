use std::sync::Arc;

use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV};
use bdk_wallet::bitcoin::taproot::TaprootBuilder;
use bdk_wallet::bitcoin::{ScriptBuf, TapNodeHash, XOnlyPublicKey, relative, script};
use bdk_wallet::miniscript::descriptor::TapTree;
use bdk_wallet::miniscript::{DefiniteDescriptorKey, Descriptor, Miniscript, Tap};

use crate::transaction::{NetworkParams, Result};

pub fn deposit_payout_merkle_root(
    buyer_pub_key: &XOnlyPublicKey,
    seller_pub_key: &XOnlyPublicKey,
) -> Result<TapNodeHash> {
    single_path_merkle_root(multisig_script(buyer_pub_key, seller_pub_key))
}

pub fn warning_escrow_merkle_root(
    claim_pub_key: &XOnlyPublicKey,
    network: impl NetworkParams + Copy,
) -> Result<TapNodeHash> {
    single_path_merkle_root(claim_script(claim_pub_key, network.claim_lock_time()))
}

pub fn deposit_payout_descriptor(
    internal_key: &XOnlyPublicKey,
    buyer_pub_key: &XOnlyPublicKey,
    seller_pub_key: &XOnlyPublicKey,
) -> Result<Descriptor<DefiniteDescriptorKey>> {
    Ok(format!("tr({internal_key},and_v(v:pk({buyer_pub_key}),pk({seller_pub_key})))").parse()?)
}

/// The tap tree of a deposit payout output, in the form
/// [`ProtocolWalletApi::import_private_key`](wallet::protocol_wallet_api::ProtocolWalletApi::import_private_key)
/// expects when the aggregated payout key is swept into the wallet.
pub fn deposit_payout_tap_tree(
    buyer_pub_key: &XOnlyPublicKey,
    seller_pub_key: &XOnlyPublicKey,
) -> Result<TapTree<XOnlyPublicKey>> {
    single_path_tap_tree(&multisig_script(buyer_pub_key, seller_pub_key))
}

/// The tap tree of a Warning Tx escrow output; see [`deposit_payout_tap_tree`].
pub fn warning_escrow_tap_tree(
    claim_pub_key: &XOnlyPublicKey,
    network: impl NetworkParams + Copy,
) -> Result<TapTree<XOnlyPublicKey>> {
    single_path_tap_tree(&claim_script(claim_pub_key, network.claim_lock_time()))
}

fn single_path_tap_tree(script: &ScriptBuf) -> Result<TapTree<XOnlyPublicKey>> {
    Ok(TapTree::Leaf(Arc::new(
        Miniscript::<XOnlyPublicKey, Tap>::parse(script)?,
    )))
}

fn single_path_merkle_root(script: ScriptBuf) -> Result<TapNodeHash> {
    // Check for repeated keys, zero locktime or any other issues when decoding to miniscript:
    Miniscript::<XOnlyPublicKey, Tap>::parse(&script)?;

    Ok(TaprootBuilder::with_capacity(1)
        .add_leaf(0, script)
        .expect("hardcoded TapTree build sequence should be valid")
        .try_into_taptree()
        .expect("hardcoded TapTree build sequence should be complete")
        .root_hash())
}

fn multisig_script(buyer_pub_key: &XOnlyPublicKey, seller_pub_key: &XOnlyPublicKey) -> ScriptBuf {
    // Comes from miniscript policy: format!("and(pk({buyer_pub_key}),pk({seller_pub_key}))")
    // which compiles to miniscript: format!("and_v(v:pk({buyer_pub_key}),pk({seller_pub_key}))")
    script::Builder::new()
        .push_x_only_key(buyer_pub_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(seller_pub_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn claim_script(pub_key: &XOnlyPublicKey, lock_time: relative::LockTime) -> ScriptBuf {
    // Comes from miniscript policy: format!("and(pk({pub_key}),older({lock_time}))")
    // which compiles to miniscript: format!("and_v(v:pk({pub_key}),older({lock_time}))")
    script::Builder::new()
        .push_x_only_key(pub_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_sequence(lock_time.to_sequence())
        .push_opcode(OP_CSV)
        .into_script()
}

#[cfg(test)]
mod tests {
    use bdk_wallet::miniscript::descriptor::Tr;

    use super::*;

    #[test]
    fn scripts_match_miniscript() {
        let buyer_pub_key =
            &"0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        let seller_pub_key =
            &"0000000000000000000000000000000000000000000000000000000000000002".parse().unwrap();
        let lock_time = relative::LockTime::from_height(720);

        let multisig_ms = format!("and_v(v:pk({buyer_pub_key}),pk({seller_pub_key}))")
            .parse::<Miniscript<XOnlyPublicKey, Tap>>().unwrap();
        assert_eq!(multisig_ms.encode(), multisig_script(buyer_pub_key, seller_pub_key));

        let claim_ms = format!("and_v(v:pk({buyer_pub_key}),older({lock_time}))")
            .parse::<Miniscript<XOnlyPublicKey, Tap>>().unwrap();
        assert_eq!(claim_ms.encode(), claim_script(buyer_pub_key, lock_time));
    }

    #[test]
    fn multisig_script_matches_descriptor_leaf() {
        let internal_key =
            &"0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        let buyer_pub_key =
            &"0000000000000000000000000000000000000000000000000000000000000002".parse().unwrap();
        let seller_pub_key =
            &"0000000000000000000000000000000000000000000000000000000000000003".parse().unwrap();

        let desc = deposit_payout_descriptor(internal_key, buyer_pub_key, seller_pub_key)
            .unwrap();
        let Descriptor::Tr(tr) = desc else {
            panic!("expected Taproot descriptor")
        };
        let Some(TapTree::Leaf(ms)) = tr.tap_tree() else {
            panic!("expected nonempty single-leaf TapTree")
        };
        assert_eq!(ms.encode(), multisig_script(buyer_pub_key, seller_pub_key));

        let merkle_root = tr.spend_info().merkle_root().unwrap();
        assert_eq!(merkle_root, deposit_payout_merkle_root(buyer_pub_key, seller_pub_key).unwrap());
    }

    #[test]
    fn tap_trees_match_descriptors_and_merkle_roots() {
        let internal_key = &"0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let buyer_pub_key = &"0000000000000000000000000000000000000000000000000000000000000002"
            .parse()
            .unwrap();
        let seller_pub_key = &"0000000000000000000000000000000000000000000000000000000000000003"
            .parse()
            .unwrap();
        let network = bdk_wallet::bitcoin::Network::Regtest;

        // Deposit payout: same leaf as the descriptor, same merkle root, same SPK
        let tree = deposit_payout_tap_tree(buyer_pub_key, seller_pub_key).unwrap();
        let desc = deposit_payout_descriptor(internal_key, buyer_pub_key, seller_pub_key).unwrap();
        assert_eq!(tree.to_string(), desc_tap_tree_string(&desc));
        let tr = Tr::new(*internal_key, Some(tree)).unwrap();
        assert_eq!(
            tr.spend_info().merkle_root(),
            Some(deposit_payout_merkle_root(buyer_pub_key, seller_pub_key).unwrap())
        );
        assert_eq!(tr.script_pubkey(), desc.script_pubkey());

        // Warning escrow: same merkle root
        let tree = warning_escrow_tap_tree(buyer_pub_key, network).unwrap();
        let tr = Tr::new(*internal_key, Some(tree)).unwrap();
        assert_eq!(
            tr.spend_info().merkle_root(),
            Some(warning_escrow_merkle_root(buyer_pub_key, network).unwrap())
        );
    }

    fn desc_tap_tree_string(desc: &Descriptor<DefiniteDescriptorKey>) -> String {
        let Descriptor::Tr(tr) = desc else {
            panic!("expected Taproot descriptor")
        };
        tr.tap_tree().as_ref().unwrap().to_string()
    }
}
