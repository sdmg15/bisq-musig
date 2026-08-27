use std::collections::BTreeMap;

use bdk_kyoto::ScanType;
use bdk_wallet::chain::DescriptorExt as _;
use bdk_wallet::{KeychainKind, PersistedWallet};
use chain::CBFScanner;

use crate::persisted::BMPWalletPersister;

#[trait_variant::make(Send)]
pub trait ChainDataSource {
    const RECOVERY_HEIGHT: usize;
    const BATCH_SIZE: usize;
    const STOP_GAP: usize;

    async fn sync(
        &self,
        _persister: Vec<&mut PersistedWallet<impl BMPWalletPersister>>,
    ) -> anyhow::Result<()>;
}

impl ChainDataSource for CBFScanner {
    const RECOVERY_HEIGHT: usize = 190_000;
    const BATCH_SIZE: usize = 16;
    const STOP_GAP: usize = 10;

    async fn sync(
        &self,
        mut wallets: Vec<&mut PersistedWallet<impl BMPWalletPersister>>,
    ) -> anyhow::Result<()> {
        let network = wallets[0].network();
        let wallet_iter = wallets
            .iter()
            .map(|w| {
                let wallet_deref = &***w;
                (wallet_deref, ScanType::Sync)
            })
            .collect::<Vec<_>>();

        let descriptors_map = wallets
            .iter()
            .enumerate()
            .map(|(idx, w)| {
                let key = w.public_descriptor(KeychainKind::External).descriptor_id();
                (key, idx)
            })
            .collect::<BTreeMap<_, _>>();

        let updates = self
            .sync_cbf(network, self.peers.clone(), wallet_iter)
            .await?;

        for (descriptor, update) in updates {
            let idx = descriptors_map
                .get(&descriptor)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("unknown descriptor in update: {descriptor:?}"))?;
            let wallet_to_update = wallets
                .get_mut(idx)
                .ok_or_else(|| anyhow::anyhow!("missing wallet for descriptor index {idx}"))?;
            let wallet_to_update = &mut **wallet_to_update;
            wallet_to_update.apply_update(update)?;
        }
        Ok(())
    }
}
