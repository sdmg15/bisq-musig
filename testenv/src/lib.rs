//! Bitcoin regtest environment using electrsd with automatic executable downloads

use std::net::SocketAddrV4;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, RpcApi as _};
use bdk_electrum::BdkElectrumClient;
use bdk_electrum::bdk_core::bitcoin::{KnownHrp, XOnlyPublicKey};
use bdk_electrum::electrum_client::Error;
use bdk_wallet::bitcoin::address::NetworkChecked;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::All;
use bdk_wallet::bitcoin::{Address, Amount, BlockHash, Network, Transaction, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse};
use bdk_wallet::{PersistedWallet, serde_json};
use bmp_tracing::tracing;
use chain::{ChainApi, ChainScanner};
use electrsd::corepc_node::Node;
use electrsd::electrum_client::{Client, ElectrumApi};
use electrsd::{ElectrsD, corepc_node};
use hmac::{Hmac, Mac as _};
use rand::{Rng as _, RngCore as _};
use secp::Scalar;
use sha2::Sha256;
use tempfile::TempDir;
use tokio::net::TcpListener;
use typed_arena::Arena;
use wallet::chain_data_source::ChainDataSource;
use wallet::persisted::BMPWalletPersister;

/// Bitcoin regtest environment manager
pub struct TestEnv {
    bitcoind: Node,
    electrsd: ElectrsD,
    timeout: Duration,
    delay: Duration,
    bdk_electrum_client: BdkElectrumClient<Client>,
    ctx: Secp256k1<All>,
    explorer_process: Option<std::process::Child>,
    container_name: Option<String>,
    explorer_port: Option<u16>,
    bitcoin_rpc_pwd: String,
    mempool: Vec<Txid>,
    _guard: Option<MutexGuard<'static, ()>>,
    /// Append-only arena of every `TempDir` we've handed out a `&Path` to.
    ///
    /// `typed_arena::Arena` lets us insert through `&self` (interior mutability) and
    /// guarantees that prior items never move when we allocate more — so `&Path`s borrowed
    /// from earlier `TempDir`s stay valid for the lifetime of the `TestEnv`. The arena is
    /// dropped with `TestEnv`, which triggers each `TempDir`'s cleanup-on-drop.
    dirs: Arena<TempDir>,
}

/// Configuration parameters.
#[derive(Debug, Clone)]
pub struct Config<'a> {
    /// [`bitcoind::Conf`]
    pub bitcoind: corepc_node::Conf<'a>,
    /// [`electrsd::Conf`]
    pub electrsd: electrsd::Conf<'a>,
    pub timeout: Duration,
    pub delay: Duration,
    pub runmultithreaded: bool,
    pub password: Option<String>,
}

impl Default for Config<'_> {
    fn default() -> Self {
        Self {
            bitcoind: {
                let mut conf = corepc_node::Conf::default();
                // Listen on all interfaces (0.0.0.0) instead of just localhost
                conf.args.push("-rpcbind=0.0.0.0");
                conf.args.push("-listen=1");

                // Allow connections from any IP (use 0.0.0.0/0 for "everywhere")
                conf.args.push("-rpcallowip=0.0.0.0/0");

                conf.args.push("-blockfilterindex=1");
                conf.args.push("-peerblockfilters=1");
                conf.args.push("-txindex=1");
                conf
            },
            electrsd: {
                let mut conf = electrsd::Conf::default();
                conf.http_enabled = true;
                conf.args.push("--cors");
                conf.args.push("*");
                // conf.view_stderr = true;
                conf
            },
            timeout: Duration::from_secs(5),
            delay: Duration::from_millis(200),
            password: None,
            runmultithreaded: "true" == std::env::var("TEST_MULTITHREADED").unwrap_or_default().trim().to_lowercase(),
        }
    }
}

const NETWORK: Network = Network::Regtest;

/// Builder for `TestEnv` configuration with optional data directory support
#[derive(Debug, Clone, Default)]
pub struct TestEnvBuilder {
    config: Config<'static>,
    data_dir: Option<std::path::PathBuf>,
}

impl TestEnvBuilder {
    pub fn new(password: Option<String>) -> Self {
        Self {
            config: Config {
                password,
                ..Config::default()
            },
            data_dir: Option::default(),
        }
    }

    /// Set a persistent data directory for bitcoind and electrs data
    ///
    /// If not set, a temporary directory will be used (auto-deleted on exit).
    /// If set, the directory will be created if it doesn't exist and persist across runs.
    #[must_use]
    pub fn with_data_dir(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.data_dir = path;
        self
    }

    /// Build the `TestEnv` with the configured settings
    pub fn build(mut self) -> Result<TestEnv> {
        if let Some(data_dir) = &self.data_dir {
            // Create the data directory if it doesn't exist
            std::fs::create_dir_all(data_dir).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create data directory {}: {}",
                    data_dir.display(),
                    e
                )
            })?;

            // Wire the persistent directory into bitcoind and electrs. Both back-ends treat a
            // `staticdir` as a persistent work directory (reused across runs), whereas the
            // default `tmpdir`/`None` behaviour creates a throwaway temp dir. They must not share
            // the same directory, so each gets its own sub-directory under `data_dir`.
            //
            // Note: `staticdir` and `tmpdir` are mutually exclusive in both `corepc_node::Conf`
            // and `electrsd::Conf`, so we leave `tmpdir` as its default `None`.
            self.config.bitcoind.staticdir = Some(data_dir.join("bitcoind"));
            self.config.electrsd.staticdir = Some(data_dir.join("electrsd"));
        }
        TestEnv::new_with_conf(self.config)
    }
}

// Type alias for Hmac-Sha256
type HmacSha256 = Hmac<Sha256>;

/// Generates a Bitcoin Core rpcauth string.
///
/// - `username`: The RPC username.
/// - `password`: The password (if None, a random one is generated).
///
/// Returns a tuple of (`rpcauth_string`, `password`).
pub fn generate_rpcauth(username: &str, password: Option<&str>) -> (String, String) {
    // Generate or use provided password
    let pw = if let Some(p) = password {
        p.to_owned()
    } else {
        // Generate a random 32-char alphanumeric password
        let mut rng = rand::rng();
        (0..32)
            .map(|_| {
                let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                chars[rng.random_range(0..chars.len())] as char
            })
            .collect()
    };

    // Generate a random 16-byte salt
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt_hex = hex::encode(salt_bytes);

    // Compute HMAC-SHA256(salt, password)
    let mut mac =
        HmacSha256::new_from_slice(salt_hex.as_bytes()).expect("HMAC can take key of any size");
    mac.update(pw.as_bytes());
    let hash_bytes = mac.finalize().into_bytes();
    let hash_hex = hex::encode(hash_bytes);

    // Build the rpcauth string
    let rpcauth = format!("rpcauth={username}:{salt_hex}${hash_hex}");

    (rpcauth, pw)
}

pub fn validate_rpcauth(rpcauth_line: &str, username: &str, password: &str) -> bool {
    let line = rpcauth_line
        .trim()
        .strip_prefix("rpcauth=")
        .unwrap_or(rpcauth_line.trim());

    // Expected format: <user>:<salt_hex>$<hmac_hex>
    let Some((user_part, rest)) = line.split_once(':') else {
        return false;
    };
    if user_part != username {
        return false;
    }
    let Some((salt_hex, hmac_hex_expected)) = rest.split_once('$') else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(salt_hex.as_bytes()) else {
        return false;
    };
    mac.update(password.as_bytes());
    let hmac_hex_actual = hex::encode(mac.finalize().into_bytes());

    // Constant-time compare would be ideal; for most local tooling this is OK,
    // but you can use `subtle` crate if you want constant-time equality.
    hmac_hex_actual.eq_ignore_ascii_case(hmac_hex_expected)
}

static TESTENV_LOCK: Mutex<()> = Mutex::new(());

impl TestEnv {
    /// Create a new test environment with automatic executable downloads
    pub fn new() -> Result<Self> {
        Self::new_with_conf(Config::default())
    }

    /// Creates a fresh temp directory owned by this `TestEnv` and returns its `&Path`.
    ///
    /// The returned reference borrows from `&self`, so it stays valid for as long as the
    /// `TestEnv` lives — even after subsequent calls (the arena never moves prior items)
    /// and even across `&mut self` calls (the borrow ends at the call boundary if you use
    /// it inline). Each call returns a *different* directory.
    pub fn new_temp_path(&self) -> &Path {
        let tmp = TempDir::new().unwrap();
        self.dirs.alloc(tmp).path()
    }

    /// Create a new test environment with ZMQ enabled on bitcoind.
    ///
    /// The ZMQ socket addresses are available via
    /// [`zmq_pub_raw_tx_socket`](Self::zmq_pub_raw_tx_socket) and
    /// [`zmq_pub_raw_block_socket`](Self::zmq_pub_raw_block_socket).
    pub fn enable_zmq() -> Result<Self> {
        let mut config = Config::default();
        config.bitcoind.enable_zmq = true;
        Self::new_with_conf(config)
    }

    /// ZMQ socket for raw transaction notifications (set when created via
    /// [`enable_zmq`](Self::enable_zmq)).
    pub fn zmq_pub_raw_tx_socket(&self) -> Option<String> {
        self.bitcoind
            .params
            .zmq_pub_raw_tx_socket
            .map(|socket| format!("tcp://{socket}"))
    }

    /// ZMQ socket for raw block notifications (set when created via
    /// [`enable_zmq`](Self::enable_zmq)).
    pub const fn zmq_pub_raw_block_socket(&self) -> Option<SocketAddrV4> {
        self.bitcoind.params.zmq_pub_raw_block_socket
    }

    /// create environment with automatic downloads
    pub fn new_with_conf(config: Config) -> Result<Self> {
        let guard = if config.runmultithreaded {
            None
        } else {
            // can recover because unit type won't corrupt
            Some(TESTENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner))
        };
        // Try to start bitcoind (from environment or downloads)
        tracing::info!("Starting bitcoind...");
        // rpcauth for each bitcoind and save the pwd
        let (rpc_auth, bitcoin_rpc_pwd) = generate_rpcauth("bitcoin", config.password.as_deref());

        let auth_config = format!("-{rpc_auth}");
        let mut bitcoin_config = config.bitcoind;
        bitcoin_config.p2p = corepc_node::P2P::Yes;
        bitcoin_config.args.push(&*auth_config);

        let bitcoind = if let Ok(path) = std::env::var("BITCOIND_EXEC") {
            tracing::info!("Using custom bitcoind executable: {path}");
            Node::with_conf(&path, &bitcoin_config)?
        } else {
            tracing::info!(
                "BITCOIND_EXEC not set! Falling back to downloaded version at {}",
                corepc_node::downloaded_exe_path()?
            );
            Node::from_downloaded_with_conf(&bitcoin_config)?
        };

        // initialize global tracing subscriber, defaulting to `info`.
        bmp_tracing::init("info");

        // Try to get electrs executable (from environment or downloads)
        let electrs_exe = if let Ok(path) = std::env::var("ELECTRS_EXEC") {
            tracing::info!("Using custom electrs executable: {path}");
            path
        } else {
            // Try to use downloaded electrs
            let path = electrsd::downloaded_exe_path()
                .expect("No downloaded electrs found, trying electrs in PATH...");
            tracing::info!("Using downloaded electrs: {path}");
            path
        };

        tracing::info!("Starting electrsd...");

        let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &config.electrsd)
            .with_context(|| "Starting electrsd failed...")?;

        let client = Client::from_config(
            &electrsd.electrum_url,
            bdk_electrum::electrum_client::Config::default(),
        )?;
        let bdk_electrum_client = BdkElectrumClient::new(client);

        let test_env = Self {
            bitcoind,
            electrsd,
            timeout: config.timeout,
            delay: config.delay,
            bdk_electrum_client,
            ctx: Secp256k1::new(),
            explorer_process: None,
            container_name: None,
            explorer_port: None,
            bitcoin_rpc_pwd,
            mempool: Vec::new(),
            _guard: guard,
            dirs: Arena::new(),
        };
        tracing::info!("Bitcoin regtest environment ready!");
        Ok(test_env)
    }

    pub fn broadcast(&mut self, tx: &Transaction) -> Result<Txid> {
        let txid = self.bdk_electrum_client.transaction_broadcast(tx)?;
        let _ = self.wait_for_tx(txid);
        self.mempool.push(txid);
        Ok(txid)
    }

    pub fn new_client(&self) -> Result<BdkElectrumClient<Client>> {
        let client = Client::from_config(
            &self.electrsd.electrum_url,
            bdk_electrum::electrum_client::Config::default(),
        )?;
        Ok(BdkElectrumClient::new(client))
    }

    /// Create a new [`Testchain`] backed by a fresh electrum client connected to this environment.
    ///
    /// Each call returns an independent owned handle (with its own Electrum connection and
    /// transaction cache), suitable for `Box<dyn ChainApi>` consumers that want one handle per
    /// simulated peer. For ergonomic single-instance use, `&TestEnv` itself implements
    /// [`ChainApi`] and [`ChainScanner`].
    pub fn new_testchain(&self) -> Result<Testchain> {
        Ok(Testchain::new(self.new_client()?))
    }

    pub fn start_explorer_in_container(&mut self) -> Result<()> {
        // this start a container for debugging
        let bitcoind_rpc_port = self.bitcoin_rpc_port();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let browser_port = listener.local_addr()?.port();

        let electrum_port = self
            .electrsd
            .electrum_url
            .split(':')
            .next_back()
            .context("Failed to parse electrum port")?;

        let container_name = format!("btc-explorer-{browser_port}");

        let mut container = std::process::Command::new("podman");
        #[rustfmt::skip]
        container.args(["run", "--rm",
            "--name", &container_name,
            "-p", &format!("{browser_port}:3002"),
            "--add-host=host.containers.internal:host-gateway",
            "-e", "BTCEXP_BITCOIND_HOST=host.containers.internal",
            "-e", "BTCEXP_HOST=0.0.0.0",
            "-e", &format!("BTCEXP_BITCOIND_PORT={bitcoind_rpc_port}"),
            "-e", "BTCEXP_BITCOIND_USER=bitcoin",
            "-e", &format!("BTCEXP_BITCOIND_PASS={}", self.bitcoin_rpc_pwd),
            "-e", "BTCEXP_ADDRESS_API=electrum",
            "-e", &format!("BTCEXP_ELECTRUM_SERVERS=tcp://host.containers.internal:{electrum_port}"),
            "docker.io/getumbrel/btc-rpc-explorer:v3.5.1",
        ]);

        // println!("Spawning container: {:?}", container);
        let child = container
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("Failed to spawn rpc_proxy")?;

        self.explorer_process = Some(child);
        self.container_name = Some(container_name);
        self.explorer_port = Some(browser_port);

        // Drop the listener to free the port for the container
        drop(listener);

        tracing::info!(
            "Starting explorer in container, access it at http://127.0.0.1:{browser_port}/blocks"
        );
        tracing::info!("you can check the container logs with: ");
        tracing::info!(
            "podman logs -f --timestamps {}",
            self.container_name.as_ref().unwrap()
        );
        Ok(())
    }

    pub fn debug_tx(&self, txid: Txid) {
        if let Some(port) = self.explorer_port {
            tracing::info!("explorer tx: http://127.0.0.1:{port}/tx/{txid}");
        }
    }

    pub const fn bitcoin_rpc_port(&self) -> u16 {
        self.bitcoind.params.rpc_socket.port()
    }

    /// Get the Bitcoin RPC password
    pub fn bitcoin_rpc_password(&self) -> &str {
        &self.bitcoin_rpc_pwd
    }

    /// Get the electrum client for blockchain operations
    pub fn electrum_client(&self) -> &impl ElectrumApi {
        // &self.electrsd.client
        &self.bdk_electrum_client.inner
    }

    pub const fn bitcoind_client(&self) -> &corepc_node::Client {
        &self.bitcoind.client
    }

    pub fn bitcoin_core_rpc_client(&self) -> bitcoincore_rpc::Result<bitcoincore_rpc::Client> {
        let url = &self.bitcoind.rpc_url();
        let auth: Auth = Auth::CookieFile(self.bitcoind.params.cookie_file.clone());
        bitcoincore_rpc::Client::new(url, auth)
    }

    /// Get the electrum URL
    pub fn electrum_url(&self) -> String {
        self.electrsd.electrum_url.replace("0.0.0.0", "127.0.0.1")
    }

    pub const fn bdk_electrum_client(&self) -> &BdkElectrumClient<Client> {
        &self.bdk_electrum_client
    }

    /// Get the Esplora REST URL
    pub fn esplora_url(&self) -> Option<String> {
        self.electrsd
            .esplora_url
            .as_ref()
            .map(|url| url.replace("0.0.0.0", "127.0.0.1"))
    }

    /// Mine blocks using bitcoind RPC
    pub fn mine_blocks(&mut self, count: usize) -> Result<Vec<BlockHash>> {
        let block_hashes = self
            .bitcoind
            .client
            .generate_to_address(count, &self.new_address()?)?;

        self.wait_for_block()?;

        for txid in &self.mempool {
            let _ = self.wait_for_tx(*txid);
        }
        self.mempool.clear();

        // Convert to BlockHash format
        block_hashes
            .0
            .into_iter()
            .map(|hash_str| hash_str.parse::<BlockHash>().map_err(anyhow::Error::msg))
            .collect()
    }

    /// Mine a single block
    pub fn mine_block(&mut self) -> Result<BlockHash> {
        let hashes = self.mine_blocks(1)?;
        Ok(hashes[0])
    }

    pub fn fund_from_prv_key(&mut self, key: &Scalar, amount: Amount) -> Result<Txid> {
        let xonly_pubkey = key.base_point_mul().serialize_xonly();
        let pbk = XOnlyPublicKey::from_slice(&xonly_pubkey)?;
        let address = Address::p2tr(&self.ctx, pbk, None, KnownHrp::Regtest);
        self.fund_address(&address, amount)
    }

    /// Fund an address using bitcoind RPC
    pub fn fund_address(
        &mut self,
        address: &Address<NetworkChecked>,
        amount: Amount,
    ) -> Result<Txid> {
        // First ensure we have some coins by mining blocks if needed
        let balance = self.bitcoind.client.get_balance()?.balance()?;

        if balance < amount {
            // Mine 101 blocks (standard for regtest to make coins spendable)
            self.bitcoind
                .client
                .generate_to_address(101, &self.new_address()?)?;

            // Wait a moment for blocks to be processed
            std::thread::sleep(Duration::from_secs(1));
        }

        // Send money to the address
        let txid = self
            .bitcoind
            .client
            .send_to_address(address, amount)?
            .txid()?;
        self.mempool.push(txid);
        Ok(txid)
    }

    /// Create a new address for testing using bitcoind RPC
    pub fn new_address(&self) -> Result<Address<NetworkChecked>> {
        Ok(self
            .bitcoind
            .client
            .get_new_address(None, None)?
            .address()?
            .require_network(NETWORK)?)
    }

    /// Wait for electrum to see a new block
    pub fn wait_for_block(&self) -> Result<()> {
        self.electrsd.client.block_headers_subscribe()?;
        let start = std::time::Instant::now();

        while start.elapsed() < self.timeout {
            self.electrsd.trigger()?;
            self.electrsd.client.ping()?;

            if let Some(_header) = self.electrsd.client.block_headers_pop()? {
                return Ok(());
            }

            std::thread::sleep(self.delay);
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for electrum to see block after {:?}",
            self.timeout
        ))
    }

    /// Wait for electrum to see a specific transaction
    pub fn wait_for_tx(&self, txid: Txid) -> Result<()> {
        let start = std::time::Instant::now();
        let rpc_api = self.bitcoin_core_rpc_client()?;
        let direct_client = &self.bitcoind.client;
        self.trigger_sync()?;

        while start.elapsed() < self.timeout {
            let api_seen = rpc_api.get_transaction(&txid, Some(false)).is_ok();
            let direct_seen = direct_client.get_transaction(txid).is_ok();
            let electrum_seen = self.bdk_electrum_client.fetch_tx(txid).is_ok();
            if electrum_seen && direct_seen && api_seen {
                return Ok(());
            }
            std::thread::sleep(self.delay);
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for electrum to see transaction {txid} after {:?}",
            self.timeout
        ))
    }

    /// Get the current block count from bitcoind
    pub fn block_count(&self) -> Result<u64> {
        let count = self.bitcoind.client.get_block_count()?.0;
        Ok(count)
    }

    /// Get the best block hash from bitcoind
    pub fn best_block_hash(&self) -> Result<BlockHash> {
        let hash = self.bitcoind.client.get_best_block_hash()?.block_hash()?;
        Ok(hash)
    }

    /// Get the genesis block hash from bitcoind
    pub fn genesis_hash(&self) -> Result<BlockHash> {
        let hash = self.bitcoind.client.get_block_hash(0)?.block_hash()?;
        Ok(hash)
    }

    /// Trigger electrs sync
    pub fn trigger_sync(&self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            self.electrsd.trigger()
        }
    }

    /// Get the working directory path
    pub fn workdir(&self) -> std::path::PathBuf {
        self.electrsd.workdir()
    }

    /// Get the running bitcoind socket address
    pub const fn p2p_socket_addr(&self) -> Option<SocketAddrV4> {
        self.bitcoind.params.p2p_socket
    }

    /// Returns a `TcpListener` bound to an available port (port 0 lets OS assign).
    /// This avoids race conditions by keeping the port bound until used.
    pub async fn get_bound_port() -> Result<(u16, TcpListener)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr().unwrap().port();
        Ok((port, listener))
    }
}

// Note: `TestEnv` itself cannot implement `ChainApi` because it holds a non-`Send`
// `MutexGuard` (used to serialize tests by default), but `ChainApi: Send + Sync`. Callers
// that need an owned `Box<dyn ChainApi>` use [`TestEnv::new_testchain`], which returns a
// `Testchain` handle with its own electrum client. `ChainScanner`, which has no thread-safety
// bound, is implemented directly for ergonomic test use (e.g. `wallet.sync_all(&env)`).
impl ChainScanner for TestEnv {
    fn populate_tx_cache(&self, txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>) {
        self.bdk_electrum_client.populate_tx_cache(txs);
    }

    fn full_scan<K: Ord + Clone>(
        &self,
        request: impl Into<FullScanRequest<K>>,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
    ) -> Result<FullScanResponse<K>> {
        self.bdk_electrum_client
            .full_scan(request, stop_gap, batch_size, fetch_prev_txouts)
            .map_err(Into::into)
    }
}

/// Owned Electrum-backed [`ChainApi`] / [`ChainScanner`] handle.
///
/// Each instance owns its own [`BdkElectrumClient`] (and therefore its own connection and
/// transaction cache). Construct via [`TestEnv::new_testchain`] to get a handle connected to
/// this environment's Electrum endpoint.
pub struct Testchain {
    client: BdkElectrumClient<Client>,
}

impl Testchain {
    pub const fn new(client: BdkElectrumClient<Client>) -> Self {
        Self { client }
    }
}

impl ChainApi for Testchain {
    fn transaction_broadcast(&self, tx: &Transaction) -> Result<Txid> {
        broadcast_via(&self.client, tx)
    }
}

impl ChainScanner for Testchain {
    fn populate_tx_cache(&self, txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>) {
        self.client.populate_tx_cache(txs);
    }

    fn full_scan<K: Ord + Clone>(
        &self,
        request: impl Into<FullScanRequest<K>>,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
    ) -> Result<FullScanResponse<K>> {
        self.client
            .full_scan(request, stop_gap, batch_size, fetch_prev_txouts)
            .map_err(Into::into)
    }
}

/// `ChainDataSource` implementation for the Electrum-backed [`testenv::Testchain`] handle.
///
/// `Testchain` lives in the `testenv` crate alongside `TestEnv`; this impl ties it into the
/// wallet's sync routine. It mirrors the values previously used by the live Electrum-backed
/// implementation.
impl ChainDataSource for Testchain {
    const RECOVERY_HEIGHT: usize = 190_000;
    const BATCH_SIZE: usize = 16;
    const STOP_GAP: usize = 10;

    async fn sync(
        &self,
        persister: Vec<&mut PersistedWallet<impl BMPWalletPersister>>,
    ) -> Result<()> {
        for wallet in persister {
            let tx_nodes = wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx);
            self.populate_tx_cache(tx_nodes);
            let request = wallet.start_full_scan();

            let updates = self.full_scan(request, Self::STOP_GAP, Self::BATCH_SIZE, false)?;

            wallet.apply_update(updates)?;
        }
        Ok(())
    }
}

/// Shared `ChainApi::transaction_broadcast` body — swallows the idempotent
/// "Transaction outputs already in utxo set" Electrum error (forwarded bitcoin RPC error -27) and
/// returns the computed txid.
fn broadcast_via(client: &BdkElectrumClient<Client>, tx: &Transaction) -> Result<Txid> {
    match client.transaction_broadcast(tx) {
        Ok(txid) => Ok(txid),
        Err(Error::Protocol(serde_json::Value::String(e))) if e.starts_with(
            "sendrawtransaction RPC error: {\"code\":-27,") => {
            Ok(tx.compute_txid())
        }
        Err(e) => Err(e.into()),
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(name) = self.container_name.take() {
            tracing::info!("Stopping explorer container {name}...");
            let output = std::process::Command::new("podman")
                .args(["stop", &name])
                .output();
            tracing::info!("explorer container returned {output:?}...");
        }

        // Try graceful shutdown first (SIGTERM)
        if let Some(mut child) = self.explorer_process.take() {
            tracing::info!("Shutting down explorer process...");

            // Send SIGTERM (graceful)
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi as _;
    use bmp_tracing::tracing;

    use super::*;

    #[test]
    fn test_basic_creation() -> Result<()> {
        let env = TestEnv::new()?;

        // Basic checks
        assert!(env.block_count().is_ok());
        assert!(env.genesis_hash().is_ok());
        assert!(!env.electrum_url().is_empty());

        Ok(())
    }

    #[test]
    fn test_core_rpc() -> Result<()> {
        let env = TestEnv::new()?;
        let rpc = env.bitcoin_core_rpc_client()?;
        // check if the connection works
        rpc.ping()?;
        assert_eq!(rpc.get_block_count()?, 1);

        Ok(())
    }

    #[test]
    fn test_mining() -> Result<()> {
        let mut env = TestEnv::new()?;
        let initial_count = env.block_count()?;

        env.mine_block()?;

        let new_count = env.block_count()?;
        assert_eq!(new_count, initial_count + 1);

        Ok(())
    }

    #[test]
    fn test_address_operations() -> Result<()> {
        use electrsd::corepc_node::vtype::TransactionCategory;

        let mut env = TestEnv::new()?;

        // Create new address
        let address = env.new_address()?;
        tracing::info!("Created address: {address}");

        // Address is already verified to be on regtest network when created via new_address()

        // Get initial balance
        let initial_balance = env.bitcoind.client.get_balance()?;
        tracing::info!("Initial balance: {initial_balance:?} BTC");

        // Fund address with 1000 satoshis
        let amount = Amount::from_sat(1000);
        let txid = env.fund_address(&address, amount)?;
        tracing::info!("Funded address with txid: {txid}");

        // Verify the transaction was created
        assert_ne!(
            txid.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // Mine a block to confirm the transaction
        env.mine_block()?;

        // Wait for electrum to sync
        env.trigger_sync()?;

        // Wait for the transaction to appear in electrum
        env.wait_for_tx(txid)?;
        tracing::info!("Transaction confirmed in electrum");

        // Verify we can get the transaction from bitcoind
        let tx = env.bitcoind.client.get_transaction(txid)?;

        // Extract the received amount from transaction details
        let receive_amount = tx
            .details
            .iter()
            .find(|detail| detail.category == TransactionCategory::Receive)
            .map(|detail| Amount::from_btc(detail.amount).unwrap())
            .unwrap();

        assert_eq!(receive_amount, amount);
        tracing::info!("Transaction amount verified: {receive_amount}");

        Ok(())
    }

    #[test]
    fn test_persistent_data_dir() -> Result<()> {
        // Number of blocks beyond the initial height we mine in the first run.
        const MINED: usize = 5;

        // A persistent `data_dir` should make bitcoind's chain state survive a full
        // shut-down/restart cycle, in contrast to the default throwaway temp dirs.
        let data_root = TempDir::new()?;
        let data_dir = data_root.path().to_path_buf();
        let bitcoind_dir = data_dir.join("bitcoind");
        let electrsd_dir = data_dir.join("electrsd");

        let persisted_height = {
            let mut env = TestEnvBuilder::new(None)
                .with_data_dir(Some(data_dir.clone()))
                .build()?;

            // The configured sub-directories must actually be the ones in use.
            assert!(
                bitcoind_dir.is_dir(),
                "bitcoind data dir should exist: {}",
                bitcoind_dir.display()
            );
            assert!(
                electrsd_dir.is_dir(),
                "electrs data dir should exist: {}",
                electrsd_dir.display()
            );
            // bitcoind writes its regtest data (incl. the cookie) under its sub-directory.
            assert!(
                bitcoind_dir.join("regtest").is_dir(),
                "bitcoind should populate its regtest dir: {}",
                bitcoind_dir.join("regtest").display()
            );
            // electrs reports the persistent dir we asked for as its workdir.
            assert_eq!(
                env.workdir(),
                electrsd_dir,
                "electrs workdir should be the persistent dir"
            );

            let initial_height = env.block_count()?;
            env.mine_blocks(MINED)?;
            let height = env.block_count()?;
            assert_eq!(height, initial_height + MINED as u64);
            tracing::info!("First run mined up to height {height}");

            height
            // `env` is dropped here, shutting down bitcoind and electrs.
        };

        // Re-create the environment against the same data dir. bitcoind should reload the
        // existing chain state rather than starting from a fresh genesis-only chain.
        let env2 = TestEnvBuilder::new(None)
            .with_data_dir(Some(data_dir.clone()))
            .build()?;
        let reloaded_height = env2.block_count()?;
        tracing::info!("Second run reloaded chain at height {reloaded_height}");

        assert_eq!(
            reloaded_height, persisted_height,
            "block height should persist across restarts when a data dir is set"
        );
        drop(env2);

        // Sanity check: a default (non-persistent) env is independent and starts fresh.
        let ephemeral = TestEnv::new()?;
        assert!(
            ephemeral.block_count()? < persisted_height,
            "a fresh ephemeral env should not see the persisted blocks"
        );

        Ok(())
    }

    #[test]
    #[ignore = "for debugging only"]
    fn test_container_ui_manual() -> Result<()> {
        let mut env = TestEnv::new()?;
        env.start_explorer_in_container()?;
        env.mine_block()?;
        // put a breakpoint on the Ok statement so you inspect the blockchain before it is dropped
        Ok(())
    }

    #[test]
    fn test_enable_zmq() -> Result<()> {
        let mut env = TestEnv::enable_zmq()?;

        // Verify ZMQ sockets were assigned
        let tx_socket = env.zmq_pub_raw_tx_socket().expect("zmq rawtx socket");
        let block_socket = env.zmq_pub_raw_block_socket().expect("zmq rawblock socket");
        tracing::info!("ZMQ rawtx={tx_socket}, rawblock={block_socket}");

        // Verify the environment is fully functional with ZMQ enabled
        assert!(env.block_count().is_ok());
        env.mine_block()?;

        // Verify ZMQ is configured by querying bitcoind
        let rpc = env.bitcoin_core_rpc_client()?;
        let notifications: serde_json::Value = rpc.call("getzmqnotifications", &[])?;
        let types: Vec<&str> = notifications
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"pubrawtx"));
        assert!(types.contains(&"pubrawblock"));

        Ok(())
    }

    #[test]
    fn test_rpcauth_validation() {
        let username = "bitcoin";
        let password = "bitcoin";
        let rpcauth_line = "rpcauth=bitcoin:81ad5d600eb1df69d27323dd1ef31162$7c4315f44d8eea5cb6764295c0233a5e0d51d5ea461e122f337bc6e8502f0d93";

        assert!(validate_rpcauth(rpcauth_line, username, password));

        // Test with wrong password
        assert!(!validate_rpcauth(rpcauth_line, username, "wrongpassword"));

        // Test with wrong username
        assert!(!validate_rpcauth(rpcauth_line, "wronguser", password));

        // Test generation and validation
        let (generated_auth, generated_pw) = generate_rpcauth("testuser", None);
        assert!(validate_rpcauth(&generated_auth, "testuser", &generated_pw));
    }
}
