//! Integration test for the `testenv-server` binary's `--data-dir` / persistence feature.
//!
//! Drives the actual compiled binary the same way an external orchestrator (e.g. the Java
//! integration tests) would: start it with `--data-dir`, parse the `TESTENV_*` key=value lines it
//! prints, mine some blocks over the advertised Bitcoin Core RPC, shut it down, then start it again
//! against the same directory and assert the chain state survived.
#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use tempfile::TempDir;

/// A running `testenv-server` child plus the connection info it advertised on stdout.
struct ServerHandle {
    child: Child,
    info: HashMap<String, String>,
}

impl ServerHandle {
    /// Spawn `testenv-server --data-dir <dir>` and block until it prints its `TESTENV_*` info
    /// (or a timeout elapses).
    fn start(data_dir: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_testenv-server"))
            .args(["--data-dir", data_dir.to_str().unwrap()])
            .env("RUST_LOG", "off")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn testenv-server");

        // Read stdout on a background thread, forwarding each parsed `KEY=VALUE` line.
        let stdout = child.stdout.take().expect("child stdout");
        let (tx, rx) = mpsc::channel::<(String, String)>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some((k, v)) = line.split_once('=')
                    && k.starts_with("TESTENV_")
                {
                    // If the receiver is gone the main thread already collected what it needs.
                    if tx.send((k.to_owned(), v.to_owned())).is_err() {
                        break;
                    }
                }
            }
        });

        // Collect lines until the server signals readiness and we have the fields we need.
        let mut info = HashMap::new();
        let deadline = Instant::now() + Duration::from_mins(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for testenv-server to become ready"
            );
            match rx.recv_timeout(remaining) {
                Ok((k, v)) => {
                    info.insert(k, v);
                    // `TESTENV_DATA_DIR` is the last line the binary prints in persistent mode, so
                    // once we've seen it we have the full advertised info block.
                    if info.contains_key("TESTENV_READY")
                        && info.contains_key("TESTENV_RPC_PASS")
                        && info.contains_key("TESTENV_DATA_DIR")
                    {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("timed out waiting for testenv-server to become ready")
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("testenv-server exited before becoming ready (output: {info:?})")
                }
            }
        }
        Self { child, info }
    }

    fn rpc_client(&self) -> Client {
        let url = self.info.get("TESTENV_RPC_URL").expect("TESTENV_RPC_URL");
        let user = self
            .info
            .get("TESTENV_RPC_USER")
            .expect("TESTENV_RPC_USER")
            .clone();
        let pass = self
            .info
            .get("TESTENV_RPC_PASS")
            .expect("TESTENV_RPC_PASS")
            .clone();
        Client::new(url, Auth::UserPass(user, pass)).expect("connect to bitcoind RPC")
    }

    /// Gracefully stop the server with SIGINT and wait for it to exit, so bitcoind/electrs release
    /// the data directory cleanly before the next run reuses it.
    fn shutdown(mut self) {
        // SIGINT triggers the binary's ctrlc handler -> graceful shutdown.
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();

        // Give it a moment to tear bitcoind/electrs down, then make sure it's gone.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
                Ok(Some(_)) | Err(_) => break,
            }
        }
    }
}

#[test]
fn testenv_server_persists_chain_across_restarts() {
    // Number of blocks beyond the initial height we mine in the first run.
    const MINED: u64 = 6;

    let data_root = TempDir::new().expect("temp dir");
    let data_dir = data_root.path().join("testenv-data");

    // ---- First run: start with --data-dir, verify the persistence contract, mine blocks. ----
    let height_before;
    {
        let server = ServerHandle::start(&data_dir);

        // The binary must advertise persistence and echo back the directory it was given.
        assert_eq!(
            server.info.get("TESTENV_READY").map(String::as_str),
            Some("true"),
            "server should report readiness"
        );
        assert_eq!(
            server.info.get("TESTENV_PERSISTENT").map(String::as_str),
            Some("true"),
            "server started with --data-dir must report TESTENV_PERSISTENT=true"
        );
        assert_eq!(
            server.info.get("TESTENV_DATA_DIR").map(String::as_str),
            Some(data_dir.to_str().unwrap()),
            "server should echo back the data dir it was given"
        );

        // The directories must actually be created and used on disk.
        assert!(
            data_dir.is_dir(),
            "data dir should exist: {}",
            data_dir.display()
        );
        assert!(
            data_dir.join("bitcoind").join("regtest").is_dir(),
            "bitcoind should populate its regtest sub-dir under the data dir"
        );
        assert!(
            data_dir.join("electrsd").is_dir(),
            "electrs should populate its sub-dir under the data dir"
        );

        let rpc = server.rpc_client();
        let initial = rpc.get_block_count().expect("get_block_count");
        let address = rpc
            .get_new_address(None, None)
            .expect("new address")
            .assume_checked();
        rpc.generate_to_address(MINED, &address)
            .expect("mine blocks");
        height_before = rpc.get_block_count().expect("get_block_count");
        assert_eq!(
            height_before,
            initial + MINED,
            "blocks should have been mined"
        );

        server.shutdown();
    }

    // ---- Second run: same --data-dir, the chain height must have survived the restart. ----
    {
        let server = ServerHandle::start(&data_dir);
        assert_eq!(
            server.info.get("TESTENV_PERSISTENT").map(String::as_str),
            Some("true")
        );

        let rpc = server.rpc_client();
        let height_after = rpc.get_block_count().expect("get_block_count");
        assert_eq!(
            height_after, height_before,
            "block height should persist across restarts when --data-dir is used"
        );

        server.shutdown();
    }
}
