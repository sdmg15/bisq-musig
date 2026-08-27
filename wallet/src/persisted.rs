use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose;
use bdk_wallet::bitcoin::hex::DisplayHex as _;
use bdk_wallet::{ChangeSet, WalletPersister};
use rand::RngCore as _;
use rusqlite::{Connection, named_params};
use secp::Scalar;

use crate::bmp_wallet::ImportedKey;
use crate::utils::get_salt;

// #[cfg(any(test, feature = "test-utils"))]
static MEMORY_SALT_STORE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
> = std::sync::LazyLock::new(Default::default);

/// Where a wallet's `SQLite` database lives.
/// It could either leaves in memory or in a file
/// The Memory variant is reserve for unit-tests only.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DBStorage {
    File(PathBuf),
    Memory(String),
}

impl DBStorage {
    /// Build the storage for sub-wallets
    #[must_use]
    pub fn sibling(&self, file_name: &str) -> Self {
        match self {
            Self::File(path) => Self::File(path.clone()),
            Self::Memory(name) => Self::Memory(format!("{name}_{file_name}")),
        }
    }

    fn open_uri(&self) -> String {
        match self {
            Self::File(path) => path.to_string_lossy().into_owned(),
            Self::Memory(name) => format!("file:{name}?mode=memory&cache=shared"),
        }
    }

    pub fn open(&self, db_name: &str) -> rusqlite::Result<Connection> {
        match self {
            Self::File(path) => {
                let path = path.join(db_name);
                Connection::open(path)
            }
            Self::Memory(_) => Connection::open_with_flags(
                self.open_uri(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            ),
        }
    }

    //// Persist and return the persisted salt
    pub fn persist_salt(&self, db_name: &str) -> anyhow::Result<Vec<u8>> {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        match self {
            Self::File(path) => {
                let p = &format!("{db_name}.salt");
                let full_p = path.join(p);
                fs::write(full_p, general_purpose::STANDARD.encode(salt))?;
                Ok(salt.to_vec())
            }
            Self::Memory(name) => {
                let v = MEMORY_SALT_STORE
                    .lock()
                    .unwrap()
                    .insert(name.clone(), salt.to_vec());
                Ok(v.unwrap())
            }
        }
    }

    pub fn load_salt(&self, db_name: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::File(path) => {
                let salt_path = path.join(db_name);
                get_salt(&salt_path.display().to_string())
            }
            Self::Memory(name) => MEMORY_SALT_STORE
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no salt registered for {name}")),
        }
    }
}

impl From<&Path> for DBStorage {
    fn from(p: &Path) -> Self {
        Self::File(p.to_path_buf())
    }
}

pub struct BMPDatabase<C: BMPWalletPersister> {
    storage: DBStorage,
    conn: C,
}

impl<C: BMPWalletPersister> BMPDatabase<C> {
    pub const fn new(storage: DBStorage, conn: C) -> Self {
        Self { storage, conn }
    }

    pub const fn location(&self) -> &DBStorage {
        &self.storage
    }
}

impl<C: BMPWalletPersister> Deref for BMPDatabase<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.conn
    }
}

impl<C: BMPWalletPersister> DerefMut for BMPDatabase<C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.conn
    }
}

pub trait BMPWalletPersister: WalletPersister {
    type DB;

    fn new(
        db_location: DBStorage,
        db_name: &str,
    ) -> anyhow::Result<Self::DB, <Self as WalletPersister>::Error>;

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
    ) -> anyhow::Result<Vec<ImportedKey>>;

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[ImportedKey],
    ) -> anyhow::Result<()>;

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String>;

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error>;
}

impl BMPWalletPersister for Connection {
    type DB = Self;

    fn new(
        db_location: DBStorage,
        db_name: &str,
    ) -> Result<Self::DB, <Self as WalletPersister>::Error> {
        db_location.open(db_name)
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
                    descriptor TEXT NOT NULL
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
    ) -> anyhow::Result<Vec<ImportedKey>> {
        let mut imported_keys = vec![];

        let mut statement =
            db.prepare(&format!("SELECT key, descriptor FROM {keys_table_name}"))?;

        let row_iter = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>("key")?,
                row.get::<_, String>("descriptor")?,
            ))
        })?;

        for row in row_iter {
            let (key_hex, descriptor) = row?;
            let secret = Scalar::from_hex(&key_hex)?;
            imported_keys.push(ImportedKey::from_descriptor_str(secret, &descriptor)?);
        }

        Ok(imported_keys)
    }

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[ImportedKey],
    ) -> anyhow::Result<()> {
        let db_trx = db.transaction()?;
        {
            let mut statement = db_trx.prepare_cached(&format!(
                "INSERT OR IGNORE INTO {keys_table_name} (key, descriptor) \
                 VALUES (:key, :descriptor)"
            ))?;

            for key in keys {
                statement.execute(named_params! {
                    ":key": key.secret().serialize().to_lower_hex_string(),
                    ":descriptor": key.descriptor().to_string(),
                })?;
            }
        }

        db_trx.commit()?;
        Ok(())
    }

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String> {
        let mnemonic =
            db.query_row(&format!("SELECT seed FROM {seeds_table_name}"), (), |row| {
                row.get::<_, String>("seed")
            })?;

        Ok(mnemonic)
    }
}
