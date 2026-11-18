//! Local secret-key storage.
//!
//! Key file format (v1): `"PQSK" | 0x01 | seed[32] | agent_id[32]` (69 bytes).
//! The agent id is a consistency check: on load the keypair is re-derived from
//! the seed and its id compared in constant time.
//!
//! [`FileKeyStore`] (Unix): directory mode `0700`, files created with
//! `O_CREAT|O_EXCL` and mode `0600` (never chmod-after-write), written to a temp
//! file, fsync'd and renamed into place. Loading refuses files that are
//! group/other accessible or are symlinks. Keys are **not** encrypted at rest;
//! see the threat model.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::AgentId;
use crate::keys::{AgentKeypair, SEED_LEN};

const MAGIC: &[u8; 4] = b"PQSK";
const VERSION: u8 = 1;

/// Storage for agent secret keys.
pub trait KeyStore {
    /// Persist `key` under `name`. Must not overwrite an existing key.
    ///
    /// # Errors
    /// Implementation-specific.
    fn save(&self, name: &str, key: &AgentKeypair) -> Result<()>;
    /// Load the key stored under `name`.
    ///
    /// # Errors
    /// Implementation-specific.
    fn load(&self, name: &str) -> Result<AgentKeypair>;
}

fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidField(
            "key name must be 1..=64 of [A-Za-z0-9_-]",
        ))
    }
}

/// Encode a key file (secret!). Returned buffer zeroizes on drop.
#[must_use]
pub fn encode_key_file(key: &AgentKeypair) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    w.bytes(MAGIC);
    w.u8(VERSION);
    w.bytes(key.seed());
    w.bytes(&key.agent_id().0);
    Zeroizing::new(w.into_vec())
}

/// Decode a key file and check the stored agent id.
///
/// # Errors
/// [`Error::Decode`] / [`Error::KeyFile`].
pub fn decode_key_file(bytes: &[u8]) -> Result<AgentKeypair> {
    let mut r = Reader::new(bytes);
    r.magic(MAGIC, VERSION)?;
    let seed = Zeroizing::new(r.array::<SEED_LEN>()?);
    let id = AgentId(r.array()?);
    r.finish()?;
    let kp = AgentKeypair::from_seed(&seed)?;
    if !kp.agent_id().ct_eq(&id) {
        return Err(Error::KeyFile("stored agent id does not match seed".into()));
    }
    Ok(kp)
}

/// File-based key store rooted at a directory.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// Open (creating with mode 0700 if absent) a key directory.
    ///
    /// # Errors
    /// I/O errors, or [`Error::KeyFile`] if an existing directory is
    /// group/other accessible.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.exists() {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(&dir)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = fs::symlink_metadata(&dir)?;
            if !md.is_dir() {
                return Err(Error::KeyFile(format!(
                    "{} is not a directory",
                    dir.display()
                )));
            }
            if md.permissions().mode() & 0o077 != 0 {
                return Err(Error::KeyFile(format!(
                    "{} is accessible by group/other (chmod 700)",
                    dir.display()
                )));
            }
        }
        Ok(Self { dir })
    }

    /// Path where `name` is stored.
    ///
    /// # Errors
    /// [`Error::InvalidField`] for an invalid name.
    pub fn path_for(&self, name: &str) -> Result<PathBuf> {
        check_name(name)?;
        Ok(self.dir.join(format!("{name}.key")))
    }
}

impl KeyStore for FileKeyStore {
    fn save(&self, name: &str, key: &AgentKeypair) -> Result<()> {
        let path = self.path_for(name)?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err(Error::KeyFile(format!(
                "{} already exists; refusing to overwrite",
                path.display()
            )));
        }
        let tmp = self.dir.join(format!(".{name}.key.tmp"));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let data = encode_key_file(key);
        let res = (|| -> Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        // Re-check to narrow (not eliminate) the race with a concurrent writer.
        if fs::symlink_metadata(&path).is_ok() {
            let _ = fs::remove_file(&tmp);
            return Err(Error::KeyFile(format!(
                "{} already exists; refusing to overwrite",
                path.display()
            )));
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn load(&self, name: &str) -> Result<AgentKeypair> {
        let path = self.path_for(name)?;
        load_key_file(&path)
    }
}

/// Load a key file from an explicit path, enforcing permission checks.
///
/// # Errors
/// [`Error::KeyFile`] if the file is a symlink or group/other accessible;
/// decode errors.
pub fn load_key_file(path: &Path) -> Result<AgentKeypair> {
    let md = fs::symlink_metadata(path)?;
    if !md.is_file() {
        return Err(Error::KeyFile(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(Error::KeyFile(format!(
                "{} is accessible by group/other (chmod 600)",
                path.display()
            )));
        }
    }
    let data = Zeroizing::new(fs::read(path)?);
    decode_key_file(&data)
}

/// In-memory key store (tests / ephemeral agents). Seeds zeroize on drop.
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<String, Zeroizing<[u8; SEED_LEN]>>>,
}

impl MemoryKeyStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn save(&self, name: &str, key: &AgentKeypair) -> Result<()> {
        check_name(name)?;
        let mut m = self
            .keys
            .lock()
            .map_err(|_| Error::KeyFile("store poisoned".into()))?;
        if m.contains_key(name) {
            return Err(Error::KeyFile(format!("{name} already exists")));
        }
        m.insert(name.to_owned(), Zeroizing::new(*key.seed()));
        Ok(())
    }

    fn load(&self, name: &str) -> Result<AgentKeypair> {
        check_name(name)?;
        let m = self
            .keys
            .lock()
            .map_err(|_| Error::KeyFile("store poisoned".into()))?;
        let seed = m
            .get(name)
            .ok_or_else(|| Error::KeyFile(format!("{name} not found")))?;
        AgentKeypair::from_seed(seed)
    }
}
