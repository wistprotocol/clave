use crate::db::Db;
use crate::error::{Error, Result};
use rand::TryRngCore;
use std::io::Write;
use std::path::{Path, PathBuf};
use wist_core::crypto::{b64u_encode, hex_encode, PublicKey, SigningKey};
use wist_core::objects::AggregatorKeyEntry;

/// The `key_id` `init` gives the Log's genesis Aggregator key.
pub const GENESIS_KEY_ID: &str = "log1";

pub fn generate() -> ([u8; 32], SigningKey) {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .expect("operating system RNG failed");
    let sk = SigningKey::from_seed(&seed);
    (seed, sk)
}

pub fn public_b64u(seed: &[u8; 32]) -> String {
    let vk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key();
    b64u_encode(&vk.to_bytes())
}

pub fn save_seed(path: &Path, seed: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(seed)?;
    Ok(())
}

pub fn load(path: &Path) -> Result<SigningKey> {
    Ok(SigningKey::from_seed(&load_seed(path)?))
}

pub fn load_seed(path: &Path) -> Result<[u8; 32]> {
    std::fs::read(path)?
        .try_into()
        .map_err(|_| Error::Key("seed file must be exactly 32 bytes".into()))
}

/// The file a key's 32-octet seed occupies in the data directory's key
/// store: `keys/seed` for the Anchor's genesis key, `keys/<key_id>.seed`
/// for every key an `aggregator_key_add` admits.
pub fn seed_path(data_dir: &Path, key_id: &str, genesis_key_id: &str) -> PathBuf {
    if key_id == genesis_key_id {
        data_dir.join("keys/seed")
    } else {
        data_dir.join("keys").join(format!("{key_id}.seed"))
    }
}

fn is_seed_file_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// One Aggregator key of the Log as the data directory knows it: the
/// registry tuple the replayed Log establishes (WIST-3 §3.4, §7) and the
/// private key where the key store holds it.
pub struct Key {
    pub key_id: String,
    pub public_key: PublicKey,
    pub added_height: u64,
    pub removed_height: Option<u64>,
    seed: Option<[u8; 32]>,
}

impl Key {
    /// WIST-3 §3.4: valid at `height` from the Epoch that admitted it
    /// until, but excluding, the Epoch that removed it.
    pub fn valid_at(&self, height: u64) -> bool {
        self.added_height <= height && self.removed_height.is_none_or(|removed| removed > height)
    }

    pub fn held(&self) -> bool {
        self.seed.is_some()
    }

    pub fn signing(&self) -> Option<SigningKey> {
        self.seed.as_ref().map(SigningKey::from_seed)
    }

    pub fn note_key_id(&self, log_id: &str) -> String {
        hex_encode(&wist_core::checkpoint::aggregator_key_id(
            log_id,
            &self.public_key,
        ))
    }
}

/// The data directory's Aggregator keys: every key the Log has admitted,
/// with the private keys the key store holds for them, plus the keys a
/// queued `aggregator_key_add` generated and no Epoch has admitted yet.
pub struct Store {
    log_id: String,
    genesis_key_id: String,
    keys: Vec<Key>,
    unadmitted: Vec<(String, PublicKey)>,
    seeds: Vec<(String, [u8; 32])>,
}

impl Store {
    pub fn open(data_dir: &Path, db: &Db) -> Result<Self> {
        let anchor = crate::history::anchor(data_dir)?;
        let mut rows = db.aggregator_key_entries()?;
        if !rows.iter().any(|row| row.key_id == anchor.key_id) {
            rows.push(AggregatorKeyEntry {
                key_id: anchor.key_id.clone(),
                public_key: anchor.key.to_b64u(),
                added_height: 0,
                removed_height: None,
            });
        }
        let mut seeds = Vec::new();
        let keys_dir = data_dir.join("keys");
        if let Ok(entries) = std::fs::read_dir(&keys_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !is_seed_file_name(&name) {
                    continue;
                }
                let key_id = if name == "seed" {
                    anchor.key_id.clone()
                } else {
                    match name.strip_suffix(".seed") {
                        Some(stem) => stem.to_owned(),
                        None => continue,
                    }
                };
                seeds.push((key_id, load_seed(&entry.path())?));
            }
        }
        let mut keys: Vec<Key> = rows
            .iter()
            .map(|row| {
                let public_key = PublicKey::from_b64u(&row.public_key)?;
                let seed = seeds
                    .iter()
                    .find(|(key_id, seed)| {
                        *key_id == row.key_id && SigningKey::from_seed(seed).public() == public_key
                    })
                    .map(|(_, seed)| *seed);
                Ok(Key {
                    key_id: row.key_id.clone(),
                    public_key,
                    added_height: row.added_height,
                    removed_height: row.removed_height,
                    seed,
                })
            })
            .collect::<Result<_>>()?;
        keys.sort_by(|a, b| {
            a.added_height
                .cmp(&b.added_height)
                .then_with(|| a.key_id.cmp(&b.key_id))
        });
        let mut unadmitted: Vec<(String, PublicKey)> = seeds
            .iter()
            .filter(|(key_id, _)| !keys.iter().any(|key| key.key_id == *key_id))
            .map(|(key_id, seed)| (key_id.clone(), SigningKey::from_seed(seed).public()))
            .collect();
        unadmitted.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Store {
            log_id: anchor.log_id,
            genesis_key_id: anchor.key_id,
            keys,
            unadmitted,
            seeds,
        })
    }

    /// Whether the key store holds the private key of `public_key`, under
    /// any `key_id` and at any validity.
    pub fn holds(&self, public_key: &PublicKey) -> bool {
        self.seeds
            .iter()
            .any(|(_, seed)| SigningKey::from_seed(seed).public() == *public_key)
    }

    /// The private key the key store holds for `key_id`, where its public
    /// key is the one the registry binds to that `key_id`.
    pub fn signing_for(&self, key_id: &str, public_key: &PublicKey) -> Option<SigningKey> {
        self.seeds
            .iter()
            .filter(|(held, _)| held == key_id)
            .map(|(_, seed)| SigningKey::from_seed(seed))
            .find(|key| key.public() == *public_key)
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn genesis_key_id(&self) -> &str {
        &self.genesis_key_id
    }

    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// The keys a queued `aggregator_key_add` generated, which no Epoch
    /// has admitted yet.
    pub fn unadmitted(&self) -> &[(String, PublicKey)] {
        &self.unadmitted
    }

    pub fn valid_at(&self, height: u64) -> Vec<&Key> {
        self.keys
            .iter()
            .filter(|key| key.valid_at(height))
            .collect()
    }

    /// The held private keys valid at `height`, in ascending order of the
    /// height that admitted them and then of `key_id`.
    pub fn signers_at(&self, height: u64) -> Vec<&Key> {
        self.keys
            .iter()
            .filter(|key| key.held() && key.valid_at(height))
            .collect()
    }

    /// The one held key that signs a document this Aggregator publishes
    /// at `height`: the first of `signers_at`.
    pub fn signer_at(&self, height: u64) -> Result<&Key> {
        self.signers_at(height).into_iter().next().ok_or_else(|| {
            Error::Key(format!(
                "the key store holds no Aggregator key valid at height {height}"
            ))
        })
    }
}

/// The height a document this Aggregator signs now authenticates at: the
/// Log's current head, or 0 for a Log whose Epoch 0 is not sealed, where
/// the genesis key alone is valid (WIST-3 §3.4).
pub fn head_height(db: &Db) -> Result<u64> {
    Ok(db.last_epoch()?.map_or(0, |head| head.epoch_number))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_matching_seed_and_key() {
        let (seed, sk) = generate();
        let expected = SigningKey::from_seed(&seed);
        assert_eq!(sk.sign(b"probe"), expected.sign(b"probe"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/seed");
        let (seed, sk) = generate();
        save_seed(&path, &seed).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.sign(b"probe"), sk.sign(b"probe"));
    }

    #[cfg(unix)]
    #[test]
    fn save_seed_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("seed");
        let (seed, _) = generate();
        save_seed(&path, &seed).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_rejects_wrong_length() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("seed");
        std::fs::write(&path, b"too short").unwrap();
        assert!(load(&path).is_err());
    }
}
