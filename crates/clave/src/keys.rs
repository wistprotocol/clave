use crate::error::{Error, Result};
use rand::TryRngCore;
use std::io::Write;
use std::path::Path;
use wist_core::crypto::{b64u_encode, SigningKey};

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
    let bytes = std::fs::read(path)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Key("seed file must be exactly 32 bytes".into()))?;
    Ok(SigningKey::from_seed(&seed))
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
