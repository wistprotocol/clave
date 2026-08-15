use crate::error::{Error, Result};
use crate::WIST_VERSION;
use std::path::Path;
use wist_core::crypto::SigningKey;
use wist_core::envelope::sign_envelope;

const GENESIS_KEY_ID: &str = "log1";

fn file_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("log/mirrors.json")
}

pub fn list(data_dir: &Path) -> Result<Vec<String>> {
    let path = file_path(data_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(doc["mirrors"]["mirror_urls"]
        .as_array()
        .map(|urls| {
            urls.iter()
                .filter_map(|u| u.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

fn write(data_dir: &Path, sk: &SigningKey, urls: &[String], now_epoch: i64) -> Result<()> {
    let updated_at = jiff::Timestamp::from_second(now_epoch)
        .map_err(|_| Error::Governance("timestamp out of range".into()))?
        .to_string();
    let inner = serde_json::json!({
        "wist_version": WIST_VERSION,
        "updated_at": updated_at,
        "mirror_urls": urls,
    });
    let envelope = sign_envelope(&inner, "mirrors", GENESIS_KEY_ID, sk)?;
    std::fs::create_dir_all(data_dir.join("log"))?;
    std::fs::write(file_path(data_dir), serde_json::to_vec(&envelope)?)?;
    Ok(())
}

pub fn add(data_dir: &Path, sk: &SigningKey, url: &str, now_epoch: i64) -> Result<Vec<String>> {
    let parsed = url::Url::parse(url)
        .map_err(|e| Error::Governance(format!("invalid mirror URL {url:?}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(Error::Governance(format!(
            "mirror base URL must be https, got {url:?}"
        )));
    }
    let mut urls = list(data_dir)?;
    if !urls.iter().any(|u| u == url) {
        urls.push(url.to_string());
    }
    write(data_dir, sk, &urls, now_epoch)?;
    Ok(urls)
}

pub fn remove(data_dir: &Path, sk: &SigningKey, url: &str, now_epoch: i64) -> Result<Vec<String>> {
    let mut urls = list(data_dir)?;
    urls.retain(|u| u != url);
    write(data_dir, sk, &urls, now_epoch)?;
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn setup() -> (tempfile::TempDir, SigningKey) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("log")).unwrap();
        (tmp, SigningKey::from_seed(&[3u8; 32]))
    }

    #[test]
    fn add_remove_list_roundtrip_with_signed_file_under_log() {
        let (tmp, sk) = setup();
        assert!(list(tmp.path()).unwrap().is_empty());
        add(tmp.path(), &sk, "https://mirror-a.example/", NOW).unwrap();
        let urls = add(tmp.path(), &sk, "https://mirror-b.example/", NOW + 1).unwrap();
        assert_eq!(
            urls,
            vec![
                "https://mirror-a.example/".to_string(),
                "https://mirror-b.example/".to_string()
            ]
        );
        assert_eq!(list(tmp.path()).unwrap(), urls);

        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join("log/mirrors.json")).unwrap())
                .unwrap();
        wist_core::envelope::verify_envelope(&doc, "mirrors", &sk.public()).unwrap();
        assert_eq!(doc["mirrors"]["wist_version"], crate::WIST_VERSION);
        assert_eq!(
            doc["mirrors"]["mirror_urls"][0],
            "https://mirror-a.example/"
        );

        let after = remove(tmp.path(), &sk, "https://mirror-a.example/", NOW + 2).unwrap();
        assert_eq!(after, vec!["https://mirror-b.example/".to_string()]);
        assert_eq!(list(tmp.path()).unwrap(), after);
    }

    #[test]
    fn add_is_idempotent_and_rejects_non_https_urls() {
        let (tmp, sk) = setup();
        add(tmp.path(), &sk, "https://mirror-a.example/", NOW).unwrap();
        let urls = add(tmp.path(), &sk, "https://mirror-a.example/", NOW + 1).unwrap();
        assert_eq!(urls.len(), 1);
        assert!(add(tmp.path(), &sk, "not a url", NOW).is_err());
        assert!(add(tmp.path(), &sk, "ftp://mirror.example/", NOW).is_err());
    }
}
