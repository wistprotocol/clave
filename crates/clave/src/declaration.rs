use serde_json::Value;
use sha2::Digest;
use wist_core::crypto::PublicKey;
use wist_core::envelope::verify_envelope;
use wist_core::objects::{Publisher, PublisherKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Unchanged,
    Ordinary,
    Recovery,
    FreshIdentity,
}

pub fn inner_hash(doc: &Value) -> Result<String, String> {
    let canonical = wist_core::jcs::canonicalize(&doc["publisher"]).map_err(|e| e.to_string())?;
    Ok(format!(
        "sha256:{}",
        wist_core::crypto::hex_encode(&sha2::Sha256::digest(&canonical))
    ))
}

fn parse(doc: &Value) -> Result<Publisher, String> {
    serde_json::from_value(doc["publisher"].clone()).map_err(|e| e.to_string())
}

fn recovery_keys_bytes(p: &Publisher) -> Result<Vec<u8>, String> {
    match &p.recovery_keys {
        Some(keys) if !keys.is_empty() => {
            let v = serde_json::to_value(keys).map_err(|e| e.to_string())?;
            wist_core::jcs::canonicalize(&v).map_err(|e| e.to_string())
        }
        _ => Ok(Vec::new()),
    }
}

fn find_key<'a>(keys: &'a [PublisherKey], key_id: &str) -> Option<&'a PublisherKey> {
    keys.iter().find(|k| k.key_id == key_id)
}

/// WIST-1 §5.2: the two key sets are disjoint by `key_id` and by
/// `public_key`. A recovery key that is also a signing key is stolen with it.
fn disjoint_key_sets(p: &Publisher) -> Result<(), String> {
    let Some(recovery) = p.recovery_keys.as_deref() else {
        return Ok(());
    };
    for r in recovery {
        if let Some(clash) = p
            .keys
            .iter()
            .find(|k| k.key_id == r.key_id || k.public_key == r.public_key)
        {
            return Err(format!(
                "key {} is named in both keys and recovery_keys",
                clash.key_id
            ));
        }
    }
    Ok(())
}

fn verify_with(doc: &Value, key: &PublisherKey) -> bool {
    PublicKey::from_b64u(&key.public_key)
        .ok()
        .is_some_and(|pk| verify_envelope(doc, "publisher", &pk).is_ok())
}

pub fn publisher_of(doc: &Value) -> Result<Publisher, String> {
    parse(doc)
}

/// WIST-1 §5.1/§5.2 Key Set checks for a signed object. `observed_at`
/// activates the `valid_from` bound (Deltas); pass None for feeds.
/// Err is the rejection code.
pub fn verify_signed(
    keys: &[&PublisherKey],
    doc: &Value,
    kind: &str,
    observed_at: Option<&str>,
) -> Result<(), &'static str> {
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let Some(key) = keys.iter().find(|k| k.key_id == key_id) else {
        return Err("WIST1-E02");
    };
    if let Some(observed_at) = observed_at {
        if observed_at < key.valid_from.as_str() {
            return Err("WIST1-E02");
        }
    }
    let ok = PublicKey::from_b64u(&key.public_key)
        .ok()
        .is_some_and(|pk| verify_envelope(doc, kind, &pk).is_ok());
    if ok {
        Ok(())
    } else {
        Err("WIST1-E01")
    }
}

/// WIST-1 §5.2: evaluate a fetched Declaration against the previously
/// accepted one. An open recovery window does not change acceptance — a
/// Declaration sealed inside one is superseded at the window's end, and
/// rejecting it here would leave the attempt invisible on replay. Err
/// carries a WIST1-E08 detail.
pub fn evaluate(stored: &Value, fetched: &Value) -> Result<Decision, String> {
    let stored_p = parse(stored)?;
    let fetched_p = parse(fetched)?;
    disjoint_key_sets(&fetched_p)?;

    if fetched_p.domain != stored_p.domain {
        return Err("declaration domain changed".into());
    }

    if fetched_p.seq < stored_p.seq {
        return Err(format!(
            "stale declaration: seq {} below accepted {}",
            fetched_p.seq, stored_p.seq
        ));
    }
    if fetched_p.seq == stored_p.seq {
        if inner_hash(fetched)? == inner_hash(stored)? {
            return Ok(Decision::Unchanged);
        }
        return Err(format!(
            "declaration replayed seq {} with different content",
            fetched_p.seq
        ));
    }

    if fetched_p.prev_declaration.as_deref() != Some(inner_hash(stored)?.as_str()) {
        return Err(
            "prev_declaration does not equal the hash of the previously accepted declaration"
                .into(),
        );
    }

    let key_id = fetched["sig"]["key_id"].as_str().unwrap_or_default();
    let decision = if let Some(key) = find_key(&stored_p.keys, key_id) {
        if !verify_with(fetched, key) {
            return Err("declaration signature verification failed".into());
        }
        Decision::Ordinary
    } else if let Some(key) = stored_p
        .recovery_keys
        .as_deref()
        .and_then(|keys| find_key(keys, key_id))
    {
        if !verify_with(fetched, key) {
            return Err("declaration signature verification failed".into());
        }
        Decision::Recovery
    } else if let Some(key) = find_key(&fetched_p.keys, key_id) {
        if !verify_with(fetched, key) {
            return Err("declaration signature verification failed".into());
        }
        Decision::FreshIdentity
    } else {
        return Err(format!("sig.key_id {key_id} matches no known key"));
    };

    if decision != Decision::Recovery {
        let stored_recovery = recovery_keys_bytes(&stored_p)?;
        if !stored_recovery.is_empty() && recovery_keys_bytes(&fetched_p)? != stored_recovery {
            return Err(
                "recovery_keys altered by a declaration not signed by a recovery key".into(),
            );
        }
    }

    Ok(decision)
}

/// WIST-1 §5.2: a Declaration legitimately follows the recovery chain when
/// its signer is named in the chain head's `keys` or `recovery_keys`.
/// Anything else sealed inside the window is superseded at its end.
pub fn follows_chain_head(head: &Value, candidate: &Value) -> bool {
    let Ok(head_p) = parse(head) else {
        return false;
    };
    let key_id = candidate["sig"]["key_id"].as_str().unwrap_or_default();
    let signer = find_key(&head_p.keys, key_id).or_else(|| {
        head_p
            .recovery_keys
            .as_deref()
            .and_then(|keys| find_key(keys, key_id))
    });
    signer.is_some_and(|key| verify_with(candidate, key))
}
