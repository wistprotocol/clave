use serde_json::Value;
use sha2::Digest;
use wist_core::crypto::PublicKey;
use wist_core::envelope::verify_envelope;
use wist_core::objects::{Publisher, PublisherEnvelope, PublisherKey};

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

/// WIST-1 §5.2: the two key sets are disjoint by `key_id` and by
/// `public_key`. A recovery key that is also a signing key is stolen with it.
fn disjoint_key_sets(p: &Publisher) -> Result<(), String> {
    let mut identifiers = std::collections::BTreeSet::new();
    for key in p.keys.iter().chain(p.recovery_keys.iter().flatten()) {
        if !identifiers.insert(&key.key_id) {
            return Err(format!("duplicate key_id {} in Declaration", key.key_id));
        }
    }
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
    (key.alg == "Ed25519" && doc["sig"]["alg"] == "Ed25519")
        .then(|| PublicKey::from_b64u(&key.public_key).ok())
        .flatten()
        .is_some_and(|pk| verify_envelope(doc, "publisher", &pk).is_ok())
}

pub fn evaluate_initial(doc: &Value) -> Result<Publisher, (&'static str, String)> {
    let envelope: PublisherEnvelope =
        serde_json::from_value(doc.clone()).map_err(|e| ("WIST2-E04", e.to_string()))?;
    let publisher = envelope.publisher;
    disjoint_key_sets(&publisher).map_err(|e| ("WIST1-E08", e))?;
    if publisher.seq != 0 || publisher.prev_declaration.is_some() {
        return Err((
            "WIST1-E08",
            "first Declaration must start at seq 0 without a predecessor".into(),
        ));
    }
    resolve_signer(doc, &publisher, None)?;
    Ok(publisher)
}

fn resolve_signer<'a>(
    doc: &Value,
    incoming: &'a Publisher,
    previous: Option<&'a Publisher>,
) -> Result<&'a PublisherKey, (&'static str, String)> {
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let candidates: Vec<_> = previous
        .into_iter()
        .flat_map(|p| p.keys.iter().chain(p.recovery_keys.iter().flatten()))
        .chain(incoming.keys.iter())
        .filter(|key| key.key_id == key_id)
        .collect();
    if candidates.is_empty() {
        return Err((
            "WIST1-E02",
            format!("sig.key_id {key_id} matches no known key"),
        ));
    }
    candidates
        .into_iter()
        .find(|key| verify_with(doc, key))
        .ok_or((
            "WIST1-E01",
            "declaration signature verification failed".into(),
        ))
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
/// carries the WIST-1 §7 code for the failure and its detail.
pub fn evaluate(stored: &Value, fetched: &Value) -> Result<Decision, (&'static str, String)> {
    let stored_p = parse(stored).map_err(|e| ("WIST2-E04", e))?;
    let fetched_p = parse(fetched).map_err(|e| ("WIST2-E04", e))?;
    disjoint_key_sets(&fetched_p).map_err(|e| ("WIST1-E08", e))?;

    if fetched_p.domain != stored_p.domain {
        return Err(("WIST2-E04", "declaration domain changed".into()));
    }

    if fetched_p.seq < stored_p.seq {
        return Err((
            "WIST1-E08",
            format!(
                "stale declaration: seq {} below accepted {}",
                fetched_p.seq, stored_p.seq
            ),
        ));
    }
    if fetched_p.seq == stored_p.seq {
        if inner_hash(fetched).map_err(|e| ("WIST2-E04", e))?
            == inner_hash(stored).map_err(|e| ("WIST2-E04", e))?
        {
            return Ok(Decision::Unchanged);
        }
        return Err((
            "WIST1-E08",
            format!(
                "declaration replayed seq {} with different content",
                fetched_p.seq
            ),
        ));
    }

    if fetched_p.prev_declaration.as_deref()
        != Some(inner_hash(stored).map_err(|e| ("WIST2-E04", e))?.as_str())
    {
        return Err((
            "WIST1-E08",
            "prev_declaration does not equal the hash of the previously accepted declaration"
                .into(),
        ));
    }

    let signer = resolve_signer(fetched, &fetched_p, Some(&stored_p))?;
    let decision = if stored_p
        .keys
        .iter()
        .any(|key| key.public_key == signer.public_key)
    {
        Decision::Ordinary
    } else if stored_p
        .recovery_keys
        .iter()
        .flatten()
        .any(|key| key.public_key == signer.public_key)
    {
        Decision::Recovery
    } else {
        Decision::FreshIdentity
    };

    if decision != Decision::Recovery {
        let stored_recovery = recovery_keys_bytes(&stored_p).map_err(|e| ("WIST2-E04", e))?;
        if !stored_recovery.is_empty()
            && recovery_keys_bytes(&fetched_p).map_err(|e| ("WIST2-E04", e))? != stored_recovery
        {
            return Err((
                "WIST1-E08",
                "recovery_keys altered by a declaration not signed by a recovery key".into(),
            ));
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
    let Ok(candidate_p) = parse(candidate) else {
        return false;
    };
    if disjoint_key_sets(&candidate_p).is_err() {
        return false;
    }
    resolve_signer(candidate, &candidate_p, Some(&head_p)).is_ok_and(|signer| {
        head_p
            .keys
            .iter()
            .chain(head_p.recovery_keys.iter().flatten())
            .any(|key| key.public_key == signer.public_key)
    })
}
