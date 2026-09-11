use serde_json::Value;
use sha2::Digest;
use wist_core::crypto::{b64u_decode, b64u_encode, PublicKey};
use wist_core::envelope::verify_envelope;
use wist_core::objects::{Publisher, PublisherEnvelope, PublisherKey};

mod time;

pub fn validate_fields(doc: &Value) -> Result<PublisherEnvelope, (&'static str, String)> {
    let canonical = wist_core::jcs::canonicalize(doc).map_err(|e| ("WIST1-E05", e.to_string()))?;
    let envelope: PublisherEnvelope =
        serde_json::from_slice(&canonical).map_err(|e| ("WIST1-E14", e.to_string()))?;
    validate_structure(doc, &envelope).map_err(|e| ("WIST1-E14", e))?;
    for key in envelope
        .publisher
        .keys
        .iter()
        .chain(envelope.publisher.recovery_keys.iter().flatten())
    {
        canonical_encoding(&key.public_key, 32)
            .map_err(|e| ("WIST1-E14", format!("public_key: {e}")))?;
    }
    canonical_encoding(&envelope.sig.value, 64)
        .map_err(|e| ("WIST1-E14", format!("sig.value: {e}")))?;
    Ok(envelope)
}

fn validate_structure(doc: &Value, envelope: &PublisherEnvelope) -> Result<(), String> {
    let publisher = &envelope.publisher;
    for field in [
        "prev_declaration",
        "subdomain_scope",
        "recovery_keys",
        "contact",
    ] {
        if doc["publisher"].get(field).is_some_and(Value::is_null) {
            return Err(format!("{field} must not be null"));
        }
    }
    if publisher.seq > 9_007_199_254_740_991 {
        return Err("seq exceeds the safe integer range".into());
    }
    let version: Vec<_> = publisher.wist_version.split('.').collect();
    if version.len() != 3
        || version.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("wist_version must contain three decimal components".into());
    }
    if publisher.prev_declaration.as_ref().is_some_and(|hash| {
        !hash.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    }) {
        return Err("prev_declaration must be a lowercase SHA-256 hash".into());
    }
    for host in std::iter::once(&publisher.domain).chain(publisher.subdomain_scope.iter().flatten())
    {
        if !wist_core::host::canonical_host(host).is_ok_and(|canonical| canonical == *host) {
            return Err("Declaration hosts must equal their Canonical Host".into());
        }
    }
    if publisher
        .contact
        .as_ref()
        .is_some_and(|value| value.chars().count() > 256)
    {
        return Err("contact exceeds 256 characters".into());
    }
    if publisher.keys.is_empty() {
        return Err("keys must not be empty".into());
    }
    for key in publisher
        .keys
        .iter()
        .chain(publisher.recovery_keys.iter().flatten())
    {
        if key.key_id.chars().count() > 64 || key.alg != "Ed25519" {
            return Err("key_id exceeds 64 characters or alg is not Ed25519".into());
        }
        if !time::valid(&key.valid_from) {
            return Err("valid_from must satisfy the Publisher timestamp profile".into());
        }
    }
    if envelope.sig.key_id.chars().count() > 64 || envelope.sig.alg != "Ed25519" {
        return Err("signature key_id exceeds 64 characters or alg is not Ed25519".into());
    }
    Ok(())
}

fn canonical_encoding(value: &str, length: usize) -> Result<(), String> {
    let bytes = b64u_decode(value).map_err(|e| e.to_string())?;
    if bytes.len() != length || b64u_encode(&bytes) != value {
        return Err(format!(
            "expected canonical base64url encoding of {length} octets"
        ));
    }
    Ok(())
}

pub fn usable_keys(keys: &[PublisherKey]) -> impl Iterator<Item = &PublisherKey> {
    keys.iter()
        .filter(|key| key.alg == "Ed25519" && PublicKey::from_b64u(&key.public_key).is_ok())
}

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
    validate_fields(doc)
        .map(|envelope| envelope.publisher)
        .map_err(|(code, detail)| format!("{code}: {detail}"))
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
    let envelope = validate_fields(doc)?;
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
        .flat_map(|p| {
            usable_keys(&p.keys).chain(usable_keys(p.recovery_keys.as_deref().unwrap_or(&[])))
        })
        .chain(usable_keys(&incoming.keys))
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
    if kind == "delta"
        && !doc["delta"]["observed_at"]
            .as_str()
            .is_some_and(time::valid)
    {
        return Err("WIST1-E14");
    }
    if observed_at.is_some_and(|value| !time::valid(value))
        || keys.iter().any(|key| !time::valid(&key.valid_from))
    {
        return Err("WIST1-E14");
    }
    canonical_encoding(doc["sig"]["value"].as_str().ok_or("WIST1-E14")?, 64)
        .map_err(|_| "WIST1-E14")?;
    for key in keys {
        canonical_encoding(&key.public_key, 32).map_err(|_| "WIST1-E14")?;
    }
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let mut eligible = false;
    for key in keys.iter().filter(|key| key.key_id == key_id) {
        if key.alg != "Ed25519" {
            continue;
        }
        let Ok(public) = PublicKey::from_b64u(&key.public_key) else {
            continue;
        };
        if observed_at.is_some_and(|at| {
            !time::compare(at, &key.valid_from).is_some_and(|order| !order.is_lt())
        }) {
            continue;
        }
        eligible = true;
        if verify_envelope(doc, kind, &public).is_ok() {
            return Ok(());
        }
    }
    if eligible {
        Err("WIST1-E01")
    } else {
        Err("WIST1-E02")
    }
}

/// WIST-1 §5.2: evaluate a fetched Declaration against the previously
/// accepted one. An open recovery window does not change acceptance — a
/// Declaration sealed inside one is superseded at the window's end, and
/// rejecting it here would leave the attempt invisible on replay. Err
/// carries the WIST-1 §7 code for the failure and its detail.
pub fn evaluate(stored: &Value, fetched: &Value) -> Result<Decision, (&'static str, String)> {
    let stored_p = parse(stored).map_err(|e| ("WIST2-E04", e))?;
    let fetched_p = validate_fields(fetched)?.publisher;
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
    let Ok(candidate_envelope) = validate_fields(candidate) else {
        return false;
    };
    let candidate_p = candidate_envelope.publisher;
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
