//! WIST-3 §5, through the C2SP witness protocol's `add-checkpoint` call.
use crate::db::{Db, WitnessRow};
use crate::error::{Error, Result};
use crate::fetch::Client;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::path::Path;
use wist_core::checkpoint::{self, witness_key_id, Checkpoint, SignatureLine, WITNESS_KEY_TYPE};
use wist_core::crypto::{hex_encode, PublicKey};

pub const RESPONSE_CAP_BYTES: u64 = 1 << 16;

const SIZE_CONTENT_TYPE: &str = "text/x.tlog.size";

/// The signed-note Ed25519 cosignature/v1 type (key type 0x04).
pub fn parse_verifier_key(encoded: &str) -> Result<(String, PublicKey)> {
    let invalid = |detail: &str| Error::Governance(format!("witness verifier key: {detail}"));
    let parts: Vec<&str> = encoded.splitn(3, '+').collect();
    if parts.len() != 3 {
        return Err(invalid("expected <name>+<key ID>+<key>"));
    }
    let name = parts[0];
    if name.is_empty() {
        return Err(invalid("the name is empty"));
    }
    let raw = STANDARD
        .decode(parts[2])
        .map_err(|_| invalid("the key is not base64"))?;
    if raw.len() != 33 || raw[0] != WITNESS_KEY_TYPE {
        return Err(invalid("the key is not an Ed25519 cosignature/v1 key"));
    }
    let key = PublicKey::from_bytes(raw[1..].try_into().expect("32 octets"))
        .map_err(|_| invalid("the key is not an Ed25519 public key"))?;
    if hex_encode(&witness_key_id(name, &key)) != parts[1].to_ascii_lowercase() {
        return Err(invalid("the key ID is not the one the name and key derive"));
    }
    Ok((name.to_owned(), key))
}

pub fn verifier_key(name: &str, key: &PublicKey) -> String {
    let mut encoded = vec![WITNESS_KEY_TYPE];
    encoded.extend_from_slice(&key.to_bytes());
    format!(
        "{name}+{}+{}",
        hex_encode(&witness_key_id(name, key)),
        STANDARD.encode(&encoded)
    )
}

fn submission_url(base_url: &str) -> String {
    format!("{}/add-checkpoint", base_url.trim_end_matches('/'))
}

pub fn request_body(old_size: u64, proof: &[[u8; 32]], note: &str) -> Vec<u8> {
    let mut body = format!("old {old_size}\n");
    for hash in proof {
        body.push_str(&STANDARD.encode(hash));
        body.push('\n');
    }
    body.push('\n');
    body.push_str(note);
    body.into_bytes()
}

/// WIST-3 §5: each line is verified under the Witness's key over the note
/// text before it is accepted.
fn accepted_lines(
    witness: &WitnessRow,
    key: &PublicKey,
    note_text: &str,
    body: &[u8],
) -> Result<Vec<SignatureLine>> {
    let body = std::str::from_utf8(body)
        .map_err(|_| Error::Governance("a Witness answered with bytes that are not text".into()))?;
    let mut lines = Vec::new();
    for line in body.lines().filter(|line| !line.is_empty()) {
        let parsed = SignatureLine::parse(line)
            .map_err(|e| Error::Governance(format!("a Witness answered with {e}")))?;
        if parsed.name != witness.name || parsed.key_id != witness_key_id(&witness.name, key) {
            return Err(Error::Governance(
                "a Witness answered with a Cosignature under another name or key".into(),
            ));
        }
        checkpoint::verify_cosignature(key, note_text, &parsed.signature).map_err(|_| {
            Error::Governance("a Witness answered with a Cosignature that does not verify".into())
        })?;
        lines.push(parsed);
    }
    if lines.is_empty() {
        return Err(Error::Governance(
            "a Witness accepted the Checkpoint without a Cosignature".into(),
        ));
    }
    Ok(lines)
}

fn stated_size(content_type: Option<&str>, body: &[u8]) -> Result<u64> {
    if !content_type.is_some_and(|value| value.starts_with(SIZE_CONTENT_TYPE)) {
        return Err(Error::Governance(
            "a Witness refused the Checkpoint without stating its size".into(),
        ));
    }
    std::str::from_utf8(body)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or_else(|| Error::Governance("a Witness stated a size that is not a number".into()))
}

enum Exchange {
    Cosigned(Vec<SignatureLine>),
    Conflict(u64),
}

fn call(
    client: &Client,
    witness: &WitnessRow,
    key: &PublicKey,
    note: &str,
    note_text: &str,
    old_size: u64,
    proof: &[[u8; 32]],
) -> Result<Exchange> {
    let response = client.post_bounded(
        &submission_url(&witness.base_url),
        request_body(old_size, proof, note),
        RESPONSE_CAP_BYTES,
    )?;
    match response.status {
        200 => Ok(Exchange::Cosigned(accepted_lines(
            witness,
            key,
            note_text,
            &response.body,
        )?)),
        409 => Ok(Exchange::Conflict(stated_size(
            response.content_type.as_deref(),
            &response.body,
        )?)),
        status => Err(Error::Governance(format!(
            "a Witness answered {status} to add-checkpoint"
        ))),
    }
}

fn submit_to(
    db: &Db,
    client: &Client,
    witness: &WitnessRow,
    key: &PublicKey,
    note: &str,
    note_text: &str,
    size: u64,
) -> Result<Vec<SignatureLine>> {
    let mut old_size = witness.last_size.min(size);
    let mut proof = db.consistency_proof(old_size, size)?;
    match call(client, witness, key, note, note_text, old_size, &proof)? {
        Exchange::Cosigned(lines) => return Ok(lines),
        Exchange::Conflict(stated) => {
            if stated > size {
                return Err(Error::Governance(format!(
                    "a Witness holds tree size {stated}, above the Checkpoint's {size}"
                )));
            }
            if stated == old_size {
                return Err(Error::Governance(
                    "a Witness refused a proof from the size it states it holds".into(),
                ));
            }
            old_size = stated;
            proof = db.consistency_proof(old_size, size)?;
        }
    }
    match call(client, witness, key, note, note_text, old_size, &proof)? {
        Exchange::Cosigned(lines) => Ok(lines),
        Exchange::Conflict(stated) => Err(Error::Governance(format!(
            "a Witness still holds tree size {stated} after one retry"
        ))),
    }
}

pub fn submit_head(db: &Db, client: &Client, data_dir: &Path) -> Result<Vec<String>> {
    let witnesses = db.witnesses()?;
    if witnesses.is_empty() {
        return Ok(Vec::new());
    }
    let Some((epoch_number, mut note)) = db.head_publication()? else {
        return Ok(Vec::new());
    };
    let mut cosigned = Vec::new();
    for witness in witnesses {
        let checkpoint = Checkpoint::parse(&note).map_err(|e| Error::Seal(e.to_string()))?;
        let note_text = checkpoint.note_text();
        let size = checkpoint.tree_size();
        let key = match parse_verifier_key(&witness.public_key) {
            Ok((_, key)) => key,
            Err(error) => {
                tracing::warn!(witness = %witness.name, %error, "witness key is unusable");
                continue;
            }
        };
        let lines = match submit_to(db, client, &witness, &key, &note, &note_text, size) {
            Ok(lines) => lines,
            Err(error) => {
                tracing::warn!(witness = %witness.name, %error, "witness did not cosign");
                continue;
            }
        };
        let mut updated = checkpoint;
        let held: Vec<String> = updated
            .signatures()
            .iter()
            .map(SignatureLine::encode)
            .collect();
        let mut added = 0usize;
        let mut dropped = 0usize;
        for line in lines {
            if held.contains(&line.encode()) {
                continue;
            }
            // WIST-3 §5: a note carries at most sixteen signature lines, and the
            // Aggregator MUST NOT publish one carrying more. The Log's own lines
            // stay; Cosignatures past the cap are dropped in the order obtained.
            if updated.signatures().len() >= checkpoint::MAX_SIGNATURE_LINES {
                dropped += 1;
                continue;
            }
            updated.add_signature(line);
            added += 1;
        }
        if dropped > 0 {
            tracing::warn!(
                witness = %witness.name,
                dropped,
                "the Checkpoint already carries the sixteen signature lines a note admits"
            );
        }
        if added == 0 && dropped > 0 {
            continue;
        }
        note = updated.encode();
        db.replace_checkpoint_note(epoch_number, &note)?;
        crate::publication::republish_checkpoint(db, data_dir, epoch_number, &note)?;
        db.set_witness_size(&witness.name, size)?;
        cosigned.push(witness.name);
    }
    Ok(cosigned)
}
