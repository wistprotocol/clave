use crate::error::{Error, Result};
use std::path::Path;

pub(crate) fn read(path: &Path, bound: u64) -> Result<Vec<u8>> {
    decode(&std::fs::read(path)?, bound)
}

fn decode(raw: &[u8], bound: u64) -> Result<Vec<u8>> {
    if !raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(failure("standard Block frame required"));
    }
    let declared = zstd::zstd_safe::get_frame_content_size(raw)
        .map_err(|_| failure("invalid Block frame"))?
        .filter(|&size| size <= bound)
        .ok_or_else(|| failure("missing or excessive Block frame size"))?;
    let compressed_size = zstd::zstd_safe::find_frame_compressed_size(raw)
        .map_err(|_| failure("invalid or truncated Block frame"))?;
    if compressed_size != raw.len() {
        return Err(failure("Block file must contain exactly one frame"));
    }
    validate_data_blocks(raw, declared)?;
    let bytes = zstd::bulk::decompress(
        raw,
        usize::try_from(declared).map_err(|_| failure("Block size is not addressable"))?,
    )
    .map_err(|e| failure(&format!("invalid compressed Block: {e}")))?;
    if bytes.len() as u64 != declared {
        return Err(failure("false Block frame size"));
    }
    Ok(bytes)
}

fn validate_data_blocks(raw: &[u8], declared: u64) -> Result<()> {
    let descriptor = raw[4];
    let single = descriptor & 32 != 0;
    let mut position = 5;
    let window = if single {
        declared
    } else {
        let descriptor = *raw
            .get(position)
            .ok_or_else(|| failure("missing frame window"))?;
        position += 1;
        let base = 1u64 << (10 + (descriptor >> 3));
        base + (base >> 3) * u64::from(descriptor & 7)
    };
    position += [0, 1, 2, 4][usize::from(descriptor & 3)];
    position += [usize::from(single), 2, 4, 8][usize::from(descriptor >> 6)];
    loop {
        let header = raw
            .get(position..position + 3)
            .ok_or_else(|| failure("truncated data block header"))?;
        let header = u32::from_le_bytes([header[0], header[1], header[2], 0]);
        let kind = (header >> 1) & 3;
        let size = header >> 3;
        if kind == 3 || u64::from(size) > window.min(131072) {
            return Err(failure("data block exceeds its frame window or size limit"));
        }
        position += 3 + if kind == 1 { 1 } else { size as usize };
        if header & 1 != 0 {
            return Ok(());
        }
    }
}

fn failure(message: &str) -> Error {
    Error::History(format!("WIST3-E03 {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn consumes_exact_frame_vectors_with_an_independent_decoder() {
        let dir = std::env::var("WIST_SPEC_DIR").unwrap_or_else(|_| "../../../spec".into());
        let vector: serde_json::Value = serde_json::from_slice(
            &std::fs::read(Path::new(&dir).join("vectors/wist3/block-frames.json")).unwrap(),
        )
        .unwrap();
        let expected = wist_core::jcs::canonicalize(&vector["block"]).unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let raw: Vec<_> = case["parts"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|part| {
                    wist_core::crypto::hex_decode(
                        vector["fragments_hex"][part.as_str().unwrap()]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap()
                })
                .collect();
            let result = decode(&raw, case["bound"].as_u64().unwrap());
            if case["expected"] == "valid" {
                assert_eq!(result.unwrap(), expected, "{}", case["label"]);
            } else {
                assert!(
                    result.unwrap_err().to_string().contains("WIST3-E03"),
                    "{}",
                    case["label"]
                );
            }
        }
    }

    #[test]
    fn compressed_frames_accept_checksums_and_reject_corruption() {
        let bytes = vec![b'a'; 4096];
        for checksum in [false, true] {
            let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
            encoder.include_checksum(checksum).unwrap();
            encoder
                .set_pledged_src_size(Some(bytes.len() as u64))
                .unwrap();
            encoder.write_all(&bytes).unwrap();
            let mut frame = encoder.finish().unwrap();
            assert!(frame.len() < bytes.len());
            assert_eq!(decode(&frame, bytes.len() as u64).unwrap(), bytes);
            if checksum {
                *frame.last_mut().unwrap() ^= 1;
                assert!(decode(&frame, bytes.len() as u64).is_err());
            }
        }
    }
}
