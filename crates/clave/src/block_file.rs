use crate::error::{Error, Result};
use std::path::Path;

pub(crate) fn read(path: &Path, bound: u64) -> Result<Vec<u8>> {
    decode(&std::fs::read(path)?, bound)
}

fn decode(raw: &[u8], bound: u64) -> Result<Vec<u8>> {
    wist_core::block_frames::decode(raw, bound).map_err(|e| Error::History(e.to_string()))
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
