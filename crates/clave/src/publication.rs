//! WIST-3 §5 and §6: a Block and its Checkpoint reach disk complete and
//! durable, the Checkpoint only after the Block, and a publication the
//! store committed to is finished after a restart from the recorded
//! bytes rather than sealed again.
use crate::db::Db;
use crate::error::Result;
use std::io::Write;
use std::path::Path;

/// Writes `bytes` to `path` through a sibling temporary file, syncing the
/// file and then its directory, so the path holds either the previous
/// content or all of the new one.
pub fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let temporary = directory.join(format!(".{name}.tmp"));
    let mut output = std::fs::File::create(&temporary)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    drop(output);
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn block_path(data_dir: &Path, block_number: u64) -> std::path::PathBuf {
    data_dir.join(format!("log/blocks/{block_number:09}.json.zst"))
}

fn checkpoint_path(data_dir: &Path, block_number: u64) -> std::path::PathBuf {
    data_dir.join(format!("log/checkpoints/{block_number:09}.json"))
}

fn publish_block(data_dir: &Path, block_number: u64, block_json: &[u8]) -> Result<()> {
    let compressed = zstd::bulk::compress(block_json, zstd::DEFAULT_COMPRESSION_LEVEL)?;
    write_durable(&block_path(data_dir, block_number), &compressed)
}

fn publish_checkpoint(data_dir: &Path, block_number: u64, checkpoint_json: &[u8]) -> Result<()> {
    write_durable(&checkpoint_path(data_dir, block_number), checkpoint_json)?;
    write_durable(&data_dir.join("log/checkpoint.json"), checkpoint_json)
}

/// Publishes one committed Block: the Block file first, then its
/// numbered Checkpoint copy, then the fixed Checkpoint path, each
/// durable before the next.
pub fn publish(
    data_dir: &Path,
    block_number: u64,
    block_json: &[u8],
    checkpoint_json: &[u8],
) -> Result<()> {
    publish_block(data_dir, block_number, block_json)?;
    publish_checkpoint(data_dir, block_number, checkpoint_json)
}

enum BlockFile {
    Recorded,
    Missing,
    Recoded,
    Other(String),
}

/// How the head Block's file on disk relates to the bytes the store
/// committed to: the same bytes, absent or unreadable, the same Block in
/// another encoding, or a different Block at that height.
fn block_file_state(data_dir: &Path, block_number: u64, block_json: &[u8]) -> Result<BlockFile> {
    let Some(decoded) = std::fs::read(block_path(data_dir, block_number))
        .ok()
        .and_then(|raw| zstd::decode_all(raw.as_slice()).ok())
    else {
        return Ok(BlockFile::Missing);
    };
    if decoded == block_json {
        return Ok(BlockFile::Recorded);
    }
    let Ok(on_disk) = crate::json::parse(&decoded) else {
        return Ok(BlockFile::Missing);
    };
    let recorded = crate::json::parse(block_json)?;
    let recorded_hash = wist_core::block::block_hash(&recorded["header"])?;
    match wist_core::block::block_hash(&on_disk["header"]) {
        Ok(hash) if hash == recorded_hash => Ok(BlockFile::Recoded),
        Ok(hash) => Ok(BlockFile::Other(hash)),
        Err(_) => Ok(BlockFile::Missing),
    }
}

/// Finishes every publication the store committed to that the disk does
/// not hold as recorded: each unpublished height, lowest first, and the
/// head Block whose files a crash, a torn write or a restore may have
/// left behind. A head file holding a different Block is refused rather
/// than overwritten, since the store and the disk then disagree beyond a
/// torn write. Returns the heights republished.
pub fn recover(db: &Db, data_dir: &Path) -> Result<Vec<u64>> {
    let mut republished = Vec::new();
    for (block_number, block_json, checkpoint_json) in db.unpublished_publications()? {
        publish(data_dir, block_number, &block_json, &checkpoint_json)?;
        db.mark_published(block_number)?;
        republished.push(block_number);
    }
    let Some((block_number, block_json, checkpoint_json)) = db.head_publication()? else {
        return Ok(republished);
    };
    if republished.contains(&block_number) {
        return Ok(republished);
    }
    let block_written = match block_file_state(data_dir, block_number, &block_json)? {
        BlockFile::Recorded => false,
        BlockFile::Missing | BlockFile::Recoded => {
            publish_block(data_dir, block_number, &block_json)?;
            true
        }
        BlockFile::Other(hash) => {
            let recorded = crate::json::parse(&block_json)?;
            return Err(crate::error::Error::Seal(format!(
                "Block {block_number} on disk hashes to {hash} but the store committed {}",
                wist_core::block::block_hash(&recorded["header"])?
            )));
        }
    };
    let checkpoints_written = if std::fs::read(checkpoint_path(data_dir, block_number))
        .is_ok_and(|raw| raw == checkpoint_json)
        && std::fs::read(data_dir.join("log/checkpoint.json"))
            .is_ok_and(|raw| raw == checkpoint_json)
    {
        false
    } else {
        publish_checkpoint(data_dir, block_number, &checkpoint_json)?;
        true
    };
    if block_written || checkpoints_written {
        republished.push(block_number);
    }
    Ok(republished)
}
