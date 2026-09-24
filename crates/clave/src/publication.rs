//! WIST-3 §5, §6: entry bundles and tiles are written before the Epoch's
//! Checkpoint is archived, and the head Checkpoint last, so `/checkpoint`
//! never names a tree size whose Entries no path serves.
use crate::db::Db;
use crate::error::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use wist_core::checkpoint::Checkpoint;
use wist_core::tiles::{self, TILE_WIDTH};

/// The path holds either the previous content or all of the new one.
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

pub fn served(data_dir: &Path, path: &str) -> PathBuf {
    data_dir.join(path.trim_start_matches('/'))
}

pub fn head_path(data_dir: &Path) -> PathBuf {
    data_dir.join("checkpoint")
}

pub fn archive_path(data_dir: &Path, epoch_number: u64) -> PathBuf {
    served(data_dir, &wist_core::checkpoint::archive_path(epoch_number))
}

fn meets(range: (u64, u64), from: u64, to: u64) -> bool {
    range.0 < to && from < range.1
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if std::fs::read(path).is_ok_and(|held| held == bytes) {
        return Ok(false);
    }
    write_durable(path, bytes)?;
    Ok(true)
}

/// WIST-3 §6: a partial tile or bundle is removed once the full one at its
/// index exists.
fn publish_tree(db: &Db, data_dir: &Path, from: u64, to: u64) -> Result<bool> {
    let mut wrote = false;
    for bundle in tiles::required_entry_bundles(to) {
        let path = served(data_dir, &bundle.path());
        let (start, end) = bundle.leaf_range();
        let recompute = bundle.width < TILE_WIDTH || meets((start, end), from, to);
        if !recompute && path.exists() {
            continue;
        }
        let bytes = tiles::encode_entry_bundle(&db.entry_range(start, end)?)
            .map_err(|e| Error::Seal(e.to_string()))?;
        wrote |= write_if_changed(&path, &bytes)?;
        if bundle.width == TILE_WIDTH {
            remove_partials(
                data_dir,
                &tiles::EntryBundle {
                    index: bundle.index,
                    width: 1,
                }
                .path(),
            )?;
        }
    }
    for tile in tiles::required_tiles(to) {
        let path = served(data_dir, &tile.path());
        let recompute = tile.width < TILE_WIDTH || meets(tile.leaf_range(), from, to);
        if !recompute && path.exists() {
            continue;
        }
        let hashes = db
            .tile_hashes(tile.level, tile.index)?
            .ok_or_else(|| Error::Seal("the store is missing a tile the tree requires".into()))?;
        let width = tile.width as usize;
        if hashes.len() < width {
            return Err(Error::Seal(
                "the store holds fewer hashes than the tile the tree requires".into(),
            ));
        }
        wrote |= write_if_changed(&path, &tiles::encode_tile(&hashes[..width]))?;
        if tile.width == TILE_WIDTH {
            remove_partials(
                data_dir,
                &tiles::Tile {
                    level: tile.level,
                    index: tile.index,
                    width: 1,
                }
                .path(),
            )?;
        }
    }
    Ok(wrote)
}

fn remove_partials(data_dir: &Path, partial_path: &str) -> Result<()> {
    let directory = served(data_dir, partial_path);
    let Some(directory) = directory.parent() else {
        return Ok(());
    };
    if directory.is_dir() {
        std::fs::remove_dir_all(directory)?;
    }
    Ok(())
}

fn publish_epoch(db: &Db, data_dir: &Path, epoch_number: u64, note: &str) -> Result<bool> {
    let checkpoint = Checkpoint::parse(note).map_err(|e| Error::Seal(e.to_string()))?;
    if checkpoint.epoch_number() != epoch_number {
        return Err(Error::Seal(
            "the stored note is not the Epoch's Checkpoint".into(),
        ));
    }
    let from = db.size_before(epoch_number)?;
    let mut wrote = publish_tree(db, data_dir, from, checkpoint.tree_size())?;
    wrote |= write_if_changed(&archive_path(data_dir, epoch_number), note.as_bytes())?;
    wrote |= write_if_changed(&head_path(data_dir), note.as_bytes())?;
    Ok(wrote)
}

/// WIST-3 §6.2: a withdrawal's removal precedes the Checkpoint at its
/// height, so no served head names content still served.
pub fn finish_committed(db: &Db, data_dir: &Path) -> Result<Vec<u64>> {
    db.check_fence()?;
    crate::snapshot::apply_pending_removals(db, data_dir)?;
    let mut published = Vec::new();
    for (epoch_number, note) in db.unpublished_publications()? {
        db.check_fence()?;
        publish_epoch(db, data_dir, epoch_number, &note)?;
        db.mark_published(epoch_number)?;
        published.push(epoch_number);
    }
    Ok(published)
}

/// WIST-3 §3.4: unsealed documents a key removed at or below the head
/// signed are re-signed before a Checkpoint at that head is served to
/// verify them against.
pub fn recover(db: &Db, data_dir: &Path) -> Result<Vec<u64>> {
    db.check_fence()?;
    crate::snapshot::reconcile(db, data_dir)?;
    crate::snapshot::resign_unsealed(db, data_dir)?;
    let mut republished = finish_committed(db, data_dir)?;
    if let Some((epoch_number, note)) = db.head_publication()? {
        db.check_fence()?;
        if !republished.contains(&epoch_number) && publish_epoch(db, data_dir, epoch_number, &note)?
        {
            republished.push(epoch_number);
        }
    }
    Ok(republished)
}

/// WIST-3 §6: the note text is untouched; only its signature lines changed.
pub fn republish_checkpoint(db: &Db, data_dir: &Path, epoch_number: u64, note: &str) -> Result<()> {
    db.check_fence()?;
    write_durable(&archive_path(data_dir, epoch_number), note.as_bytes())?;
    if db
        .head_publication()?
        .is_some_and(|(head, _)| head == epoch_number)
    {
        write_durable(&head_path(data_dir), note.as_bytes())?;
    }
    Ok(())
}
