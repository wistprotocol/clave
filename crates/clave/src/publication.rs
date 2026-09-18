//! WIST-3 §5 and §6: the distribution stage. A sealed Epoch's Entries
//! reach their entry bundles and the tree its tiles before the Epoch's
//! Checkpoint is archived, and the head Checkpoint is written last, so
//! `/checkpoint` never names a tree size whose Entries no path serves.
//! A run interrupted anywhere is finished by the next one from the
//! Epochs the store has committed but not marked published.
use crate::db::Db;
use crate::error::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use wist_core::checkpoint::Checkpoint;
use wist_core::tiles::{self, TILE_WIDTH};

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

/// The file under `data_dir` that serves a path of the static layout.
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

/// Lays out the tree at size `to`: every entry bundle and tile whose
/// leaves the range `[from, to)` reaches is recomputed and rewritten
/// where it differs, every partial one the size requires is rewritten
/// where it differs, and any other required file the disk has lost is
/// restored. A partial tile or bundle is removed once the full one at
/// its index exists (WIST-3 §6).
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

/// Removes the directory of partial files at a tile or bundle index,
/// named by the `.p/<width>` path any of its partials carries.
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

/// Publishes one committed Epoch: its Entries and the tree's hashes
/// first, then the Checkpoint's archive copy, then the head.
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

/// Finishes every publication the store committed to that the disk does
/// not hold, lowest height first, then restores any file of the head
/// Epoch a crash, a torn write or a deletion left wrong. Returns the
/// heights it wrote for.
pub fn recover(db: &Db, data_dir: &Path) -> Result<Vec<u64>> {
    let mut republished = Vec::new();
    for (epoch_number, note) in db.unpublished_publications()? {
        publish_epoch(db, data_dir, epoch_number, &note)?;
        db.mark_published(epoch_number)?;
        republished.push(epoch_number);
    }
    let Some((epoch_number, note)) = db.head_publication()? else {
        return Ok(republished);
    };
    if republished.contains(&epoch_number) {
        return Ok(republished);
    }
    if publish_epoch(db, data_dir, epoch_number, &note)? {
        republished.push(epoch_number);
    }
    Ok(republished)
}

/// Rewrites the files that carry a Checkpoint whose signature lines have
/// changed: the archive copy and, where it is the head, `/checkpoint`.
/// The note text is untouched (WIST-3 §6).
pub fn republish_checkpoint(db: &Db, data_dir: &Path, epoch_number: u64, note: &str) -> Result<()> {
    write_durable(&archive_path(data_dir, epoch_number), note.as_bytes())?;
    if db
        .head_publication()?
        .is_some_and(|(head, _)| head == epoch_number)
    {
        write_durable(&head_path(data_dir), note.as_bytes())?;
    }
    Ok(())
}
