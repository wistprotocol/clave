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

pub const MIRROR_HEAD_CAP_BYTES: u64 = 65_536;

const ARCHIVE_NAME_MIN_DIGITS: usize = 9;

fn published_at(path: &Path) -> Result<Option<Checkpoint>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(String::from_utf8(bytes)
            .ok()
            .and_then(|note| Checkpoint::parse(&note).ok())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn highest_archived(data_dir: &Path) -> Result<Option<(u64, PathBuf)>> {
    let archive = archive_path(data_dir, 0);
    let Some(directory) = archive.parent() else {
        return Ok(None);
    };
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut highest: Option<(u64, PathBuf)> = None;
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.len() < ARCHIVE_NAME_MIN_DIGITS || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let epoch_number = name.parse::<u64>().unwrap_or(u64::MAX);
        let path = entry.path();
        if highest.as_ref().is_none_or(|(held, held_path)| {
            epoch_number > *held || (epoch_number == *held && path < *held_path)
        }) {
            highest = Some((epoch_number, path));
        }
    }
    Ok(highest)
}

fn ahead(holder: String, published: u64, store_head: Option<u64>) -> Error {
    Error::PublishedAhead {
        holder,
        published,
        store_head,
    }
}

fn stored_head(db: &Db) -> Result<Option<(u64, String)>> {
    db.head_publication()?
        .map(|(epoch_number, note)| {
            let text = Checkpoint::parse(&note)
                .map_err(|e| Error::Seal(e.to_string()))?
                .note_text();
            Ok((epoch_number, text))
        })
        .transpose()
}

/// WIST-3 §5: a second validly signed Checkpoint at a published
/// `epoch_number` is Equivocation.
pub fn guard_published(db: &Db, data_dir: &Path) -> Result<()> {
    let store = stored_head(db)?;
    let store_head = store.as_ref().map(|(epoch_number, _)| *epoch_number);
    let head_file = head_path(data_dir);
    let head_checkpoint = published_at(&head_file)?;
    let mut highest = head_checkpoint
        .as_ref()
        .map(|checkpoint| (checkpoint.epoch_number(), head_file.clone()));
    if let Some((epoch_number, path)) = highest_archived(data_dir)? {
        if highest
            .as_ref()
            .is_none_or(|(held, _)| epoch_number >= *held)
        {
            highest = Some((epoch_number, path));
        }
    }
    if let Some((published, path)) = highest {
        if store_head.is_none_or(|head| published > head) {
            return Err(ahead(path.display().to_string(), published, store_head));
        }
    }
    let Some((epoch_number, stored_text)) = store else {
        return Ok(());
    };
    let archived = archive_path(data_dir, epoch_number);
    if published_at(&archived)?.is_some_and(|checkpoint| checkpoint.note_text() != stored_text) {
        return Err(ahead(
            archived.display().to_string(),
            epoch_number,
            store_head,
        ));
    }
    if head_checkpoint.is_some_and(|checkpoint| {
        checkpoint.epoch_number() == epoch_number && checkpoint.note_text() != stored_text
    }) {
        return Err(ahead(
            head_file.display().to_string(),
            epoch_number,
            store_head,
        ));
    }
    Ok(())
}

fn confirm_mirror(
    client: &crate::fetch::Client,
    base_url: &str,
    origin: &str,
    store: Option<&(u64, String)>,
) -> Result<()> {
    let url = format!("{base_url}checkpoint");
    let unconfirmed = |reason: String| Error::MirrorUnconfirmed {
        url: url.clone(),
        reason,
    };
    let body = match client.get_bytes_unless_absent(&url, MIRROR_HEAD_CAP_BYTES) {
        Ok(None) => return Ok(()),
        Ok(Some(body)) => body,
        Err(error) => return Err(unconfirmed(error.to_string())),
    };
    let note = String::from_utf8(body)
        .map_err(|_| unconfirmed("it answered with bytes that are not text".into()))?;
    let published = Checkpoint::parse(&note)
        .map_err(|e| unconfirmed(format!("it answered with no Checkpoint: {e}")))?;
    if published.origin() != origin {
        return Err(unconfirmed(format!(
            "it serves a Checkpoint of Log {:?}, not of {origin:?}",
            published.origin()
        )));
    }
    let store_head = store.map(|(epoch_number, _)| *epoch_number);
    let refuse = || ahead(url.clone(), published.epoch_number(), store_head);
    match store {
        None => Err(refuse()),
        Some((head, _)) if published.epoch_number() > *head => Err(refuse()),
        Some((head, text))
            if published.epoch_number() == *head && published.note_text() != *text =>
        {
            Err(refuse())
        }
        Some(_) => Ok(()),
    }
}

pub fn confirm_mirrors(
    db: &Db,
    data_dir: &Path,
    client: &crate::fetch::Client,
    mirror_urls: &[String],
) -> Result<()> {
    if mirror_urls.is_empty() {
        return Ok(());
    }
    let origin = crate::history::anchor(data_dir)?.log_id;
    let store = stored_head(db)?;
    for base_url in mirror_urls {
        confirm_mirror(client, base_url, &origin, store.as_ref())?;
    }
    Ok(())
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
    guard_published(db, data_dir)?;
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
    guard_published(db, data_dir)?;
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
    guard_published(db, data_dir)?;
    write_durable(&archive_path(data_dir, epoch_number), note.as_bytes())?;
    if db
        .head_publication()?
        .is_some_and(|(head, _)| head == epoch_number)
    {
        write_durable(&head_path(data_dir), note.as_bytes())?;
    }
    Ok(())
}
