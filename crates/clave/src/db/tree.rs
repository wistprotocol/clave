use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use std::cell::RefCell;
use std::collections::BTreeMap;
use wist_core::merkle::{self, Extended, HashReader};
use wist_core::tiles::{self, TILE_HEIGHT, TILE_WIDTH};

fn absent() -> wist_core::error::Error {
    wist_core::error::Error::Tile("WIST3-E01 a tile the tree needs is absent".into())
}

fn merkle_failure(error: wist_core::error::Error) -> Error {
    Error::History(error.to_string())
}

type TileCache = BTreeMap<(u8, u64), Vec<[u8; 32]>>;

pub struct StoredTree<'a> {
    conn: &'a Connection,
    cache: RefCell<TileCache>,
}

impl<'a> StoredTree<'a> {
    pub(super) fn new(conn: &'a Connection) -> Self {
        StoredTree {
            conn,
            cache: RefCell::new(BTreeMap::new()),
        }
    }
}

impl HashReader for StoredTree<'_> {
    fn node(
        &self,
        level: u32,
        index: u64,
    ) -> std::result::Result<[u8; 32], wist_core::error::Error> {
        if !level.is_multiple_of(TILE_HEIGHT) {
            let left = self.node(level - 1, index * 2)?;
            let right = self.node(level - 1, index * 2 + 1)?;
            return Ok(merkle::node_hash(&left, &right));
        }
        let tile_level = u8::try_from(level / TILE_HEIGHT).map_err(|_| absent())?;
        let tile_index = index / u64::from(TILE_WIDTH);
        let offset = usize::try_from(index % u64::from(TILE_WIDTH)).expect("below 256");
        if let Some(hash) = self
            .cache
            .borrow()
            .get(&(tile_level, tile_index))
            .map(|hashes| hashes.get(offset).copied())
        {
            return hash.ok_or_else(absent);
        }
        let hashes = read_tile(self.conn, tile_level, tile_index)
            .map_err(|e| wist_core::error::Error::Tile(e.to_string()))?
            .ok_or_else(absent)?;
        let hash = hashes.get(offset).copied();
        self.cache
            .borrow_mut()
            .insert((tile_level, tile_index), hashes);
        hash.ok_or_else(absent)
    }
}

pub(super) fn read_tile(conn: &Connection, level: u8, index: u64) -> Result<Option<Vec<[u8; 32]>>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hashes FROM log_tiles WHERE level = ?1 AND tile_index = ?2",
            (i64::from(level), index as i64),
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| tiles::decode_tile(&bytes).map_err(|e| Error::History(e.to_string())))
        .transpose()
}

pub(super) fn root_after_appending(
    conn: &Connection,
    previous_size: u64,
    leaves: &[[u8; 32]],
) -> Result<[u8; 32]> {
    let prior = StoredTree::new(conn);
    merkle::root_after_appending(&prior, previous_size, leaves).map_err(merkle_failure)
}

pub(super) fn append(
    conn: &Connection,
    previous_size: u64,
    leaves: &[[u8; 32]],
) -> Result<[u8; 32]> {
    let size = previous_size
        .checked_add(leaves.len() as u64)
        .ok_or_else(|| Error::History("tree size is not addressable".into()))?;
    let prior = StoredTree::new(conn);
    let extended = Extended::new(&prior, previous_size, leaves);
    let mut written = Vec::new();
    for tile in tiles::required_tiles(size) {
        if tile.leaf_range().1 <= previous_size {
            continue;
        }
        let level = TILE_HEIGHT * u32::from(tile.level);
        let first = tile.index * u64::from(TILE_WIDTH);
        let hashes = (0..u64::from(tile.width))
            .map(|offset| extended.node(level, first + offset))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(merkle_failure)?;
        written.push((tile.level, tile.index, tiles::encode_tile(&hashes)));
    }
    let root = merkle::root_from(&extended, size).map_err(merkle_failure)?;
    for (level, index, bytes) in written {
        conn.execute(
            "INSERT INTO log_tiles(level, tile_index, hashes) VALUES (?1, ?2, ?3)
             ON CONFLICT(level, tile_index) DO UPDATE SET hashes = excluded.hashes",
            (i64::from(level), index as i64, bytes),
        )?;
    }
    Ok(root)
}

pub(super) fn put_entries(
    conn: &Connection,
    epoch_number: u64,
    first_index: u64,
    entries: &[Vec<u8>],
) -> Result<()> {
    for (offset, entry) in entries.iter().enumerate() {
        conn.execute(
            "INSERT INTO log_entries(leaf_index, epoch_number, entry_json) VALUES (?1, ?2, ?3)",
            (
                (first_index + offset as u64) as i64,
                epoch_number as i64,
                entry,
            ),
        )?;
    }
    Ok(())
}

pub(super) fn entry_range(conn: &Connection, from: u64, to: u64) -> Result<Vec<Vec<u8>>> {
    let mut statement = conn.prepare(
        "SELECT entry_json FROM log_entries WHERE leaf_index >= ?1 AND leaf_index < ?2 ORDER BY leaf_index",
    )?;
    let rows = statement
        .query_map([from as i64, to as i64], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() as u64 != to.saturating_sub(from) {
        return Err(Error::History(
            "the store is missing leaf data the tree commits to".into(),
        ));
    }
    Ok(rows)
}
