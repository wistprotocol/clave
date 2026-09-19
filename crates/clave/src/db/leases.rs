//! Leases that make one holder at a time the writer for a pull partition
//! or for the Log's seals. Every takeover increments the lease's token,
//! and work begun under an older token is refused its writes.
use super::{Db, Mutation};
use crate::error::Result;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// How many partitions a new store divides its domains into; a store
/// keeps the count it was created with.
pub const PARTITIONS: i64 = 16;
/// How long a dispatcher's hold on a partition lasts unless renewed; each
/// dispatcher pass renews it.
pub const PARTITION_LEASE_SECONDS: i64 = 30;
/// How long a sealer's hold on the Log's seals lasts unless renewed.
pub const SEALER_LEASE_SECONDS: i64 = 30;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pull_partitions(partition INTEGER PRIMARY KEY, owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0, token INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sealer_lease(id INTEGER PRIMARY KEY CHECK(id = 0), owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0, token INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO sealer_lease(id) VALUES (0);
";

/// An owner name unique to this process and its start: the process ID
/// and the Unix nanosecond it was taken at.
pub fn process_owner() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        jiff::Timestamp::now().as_nanosecond()
    )
}

/// The lease a connection's writes are fenced by, at the token it was
/// held with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fence {
    Partition { partition: i64, token: i64 },
    Sealer { token: i64 },
}

/// A lease as the store records it: its holder, the instant the hold
/// lapses unless renewed and the token of the latest takeover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub owner: Option<String>,
    pub lease_until: i64,
    pub token: i64,
}

fn lease_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Lease> {
    Ok(Lease {
        owner: row.get(0)?,
        lease_until: row.get(1)?,
        token: row.get(2)?,
    })
}

/// Creates the lease tables on a store that lacks them, dividing a new
/// store into `PARTITIONS` partitions in one transaction.
pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    let tx = Mutation::new(conn)?;
    let empty: bool = tx.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM pull_partitions)",
        [],
        |row| row.get(0),
    )?;
    if empty {
        for partition in 0..PARTITIONS {
            tx.execute(
                "INSERT INTO pull_partitions(partition) VALUES (?1)",
                [partition],
            )?;
        }
    }
    tx.commit()
}

/// The partition `domain` belongs to: the first eight bytes of the
/// SHA-256 of its canonical host, read big-endian, modulo the store's
/// partition count.
pub(super) fn partition_of(conn: &Connection, domain: &str) -> Result<i64> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM pull_partitions", [], |row| row.get(0))?;
    let digest = Sha256::digest(domain.as_bytes());
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    Ok((u64::from_be_bytes(prefix) % count.max(1) as u64) as i64)
}

/// Whether the lease `fence` names is still at the fence's token.
pub(super) fn fence_holds(conn: &Connection, fence: Fence) -> Result<bool> {
    let (current, token) = match fence {
        Fence::Partition { partition, token } => (
            conn.query_row(
                "SELECT token FROM pull_partitions WHERE partition = ?1",
                [partition],
                |row| row.get::<_, i64>(0),
            )
            .optional()?,
            token,
        ),
        Fence::Sealer { token } => (
            conn.query_row("SELECT token FROM sealer_lease WHERE id = 0", [], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?,
            token,
        ),
    };
    Ok(current == Some(token))
}

impl Db {
    /// The partition `domain` is pulled under.
    pub fn partition_of(&self, domain: &str) -> Result<i64> {
        partition_of(&self.conn, domain)
    }

    /// Every partition's lease, by partition.
    pub fn partition_leases(&self) -> Result<Vec<(i64, Lease)>> {
        Ok(self
            .conn
            .prepare("SELECT owner, lease_until, token, partition FROM pull_partitions ORDER BY partition")?
            .query_map([], |row| Ok((row.get(3)?, lease_row(row)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Renews `owner`'s sealer lease to `SEALER_LEASE_SECONDS` past `now`,
    /// or takes it over when it is unheld or lapsed at `now`, and returns
    /// the token `owner` holds it with; `None` while another owner's lease
    /// is live.
    pub fn hold_sealer_lease(&self, owner: &str, now: i64) -> Result<Option<i64>> {
        self.hold_sealer_lease_for(owner, now, SEALER_LEASE_SECONDS)
    }

    /// `hold_sealer_lease` with a lease of `lease_seconds`.
    pub fn hold_sealer_lease_for(
        &self,
        owner: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<i64>> {
        self.write(|conn| {
            let until = now.saturating_add(lease_seconds);
            let renewed = conn
                .query_row(
                    "UPDATE sealer_lease SET lease_until = ?2 WHERE id = 0 AND owner = ?1 RETURNING token",
                    (owner, until),
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if renewed.is_some() {
                return Ok(renewed);
            }
            Ok(conn
                .query_row(
                    "UPDATE sealer_lease SET owner = ?1, lease_until = ?2, token = token + 1 WHERE id = 0 AND (owner IS NULL OR lease_until <= ?3) RETURNING token",
                    (owner, until, now),
                    |row| row.get::<_, i64>(0),
                )
                .optional()?)
        })
    }

    /// Extends `owner`'s sealer lease to `lease_seconds` past `now` while
    /// it is still at `token`, returning whether it was; `false` means the
    /// lease was taken over.
    pub fn renew_sealer_lease(
        &self,
        owner: &str,
        token: i64,
        now: i64,
        lease_seconds: i64,
    ) -> Result<bool> {
        Ok(self.execute(
            "UPDATE sealer_lease SET lease_until = ?3 WHERE id = 0 AND owner = ?1 AND token = ?2",
            (owner, token, now.saturating_add(lease_seconds)),
        )? == 1)
    }

    /// Gives up every partition lease `owner` holds so other dispatchers
    /// need not wait for them to lapse; a partition's next holder still
    /// increments its token, fencing out any pull `owner` has in flight.
    pub fn release_partitions(&self, owner: &str) -> Result<()> {
        self.execute(
            "UPDATE pull_partitions SET owner = NULL, lease_until = 0 WHERE owner = ?1",
            [owner],
        )?;
        Ok(())
    }

    /// Fails with `Error::Fenced` when this connection is fenced by a lease
    /// that has since been taken over; work that writes outside the store
    /// checks it first.
    pub fn check_fence(&self) -> Result<()> {
        match self.fence {
            Some(fence) if !fence_holds(&self.conn, fence)? => Err(crate::error::Error::Fenced),
            _ => Ok(()),
        }
    }

    /// Gives up `owner`'s sealer lease so the next sealer need not wait
    /// for it to lapse.
    pub fn release_sealer_lease(&self, owner: &str) -> Result<()> {
        self.execute(
            "UPDATE sealer_lease SET owner = NULL, lease_until = 0 WHERE id = 0 AND owner = ?1",
            [owner],
        )?;
        Ok(())
    }

    /// The Log's sealer lease.
    pub fn sealer_lease(&self) -> Result<Lease> {
        Ok(self.conn.query_row(
            "SELECT owner, lease_until, token FROM sealer_lease WHERE id = 0",
            [],
            lease_row,
        )?)
    }
}
