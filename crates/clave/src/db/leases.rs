use super::{Db, Mutation};
use crate::error::Result;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

pub const PARTITIONS: i64 = 16;
pub const PARTITION_LEASE_SECONDS: i64 = 30;
pub const SEALER_LEASE_SECONDS: i64 = 30;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pull_partitions(partition INTEGER PRIMARY KEY, owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0, token INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sealer_lease(id INTEGER PRIMARY KEY CHECK(id = 0), owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0, token INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO sealer_lease(id) VALUES (0);
";

pub fn process_owner() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        jiff::Timestamp::now().as_nanosecond()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fence {
    Partition { partition: i64, token: i64 },
    Sealer { token: i64 },
}

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

pub(super) fn partition_of(conn: &Connection, domain: &str) -> Result<i64> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM pull_partitions", [], |row| row.get(0))?;
    let digest = Sha256::digest(domain.as_bytes());
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    Ok((u64::from_be_bytes(prefix) % count.max(1) as u64) as i64)
}

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
    pub fn partition_of(&self, domain: &str) -> Result<i64> {
        partition_of(&self.conn, domain)
    }

    pub fn partition_leases(&self) -> Result<Vec<(i64, Lease)>> {
        Ok(self
            .conn
            .prepare("SELECT owner, lease_until, token, partition FROM pull_partitions ORDER BY partition")?
            .query_map([], |row| Ok((row.get(3)?, lease_row(row)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn hold_sealer_lease(&self, owner: &str, now: i64) -> Result<Option<i64>> {
        self.hold_sealer_lease_for(owner, now, SEALER_LEASE_SECONDS)
    }

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

    /// A partition's next holder still increments its token, fencing out any
    /// pull `owner` has in flight.
    pub fn release_partitions(&self, owner: &str) -> Result<()> {
        self.execute(
            "UPDATE pull_partitions SET owner = NULL, lease_until = 0 WHERE owner = ?1",
            [owner],
        )?;
        Ok(())
    }

    /// Work that writes outside the store checks this first.
    pub fn check_fence(&self) -> Result<()> {
        match self.fence {
            Some(fence) if !fence_holds(&self.conn, fence)? => Err(crate::error::Error::Fenced),
            _ => Ok(()),
        }
    }

    pub fn release_sealer_lease(&self, owner: &str) -> Result<()> {
        self.execute(
            "UPDATE sealer_lease SET owner = NULL, lease_until = 0 WHERE id = 0 AND owner = ?1",
            [owner],
        )?;
        Ok(())
    }

    pub fn sealer_lease(&self) -> Result<Lease> {
        Ok(self.conn.query_row(
            "SELECT owner, lease_until, token FROM sealer_lease WHERE id = 0",
            [],
            lease_row,
        )?)
    }
}
