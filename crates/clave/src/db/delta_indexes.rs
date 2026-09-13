use super::{Db, Result};
use crate::declaration;
use crate::error::Error;
use crate::history::{declarations::Declarations, History};
use rusqlite::TransactionBehavior;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

struct Delta {
    id: String,
    domain: String,
    url: String,
    prev: Option<String>,
    observed_at: String,
}

impl Delta {
    fn read(envelope: &Value) -> Result<Self> {
        declaration::delta::validate_content_and_prev(envelope).map_err(failure)?;
        let body = &envelope["delta"];
        let domain = wist_core::delta::publisher(body).map_err(|e| failure(&e.to_string()))?;
        let url = body["url"]
            .as_str()
            .filter(|url| !url.is_empty())
            .ok_or_else(|| failure("retained Delta has no URL"))?;
        let prev = body["prev"].as_str().map(str::to_string);
        Ok(Self {
            id: wist_core::delta::delta_id(body)?,
            domain: domain.into(),
            url: url.into(),
            prev,
            observed_at: body["observed_at"].as_str().unwrap().into(),
        })
    }
}

#[derive(Default)]
struct Indexes {
    seen: BTreeMap<String, String>,
    tips: BTreeMap<(String, String), Tip>,
}

struct Tip {
    id: String,
    observed_at: String,
}

impl Indexes {
    fn append(&mut self, delta: Delta) -> Result<()> {
        let pair = (delta.domain.clone(), delta.url);
        if self.seen.contains_key(&delta.id) {
            return Err(failure("duplicate retained Delta ID"));
        }
        let tip = self.tips.get(&pair);
        if tip.map(|tip| &tip.id) != delta.prev.as_ref() {
            return Err(failure("retained Delta does not extend its Publisher/URL tip; restore missing accepted Envelopes or reconcile invalid retained copies"));
        }
        if let Some(tip) = tip {
            declaration::verify_observation_order(&delta.observed_at, &tip.observed_at)
                .map_err(failure)?;
        }
        self.tips.insert(
            pair,
            Tip {
                id: delta.id.clone(),
                observed_at: delta.observed_at,
            },
        );
        self.seen.insert(delta.id, delta.domain);
        Ok(())
    }

    fn block(&mut self, deltas: Vec<Delta>) -> Result<()> {
        let mut chains = BTreeMap::<_, BTreeMap<_, _>>::new();
        for delta in deltas {
            let chain = chains
                .entry((delta.domain.clone(), delta.url.clone()))
                .or_default();
            if chain.insert(delta.prev.clone(), delta).is_some() {
                return Err(failure("sealed Delta chain forks or repeats an ID"));
            }
        }
        for (pair, mut chain) in chains {
            while let Some(delta) = chain.remove(&self.tips.get(&pair).map(|tip| tip.id.clone())) {
                self.append(delta)?;
            }
            if !chain.is_empty() {
                return Err(failure(
                    "sealed Delta chain is disconnected from its Publisher/URL tip",
                ));
            }
        }
        Ok(())
    }
}

impl Db {
    pub(super) fn restore_delta_indexes(&self, path: &Path) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS delta_index_reconciliation(id INTEGER PRIMARY KEY CHECK(id = 1));")?;
        let complete: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_index_reconciliation WHERE id = 1)",
            [],
            |row| row.get(0),
        )?;
        if complete {
            tx.commit()?;
            return Ok(());
        }
        let mut indexes = Indexes::default();
        let head = self.last_block()?;
        if head.is_some() {
            let mut history = History::open(path.parent().unwrap_or_else(|| Path::new(".")), head)?;
            let mut declarations = Declarations::default();
            while let Some(block) = history.next_block()? {
                declarations.apply(&block)?;
                let mut deltas = Vec::new();
                for entry in block
                    .block()
                    .entries
                    .iter()
                    .filter(|entry| entry["type"] == "publisher_delta")
                {
                    let envelope = &entry["body"];
                    block
                        .delta_size_caps()
                        .validate_delta(envelope)
                        .map_err(failure)?;
                    let delta = Delta::read(envelope)?;
                    let source = declarations
                        .domains()
                        .get(&delta.domain)
                        .and_then(|domain| domain.delta_sealing_source())
                        .ok_or_else(|| {
                            failure("sealed Delta lacks an eligible Declaration source")
                        })?;
                    let publisher =
                        declaration::publisher_of(source.envelope()).map_err(|e| failure(&e))?;
                    declaration::verify_delta_authority(&[&publisher], envelope)
                        .map_err(failure)?;
                    deltas.push(delta);
                }
                indexes.block(deltas)?;
            }
        }
        let mut statement = tx.prepare(
            "SELECT domain, entry_json, acceptance_order, NULL, NULL FROM pending_entries WHERE entry_type = 'publisher_delta' UNION ALL SELECT domain, entry_json, acceptance_order, delta_id, url FROM queued_deltas ORDER BY acceptance_order",
        )?;
        let mut rows = statement.query([])?;
        let mut positions = BTreeSet::new();
        while let Some(row) = rows.next()? {
            let domain: String = row.get(0)?;
            let envelope: Value = serde_json::from_slice(&row.get::<_, Vec<u8>>(1)?)?;
            let position: i64 = row.get(2)?;
            let stored_id: Option<String> = row.get(3)?;
            let stored_url: Option<String> = row.get(4)?;
            let delta = Delta::read(&envelope)?;
            if position <= 0 || !positions.insert(position) {
                return Err(failure(
                    "retained Delta acceptance positions are invalid or duplicated",
                ));
            }
            if domain != delta.domain
                || stored_id.as_ref().is_some_and(|id| id != &delta.id)
                || stored_url.as_ref().is_some_and(|url| url != &delta.url)
            {
                return Err(failure("retained Delta disagrees with its admission row"));
            }
            indexes.append(delta)?;
        }
        drop(rows);
        drop(statement);
        tx.execute_batch("DELETE FROM seen_deltas; DELETE FROM url_tips;")?;
        for (id, domain) in indexes.seen {
            super::exec_insert_seen_delta(&tx, &id, &domain)?;
        }
        for ((domain, url), tip) in indexes.tips {
            super::exec_set_url_tip(&tx, &url, &domain, &tip.id)?;
        }
        tx.execute("INSERT INTO delta_index_reconciliation VALUES (1)", [])?;
        tx.commit()?;
        Ok(())
    }
}

fn failure(detail: &str) -> Error {
    Error::History(format!("Delta index reconciliation: {detail}"))
}
