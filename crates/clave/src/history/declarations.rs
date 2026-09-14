use super::{History, VerifiedBlock};
use crate::db::BlockRow;
use crate::declaration::{evaluate, evaluate_initial, inner_hash, validate_fields, Decision};
use crate::error::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub block_number: u64,
    pub entry_index: usize,
}

#[derive(Debug, Clone)]
pub struct Declaration {
    envelope: Value,
    hash: String,
    position: Position,
    sealed_at_s: i64,
}

impl Declaration {
    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn position(&self) -> Position {
        self.position
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryWindow {
    owner: Arc<Declaration>,
    head: Arc<Declaration>,
    before: Arc<Declaration>,
    end_s: i128,
    competitors: Vec<Arc<Declaration>>,
}

impl RecoveryWindow {
    pub fn owner(&self) -> &Declaration {
        &self.owner
    }

    pub fn head(&self) -> &Declaration {
        &self.head
    }

    pub fn before(&self) -> &Declaration {
        &self.before
    }

    pub fn end_s(&self) -> i128 {
        self.end_s
    }
}

#[derive(Debug, Clone)]
pub struct Domain {
    current: Arc<Declaration>,
    highest_accepted_seq: u64,
    first: Position,
    reset: Option<Position>,
    window: Option<RecoveryWindow>,
}

impl Domain {
    pub fn current(&self) -> &Declaration {
        &self.current
    }

    pub fn highest_accepted_seq(&self) -> u64 {
        self.highest_accepted_seq
    }

    pub fn first(&self) -> Position {
        self.first
    }

    pub fn reset(&self) -> Option<Position> {
        self.reset
    }

    pub fn window(&self) -> Option<&RecoveryWindow> {
        self.window.as_ref()
    }

    pub fn delta_admission_sources(&self) -> Vec<&Declaration> {
        self.window.as_ref().map_or_else(
            || vec![self.current()],
            |window| vec![window.before(), window.owner()],
        )
    }

    pub fn delta_sealing_source(&self) -> Option<&Declaration> {
        self.window.is_none().then(|| self.current())
    }

    pub fn appeal_declaration(&self) -> &Declaration {
        self.window.as_ref().map_or(&self.current, |w| &w.head)
    }
}

#[derive(Debug, Clone)]
pub struct Installation {
    pub declaration: Arc<Declaration>,
    pub decision: Option<Decision>,
    pub opens_window: bool,
    pub resets_identity: bool,
}

#[derive(Debug, Clone)]
pub struct Settlement {
    pub domain: String,
    pub restored: Arc<Declaration>,
    pub superseded: Vec<Arc<Declaration>>,
}

#[derive(Debug, Clone, Default)]
pub struct Effects {
    pub settlements: Vec<Settlement>,
    pub installations: Vec<Installation>,
}

#[derive(Debug, Clone)]
pub struct Projection {
    domains: BTreeMap<String, Domain>,
    effects: Effects,
    block_number: u64,
    sealed_at_s: i64,
}

impl Projection {
    pub fn domains(&self) -> &BTreeMap<String, Domain> {
        &self.domains
    }

    pub fn effects(&self) -> &Effects {
        &self.effects
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }
}

#[derive(Debug, Clone, Default)]
pub struct Declarations {
    domains: BTreeMap<String, Domain>,
    head: Option<(u64, String)>,
    sealed_at_s: Option<i64>,
}

impl Declarations {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>) -> Result<Self> {
        let mut history = History::open(directory, head)?;
        let mut state = Self::default();
        while let Some(block) = history.next_block()? {
            state.apply(&block)?;
        }
        Ok(state)
    }

    pub fn domains(&self) -> &BTreeMap<String, Domain> {
        &self.domains
    }

    pub fn head(&self) -> Option<(u64, &str)> {
        self.head
            .as_ref()
            .map(|(height, hash)| (*height, hash.as_str()))
    }

    pub fn apply(&mut self, verified: &VerifiedBlock) -> Result<Effects> {
        let block = verified.block();
        let continues = match &self.head {
            None => block.header.block_number == 0,
            Some((height, hash)) => {
                height.checked_add(1) == Some(block.header.block_number)
                    && *hash == block.header.prev_block_hash
            }
        };
        if !continues {
            return Err(Error::History(
                "Declaration replay requires the next Block of its accepted prefix".into(),
            ));
        }
        let projection = self.project(
            &block.header.sealed_at,
            verified.recovery_window_days,
            &block.entries,
        )?;
        self.domains = projection.domains;
        self.head = Some((block.header.block_number, verified.hash().into()));
        self.sealed_at_s = Some(projection.sealed_at_s);
        Ok(projection.effects)
    }

    pub fn project(
        &self,
        sealed_at: &str,
        recovery_window_days: i64,
        entries: &[Value],
    ) -> Result<Projection> {
        let sealed_at_s = crate::registry::epoch(sealed_at)?;
        if self
            .sealed_at_s
            .is_some_and(|previous| sealed_at_s <= previous)
        {
            return Err(failure(
                "candidate timestamp must follow the accepted prefix",
            ));
        }
        wist_core::parameters::validate_value("recovery_window_days", recovery_window_days)?;
        super::validate_entry_order(entries)?;
        let block_number = self.head.as_ref().map_or(Ok(0), |(height, _)| {
            height
                .checked_add(1)
                .ok_or_else(|| failure("Block height overflow"))
        })?;
        let mut staged = self.domains.clone();
        let mut effects = Effects::default();
        for (domain, state) in &mut staged {
            if state
                .window
                .as_ref()
                .is_some_and(|window| i128::from(sealed_at_s) >= window.end_s)
            {
                let window = state.window.take().unwrap();
                state.current = window.head.clone();
                effects.settlements.push(Settlement {
                    domain: domain.clone(),
                    restored: window.head,
                    superseded: window.competitors,
                });
            }
        }
        let mut groups = BTreeMap::<(String, u64), Vec<(usize, &Value)>>::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry["type"] != "publisher_declaration" {
                continue;
            }
            let envelope = validate_fields(&entry["body"]).map_err(rejection)?;
            if envelope.publisher.wist_version != crate::WIST_VERSION {
                return Err(Error::History("unsupported Declaration version".into()));
            }
            groups
                .entry((envelope.publisher.domain, envelope.publisher.seq))
                .or_default()
                .push((index, &entry["body"]));
        }
        for ((domain, seq), group) in groups {
            let (index, incoming) = group[0];
            if let Some(state) = staged.get(&domain) {
                let mut unchanged = true;
                for (_, envelope) in &group {
                    unchanged &= inner_hash(envelope).map_err(failure)? == state.current.hash;
                }
                if unchanged {
                    continue;
                }
            }
            let canonical = wist_core::jcs::canonicalize(incoming)?;
            for (_, envelope) in &group[1..] {
                if wist_core::jcs::canonicalize(envelope)? != canonical {
                    return Err(failure("WIST1-E08 conflicting Declaration group"));
                }
            }
            let declaration = Arc::new(Declaration {
                envelope: incoming.clone(),
                hash: inner_hash(incoming).map_err(failure)?,
                position: Position {
                    block_number,
                    entry_index: index,
                },
                sealed_at_s,
            });
            let mut installation = Installation {
                declaration: declaration.clone(),
                decision: None,
                opens_window: false,
                resets_identity: false,
            };
            if let Some(state) = staged.get_mut(&domain) {
                if seq <= state.highest_accepted_seq {
                    return Err(failure(
                        "WIST1-E08 Declaration sequence does not exceed accepted floor",
                    ));
                }
                let previous = std::iter::once(&state.current)
                    .chain(state.window.iter().map(|window| &window.head))
                    .find(|head| incoming["publisher"]["prev_declaration"] == head.hash)
                    .ok_or_else(|| failure("WIST1-E08 ineligible Declaration predecessor"))?
                    .clone();
                let decision = evaluate(previous.envelope(), incoming).map_err(rejection)?;
                if let Some(window) = &mut state.window {
                    if previous.hash == window.head.hash
                        && matches!(decision, Decision::Ordinary | Decision::Recovery)
                    {
                        window.head = declaration.clone();
                    } else {
                        window.competitors.push(declaration.clone());
                    }
                } else if decision == Decision::Recovery {
                    state.window = Some(RecoveryWindow {
                        owner: declaration.clone(),
                        head: declaration.clone(),
                        before: previous,
                        end_s: i128::from(sealed_at_s) + i128::from(recovery_window_days) * 86_400,
                        competitors: Vec::new(),
                    });
                    installation.opens_window = true;
                } else if decision == Decision::FreshIdentity {
                    state.reset = Some(declaration.position);
                    installation.resets_identity = true;
                }
                state.current = declaration;
                state.highest_accepted_seq = seq;
                installation.decision = Some(decision);
            } else {
                evaluate_initial(incoming).map_err(rejection)?;
                staged.insert(
                    domain,
                    Domain {
                        current: declaration.clone(),
                        highest_accepted_seq: seq,
                        first: declaration.position,
                        reset: None,
                        window: None,
                    },
                );
            }
            effects.installations.push(installation);
        }
        Ok(Projection {
            domains: staged,
            effects,
            block_number,
            sealed_at_s,
        })
    }
}

fn failure(detail: impl Into<String>) -> Error {
    Error::History(detail.into())
}

fn rejection((code, detail): (&str, String)) -> Error {
    failure(format!("{code} {detail}"))
}
