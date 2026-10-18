use super::*;
use crate::history::declarations::DeclarationsReplay;
use crate::ingest::stage_tests::Log;
use serde_json::json;
use wist_core::crypto::SigningKey;

const HOST: &str = "example.com";
const OTHER: &str = "other.example";
const HOUR: i64 = 3_600;
const START: &str = "2026-08-09T00:00:00Z";

type Sources = Vec<(i64, u64, Vec<PublisherKey>)>;

struct Signer {
    sk: SigningKey,
    key: PublisherKey,
}

fn signer(seed: u8) -> Signer {
    let sk = SigningKey::from_seed(&[seed; 32]);
    let key = PublisherKey::new(
        &sk.public().to_b64u(),
        registry::unix("2026-08-01T00:00:00Z").unwrap() as u64,
        None,
    );
    Signer { sk, key }
}

fn declaration(
    domain: &str,
    seq: u64,
    prev: Option<&Value>,
    keys: &[&Signer],
    recovery: Option<&Signer>,
    by: &Signer,
) -> Value {
    let mut publisher = json!({
        "wist_version": "1.0.0", "domain": domain, "seq": seq,
        "keys": keys.iter().map(|signer| signer.key.clone()).collect::<Vec<_>>(),
    });
    if let Some(prev) = prev {
        publisher["prev_declaration"] = declaration::inner_hash(prev).unwrap().into();
    }
    if let Some(recovery) = recovery {
        publisher["recovery_keys"] = json!([recovery.key]);
    }
    wist_core::envelope::sign_envelope(&publisher, "publisher", &by.key.kid, &by.sk).unwrap()
}

fn entry(envelope: &Value) -> Value {
    json!({"type": "publisher_declaration", "body": envelope})
}

fn repeated_label() -> [Value; 2] {
    let label = json!({"labeler": "a.example"});
    [
        json!({"type": "label", "body": {"label": label, "sig": {}}}),
        json!({"type": "label", "body": {"label": label, "sig": 1}}),
    ]
}

fn keys_of(envelope: &Value) -> Vec<PublisherKey> {
    declaration::publisher_of(envelope).unwrap().keys
}

struct Chain {
    log: Log,
    next: u64,
    sealed_at_s: Vec<i64>,
}

impl Chain {
    fn new() -> Chain {
        Chain {
            log: Log::new(),
            next: 0,
            sealed_at_s: Vec::new(),
        }
    }

    fn seal(&mut self, entries: &[Value]) -> u64 {
        self.seal_after(HOUR, entries)
    }

    fn seal_after(&mut self, seconds: i64, entries: &[Value]) -> u64 {
        let at = match self.sealed_at_s.last() {
            Some(previous) => previous + seconds,
            None => registry::unix(START).unwrap(),
        };
        let dir = self.log.data.path();
        let sk = crate::keys::load(&dir.join("keys/seed")).unwrap();
        let log_id = crate::history::anchor(dir).unwrap().log_id;
        let mut ordered = entries.to_vec();
        wist_core::epoch::sort_entries(&mut ordered).unwrap();
        let octets = wist_core::epoch::epoch_octets(&ordered).unwrap();
        let height = self.next;
        self.log
            .db
            .commit_seal(
                &sk,
                &log_id,
                &[],
                height,
                &registry::instant(at).unwrap(),
                &ordered,
                octets,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        self.next += 1;
        self.sealed_at_s.push(at);
        height
    }

    fn seal_empty_through(&mut self, height: u64) {
        while self.next <= height {
            self.seal(&[]);
        }
    }

    fn head(&self) -> u64 {
        self.next - 1
    }

    fn sources(&self, domain: &str, at: Option<u64>) -> Sources {
        page_declarations(&self.log.db, self.log.data.path(), domain, at).unwrap()
    }

    fn replayed(&self, domain: &str, at: Option<u64>) -> Sources {
        let mut seen = Vec::new();
        for source in replayed_sources(&self.log.db, self.log.data.path(), domain, at) {
            if !seen.contains(&source) {
                seen.push(source);
            }
        }
        seen
    }

    fn recorded(&self) -> Option<u64> {
        self.log.db.sealed_page_sources_recorded().unwrap()
    }

    fn forget_sources(&self) {
        rusqlite::Connection::open(self.log.path())
            .unwrap()
            .execute_batch(
                "DELETE FROM sealed_page_sources; DELETE FROM sealed_page_pending_heads; DELETE FROM sealed_page_exclusions; DELETE FROM sealed_page_sources_recorded;",
            )
            .unwrap();
    }

    fn assert_matches_replay_at_every_height(&self) {
        for domain in [HOST, OTHER] {
            assert!(self.sources(domain, None).is_empty());
            for at in 0..=self.head() {
                assert_eq!(
                    self.sources(domain, Some(at)),
                    self.replayed(domain, Some(at)),
                    "{domain} at {at}"
                );
            }
        }
    }
}

fn replayed_sources(db: &Db, data_dir: &Path, host: &str, at: Option<u64>) -> Sources {
    let head = match at {
        Some(height) => db.epoch_at(height).unwrap(),
        None => None,
    };
    let mut history = crate::history::History::open(db, data_dir, head).unwrap();
    let mut state = crate::history::declarations::Declarations::default();
    let mut sources = Vec::new();
    let mut superseded = std::collections::BTreeSet::new();
    let mut pending = std::collections::BTreeSet::new();
    let mut excluded = std::collections::BTreeSet::new();
    while let Some(epoch) = history.next_epoch().unwrap() {
        if epoch.rejected().is_some() {
            state.seed_head(
                epoch.epoch_number(),
                epoch.root(),
                Some(epoch.sealed_at_s()),
            );
            continue;
        }
        let effects = state.apply(&epoch).unwrap();
        for settlement in &effects.settlements {
            if settlement.domain == host {
                for source in &settlement.superseded {
                    superseded.insert(source.hash().to_string());
                }
            }
        }
        for installation in &effects.installations {
            if installation.declaration.envelope()["publisher"]["domain"] != host {
                continue;
            }
            if installation.pending {
                pending.insert(installation.declaration.hash().to_string());
            }
            if installation.reversed.is_some() {
                excluded.append(&mut pending);
            }
        }
        for activation in effects
            .activations
            .iter()
            .filter(|activation| activation.domain == host)
        {
            pending.remove(activation.activated.hash());
            let publisher = declaration::publisher_of(activation.activated.envelope()).unwrap();
            sources.push((
                activation.activated.hash().to_string(),
                (epoch.sealed_at_s(), publisher.seq, publisher.keys),
            ));
        }
        for entry in epoch.entries().iter().filter(|entry| {
            entry["type"] == "publisher_declaration" && entry["body"]["publisher"]["domain"] == host
        }) {
            let source = &entry["body"];
            let hash = declaration::inner_hash(source).unwrap();
            if pending.contains(&hash) || excluded.contains(&hash) {
                continue;
            }
            let publisher = declaration::publisher_of(source).unwrap();
            sources.push((hash, (epoch.sealed_at_s(), publisher.seq, publisher.keys)));
        }
    }
    sources
        .into_iter()
        .filter_map(|(hash, source)| {
            (!superseded.contains(&hash) && !excluded.contains(&hash)).then_some(source)
        })
        .collect()
}

struct Rotations {
    chain: Chain,
    declarations: Vec<Value>,
    other: Vec<Value>,
}

const PENDING_SEALED: u64 = 2;
const REJECTED: u64 = 3;
const ACTIVATED: u64 = PENDING_SEALED + 24;
const REVERSED: u64 = ACTIVATED + 3;
const RECOVERED: u64 = REVERSED + 1;
const COMPETED: u64 = RECOVERED + 1;
const SETTLED: u64 = COMPETED + 2;

fn rotation_history() -> Rotations {
    let (k, h, f, g, n, r, c, p) = (
        signer(21),
        signer(22),
        signer(23),
        signer(24),
        signer(25),
        signer(26),
        signer(27),
        signer(28),
    );
    let mut chain = Chain::new();
    let d0 = declaration(HOST, 0, None, &[&k], Some(&r), &k);
    let o0 = declaration(OTHER, 0, None, &[&p], None, &p);
    chain.seal(&[entry(&d0), entry(&o0)]);
    let d1 = declaration(HOST, 1, Some(&d0), &[&k, &h], Some(&r), &k);
    chain.seal(&[entry(&d1)]);
    let d2 = declaration(HOST, 2, Some(&d1), &[&f], Some(&r), &f);
    assert_eq!(chain.seal(&[entry(&d2)]), PENDING_SEALED);
    let o1 = declaration(OTHER, 1, Some(&o0), &[&p, &h], None, &p);
    let [first, second] = repeated_label();
    assert_eq!(chain.seal(&[entry(&o1), first, second]), REJECTED);
    chain.seal(&[entry(&o1)]);
    chain.seal_empty_through(ACTIVATED);
    let d3 = declaration(HOST, 3, Some(&d2), &[&g], Some(&r), &g);
    chain.seal(&[entry(&d3)]);
    let d4 = declaration(HOST, 4, Some(&d3), &[&g, &h], Some(&r), &g);
    chain.seal(&[entry(&d4)]);
    let d5 = declaration(HOST, 5, Some(&d2), &[&f, &k], Some(&r), &f);
    assert_eq!(chain.seal(&[entry(&d5)]), REVERSED);
    let d6 = declaration(HOST, 6, Some(&d5), &[&k, &n], Some(&r), &r);
    assert_eq!(chain.seal(&[entry(&d6)]), RECOVERED);
    let d7 = declaration(HOST, 7, Some(&d6), &[&c], Some(&r), &c);
    assert_eq!(chain.seal(&[entry(&d7)]), COMPETED);
    let d8 = declaration(HOST, 8, Some(&d6), &[&k, &n, &h], Some(&r), &k);
    chain.seal(&[entry(&d8)]);
    assert_eq!(chain.seal_after(8 * 24 * HOUR, &[]), SETTLED);
    chain.seal(&[]);
    Rotations {
        chain,
        declarations: vec![d0, d1, d2, d3, d4, d5, d6, d7, d8],
        other: vec![o0, o1],
    }
}

fn seqs(sources: &Sources) -> Vec<u64> {
    sources.iter().map(|(_, seq, _)| *seq).collect()
}

#[test]
fn a_pending_head_is_a_source_from_its_activation_epoch_with_that_epoch_s_time() {
    let history = rotation_history();
    let chain = &history.chain;
    for at in [PENDING_SEALED, ACTIVATED - 1] {
        assert_eq!(seqs(&chain.sources(HOST, Some(at))), vec![0, 1], "at {at}");
    }
    let activated = chain.sources(HOST, Some(ACTIVATED));
    assert_eq!(seqs(&activated), vec![0, 1, 2]);
    assert_eq!(
        activated[2],
        (
            chain.sealed_at_s[ACTIVATED as usize],
            2,
            keys_of(&history.declarations[2])
        )
    );
}

#[test]
fn a_reversal_excludes_every_pending_head_it_discards() {
    let history = rotation_history();
    let chain = &history.chain;
    assert_eq!(
        seqs(&chain.sources(HOST, Some(REVERSED - 1))),
        vec![0, 1, 2]
    );
    assert_eq!(seqs(&chain.sources(HOST, Some(REVERSED))), vec![0, 1, 2, 5]);
    for at in 0..=chain.head() {
        let sources = seqs(&chain.sources(HOST, Some(at)));
        assert!(!sources.contains(&3) && !sources.contains(&4), "at {at}");
    }
    let excluded: Vec<(String, i64)> = rusqlite::Connection::open(chain.log.path())
        .unwrap()
        .prepare("SELECT hash, epoch_number FROM sealed_page_exclusions WHERE domain = ?1 ORDER BY epoch_number, hash")
        .unwrap()
        .query_map([HOST], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut reversed: Vec<(String, i64)> = [3, 4]
        .iter()
        .map(|seq| {
            (
                declaration::inner_hash(&history.declarations[*seq]).unwrap(),
                REVERSED as i64,
            )
        })
        .collect();
    reversed.sort();
    reversed.push((
        declaration::inner_hash(&history.declarations[7]).unwrap(),
        SETTLED as i64,
    ));
    assert_eq!(excluded, reversed);
}

#[test]
fn a_settlement_removes_the_superseded_declaration_from_pins_at_or_after_it() {
    let history = rotation_history();
    let chain = &history.chain;
    let before = chain.sources(HOST, Some(SETTLED - 1));
    assert_eq!(seqs(&before), vec![0, 1, 2, 5, 6, 7, 8]);
    assert_eq!(
        before[5],
        (
            chain.sealed_at_s[COMPETED as usize],
            7,
            keys_of(&history.declarations[7])
        )
    );
    for at in [SETTLED, chain.head()] {
        assert_eq!(
            seqs(&chain.sources(HOST, Some(at))),
            vec![0, 1, 2, 5, 6, 8],
            "at {at}"
        );
    }
}

#[test]
fn a_rejected_epoch_contributes_no_source() {
    let history = rotation_history();
    let chain = &history.chain;
    assert_eq!(
        chain.sources(OTHER, Some(REJECTED)),
        vec![(chain.sealed_at_s[0], 0, keys_of(&history.other[0]))]
    );
    assert_eq!(
        chain.sources(OTHER, Some(REJECTED + 1))[1],
        (
            chain.sealed_at_s[REJECTED as usize + 1],
            1,
            keys_of(&history.other[1])
        )
    );
    let rejected: bool = rusqlite::Connection::open(chain.log.path())
        .unwrap()
        .query_row(
            "SELECT judged AND rejected FROM epochs WHERE epoch_number = ?1",
            [REJECTED as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(rejected);
}

#[test]
fn a_pinned_height_reads_the_same_sources_after_later_epochs_are_sealed() {
    let mut chain = Chain::new();
    let (k, f) = (signer(21), signer(23));
    let d0 = declaration(HOST, 0, None, &[&k], None, &k);
    chain.seal(&[entry(&d0)]);
    let d1 = declaration(HOST, 1, Some(&d0), &[&f], None, &f);
    chain.seal(&[entry(&d1)]);
    chain.seal_empty_through(10);
    let pinned = chain.sources(HOST, Some(10));
    assert_eq!(chain.recorded(), Some(10));
    chain.seal_empty_through(30);
    assert_eq!(chain.recorded(), Some(10));
    assert_eq!(chain.sources(HOST, Some(10)), pinned);
    assert_eq!(seqs(&pinned), vec![0]);
    assert_eq!(seqs(&chain.sources(HOST, Some(30))), vec![0, 1]);
    assert_eq!(chain.recorded(), Some(30));
}

#[test]
fn a_store_without_recorded_sources_is_backfilled_by_the_seal_and_by_a_pull() {
    let history = rotation_history();
    let chain = &history.chain;
    let dir = chain.log.data.path();
    chain.forget_sources();
    assert_eq!(chain.recorded(), None);
    let signing = crate::keys::load(&dir.join("keys/seed")).unwrap();
    let report = crate::seal::run(
        &chain.log.db,
        dir,
        &signing,
        chain.sealed_at_s.last().unwrap() + HOUR,
    )
    .unwrap();
    assert_eq!(report.epoch_number, chain.head() + 1);
    assert_eq!(chain.recorded(), Some(report.epoch_number));
    for at in [ACTIVATED, SETTLED, report.epoch_number] {
        assert_eq!(
            chain.sources(HOST, Some(at)),
            chain.replayed(HOST, Some(at)),
            "at {at}"
        );
    }

    chain.forget_sources();
    let pulled = chain.sources(HOST, Some(ACTIVATED));
    assert_eq!(chain.recorded(), Some(report.epoch_number));
    assert_eq!(pulled, chain.replayed(HOST, Some(ACTIVATED)));
}

#[test]
fn recorded_sources_equal_the_replayed_ones_at_every_height() {
    let history = rotation_history();
    history.chain.assert_matches_replay_at_every_height();
    history.chain.forget_sources();
    crate::history::record_sealed_page_sources(
        &history.chain.log.db,
        history.chain.log.data.path(),
    )
    .unwrap();
    assert_eq!(history.chain.recorded(), Some(history.chain.head()));
    history.chain.assert_matches_replay_at_every_height();
}

fn feed_page(by: &Signer, generated_at: &str) -> Value {
    wist_core::envelope::sign_envelope(
        &json!({
            "wist_version": "1.0.0", "domain": HOST,
            "generated_at": generated_at, "deltas": [], "next": null
        }),
        "feed",
        &by.key.kid,
        &by.sk,
    )
    .unwrap()
}

#[test]
fn a_sealed_page_verifies_under_the_key_set_in_force_on_either_side_of_an_activation() {
    let mut chain = Chain::new();
    let (k, f) = (signer(21), signer(23));
    let d0 = declaration(HOST, 0, None, &[&k], None, &k);
    chain.seal(&[entry(&d0)]);
    let d1 = declaration(HOST, 1, Some(&d0), &[&f], None, &f);
    chain.seal(&[entry(&d1)]);
    let activation = 1 + 24;
    chain.seal_empty_through(activation);
    let instant = |height: u64, offset: i64| {
        registry::instant(chain.sealed_at_s[height as usize] + offset).unwrap()
    };
    let between = instant(1, HOUR / 2);
    let after = instant(activation, HOUR / 2);
    let before_activation = chain.sources(HOST, Some(activation - 1));
    let activated = chain.sources(HOST, Some(activation));
    let verifies = |sources: &Sources, by: &Signer, at: &str| {
        verify::sealed_page(sources, &feed_page(by, at), at)
    };
    assert!(verifies(&activated, &k, &between));
    assert!(verifies(&activated, &f, &between));
    assert!(!verifies(&activated, &k, &after));
    assert!(verifies(&activated, &f, &after));
    assert!(verifies(&before_activation, &k, &between));
    assert!(!verifies(&before_activation, &f, &between));
    assert!(verifies(&before_activation, &k, &after));
    assert!(!verifies(&before_activation, &f, &after));
}
