mod common;

use common::*;
use serde_json::{json, Value};

struct Fixture {
    host: String,
    publisher: TestPub,
    directory: tempfile::TempDir,
    db: clave::db::Db,
    client: clave::fetch::Client,
    attempts: usize,
}

impl Fixture {
    fn new() -> Self {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher(&host);
        serve_static(listener, publisher.dir.path().into());
        let directory = tempfile::tempdir().unwrap();
        clave::init::run(&host, directory.path()).unwrap();
        let db = clave::db::Db::open(&directory.path().join("clave.sqlite")).unwrap();
        Self {
            host,
            publisher,
            directory,
            db,
            client,
            attempts: 0,
        }
    }

    fn install(&self, seq: u64, page_key: Value, now: &str, seal: bool) {
        let previous = current_declaration(&self.publisher);
        let mut publisher = previous["publisher"].clone();
        publisher["seq"] = seq.into();
        publisher["keys"] = json!([key_entry("k1", &K1_SEED, "2026-08-09T00:00:00Z"), page_key]);
        if seq > 0 {
            publisher["prev_declaration"] = declaration_hash(&previous).into();
        }
        write_declaration(&self.publisher, &publisher, "k1", &K1_SEED);
        write_feed(&self.publisher, &self.host, &[], now);
        let report = self.ingest(now);
        assert!(report.rejected.is_empty());
        assert_ne!(report.noise, Some("WIST2-E04"));
        let stored: Value = serde_json::from_slice(
            &self
                .db
                .get_publisher_declaration(&self.host)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(stored["publisher"], publisher);
        if seal {
            let signing = clave::keys::load(&self.directory.path().join("keys/seed")).unwrap();
            clave::seal::run(
                &self.db,
                self.directory.path(),
                &signing,
                now.parse::<jiff::Timestamp>().unwrap().as_second(),
            )
            .unwrap();
            let restored = clave::history::declarations::Declarations::reconstruct(
                self.directory.path(),
                self.db.last_block().unwrap(),
            )
            .unwrap();
            assert_eq!(restored.domains()[&self.host].current().envelope(), &stored);
        }
    }

    fn ingest(&self, now: &str) -> clave::ingest::IngestReport {
        clave::ingest::run(
            &self.db,
            &self.client,
            self.directory.path(),
            &self.host,
            now,
        )
        .unwrap()
    }

    fn probe(&mut self, cut: &str, seed: &[u8; 32], accepted: bool) {
        for reopen in [false, true] {
            if reopen {
                self.db = clave::db::Db::open(&self.directory.path().join("clave.sqlite")).unwrap();
            }
            self.attempts += 1;
            let live = add_delta(
                &self.publisher,
                &format!("https://{}/{}", self.host, self.attempts),
                "page authentication probe",
                None,
            );
            write_feed_with_next(
                &self.publisher,
                &self.host,
                std::slice::from_ref(&live),
                "2026-08-09T18:00:00Z",
                Some(&page_url(&self.host, 0)),
            );
            write_feed_page_signed(&self.publisher, &self.host, 0, &[], cut, None, "page", seed);
            let report = self.ingest("2026-08-09T18:00:05Z");
            assert_eq!(
                report.noise,
                if accepted { None } else { Some("WIST2-E04") },
                "cut {cut}, seed {seed:?}, reopened {reopen}"
            );
            assert_eq!(
                report.accepted,
                if accepted { vec![live.clone()] } else { vec![] }
            );
            assert_eq!(self.db.is_delta_seen(&live).unwrap(), accepted);
            if !accepted {
                let failures = self.db.list_rejections(&self.host).unwrap();
                assert_eq!(failures.last().unwrap().code, "WIST2-E04");
            }
        }
    }
}

fn page_key(seed: &[u8; 32]) -> Value {
    key_entry("page", seed, "2099-01-01T00:00:00Z")
}

#[test]
fn reused_page_identifiers_preserve_current_and_first_next_authority() {
    let mut fixture = Fixture::new();
    for (seq, seed, at) in [
        (0, &K2_SEED, "2026-08-09T12:00:00Z"),
        (1, &R1_SEED, "2026-08-09T13:00:00Z"),
        (2, &X1_SEED, "2026-08-09T14:00:00Z"),
        (3, &[13; 32], "2026-08-09T15:00:00Z"),
    ] {
        fixture.install(seq, page_key(seed), at, true);
    }
    for cut in ["2026-08-09T13:00:00Z", "2026-08-09T13:30:00Z"] {
        fixture.probe(cut, &K2_SEED, false);
        fixture.probe(cut, &R1_SEED, true);
        fixture.probe(cut, &X1_SEED, true);
        fixture.probe(cut, &[13; 32], false);
        fixture.probe(cut, &[17; 32], false);
    }
    fixture.probe("2026-08-09T11:00:00Z", &K2_SEED, true);
    fixture.probe("2026-08-09T11:00:00Z", &R1_SEED, false);
    fixture.probe("2026-08-09T15:30:00Z", &[13; 32], true);
    fixture.probe("2026-08-09T15:30:00Z", &X1_SEED, false);
}

#[test]
fn a_lower_sequence_in_the_selected_block_cannot_supply_page_keys() {
    let mut fixture = Fixture::new();
    fixture.install(0, page_key(&K2_SEED), "2026-08-09T12:00:00Z", true);
    fixture.install(1, page_key(&R1_SEED), "2026-08-09T12:30:00Z", false);
    fixture.install(2, page_key(&X1_SEED), "2026-08-09T13:00:00Z", true);
    for cut in ["2026-08-09T12:30:00Z", "2026-08-09T13:00:00Z"] {
        fixture.probe(cut, &R1_SEED, false);
        fixture.probe(cut, &X1_SEED, true);
    }
}

#[test]
fn excluded_page_bindings_cannot_borrow_keys_from_other_declarations() {
    let mut fixture = Fixture::new();
    fixture.install(0, page_key(&K2_SEED), "2026-08-09T12:00:00Z", true);
    let mut excluded = page_key(&R1_SEED);
    excluded["public_key"] = wist_core::crypto::b64u_encode(&[0; 32]).into();
    fixture.install(1, excluded, "2026-08-09T13:00:00Z", true);
    fixture.install(2, page_key(&X1_SEED), "2026-08-09T14:00:00Z", true);
    fixture.probe("2026-08-09T13:30:00Z", &K2_SEED, false);
    fixture.probe("2026-08-09T13:30:00Z", &R1_SEED, false);
    fixture.probe("2026-08-09T13:30:00Z", &X1_SEED, true);
}
