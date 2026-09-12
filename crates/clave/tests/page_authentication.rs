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
        self.install_document(publisher, "k1", &K1_SEED, now, seal);
    }

    fn install_document(
        &self,
        publisher: Value,
        signer: &str,
        seed: &[u8; 32],
        now: &str,
        seal: bool,
    ) {
        write_declaration(&self.publisher, &publisher, signer, seed);
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
        self.probe_at(cut, seed, accepted, "2026-08-09T18:00:05Z");
    }

    fn probe_at(&mut self, cut: &str, seed: &[u8; 32], accepted: bool, now: &str) {
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
                now,
                Some(&page_url(&self.host, 0)),
            );
            write_feed_page_signed(&self.publisher, &self.host, 0, &[], cut, None, "page", seed);
            let report = self.ingest(now);
            assert_eq!(
                report.noise,
                if accepted { None } else { Some("WIST2-E04") },
                "cut {cut}, seed {seed:?}, reopened {reopen}"
            );
            assert_eq!(
                report
                    .accepted
                    .into_iter()
                    .chain(report.queued)
                    .collect::<Vec<_>>(),
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

#[test]
fn page_authority_waits_for_actual_declaration_inclusion() {
    for first_contact in [false, true] {
        let mut fixture = Fixture::new();
        if !first_contact {
            fixture.install(0, page_key(&K2_SEED), "2026-08-09T12:00:00Z", true);
        }
        fixture.install(
            u64::from(!first_contact),
            page_key(&R1_SEED),
            "2026-08-09T13:00:00Z",
            false,
        );
        fixture.probe("2026-08-09T12:30:00Z", &R1_SEED, false);
        let signing = clave::keys::load(&fixture.directory.path().join("keys/seed")).unwrap();
        clave::seal::run(
            &fixture.db,
            fixture.directory.path(),
            &signing,
            "2026-08-09T19:00:00Z"
                .parse::<jiff::Timestamp>()
                .unwrap()
                .as_second(),
        )
        .unwrap();
        fixture.probe_at(
            "2026-08-09T12:30:00Z",
            &R1_SEED,
            true,
            "2026-08-09T20:00:00Z",
        );
    }
}

#[test]
fn page_sources_ignore_unauthenticated_declaration_rows() {
    let mut fixture = Fixture::new();
    fixture.install(0, page_key(&K2_SEED), "2026-08-09T12:00:00Z", true);
    let mut forged = current_declaration(&fixture.publisher);
    forged["publisher"]["keys"][1] = page_key(&R1_SEED);
    let connection =
        rusqlite::Connection::open(fixture.directory.path().join("clave.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE sealed_declarations SET declaration_json = ?1",
            [serde_json::to_vec(&forged).unwrap()],
        )
        .unwrap();
    fixture.probe("2026-08-09T12:30:00Z", &R1_SEED, false);
    fixture.probe("2026-08-09T12:30:00Z", &K2_SEED, true);
    connection
        .execute("DELETE FROM sealed_declarations", [])
        .unwrap();
    fixture.probe("2026-08-09T12:30:00Z", &K2_SEED, true);
}

#[test]
fn repeated_declaration_entries_bound_the_first_next_page_source() {
    let mut fixture = Fixture::new();
    fixture.install(0, page_key(&K2_SEED), "2026-08-09T12:00:00Z", true);
    fixture
        .db
        .insert_pending_entry(
            "publisher_declaration",
            &fixture.host,
            &current_declaration(&fixture.publisher),
            0,
        )
        .unwrap();
    let signing = clave::keys::load(&fixture.directory.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &fixture.db,
        fixture.directory.path(),
        &signing,
        "2026-08-09T13:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    let bytes = zstd::bulk::decompress(
        &std::fs::read(
            fixture
                .directory
                .path()
                .join("log/blocks/000000001.json.zst"),
        )
        .unwrap(),
        1_048_576,
    )
    .unwrap();
    let block: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        block["entries"][0]["body"],
        current_declaration(&fixture.publisher)
    );
    fixture.install(1, page_key(&R1_SEED), "2026-08-09T14:00:00Z", true);
    fixture.probe("2026-08-09T12:30:00Z", &R1_SEED, false);
    fixture.probe("2026-08-09T13:00:00Z", &R1_SEED, true);
    fixture.probe("2026-08-09T12:30:00Z", &K2_SEED, true);
}

#[test]
fn completed_recovery_excludes_page_sources_at_current_and_first_next_cutoffs() {
    let mut fixture = Fixture::new();
    let mut initial = current_declaration(&fixture.publisher)["publisher"].clone();
    initial["keys"]
        .as_array_mut()
        .unwrap()
        .push(page_key(&K2_SEED));
    initial["recovery_keys"] = json!([key_entry("r1", &R1_SEED, "2026-08-09T00:00:00Z")]);
    fixture.install_document(initial, "k1", &K1_SEED, "2026-08-09T12:00:00Z", true);
    let mut owner = current_declaration(&fixture.publisher)["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&current_declaration(&fixture.publisher)).into();
    owner["keys"][1] = page_key(&X1_SEED);
    fixture.install_document(owner, "r1", &R1_SEED, "2026-08-09T13:00:00Z", true);
    let owner = current_declaration(&fixture.publisher);
    let mut competitor = owner["publisher"].clone();
    competitor["seq"] = 2.into();
    competitor["prev_declaration"] = declaration_hash(&owner).into();
    competitor["keys"][1] = page_key(&[13; 32]);
    fixture.install_document(competitor, "page", &[13; 32], "2026-08-09T14:00:00Z", true);
    let mut follower = owner["publisher"].clone();
    follower["seq"] = 3.into();
    follower["prev_declaration"] = declaration_hash(&owner).into();
    follower["keys"][1] = page_key(&[17; 32]);
    fixture.install_document(follower, "k1", &K1_SEED, "2026-08-09T15:00:00Z", true);
    for now in ["2026-08-09T18:00:00Z", "2026-08-16T13:00:00Z"] {
        for cut in ["2026-08-09T13:30:00Z", "2026-08-09T14:00:00Z"] {
            fixture.probe_at(cut, &[13; 32], true, now);
        }
    }
    let signing = clave::keys::load(&fixture.directory.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &fixture.db,
        fixture.directory.path(),
        &signing,
        "2026-08-16T13:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    for cut in ["2026-08-09T13:30:00Z", "2026-08-09T14:00:00Z"] {
        fixture.probe_at(cut, &[13; 32], false, "2026-08-16T18:00:00Z");
        fixture.probe_at(cut, &X1_SEED, true, "2026-08-16T18:00:00Z");
        fixture.probe_at(cut, &[17; 32], true, "2026-08-16T18:00:00Z");
    }
}
