mod common;

use common::*;
use serde_json::Value;

const SEAL_START: i64 = 1_786_276_800;
const NOW: &str = "2026-08-09T12:00:00Z";

/// The Epochs a fresh identity waits before it takes effect (WIST-1 §5.2).
fn activation_delay() -> u64 {
    u64::try_from(
        wist_core::parameters::spec("declaration_activation_epochs")
            .unwrap()
            .default
            .unwrap(),
    )
    .unwrap()
}

struct Harness {
    p: TestPub,
    host: String,
    client: clave::fetch::Client,
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
    height: u64,
}

impl Harness {
    fn start() -> Self {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        write_feed(&p, &host, &[], NOW);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        db.set_param("epoch_cadence_seconds", 1).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        let mut harness = Harness {
            p,
            host,
            client,
            data,
            db,
            sk,
            height: 0,
        };
        harness.seal();
        harness
    }

    fn ingest(&self, at: &str) -> clave::ingest::IngestReport {
        clave::ingest::run(&self.db, &self.client, self.data.path(), &self.host, at).unwrap()
    }

    fn seal(&mut self) -> u64 {
        let at = SEAL_START + self.height as i64 * 3600;
        let report = clave::seal::run(&self.db, self.data.path(), &self.sk, at).unwrap();
        self.height += 1;
        report.epoch_number
    }

    fn stored_declaration(&self) -> Value {
        serde_json::from_slice(
            &self
                .db
                .get_publisher_declaration(&self.host)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    fn pending_declaration(&self) -> Option<Value> {
        self.db
            .get_pending_identity(&self.host)
            .unwrap()
            .map(|raw| serde_json::from_slice(&raw).unwrap())
    }

    /// The `pending_declaration` tuple of the newest Snapshot, if any.
    fn pending_tuple(&self) -> Option<Value> {
        let read = |path: &std::path::Path| -> Value {
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        };
        let index = read(&self.data.path().join("snapshots/index.json"));
        let manifest_url = index["index"]["snapshots"][0]["manifest_url"]
            .as_str()
            .unwrap()
            .trim_start_matches('/')
            .to_string();
        let manifest_path = self.data.path().join(&manifest_url);
        let manifest = read(&manifest_path);
        let state_path = manifest_path
            .parent()
            .unwrap()
            .join(manifest["manifest"]["state"]["path"].as_str().unwrap());
        read(&state_path)["state"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry[0] == "pending_declaration")
            .cloned()
    }

    /// Serves a replacement Declaration naming `prev`, signed by `seed`, and
    /// keeps the Feed under whichever key the Aggregator still holds.
    fn serve_replacement(&self, seq: u64, prev: &Value, keys: Value, seed: &[u8; 32]) -> Value {
        let mut replacement = current_declaration(&self.p)["publisher"].clone();
        replacement["seq"] = seq.into();
        replacement["prev_declaration"] = declaration_hash(prev).into();
        replacement["keys"] = keys;
        write_declaration(&self.p, &replacement, seed);
        current_declaration(&self.p)
    }
}

#[test]
fn a_fresh_identity_is_pending_and_supplies_no_authority_until_activation() {
    let mut h = Harness::start();
    let original = h.stored_declaration();
    let fresh = h.serve_replacement(
        1,
        &original,
        serde_json::json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]),
        &K2_SEED,
    );
    write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:30:00Z", &K1_SEED);
    h.ingest("2026-08-09T12:30:00Z");

    assert_eq!(h.stored_declaration(), original, "the Declaration in force");
    assert_eq!(h.pending_declaration().unwrap(), fresh);
    let sealed_at = h.seal();
    let tuple = h.pending_tuple().expect("a pending head is Snapshot state");
    assert_eq!(tuple[2], fresh);
    assert_eq!(tuple[3], sealed_at);
    assert_eq!(tuple[4], sealed_at + activation_delay());

    // A Delta under the pending key has no authority; one under the key in
    // force keeps it.
    let rejected = add_delta_signed(
        &h.p,
        &format!("https://{}/pending", h.host),
        "pending",
        None,
        "2026-08-09T12:40:00Z",
        &K2_SEED,
    );
    let accepted = add_delta_signed(
        &h.p,
        &format!("https://{}/current", h.host),
        "current",
        None,
        "2026-08-09T12:40:00Z",
        &K1_SEED,
    );
    write_feed_signed(
        &h.p,
        &h.host,
        &[rejected.clone(), accepted.clone()],
        "2026-08-09T12:45:00Z",
        &K1_SEED,
    );
    let report = h.ingest("2026-08-09T12:45:00Z");
    assert_eq!(report.accepted, vec![accepted]);
    assert_eq!(report.rejected, vec![(rejected, "WIST1-E02".to_string())]);
}

#[test]
fn a_pending_identity_activates_at_its_frozen_height() {
    let mut h = Harness::start();
    let original = h.stored_declaration();
    let fresh = h.serve_replacement(
        1,
        &original,
        serde_json::json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]),
        &K2_SEED,
    );
    write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:30:00Z", &K1_SEED);
    h.ingest("2026-08-09T12:30:00Z");
    let sealed_at = h.seal();
    let activation_height = sealed_at + activation_delay();

    while h.height <= activation_height {
        assert_eq!(h.stored_declaration(), original, "before activation");
        h.seal();
    }

    assert_eq!(h.stored_declaration(), fresh, "at the activation height");
    assert!(h.pending_declaration().is_none());
    assert!(h.pending_tuple().is_none());

    let accepted = add_delta_signed(
        &h.p,
        &format!("https://{}/activated", h.host),
        "activated",
        None,
        "2026-08-09T12:40:00Z",
        &K2_SEED,
    );
    write_feed_signed(
        &h.p,
        &h.host,
        std::slice::from_ref(&accepted),
        "2026-08-10T13:00:00Z",
        &K2_SEED,
    );
    assert_eq!(h.ingest("2026-08-10T13:00:00Z").accepted, vec![accepted]);
}

#[test]
fn a_replacement_of_the_declaration_in_force_reverses_a_pending_identity() {
    for recovery_signed in [false, true] {
        let mut h = Harness::start();
        if recovery_signed {
            let recovery = h.serve_replacement(
                1,
                &h.stored_declaration(),
                serde_json::json!([key_entry(&K1_SEED, "2026-08-09T00:00:00Z")]),
                &K1_SEED,
            );
            let mut with_recovery = recovery["publisher"].clone();
            with_recovery["recovery_keys"] =
                serde_json::json!([key_entry(&R1_SEED, "2026-08-09T00:00:00Z")]);
            write_declaration(&h.p, &with_recovery, &K1_SEED);
            write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:10:00Z", &K1_SEED);
            h.ingest("2026-08-09T12:10:00Z");
        }
        let in_force = h.stored_declaration();
        let floor = if recovery_signed { 1 } else { 0 };
        let fresh = h.serve_replacement(
            floor + 1,
            &in_force,
            serde_json::json!([key_entry(&X1_SEED, "2026-08-09T00:00:00Z")]),
            &X1_SEED,
        );
        write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:30:00Z", &K1_SEED);
        h.ingest("2026-08-09T12:30:00Z");
        assert_eq!(h.pending_declaration().unwrap(), fresh, "{recovery_signed}");

        // The owner still holds a listed key and answers with a Declaration
        // naming the one in force; the pending head is discarded.
        let signer = if recovery_signed { &R1_SEED } else { &K1_SEED };
        let reversal = h.serve_replacement(
            floor + 2,
            &in_force,
            serde_json::json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]),
            signer,
        );
        write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:50:00Z", &K1_SEED);
        h.ingest("2026-08-09T12:50:00Z");
        assert_eq!(h.stored_declaration(), reversal, "{recovery_signed}");
        assert!(h.pending_declaration().is_none(), "{recovery_signed}");

        h.seal();
        assert!(h.pending_tuple().is_none(), "{recovery_signed}");
    }
}

#[test]
fn a_second_fresh_identity_names_the_pending_head_or_is_rejected() {
    let h = Harness::start();
    let original = h.stored_declaration();
    let fresh = h.serve_replacement(
        1,
        &original,
        serde_json::json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]),
        &K2_SEED,
    );
    write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:30:00Z", &K1_SEED);
    h.ingest("2026-08-09T12:30:00Z");

    // Naming the Declaration in force beside a pending head is WIST1-E08.
    h.serve_replacement(
        2,
        &original,
        serde_json::json!([key_entry(&X1_SEED, "2026-08-09T00:00:00Z")]),
        &X1_SEED,
    );
    write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:40:00Z", &K1_SEED);
    h.ingest("2026-08-09T12:40:00Z");
    assert_eq!(h.pending_declaration().unwrap(), fresh);
    assert!(h
        .db
        .list_rejections(&h.host)
        .unwrap()
        .iter()
        .any(|rejection| rejection.code == "WIST1-E08"));

    // Naming the pending head advances it without moving the Declaration in
    // force.
    let follower = h.serve_replacement(
        3,
        &fresh,
        serde_json::json!([key_entry(&X1_SEED, "2026-08-09T00:00:00Z")]),
        &K2_SEED,
    );
    write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:50:00Z", &K1_SEED);
    h.ingest("2026-08-09T12:50:00Z");
    assert_eq!(h.pending_declaration().unwrap(), follower);
    assert_eq!(h.stored_declaration(), original);
}

#[test]
fn a_pending_or_reversed_declaration_supplies_no_page_authority() {
    let mut h = Harness::start();
    let original = h.stored_declaration();
    // A party holding the web host publishes a fresh identity and cuts a
    // Page under its key.
    h.serve_replacement(
        1,
        &original,
        serde_json::json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]),
        &K2_SEED,
    );
    write_feed_signed(&h.p, &h.host, &[], "2026-08-09T12:30:00Z", &K1_SEED);
    h.ingest("2026-08-09T12:30:00Z");
    h.seal();

    let paged = add_delta_signed(
        &h.p,
        &format!("https://{}/paged", h.host),
        "paged",
        None,
        "2026-08-09T12:40:00Z",
        &K2_SEED,
    );
    write_feed_page_signed(
        &h.p,
        &h.host,
        0,
        std::slice::from_ref(&paged),
        "2026-08-09T12:35:00Z",
        None,
        &K2_SEED,
    );
    let live = add_delta_signed(
        &h.p,
        &format!("https://{}/live", h.host),
        "live",
        None,
        "2026-08-09T12:40:00Z",
        &K1_SEED,
    );
    write_feed_with_next(
        &h.p,
        &h.host,
        std::slice::from_ref(&live),
        "2026-08-09T12:45:00Z",
        Some(&page_url(&h.host, 0)),
    );
    let report = h.ingest("2026-08-09T12:45:00Z");
    assert_eq!(
        report.noise,
        Some("WIST2-E04"),
        "a Page signed under a pending key must not authenticate: {report:?}"
    );
    assert!(!report.accepted.contains(&paged));
}
