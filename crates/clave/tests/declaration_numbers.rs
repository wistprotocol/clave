mod common;

use clave::history::declarations::DeclarationsReplay;
use common::*;
use serde_json::{json, Value};
use wist_core::{envelope, jcs};

struct Rig {
    host: String,
    publisher: TestPub,
    data: tempfile::TempDir,
    db: clave::db::Db,
    client: clave::fetch::Client,
    key: wist_core::crypto::SigningKey,
}

impl Rig {
    fn new() -> Self {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher_with_recovery(&host);
        serve_static(listener, publisher.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.com", data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Self {
            host,
            publisher,
            data,
            db,
            client,
            key,
        }
    }

    fn reopen(&mut self) {
        self.db = clave::db::Db::open(&self.data.path().join("clave.sqlite")).unwrap();
    }

    fn admit(&self, body: &Value, seed: &[u8; 32], at: &str) -> Value {
        write_declaration(&self.publisher, body, seed);
        let declaration = current_declaration(&self.publisher);
        clave::ingest::run(&self.db, &self.client, self.data.path(), &self.host, at).unwrap();
        assert_eq!(
            self.db
                .get_publisher_declaration(&self.host)
                .unwrap()
                .unwrap(),
            serde_json::to_vec(&declaration).unwrap()
        );
        assert_eq!(
            self.db
                .highest_accepted_declaration_seq(&self.host)
                .unwrap(),
            Some(clave::declaration::publisher_of(&declaration).unwrap().seq)
        );
        declaration
    }

    fn seal(&self, at: &str) -> u64 {
        clave::seal::run(
            &self.db,
            self.data.path(),
            &self.key,
            at.parse::<jiff::Timestamp>().unwrap().as_second(),
        )
        .unwrap()
        .epoch_number
    }

    fn assert_sealed(&self, declaration: &Value, height: u64, at: &str) {
        let seq = clave::declaration::publisher_of(declaration).unwrap().seq;
        let rows = self.db.sealed_declarations(&self.host).unwrap();
        let row = rows
            .iter()
            .find(|row| row.seq == seq)
            .expect("sealed Declaration metadata");
        assert_eq!(row.epoch_number, height);
        assert_eq!(
            row.declaration_json,
            serde_json::to_vec(declaration).unwrap()
        );
        let history = clave::history::declarations::Declarations::reconstruct(
            &self.db,
            self.data.path(),
            self.db.last_epoch().unwrap(),
        )
        .unwrap();
        assert_eq!(
            jcs::canonicalize(history.domains()[&self.host].current().envelope()).unwrap(),
            jcs::canonicalize(declaration).unwrap()
        );
        clave::snapshot::produce(&self.data.path().join("clave.sqlite"), self.data.path()).unwrap();
        let raw =
            std::fs::read(common::served_snapshot(self.data.path(), &at[..10]).join("state.json"))
                .unwrap();
        let state: Value = serde_json::from_slice(&raw).unwrap();
        envelope::verify_envelope(&state, "state", &self.key.public()).unwrap();
        let state: wist_core::objects::SnapshotState =
            serde_json::from_value(state["state"].clone()).unwrap();
        let entry = state
            .entries
            .iter()
            .find_map(|entry| match entry {
                wist_core::objects::StateEntry::Declaration(entry) if entry.domain == self.host => {
                    Some(entry)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(entry.sealing_height, height);
        assert_eq!(
            jcs::canonicalize(&entry.declaration).unwrap(),
            jcs::canonicalize(declaration).unwrap()
        );
    }
}

#[test]
fn integral_declaration_sequences_preserve_admission_metadata_and_snapshot_heights() {
    for spellings in [
        ["-0", "1.0", "2e0"],
        ["0e0", "1", "2.0"],
        ["0.0", "1e0", "2"],
    ] {
        let mut rig = Rig::new();
        assert_eq!(rig.seal("2026-08-09T11:00:00Z"), 0);
        let mut body = current_declaration(&rig.publisher)["publisher"].clone();
        for (index, spelling) in spellings.into_iter().enumerate() {
            body["seq"] = serde_json::from_str(spelling).unwrap();
            let at = format!("2026-08-09T{:02}:00:00Z", 12 + index);
            let declaration = rig.admit(&body, &K1_SEED, &at);
            let raw = serde_json::to_vec(&declaration).unwrap();
            rig.reopen();
            assert_eq!(
                rig.db.discovered_declarations(&rig.host).unwrap()[0],
                declaration
            );
            let height = rig.seal(&at);
            assert_eq!(height, index as u64 + 1);
            rig.reopen();
            assert_eq!(
                rig.db
                    .get_publisher_declaration(&rig.host)
                    .unwrap()
                    .unwrap(),
                raw
            );
            rig.assert_sealed(&declaration, height, &at);
            body["prev_declaration"] = declaration_hash(&declaration).into();
        }
        let at = "2026-08-09T15:00:00Z";
        let current = current_declaration(&rig.publisher);
        let mut equivalent = current["publisher"].clone();
        equivalent["seq"] = json!(2);
        let retained = rig
            .db
            .get_publisher_declaration(&rig.host)
            .unwrap()
            .unwrap();
        write_declaration(&rig.publisher, &equivalent, &K1_SEED);
        write_label_feed(&rig.publisher, &rig.host, &[], at);
        clave::ingest::run(&rig.db, &rig.client, rig.data.path(), &rig.host, at).unwrap();
        assert_eq!(
            rig.db
                .get_publisher_declaration(&rig.host)
                .unwrap()
                .unwrap(),
            retained
        );
        assert_eq!(rig.db.count_discovered_declarations(&rig.host).unwrap(), 0);
    }
}

#[test]
fn integral_pending_recovery_sequences_settle_in_order_and_preserve_the_floor() {
    for (sealing_settlement, spellings) in
        [(false, ["2", "3.0", "4e0"]), (true, ["2e0", "3", "4.0"])]
    {
        let mut rig = Rig::new();
        let initial_body = current_declaration(&rig.publisher)["publisher"].clone();
        let initial = rig.admit(&initial_body, &K1_SEED, "2026-08-09T12:00:00Z");
        rig.seal("2026-08-09T12:00:00Z");
        let mut owner = initial_body;
        owner["seq"] = json!(1.0);
        owner["prev_declaration"] = declaration_hash(&initial).into();
        owner["keys"] = json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
        let owner_envelope = rig.admit(&owner, &R1_SEED, "2026-08-09T13:00:00Z");
        rig.seal("2026-08-09T13:00:00Z");
        let mut follower = owner.clone();
        follower["seq"] = serde_json::from_str(spellings[0]).unwrap();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        let first = rig.admit(&follower, &K2_SEED, "2026-08-09T14:00:00Z");
        follower["seq"] = serde_json::from_str(spellings[1]).unwrap();
        follower["prev_declaration"] = declaration_hash(&first).into();
        let retained = rig.admit(&follower, &K2_SEED, "2026-08-09T15:00:00Z");
        let mut competitor = follower.clone();
        competitor["seq"] = serde_json::from_str(spellings[2]).unwrap();
        competitor["prev_declaration"] = declaration_hash(&retained).into();
        competitor["keys"] = json!([key_entry(&X1_SEED, "2026-08-09T13:00:00Z")]);
        rig.admit(&competitor, &X1_SEED, "2026-08-09T16:00:00Z");
        rig.reopen();
        follower["seq"] = json!(5.0);
        follower["prev_declaration"] = declaration_hash(&retained).into();
        let last = rig.admit(&follower, &K2_SEED, "2026-08-09T17:00:00Z");
        competitor["seq"] = json!(6.0);
        competitor["prev_declaration"] = declaration_hash(&last).into();
        rig.admit(&competitor, &X1_SEED, "2026-08-09T18:00:00Z");
        rig.reopen();
        let deadline = "2026-08-16T13:00:00Z";
        if !sealing_settlement {
            clave::ingest::run(&rig.db, &rig.client, rig.data.path(), &rig.host, deadline).unwrap();
            rig.reopen();
            assert_eq!(
                rig.db
                    .get_publisher_declaration(&rig.host)
                    .unwrap()
                    .unwrap(),
                serde_json::to_vec(&last).unwrap()
            );
            assert_eq!(
                rig.db.discovered_declarations(&rig.host).unwrap(),
                vec![first.clone(), retained.clone(), last.clone()]
            );
        }
        let height = rig.seal(deadline);
        rig.reopen();
        rig.assert_sealed(&last, height, deadline);
        assert_eq!(
            rig.db.highest_accepted_declaration_seq(&rig.host).unwrap(),
            Some(6)
        );
        assert!(rig.db.get_recovery_window(&rig.host).unwrap().is_none());
        assert_eq!(rig.db.count_discovered_declarations(&rig.host).unwrap(), 0);
        clave::ingest::run(&rig.db, &rig.client, rig.data.path(), &rig.host, deadline).unwrap();
        let mut rejected = follower.clone();
        rejected["seq"] = json!(6.0);
        rejected["prev_declaration"] = declaration_hash(&last).into();
        let rejected = envelope::sign_envelope(
            &rejected,
            "publisher",
            &kid(&K2_SEED),
            &wist_core::crypto::SigningKey::from_seed(&K2_SEED),
        )
        .unwrap();
        assert_eq!(
            clave::declaration::evaluate_with_heads(
                &last,
                None,
                None,
                6,
                &rejected,
                &Default::default()
            )
            .unwrap_err()
            .0,
            "WIST1-E08"
        );
        follower["seq"] = json!(7.0);
        follower["prev_declaration"] = declaration_hash(&last).into();
        let next = rig.admit(&follower, &K2_SEED, "2026-08-16T14:00:00Z");
        rig.reopen();
        let height = rig.seal("2026-08-16T14:00:00Z");
        rig.assert_sealed(&next, height, "2026-08-16T14:00:00Z");
    }
}
