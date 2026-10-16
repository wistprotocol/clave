use super::LIST_ROWS_PER_TRANSACTION;
use super::{adopt_prewritten, mark_prewritten, prewrite_new_lists, Prewritten};
use crate::collection::state::{Admission, ItemKind, ListItem, ListKey, State};
use crate::db::{Db, NewRun, Sealed};
use std::collections::BTreeSet;

const AT: &str = "2026-08-09T12:00:05Z";
const PUBLISHER: &str = "a.example";

struct Store {
    data: tempfile::TempDir,
    db: Db,
}

fn store() -> Store {
    let data = tempfile::tempdir().unwrap();
    crate::init::run("127.0.0.1:0", data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    Store { data, db }
}

fn item_id(n: usize) -> String {
    format!("sha256:{n:064x}")
}

fn key(publisher: &str) -> ListKey {
    (publisher.into(), "default".into(), item_id(usize::MAX))
}

fn list(len: usize) -> Vec<ListItem> {
    (0..len)
        .map(|n| ListItem {
            url: format!("https://{PUBLISHER}/{n}"),
            item_id: item_id(n),
            kind: ItemKind::Page,
            admission: if n % 3 == 0 {
                Admission::Admitted
            } else {
                Admission::Unjudged
            },
            code: None,
            read: Vec::new(),
        })
        .collect()
}

fn scope(publisher: &str) -> BTreeSet<String> {
    BTreeSet::from([publisher.to_owned()])
}

fn loaded(db: &Db, publisher: &str) -> State {
    db.load_state(Sealed::of(&State::default()), &scope(publisher))
        .unwrap()
}

fn rows(store: &Store, publisher: &str) -> i64 {
    rusqlite::Connection::open(store.data.path().join("clave.sqlite"))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM list_items WHERE publisher = ?1",
            [publisher],
            |row| row.get(0),
        )
        .unwrap()
}

fn with_list(publisher: &str, len: usize) -> State {
    let mut state = State::default();
    state.lists.insert(key(publisher), list(len));
    state
}

fn start_pull(db: &Db, domain: &str) {
    db.start_pull_run(&NewRun {
        domain,
        now: AT,
        day: &AT[..10],
        unit: domain,
        work_bytes: 1 << 20,
        work_objects: 64,
        pages_epoch: None,
    })
    .unwrap();
}

fn prewrite(db: &Db, state: &State) -> Prewritten {
    let mut prewritten = Prewritten::new();
    prewrite_new_lists(db, &State::default(), state, &mut prewritten).unwrap();
    prewritten
}

fn commit_catalog(db: &Db, state: &State, prewritten: &Prewritten) {
    let mut stored = State::default();
    let mutation = db.mutation().unwrap();
    adopt_prewritten(&mut stored, state, prewritten);
    crate::db::store_changes(db, &stored, state, &scope(PUBLISHER), AT).unwrap();
    mark_prewritten(db, state, prewritten).unwrap();
    mutation.commit().unwrap();
}

#[test]
fn a_new_list_larger_than_one_batch_is_written_over_several_transactions_and_stores_as_whole() {
    let len = 2 * LIST_ROWS_PER_TRANSACTION + 7;
    let state = with_list(PUBLISHER, len);
    let whole = store();
    whole
        .db
        .store_state(&State::default(), &state, &scope(PUBLISHER), AT)
        .unwrap();

    let batched = store();
    crate::db::interrupt::after(0);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prewrite(&batched.db, &state);
    }));
    assert!(!crate::db::interrupt::disarm());
    assert!(interrupted.is_err(), "the first batch commits on its own");
    assert_eq!(rows(&batched, PUBLISHER), LIST_ROWS_PER_TRANSACTION as i64);

    let prewritten = prewrite(&batched.db, &state);
    assert_eq!(rows(&batched, PUBLISHER), len as i64);
    assert!(loaded(&batched.db, PUBLISHER).lists.is_empty());
    commit_catalog(&batched.db, &state, &prewritten);

    let stored = loaded(&batched.db, PUBLISHER).lists;
    assert_eq!(stored, loaded(&whole.db, PUBLISHER).lists);
    assert_eq!(stored[&key(PUBLISHER)].len(), len);
    assert_eq!(
        batched.db.waiting_versions(&scope(PUBLISHER)).unwrap()[PUBLISHER],
        1
    );
}

#[test]
fn a_catalog_commit_drops_rows_an_earlier_prewrite_left_past_the_list_s_end() {
    let batched = store();
    prewrite(&batched.db, &with_list(PUBLISHER, 5));
    let state = with_list(PUBLISHER, 3);
    let prewritten = prewrite(&batched.db, &state);
    commit_catalog(&batched.db, &state, &prewritten);
    assert_eq!(rows(&batched, PUBLISHER), 3);
    assert_eq!(
        loaded(&batched.db, PUBLISHER).lists[&key(PUBLISHER)],
        list(3)
    );
}

#[test]
fn loading_a_publisher_ignores_list_rows_without_their_marker() {
    let batched = store();
    let state = with_list(PUBLISHER, 4);
    let prewritten = prewrite(&batched.db, &state);
    assert_eq!(rows(&batched, PUBLISHER), 4);
    assert!(loaded(&batched.db, PUBLISHER).lists.is_empty());
    let mutation = batched.db.mutation().unwrap();
    mark_prewritten(&batched.db, &state, &prewritten).unwrap();
    mutation.commit().unwrap();
    assert_eq!(
        loaded(&batched.db, PUBLISHER).lists[&key(PUBLISHER)],
        list(4)
    );
}

fn hold_payload(store: &Store, n: usize) -> std::path::PathBuf {
    let path = crate::db::held_payload_path(store.data.path(), &item_id(n)).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"{}").unwrap();
    path
}

#[test]
fn retention_keeps_the_rows_and_held_payload_files_of_a_pull_in_flight() {
    let store = store();
    start_pull(&store.db, PUBLISHER);
    prewrite(&store.db, &with_list(PUBLISHER, 3));
    let held = hold_payload(&store, 1);

    crate::seal::retain(&store.db, store.data.path(), AT).unwrap();

    assert_eq!(rows(&store, PUBLISHER), 3);
    assert!(held.exists());
}

#[test]
fn retention_deletes_unmarked_rows_of_a_domain_with_no_pull_in_flight() {
    let store = store();
    let other = "b.example";
    let marked = with_list(other, 2);
    let prewritten = prewrite(&store.db, &marked);
    let mutation = store.db.mutation().unwrap();
    mark_prewritten(&store.db, &marked, &prewritten).unwrap();
    mutation.commit().unwrap();
    start_pull(&store.db, other);
    prewrite(&store.db, &with_list(PUBLISHER, 3));
    let held = hold_payload(&store, 2);

    crate::seal::retain(&store.db, store.data.path(), AT).unwrap();

    assert_eq!(rows(&store, PUBLISHER), 0);
    assert!(!held.exists());
    assert_eq!(rows(&store, other), 2);
}
