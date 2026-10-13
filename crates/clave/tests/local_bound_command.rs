use std::path::Path;
use std::process::{Command, Output};

fn clave(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_clave"))
        .args(args)
        .output()
        .unwrap()
}

fn bound(data: &Path, args: &[&str]) -> Output {
    let mut all = vec!["bound", "--data", data.to_str().unwrap()];
    all.extend_from_slice(args);
    clave(&all)
}

fn initialized() -> tempfile::TempDir {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("bound-log.test", data.path()).unwrap();
    data
}

fn local(data: &Path, name: &str) -> Option<i64> {
    let db = clave::db::Db::open(&data.join("clave.sqlite")).unwrap();
    clave::registry::local_bound(&db, name).unwrap()
}

#[test]
fn bound_sets_a_local_bound_and_clear_removes_it() {
    let data = initialized();
    let set = bound(
        data.path(),
        &["--parameter", "epoch_cap_bytes", "--value", "1048576"],
    );
    assert!(set.status.success(), "{set:?}");
    assert_eq!(
        String::from_utf8(set.stdout).unwrap().trim(),
        "local bound epoch_cap_bytes = 1048576; the Log's value applies where it is smaller"
    );
    assert_eq!(local(data.path(), "epoch_cap_bytes"), Some(1_048_576));

    let cleared = bound(data.path(), &["--parameter", "epoch_cap_bytes", "--clear"]);
    assert!(cleared.status.success(), "{cleared:?}");
    assert_eq!(local(data.path(), "epoch_cap_bytes"), None);
}

#[test]
fn bound_refuses_a_parameter_without_a_local_bound() {
    let data = initialized();
    for name in [
        "quota_base",
        "ingest_budget_bytes_day",
        "feed_window",
        "no_such_param",
    ] {
        let refused = bound(data.path(), &["--parameter", name, "--value", "2000000"]);
        assert!(!refused.status.success(), "{name}");
        let refused = bound(data.path(), &["--parameter", name, "--clear"]);
        assert!(!refused.status.success(), "{name}");
    }
}

#[test]
fn bound_refuses_a_value_below_the_registry_floor() {
    let data = initialized();
    for (name, floor) in [
        ("epoch_cap_bytes", 65_537),
        ("domain_epoch_entries_max", 1),
        ("labeler_epoch_entries_max", 1),
        ("max_inclusion_epochs", 1),
    ] {
        let below = (floor - 1).to_string();
        let refused = bound(data.path(), &["--parameter", name, "--value", &below]);
        assert!(!refused.status.success(), "{name}");
        assert_eq!(local(data.path(), name), None, "{name}");
        let at = floor.to_string();
        let accepted = bound(data.path(), &["--parameter", name, "--value", &at]);
        assert!(accepted.status.success(), "{name}: {accepted:?}");
        assert_eq!(local(data.path(), name), Some(floor), "{name}");
    }
}

#[test]
fn bound_takes_exactly_one_of_value_and_clear() {
    let data = initialized();
    let both = bound(
        data.path(),
        &[
            "--parameter",
            "max_inclusion_epochs",
            "--value",
            "2",
            "--clear",
        ],
    );
    assert!(!both.status.success());
    let neither = bound(data.path(), &["--parameter", "max_inclusion_epochs"]);
    assert!(!neither.status.success());
    assert_eq!(local(data.path(), "max_inclusion_epochs"), None);
}
