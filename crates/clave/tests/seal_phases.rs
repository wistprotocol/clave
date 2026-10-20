use std::process::Command;

const PHASES: [&str; 11] = [
    "catch_up",
    "planning",
    "lock_wait",
    "merge",
    "entries",
    "replay",
    "state",
    "commit",
    "publication",
    "retention",
    "witness",
];

fn seal_stdout(data: &std::path::Path, at: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_clave"))
        .args([
            "seal",
            "--data",
            data.to_str().unwrap(),
            "--at",
            at,
            "--no-snapshot",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn line<'a>(stdout: &'a str, prefix: &str) -> &'a str {
    let lines: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    lines[0]
}

#[test]
fn clave_seal_prints_its_write_lock_wait_and_its_eleven_phases_in_order_with_integer_fields() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("phases-log.test", data.path()).unwrap();
    let now = jiff::Timestamp::now().as_second();
    for hours in [2, 4] {
        let at = clave::registry::instant(now + hours * 3600).unwrap();
        let stdout = seal_stdout(data.path(), &at);
        let lines: Vec<&str> = stdout.lines().collect();
        let held = lines
            .iter()
            .position(|line| line.starts_with("write lock held "))
            .unwrap();
        assert!(lines[held + 1].starts_with("write lock waited "));
        let waited = line(&stdout, "write lock waited ");
        waited.strip_suffix(" ms").unwrap().parse::<u64>().unwrap();

        let phases = line(&stdout, "seal phases ");
        let parsed: serde_json::Value = serde_json::from_str(phases).unwrap();
        let object = parsed.as_object().unwrap();
        assert_eq!(object.len(), PHASES.len());
        let mut at = 0;
        for name in PHASES {
            let found = phases[at..].find(&format!("\"{name}\":")).unwrap();
            at += found + 1;
            let phase = object[name].as_object().unwrap();
            let mut fields: Vec<&str> = phase.keys().map(String::as_str).collect();
            fields.sort_unstable();
            assert_eq!(fields, ["hwm_kb", "ms", "rss_kb", "sqlite_ms"]);
            assert!(phase.values().all(serde_json::Value::is_u64), "{phases}");
        }
        assert!(object["commit"]["hwm_kb"].as_u64().unwrap() > 0 || !cfg!(target_os = "linux"));
    }
}
