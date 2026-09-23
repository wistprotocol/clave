use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const INSTANCE: &str = clave::serve::DEFAULT_INSTANCE;

struct Served(Child);

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Served {
    fn hard_kill(mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
        std::mem::forget(self);
    }

    fn terminate(mut self) {
        let pid = rustix::process::Pid::from_raw(self.0.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let status = self.0.wait().unwrap();
        assert!(status.success(), "clave serve exited with {status}");
        std::mem::forget(self);
    }
}

fn serve(data: &Path, instance: &str, seal: bool) -> (Served, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_clave"));
    command.args([
        "serve",
        "--data",
        data.to_str().unwrap(),
        "--bind",
        "127.0.0.1:0",
        "--allow-http",
        "--instance",
        instance,
    ]);
    if !seal {
        command.arg("--no-seal");
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = lines
        .next()
        .expect("clave serve prints the address it bound")
        .unwrap();
    std::thread::spawn(move || lines.for_each(|_| {}));
    let addr = line
        .trim()
        .strip_prefix("listening on http://")
        .unwrap_or_else(|| panic!("clave serve printed {line:?}"))
        .to_string();
    (Served(child), format!("http://{addr}"))
}

fn store(data: &Path) -> clave::db::Db {
    clave::db::Db::connect(&data.join("clave.sqlite")).unwrap()
}

fn ping(base: &str, host: &str) -> u16 {
    reqwest::blocking::Client::new()
        .post(format!("{base}/ingest"))
        .json(&serde_json::json!({ "host": host }))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

fn poll_until(what: &str, timeout: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !ready() {
        assert!(Instant::now() < deadline, "{what} within {timeout:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Its pull ends at WIST-2 §5 step 0's first-contact rejection once
/// claimed. It carries no port, which WIST-2 §4's Canonical Host bars.
fn unreachable_host() -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nth = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("127.0.0.{}", 2 + nth % 250)
}

fn rejected(data: &Path, host: &str) -> bool {
    !store(data).list_rejections(host).unwrap().is_empty()
}

#[test]
fn a_hard_killed_instance_is_reclaimed_by_its_restart_and_pulls_a_waiting_ping_at_once() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", data.path()).unwrap();
    let (first, base) = serve(data.path(), INSTANCE, false);
    let before = unreachable_host();
    assert_eq!(ping(&base, &before), 202);
    poll_until(
        "the running instance pulls its Ping",
        Duration::from_secs(10),
        || rejected(data.path(), &before),
    );
    let held = store(data.path()).partition_leases().unwrap();
    assert!(
        held.iter()
            .all(|(_, lease)| lease.owner.as_deref() == Some(INSTANCE)),
        "the instance holds its partitions under its own name"
    );
    first.hard_kill();
    assert!(
        store(data.path())
            .partition_leases()
            .unwrap()
            .iter()
            .all(|(_, lease)| lease.owner.as_deref() == Some(INSTANCE)),
        "a hard-killed instance releases nothing"
    );

    let (_restarted, base) = serve(data.path(), INSTANCE, false);
    let after = unreachable_host();
    let started = Instant::now();
    assert_eq!(ping(&base, &after), 202);
    poll_until(
        "the restarted instance pulls a waiting Ping",
        Duration::from_secs(2),
        || rejected(data.path(), &after),
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    let reclaimed = store(data.path()).partition_leases().unwrap();
    for ((partition, before), (_, after)) in held.iter().zip(&reclaimed) {
        assert_eq!(
            after.token,
            before.token + 1,
            "partition {partition} fences the killed incarnation's pulls"
        );
        assert_eq!(after.owner.as_deref(), Some(INSTANCE));
    }
}

#[test]
fn a_second_process_under_the_same_instance_name_is_refused_while_the_first_serves() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", data.path()).unwrap();
    let (_first, _base) = serve(data.path(), INSTANCE, false);
    let refused = clave::serve::run_with_options(
        data.path().to_path_buf(),
        data.path().join("clave.sqlite"),
        "127.0.0.1:0".parse().unwrap(),
        clave::fetch::Client::new(true),
        clave::serve::ServeOptions {
            instance: INSTANCE.to_string(),
            seal: false,
            ..clave::serve::ServeOptions::default()
        },
    );
    let Err(clave::Error::Instance(message)) = refused else {
        panic!("a second process took the instance name: {refused:?}");
    };
    assert!(message.contains(INSTANCE), "{message}");
    assert!(
        data.path()
            .join(format!("instance-{INSTANCE}.lock"))
            .exists(),
        "the instance lock names one file inside the data directory"
    );
}

#[test]
fn an_instance_name_outside_one_path_component_is_refused() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", data.path()).unwrap();
    for name in ["", "..", "../elsewhere", "a/b"] {
        let refused = clave::serve::run_with_options(
            data.path().to_path_buf(),
            data.path().join("clave.sqlite"),
            "127.0.0.1:0".parse().unwrap(),
            clave::fetch::Client::new(true),
            clave::serve::ServeOptions {
                instance: name.to_string(),
                seal: false,
                ..clave::serve::ServeOptions::default()
            },
        );
        assert!(
            matches!(refused, Err(clave::Error::Instance(_))),
            "{name:?}: {refused:?}"
        );
    }
}

#[test]
fn a_graceful_shutdown_releases_every_lease_after_its_passes_have_stopped() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", data.path()).unwrap();
    let (served, base) = serve(data.path(), INSTANCE, true);
    let host = unreachable_host();
    assert_eq!(ping(&base, &host), 202);
    poll_until(
        "the instance takes its leases",
        Duration::from_secs(10),
        || {
            let db = store(data.path());
            db.sealer_lease().unwrap().owner.as_deref() == Some(INSTANCE)
                && db
                    .partition_leases()
                    .unwrap()
                    .iter()
                    .all(|(_, lease)| lease.owner.as_deref() == Some(INSTANCE))
        },
    );
    served.terminate();

    let db = store(data.path());
    assert_eq!(db.sealer_lease().unwrap().owner, None);
    let held: Vec<_> = db
        .partition_leases()
        .unwrap()
        .into_iter()
        .filter(|(_, lease)| lease.owner.is_some())
        .collect();
    assert!(held.is_empty(), "{held:?} stayed held after the shutdown");
}
