#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "clave", version, about = "WIST aggregator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long = "log-id")]
        log_id: String,
        #[arg(long)]
        data: PathBuf,
        #[arg(long, default_value_t = 3600)]
        cadence: i64,
        /// A Public Suffix List file to pin in Epoch 0, so quota, ingest
        /// budget and Epoch capacity are keyed per Registrable Domain from
        /// the first Epoch on; without one every Canonical Host is its own
        /// unit until `suffix-list` pins a snapshot.
        #[arg(long = "suffix-list")]
        suffix_list: Option<PathBuf>,
    },
    /// Pins a Public Suffix List file as the snapshot in force from the
    /// Epoch after the next one, and serves it at
    /// /log/suffix-lists/<hex>.dat.
    SuffixList {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    Serve {
        #[arg(long)]
        data: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        #[arg(long = "allow-http")]
        allow_http: bool,
    },
    Seal {
        #[arg(long)]
        data: PathBuf,
        /// The sealing instant as a whole-second UTC timestamp with a
        /// literal Z, in place of the wall clock; it is floored to the
        /// accepted cadence grid like the wall clock is.
        #[arg(long)]
        at: Option<String>,
        /// Reach a configured Witness at a loopback address over plain
        /// http, as `serve --allow-http` does for Publishers.
        #[arg(long = "allow-http")]
        allow_http: bool,
    },
    VerifyHistory {
        #[arg(long)]
        data: PathBuf,
    },
    ParamChange {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        parameter: String,
        #[arg(long)]
        value: i64,
        #[arg(long = "effective-at")]
        effective_at: Option<String>,
    },
    Withdraw {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        domain: String,
        #[arg(long = "delta-id")]
        delta_id: String,
        #[arg(long = "legal-basis")]
        legal_basis: String,
        #[arg(long)]
        jurisdiction: String,
    },
    Mirror {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        add: Option<String>,
        #[arg(long)]
        remove: Option<String>,
    },
    /// Rotates the Log's Aggregator keys (WIST-3 §3.4).
    LogKey {
        #[command(subcommand)]
        command: LogKeyCommand,
    },
    /// Maintains the Witnesses each sealed Checkpoint is submitted to
    /// (WIST-3 §5). Without `--add` or `--remove`, lists them.
    Witness {
        #[arg(long)]
        data: PathBuf,
        /// The Witness's `<name>+<key ID>+<key>` verifier-key string.
        #[arg(long, requires = "url")]
        add: Option<String>,
        /// The Witness's base URL, under which `add-checkpoint` is called.
        #[arg(long)]
        url: Option<String>,
        /// The name of a Witness to stop submitting to.
        #[arg(long)]
        remove: Option<String>,
    },
}

#[derive(Subcommand)]
enum LogKeyCommand {
    /// Generates an Aggregator key in the data directory's key store and
    /// queues the `aggregator_key_add` that admits it. The Epoch that
    /// seals the act signs its Checkpoint under the new key as well as the
    /// key that admitted it.
    Add {
        #[arg(long)]
        data: PathBuf,
    },
    /// Queues the `aggregator_key_remove` that retires a key. Removal is
    /// permanent: the same `key_id` is never admitted again.
    Remove {
        #[arg(long)]
        data: PathBuf,
        #[arg(long = "key-id")]
        key_id: String,
    },
    /// Lists every Aggregator key the Log has admitted with its note key
    /// ID, the heights that admitted and retired it and whether the key
    /// store holds its private key.
    List {
        #[arg(long)]
        data: PathBuf,
    },
}

/// WIST-3 §3.4: the held Aggregator key a document this Aggregator signs
/// now is signed with — one valid at the Log's head height, which is also
/// the height a key act queued now authenticates at.
fn head_signer(
    data_dir: &std::path::Path,
    db: &clave::db::Db,
) -> Result<(String, wist_core::crypto::SigningKey), clave::Error> {
    let store = clave::keys::Store::open(data_dir, db)?;
    let key = store.signer_at(clave::keys::head_height(db)?)?;
    let signing = key
        .signing()
        .ok_or_else(|| clave::Error::Key("the signing key is not held".into()))?;
    Ok((key.key_id.clone(), signing))
}

fn main() -> Result<(), clave::Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            log_id,
            data,
            cadence,
            suffix_list,
        } => {
            let verifier_key = clave::init::run(&log_id, &data)?;
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            println!("checkpoint verifier key: {verifier_key}");
            db.set_param("epoch_cadence_seconds", cadence)?;
            match suffix_list {
                Some(file) => {
                    let sk = clave::keys::load(&data.join("keys/seed"))?;
                    let report = clave::suffix_list::pin(
                        &db,
                        &data,
                        &sk,
                        &file,
                        jiff::Timestamp::now().as_second(),
                    )?;
                    println!(
                        "pinned suffix list {} ({} bytes) for Epoch 0",
                        report.identifier, report.bytes
                    );
                }
                None => eprintln!(
                    "no suffix list pinned: every Canonical Host is its own accounting unit until `suffix-list` pins one"
                ),
            }
        }
        Command::SuffixList { data, file } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let (_, sk) = head_signer(&data, &db)?;
            let report = clave::suffix_list::pin(
                &db,
                &data,
                &sk,
                &file,
                jiff::Timestamp::now().as_second(),
            )?;
            println!(
                "queued suffix list {} ({} bytes) as {}",
                report.identifier, report.bytes, report.update_id
            );
        }
        Command::Serve {
            data,
            bind,
            allow_http,
        } => {
            let db_path = data.join("clave.sqlite");
            clave::serve::run(data, db_path, bind, allow_http)?;
        }
        Command::Seal {
            data,
            at,
            allow_http,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let (_, sk) = head_signer(&data, &db)?;
            let now_unix = match at {
                Some(at) => wist_core::timestamp::log_seconds(&at)?,
                None => jiff::Timestamp::now().as_second(),
            };
            let client = clave::fetch::Client::new(allow_http);
            let report = clave::seal::run_with_client(&db, &data, &sk, &client, now_unix)?;
            let head = db
                .last_epoch()?
                .ok_or_else(|| clave::Error::Seal("the sealed Epoch is absent".into()))?;
            println!(
                "sealed epoch {} with {} entries; tree size {} root {}",
                report.epoch_number, report.entry_count, head.tree_size, head.root
            );
            for reason in &report.dropped {
                println!("dropped: {reason}");
            }
            for late in &report.late {
                println!("late inclusion: {late}");
            }
        }
        Command::VerifyHistory { data } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let mut history = clave::history::History::open(&db, &data, db.last_epoch()?)?;
            let mut epochs = 0;
            let mut entries = 0;
            let mut rejected = 0;
            let mut head = None;
            let mut head_height = 0;
            while let Some(epoch) = history.next_epoch()? {
                epochs += 1;
                entries += epoch.entries().len();
                rejected += epoch.rejected_parameters().len();
                head_height = epoch.epoch_number();
                head = Some((epoch.tree_size(), epoch.root().to_string()));
            }
            let (tree_size, root) = head.unwrap_or((0, String::from("sha256:")));
            let valid: Vec<String> = history
                .key_registry()
                .valid_at(head_height)
                .iter()
                .map(|key| key.key_id.clone())
                .collect();
            println!(
                "authenticated {epochs} Checkpoints over a tree of {tree_size} leaves at root {root}, containing {entries} Entries; {rejected} parameter candidates ignored; Entry eligibility and derived state are not verified"
            );
            println!(
                "Aggregator keys valid at height {head_height}: {}",
                valid.join(", ")
            );
        }
        Command::ParamChange {
            data,
            parameter,
            value,
            effective_at,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let (_, sk) = head_signer(&data, &db)?;
            let now_unix = jiff::Timestamp::now().as_second();
            let report = clave::param_change::run(
                &db,
                &sk,
                &parameter,
                value,
                effective_at.as_deref(),
                now_unix,
            )?;
            println!(
                "queued parameter change {} = {value}, effective {} ({})",
                parameter, report.effective_at, report.update_id
            );
        }
        Command::Withdraw {
            data,
            domain,
            delta_id,
            legal_basis,
            jurisdiction,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let (_, sk) = head_signer(&data, &db)?;
            let report = clave::governance::withdraw(
                &db,
                &sk,
                &domain,
                &delta_id,
                &legal_basis,
                &jurisdiction,
                jiff::Timestamp::now().as_second(),
            )?;
            println!("queued payload withdrawal {}", report.update_id);
        }
        Command::LogKey { command } => match command {
            LogKeyCommand::Add { data } => {
                let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
                let report = clave::log_key::add(&db, &data, jiff::Timestamp::now().as_second())?;
                println!(
                    "queued aggregator_key_add {} (note key ID {}) as {}",
                    report.key_id, report.note_key_id, report.update_id
                );
                println!("checkpoint verifier key: {}", report.verifier_key);
            }
            LogKeyCommand::Remove { data, key_id } => {
                let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
                let report = clave::log_key::remove(
                    &db,
                    &data,
                    &key_id,
                    jiff::Timestamp::now().as_second(),
                )?;
                println!(
                    "queued aggregator_key_remove {} as {}",
                    report.key_id, report.update_id
                );
            }
            LogKeyCommand::List { data } => {
                let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
                for key in clave::log_key::list(&db, &data)? {
                    let added = match key.added_height {
                        Some(height) => height.to_string(),
                        None => "unsealed".to_string(),
                    };
                    let removed = match key.removed_height {
                        Some(height) => height.to_string(),
                        None => "-".to_string(),
                    };
                    println!(
                        "{} {} added {} removed {} private key {}",
                        key.key_id,
                        key.note_key_id,
                        added,
                        removed,
                        if key.held { "held" } else { "absent" }
                    );
                }
            }
        },
        Command::Witness {
            data,
            add,
            url,
            remove,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            match (add, remove) {
                (Some(key), None) => {
                    let (name, _) = clave::witness::parse_verifier_key(&key)?;
                    let url = url.expect("--add requires --url");
                    db.add_witness(&name, &key, &url)?;
                    println!("submitting Checkpoints to {name} at {url}");
                }
                (None, Some(name)) => {
                    db.remove_witness(&name)?;
                    println!("no longer submitting Checkpoints to {name}");
                }
                (None, None) => {
                    let witnesses = db.witnesses()?;
                    if witnesses.is_empty() {
                        println!("no witnesses configured");
                    }
                    for witness in witnesses {
                        println!(
                            "{} {} last cosigned tree size {}",
                            witness.name, witness.base_url, witness.last_size
                        );
                    }
                }
                (Some(_), Some(_)) => {
                    return Err(clave::Error::Governance(
                        "pass either --add or --remove, not both".into(),
                    ));
                }
            }
        }
        Command::Mirror { data, add, remove } => {
            let now_unix = jiff::Timestamp::now().as_second();
            let urls = match (add, remove) {
                (Some(url), None) => {
                    let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
                    let (key_id, sk) = head_signer(&data, &db)?;
                    clave::mirrors::add(&data, &key_id, &sk, &url, now_unix)?
                }
                (None, Some(url)) => {
                    let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
                    let (key_id, sk) = head_signer(&data, &db)?;
                    clave::mirrors::remove(&data, &key_id, &sk, &url, now_unix)?
                }
                (None, None) => clave::mirrors::list(&data)?,
                (Some(_), Some(_)) => {
                    return Err(clave::Error::Governance(
                        "pass either --add or --remove, not both".into(),
                    ));
                }
            };
            if urls.is_empty() {
                println!("no mirrors listed");
            }
            for u in urls {
                println!("{u}");
            }
        }
    }
    Ok(())
}
