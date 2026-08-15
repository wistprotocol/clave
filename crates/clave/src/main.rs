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
    Sanction {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        level: i64,
        #[arg(long)]
        severity: i64,
        #[arg(long, value_delimiter = ',')]
        evidence: Vec<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    Rule {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        notice: String,
        #[arg(long)]
        outcome: String,
        #[arg(long)]
        reasoning: String,
    },
    Lift {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        domain: String,
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
    PollAppeals {
        #[arg(long)]
        data: PathBuf,
        #[arg(long = "allow-http")]
        allow_http: bool,
    },
    Mirror {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        add: Option<String>,
        #[arg(long)]
        remove: Option<String>,
    },
}

fn main() -> Result<(), clave::Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            log_id,
            data,
            cadence,
        } => {
            clave::init::run(&log_id, &data)?;
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            db.set_param("block_cadence_seconds", cadence)?;
        }
        Command::Serve {
            data,
            bind,
            allow_http,
        } => {
            let db_path = data.join("clave.sqlite");
            clave::serve::run(data, db_path, bind, allow_http)?;
        }
        Command::Seal { data } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let now_epoch = jiff::Timestamp::now().as_second();
            let report = clave::seal::run(&db, &data, &sk, now_epoch)?;
            println!(
                "sealed block {} with {} entries",
                report.block_number, report.entry_count
            );
            for reason in &report.dropped {
                println!("dropped parameter change: {reason}");
            }
        }
        Command::ParamChange {
            data,
            parameter,
            value,
            effective_at,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let now_epoch = jiff::Timestamp::now().as_second();
            let report = clave::param_change::run(
                &db,
                &sk,
                &parameter,
                value,
                effective_at.as_deref(),
                now_epoch,
            )?;
            println!(
                "queued parameter change {} = {value}, effective {} ({})",
                parameter, report.effective_at, report.update_id
            );
        }
        Command::Sanction {
            data,
            domain,
            level,
            severity,
            evidence,
            reason,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let report = clave::governance::sanction(
                &db,
                &sk,
                &domain,
                level,
                severity,
                &evidence,
                reason.as_deref(),
                jiff::Timestamp::now().as_second(),
            )?;
            match &report.notice_id {
                Some(n) => println!(
                    "queued level-{level} sanction {} with notice {n}",
                    report.update_id
                ),
                None => println!("queued level-{level} sanction {}", report.update_id),
            }
        }
        Command::Rule {
            data,
            domain,
            notice,
            outcome,
            reasoning,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let report = clave::governance::rule(
                &db,
                &sk,
                &domain,
                &notice,
                &outcome,
                &reasoning,
                jiff::Timestamp::now().as_second(),
            )?;
            println!("queued {outcome} ruling {}", report.update_id);
        }
        Command::Lift { data, domain } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let report =
                clave::governance::lift(&db, &sk, &domain, jiff::Timestamp::now().as_second())?;
            println!("queued sanction lift {}", report.update_id);
        }
        Command::Withdraw {
            data,
            domain,
            delta_id,
            legal_basis,
            jurisdiction,
        } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
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
        Command::PollAppeals { data, allow_http } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let client = clave::fetch::Client::new(allow_http);
            let actions =
                clave::appeals::poll(&db, &client, &sk, jiff::Timestamp::now().as_second())?;
            if actions.is_empty() {
                println!("no appeal action needed");
            }
            for a in actions {
                println!("{a}");
            }
        }
        Command::Mirror { data, add, remove } => {
            let now_epoch = jiff::Timestamp::now().as_second();
            let urls = match (add, remove) {
                (Some(url), None) => {
                    let sk = clave::keys::load(&data.join("keys/seed"))?;
                    clave::mirrors::add(&data, &sk, &url, now_epoch)?
                }
                (None, Some(url)) => {
                    let sk = clave::keys::load(&data.join("keys/seed"))?;
                    clave::mirrors::remove(&data, &sk, &url, now_epoch)?
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
