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
        /// The sealing instant as a whole-second UTC timestamp with a
        /// literal Z, in place of the wall clock; it is floored to the
        /// accepted cadence grid like the wall clock is.
        #[arg(long)]
        at: Option<String>,
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
        Command::Seal { data, at } => {
            let db = clave::db::Db::open(&data.join("clave.sqlite"))?;
            let sk = clave::keys::load(&data.join("keys/seed"))?;
            let now_epoch = match at {
                Some(at) => wist_core::timestamp::log_seconds(&at)?,
                None => jiff::Timestamp::now().as_second(),
            };
            let report = clave::seal::run(&db, &data, &sk, now_epoch)?;
            println!(
                "sealed block {} with {} entries",
                report.block_number, report.entry_count
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
            let mut history = clave::history::History::open(&data, db.last_block()?)?;
            let mut blocks = 0;
            let mut entries = 0;
            let mut rejected = 0;
            while let Some(block) = history.next_block()? {
                blocks += 1;
                entries += block.block().entries.len();
                rejected += block.rejected_parameters().len();
            }
            println!(
                "authenticated {blocks} Blocks containing {entries} Entries; {rejected} parameter candidates ignored; Entry eligibility and derived state are not verified"
            );
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
