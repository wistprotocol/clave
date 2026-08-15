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
    }
    Ok(())
}
