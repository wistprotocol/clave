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
    }
    Ok(())
}
