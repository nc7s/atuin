use std::net::SocketAddr;

use atuin_server_postgres::Postgres;
use atuin_server_sqlite::Sqlite;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use clap::Parser;
use eyre::{Context, ContextCompat, Result};

use atuin_server::{example_config, launch, launch_metrics_server, Settings};

#[derive(Parser, Debug)]
#[clap(infer_subcommands = true)]
pub enum Cmd {
    /// Start the server
    Start {
        /// The host address to bind
        #[clap(long)]
        host: Option<String>,

        /// The port to bind
        #[clap(long, short)]
        port: Option<u16>,
    },

    /// Print server example configuration
    DefaultConfig,
}

impl Cmd {
    #[tokio::main]
    pub async fn run(self) -> Result<()> {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();

        tracing::trace!(command = ?self, "server command");

        match self {
            Self::Start { host, port } => {
                let settings = Settings::new().wrap_err("could not load server settings")?;
                let host = host.as_ref().unwrap_or(&settings.host).clone();
                let port = port.unwrap_or(settings.port);
                let addr = SocketAddr::new(host.parse()?, port);

                let db_type = settings
                    .db_uri
                    .split("://")
                    .next()
                    .wrap_err("invalid db_uri setting")?;

                if settings.metrics.enable {
                    tokio::spawn(launch_metrics_server(
                        settings.metrics.host.clone(),
                        settings.metrics.port,
                    ));
                }

                match db_type {
                    "postgres" => launch::<Postgres>(settings, addr).await,
                    "sqlite" => launch::<Sqlite>(settings, addr).await,
                    t => eyre::bail!("unknown db type: {t}"),
                }
            }
            Self::DefaultConfig => {
                println!("{}", example_config());
                Ok(())
            }
        }
    }
}
