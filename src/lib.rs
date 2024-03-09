use config::{Config, ConfigKind, Simple};

use color_eyre::eyre;

use crate::cert::{CaCredentials, ServerCredentials};

pub mod cert;
pub mod config;
mod daemon;
mod utils;

pub fn run(config: ConfigKind) -> eyre::Result<()> {
    match config {
        ConfigKind::Simple(config) => run_simple_mode(config)?,
        ConfigKind::Daemon(config) => daemon::run_daemon_mode(config)?,
    };

    Ok(())
}

fn run_simple_mode(config: Config<Simple>) -> eyre::Result<()> {
    log::info!("Running in simple mode");
    log::info!("Generating credentials");
    let ca_credentials = CaCredentials::generate(&config)?;

    let server_credentials = ServerCredentials::generate(&config, &ca_credentials)?;

    ca_credentials.save_root_certificate(&config)?;
    server_credentials.save(&config)?;
    log::info!("Credentials generated successfully");

    log::info!("Exiting");
    Ok(())
}
