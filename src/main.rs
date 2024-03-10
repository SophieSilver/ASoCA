use std::{fs, path::PathBuf, time::Duration};

use asoca::config::{subject_info::SubjectInfo, Config, ConfigData, ConfigKind, DaemonData};
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use color_eyre::eyre::{self, eyre, Context};
use local_ip_address::local_ip;

const MIN_CERTIFICATE_TTL: Duration = Duration::from_secs(60);
const MIN_KEY_LENGTH: u32 = 0x200; // 512
const MAX_KEY_LENGTH: u32 = 0x4000; // 16384
const RENEW_AFTER_MULTIPLIER: f64 = 0.9;

/// Simple and easy to use Certificate Authority.
///
/// Will generate its own private key, a self-signed root certificate,
/// server private key and server certificate.
#[derive(Debug, Clone, Parser)]
#[command(version)]
struct Cli {
    /// How long should the root certificate be valid for.
    #[arg(long, value_name = "TIMESPAN", default_value = "10y", value_parser = utils::parse_timespan)]
    root_cert_ttl: Duration,

    /// How long should the server certificate be valid for.
    #[arg(long, value_name = "TIMESPAN", default_value = "1M", value_parser = utils::parse_timespan)]
    server_cert_ttl: Duration,

    /// Path where to save ASoCA's private signing key.
    ///
    /// Note that the key will only be saved in daemon mode.
    #[arg(requires = "daemon_mode")]
    #[arg(long, value_name = "PATH", default_value = "asoca_priv.pem")]
    asoca_priv_path: PathBuf,

    /// Path where to save the root certificate.
    #[arg(long, value_name = "PATH", default_value = "root_cert.pem")]
    root_cert_path: PathBuf,

    /// Path where to save the server's private key.
    #[arg(long, value_name = "PATH", default_value = "priv.pem")]
    server_priv_path: PathBuf,

    /// Path where to save server's certificate.
    #[arg(long, value_name = "PATH", default_value = "cert.pem")]
    server_cert_path: PathBuf,

    /// Path to the JSON document with additional information to be included in the certificate.
    ///
    /// Currently only subject attributes and alternative names are supported. The local ip will be automatically appended to
    /// the list of alternative names, you can opt out of it with --no-local-ip or -n.
    ///
    /// If not specified, subject's CommonName will be set to "Certificate Holder".
    #[arg(long, value_name = "PATH")]
    subject_info_path: Option<PathBuf>,

    /// Do not append the local ip to the list of alternative names in the server certificate.
    #[arg(long, short, default_value_t = false)]
    no_local_ip: bool,

    /// Private key size in bits.
    #[arg(long, value_name = "INTEGER", default_value_t = 2048)]
    #[arg(value_parser = clap::value_parser!(u32).range(MIN_KEY_LENGTH as i64..=MAX_KEY_LENGTH as i64))]
    key_bits: u32,

    /// Run in daemon mode.
    ///
    /// In daemon mode, ASoCA will automatically renew server certificates
    #[arg(short, long, default_value_t = false)]
    daemon_mode: bool,

    /// After what period of time to renew the server certificate in daemon mode.
    ///
    /// Defaults to 90% of the value passed to --server-cert-ttl.
    #[arg(long, value_name="TIMESPAN", requires = "daemon_mode", value_parser = utils::parse_timespan)]
    renew_server_after: Option<Duration>,

    /// Also renew the root certificate in daemon mode.
    #[arg(short, long, default_value_t = false, requires = "daemon_mode")]
    renew_root: bool,

    /// After what period of time to renew the server certificate in daemon mode.
    ///
    /// Defaults to 90% of the value passed to --root-cert-ttl.
    #[arg(long, value_name="TIMESPAN", requires = "renew_root", value_parser = utils::parse_timespan)]
    renew_root_after: Option<Duration>,

    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

impl Cli {
    fn to_config(&self) -> eyre::Result<ConfigKind> {
        log::debug!("Creating config from CLI: {:?}", self);
        let renew_root_after = self
            .renew_root_after
            .unwrap_or(self.root_cert_ttl.mul_f64(RENEW_AFTER_MULTIPLIER));

        let renew_server_after = self
            .renew_server_after
            .unwrap_or(self.server_cert_ttl.mul_f64(RENEW_AFTER_MULTIPLIER));

        log::trace!("Creating SubjectInfo");
        let mut subject_info = match self.subject_info_path {
            Some(ref path) => {
                log::trace!("subject_info_path is provided, deserializing");
                serde_json::from_slice(&fs::read(path)?)
                    .wrap_err_with(|| eyre!("Could not parse subject info from {:?}", path))?
            }
            None => {
                log::trace!("subject_info_path not provided, initializing from default");
                SubjectInfo::default()
            }
        };
        log::trace!("resulting subject_info: {:?}", subject_info);

        if !self.no_local_ip {
            let ip = local_ip()?;
            log::trace!("Appending local ip [{ip}] to alternative Names");
            subject_info.alternative_names.ip.push(ip);
        }

        let daemon_data = if self.daemon_mode {
            Some(DaemonData {
                asoca_priv_path: self.asoca_priv_path.clone(),
                renew_server_after,
                renew_root_after: if self.renew_root {
                    Some(renew_root_after)
                } else {
                    None
                },
            })
        } else {
            None
        };

        let config_data = ConfigData {
            root_cert_ttl: self.root_cert_ttl,
            server_cert_ttl: self.server_cert_ttl,
            root_cert_path: self.root_cert_path.clone(),
            server_priv_path: self.server_priv_path.clone(),
            server_cert_path: self.server_cert_path.clone(),
            subject_info,
            key_bits: self.key_bits,
            daemon_data,
        };

        Config::new(config_data)
    }
}

fn main() -> eyre::Result<()> {
    if cfg!(debug_assertions) {
        // more informative errors in debug builds
        std::env::set_var("RUST_BACKTRACE", "full");
        color_eyre::install()?;
    } else {
        // less cluttering errors in release builds
        color_eyre::config::HookBuilder::new()
            .display_location_section(false)
            .display_env_section(false)
            .install()?;

        std::panic::set_hook(Box::new(utils::panic_handler));
    }
    
    let cli = Cli::parse();
    env_logger::builder()
        .filter_level(cli.verbosity.log_level_filter())
        .filter_module("neli", log::LevelFilter::Info)
        .init();

    log::info!("Started");

    let config = cli.to_config()?;

    log::debug!("Running asoca with config: {:?}", config);

    asoca::run(config)?;

    Ok(())
}

mod utils {
    use chrono::Utc;
    use color_eyre::{
        eyre::{self, bail, eyre},
        owo_colors::OwoColorize,
    };
    use std::{backtrace::Backtrace, fs, panic::PanicInfo, thread, time::Duration};

    use crate::MIN_CERTIFICATE_TTL;

    pub fn panic_handler(panic_info: &PanicInfo) {
        eprintln!("{}", "ASoCA crashed!".bold().bright_red());

        let current_thread = thread::current();
        let thread_name = current_thread.name().unwrap_or("<unnamed>");
        let backtrace = Backtrace::force_capture();
        let panic_formatting = format!("thread '{}' {}\n{}", thread_name, panic_info, backtrace);

        let formatted_datetime = Utc::now().format("%F_%H-%M-%S-%m_%9f");
        let crash_log_filename = format!("asoca-crash-report_{}.txt", formatted_datetime);

        match fs::write(&crash_log_filename, &panic_formatting) {
            Ok(_) => eprintln!("Crash report saved at {crash_log_filename}"),
            // fallback to outputting the report to stderr, if writing to the file fails
            Err(_) => eprintln!("{}", panic_formatting),
        };
    }

    /// Wrapper for `humantime::parse_duration` with a friendlier error message
    pub fn parse_timespan(value: &str) -> eyre::Result<Duration> {
        humantime::parse_duration(value)
            .map_err(|_| eyre!("{value:?} is not a valid timespan"))
            .and_then(|timespan| {
                if timespan < MIN_CERTIFICATE_TTL {
                    bail!(
                        "timespan too short, must be at least {:}",
                        humantime::format_duration(MIN_CERTIFICATE_TTL)
                    )
                }
                Ok(timespan)
            })
    }
}
