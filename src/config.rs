use color_eyre::eyre::{self, ensure};
use itertools::Itertools;
use std::{
    fmt::Debug,
    ops::Deref,
    path::{Path, PathBuf},
    time::Duration,
};

use self::subject_info::SubjectInfo;
pub mod subject_info;

/// Raw, unvalidated configuration data
#[derive(Debug, Clone)]
pub struct ConfigData {
    pub root_cert_ttl: Duration,
    pub server_cert_ttl: Duration,
    pub root_cert_path: PathBuf,
    pub server_priv_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub subject_info: SubjectInfo,
    pub key_bits: u32,
    pub daemon_data: Option<DaemonData>,
}

/// Additional configuration data needed for daemon mode
#[derive(Debug, Clone)]
pub struct DaemonData {
    pub asoca_priv_path: PathBuf,
    pub renew_server_after: Duration,
    pub renew_root_after: Option<Duration>,
}

// sealed trait, doing it like that so that the trait cannot be implemented outside this module
mod private {
    use std::fmt::Debug;
    pub trait Sealed: Debug + Clone {}
}

use private::Sealed;

pub trait Mode: Sealed {}

/// Stores data for the daemon mode
#[derive(Debug, Clone)]
pub struct Daemon {
    data: DaemonData,
}
impl Sealed for Daemon {}
impl Mode for Daemon {}
impl Deref for Daemon {
    type Target = DaemonData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Stores data for the simple mode
#[derive(Debug, Clone, Copy, Default)]
pub struct Simple;
impl Sealed for Simple {}
impl Mode for Simple {}

/// Validated and immutable configuration data
///
/// The generic parameter signifies the mode the app will be running in
#[derive(Debug, Clone)]
pub struct Config<D: Mode> {
    // doing indirection here instead of copying all the fields so that
    // it's easier to ensure read-only access.
    // if we just had fields, we'd have to make them private and write a bunch of getters
    inner: ConfigInner<D>,
}

// hardcoding the mode so that you can use Config::new() instead of Config::<Simple>::new()
impl Config<Simple> {
    /// Creates a new config from `ConfigData`.
    ///
    /// # Returns
    /// An enum that contains the `Config` with one of the possible modes, depending on the config data provided
    ///
    /// # Errors
    /// Returns [`Err`] if the passed in `ConfigData` is invalid
    pub fn new(config_data: ConfigData) -> eyre::Result<ConfigKind> {
        log::debug!("Validating config data: {:?}", config_data);

        ensure!(
            config_data.root_cert_ttl >= config_data.server_cert_ttl,
            "root-cert-ttl is shorter than server-cert-ttl"
        );

        if let Some(daemon_data) = &config_data.daemon_data {
            ensure!(
                daemon_data.renew_server_after <= config_data.server_cert_ttl,
                "renew-server-after is longer than server-cert-ttl"
            );

            if let Some(renew_root_after) = daemon_data.renew_root_after {
                ensure!(
                    renew_root_after <= config_data.root_cert_ttl,
                    "renew-root-after is longer than root-cert-ttl"
                );
            }
        }

        // ensuring paths don't overlap
        // storing paths along with their designations to give more precise errors when they overlap
        let mut paths: Vec<(&Path, &str)> = vec![
            (&config_data.root_cert_path, "root-cert-path"),
            (&config_data.server_cert_path, "server-cert-path"),
            (&config_data.server_priv_path, "server-priv-path"),
        ];

        if let Some(daemon_data) = &config_data.daemon_data {
            paths.push((&daemon_data.asoca_priv_path, "asoca-priv-path"));
        }

        log::trace!("Ensuring paths do not overlap. Paths: {:?}", paths);

        for combination in paths.iter().combinations(2) {
            let a = *combination[0];
            let b = *combination[1];

            ensure!(a.0 != b.0, "{} overlaps with {}", a.1, b.1);
        }

        log::debug!("Config data is valid");
        let mut config_data = config_data;

        Ok(match config_data.daemon_data.take() {
            Some(daemon_data) => ConfigKind::Daemon(Config {
                inner: ConfigInner::new(config_data, Daemon { data: daemon_data }),
            }),
            None => ConfigKind::Simple(Config {
                inner: ConfigInner::new(config_data, Simple),
            }),
        })
    }
}

// I'm too lazy to write a million getters
impl<D: Mode> Deref for Config<D> {
    type Target = ConfigInner<D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A [`Config`] with one of the possible modes
#[derive(Debug, Clone)]
pub enum ConfigKind {
    Simple(Config<Simple>),
    Daemon(Config<Daemon>),
}

// basically the same as ConfigInner but with optional deref coercion to `DaemonData` based on D

/// Config's inner data
#[derive(Debug, Clone)]
pub struct ConfigInner<D: Mode> {
    pub root_cert_ttl: Duration,
    pub server_cert_ttl: Duration,
    pub root_cert_path: PathBuf,
    pub server_priv_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub subject_info: SubjectInfo,
    pub key_bits: u32,
    mode_data: D,
}

impl<D: Mode> ConfigInner<D> {
    fn new(config_data: ConfigData, mode: D) -> Self {
        Self {
            root_cert_ttl: config_data.root_cert_ttl,
            server_cert_ttl: config_data.server_cert_ttl,
            root_cert_path: config_data.root_cert_path,
            server_priv_path: config_data.server_priv_path,
            server_cert_path: config_data.server_cert_path,
            subject_info: config_data.subject_info,
            key_bits: config_data.key_bits,
            mode_data: mode,
        }
    }
}

impl Deref for ConfigInner<Daemon> {
    type Target = DaemonData;

    fn deref(&self) -> &Self::Target {
        &self.mode_data
    }
}
