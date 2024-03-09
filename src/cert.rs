//! Convenience functions to generate private keys and certificates

// TODO: get rid of duplication here

use std::fs;

use color_eyre::eyre::{self, eyre, Context};
use openssl::{
    pkey::{PKey, PKeyRef, Private},
    x509::{X509Ref, X509},
};

use crate::{
    config::{Config, Daemon, Mode},
    utils,
};

#[derive(Debug, Clone)]
pub struct CaCredentials {
    private_key: PKey<Private>,
    root_certificate: X509,
}

impl CaCredentials {
    pub fn generate(config: &Config<impl Mode>) -> eyre::Result<Self> {
        log::debug!("Creating ASoCA's credentials");

        let private_key = utils::generate_key(config.key_bits)
            .wrap_err("Could not generate the private key for ASoCA")?;

        let root_certificate = utils::create_root_certificate(&private_key, config.root_cert_ttl)
            .wrap_err("Could not create the Root Certificate")?;

        log::debug!("ASoCA's credentials created successfully");
        Ok(Self {
            private_key,
            root_certificate,
        })
    }

    /// Try loading the credentials from paths provided in the config
    ///
    /// # Returns:
    /// - `Ok(Some(credentials))` if loaded successfully
    /// - `Ok(None)` if could not find the credentials (e.g. files don't exist, are empty, or don't contain valid credentials)
    /// - `Err(error)` if there was an error while loading the credentials (e.g. no permissions to open the files)
    pub fn try_load(config: &Config<Daemon>) -> eyre::Result<Option<Self>> {
        log::debug!("Loading CA credentials");

        let root_certificate = utils::load_certificate(&config.root_cert_path)?;
        let ca_private_key = utils::load_private_key(&config.asoca_priv_path)?;

        let (Some(cert), Some(key)) = (root_certificate, ca_private_key) else {
            log::debug!("Could not load CA credentials");
            return Ok(None);
        };

        let cert_valid = utils::validate_ca_credentials(&key, &cert).unwrap_or_else(|e| {
            log::warn!(
                "There has been an error validating the root certificate at {:?}: {e}",
                config.root_cert_path
            );
            false
        });

        if !cert_valid {
            log::debug!("Loaded CA credentials are invalid or expired");
            return Ok(None);
        }

        log::debug!("Loaded CA credentials are valid, returning.");
        Ok(Some(Self {
            private_key: key,
            root_certificate: cert,
        }))
    }

    /// Writes the private key and root certificate to specified paths in the config
    pub fn save(&self, config: &Config<Daemon>) -> eyre::Result<()> {
        log::debug!("Saving ASoCA's private key to {:?}", config.asoca_priv_path);

        let inner = || -> eyre::Result<()> {
            fs::write(
                &config.asoca_priv_path,
                self.private_key.private_key_to_pem_pkcs8()?,
            )?;
            Ok(())
        };
        // this allows us to wrap both errors at the same time
        inner().wrap_err_with(|| {
            eyre!(
                "Could not save ASoCA's private key to {:?}",
                config.root_cert_path
            )
        })?;
        log::debug!("CA private key saved successfully");

        self.save_root_certificate(config)?;

        Ok(())
    }

    /// Writes the root certificate to specified paths in the config
    pub fn save_root_certificate(&self, config: &Config<impl Mode>) -> eyre::Result<()> {
        log::debug!("Saving Root Certificate to {:?}", config.root_cert_path);

        let inner = || -> eyre::Result<()> {
            fs::write(&config.root_cert_path, self.root_certificate.to_pem()?)?;
            Ok(())
        };
        // this allows us to wrap both errors at the same time
        inner().wrap_err_with(|| {
            eyre!(
                "Could not save the Root Certificate to {:?}",
                config.root_cert_path
            )
        })?;

        log::debug!("Root Certificate successfully saved to");

        Ok(())
    }

    pub fn private_key(&self) -> &PKeyRef<Private> {
        &self.private_key
    }

    pub fn root_certificate(&self) -> &X509Ref {
        &self.root_certificate
    }
}

#[derive(Debug, Clone)]
pub struct ServerCredentials {
    private_key: PKey<Private>,
    certificate: X509,
}

impl ServerCredentials {
    pub fn generate(
        config: &Config<impl Mode>,
        ca_credentials: &CaCredentials,
    ) -> eyre::Result<Self> {
        log::debug!("Creating server's credentials");
        let private_key = utils::generate_key(config.key_bits)
            .wrap_err("Could not generate the private key for the server")?;

        let certificate = utils::create_server_certificate(
            ca_credentials.root_certificate(),
            ca_credentials.private_key(),
            &private_key,
            &config.subject_info,
            config.server_cert_ttl,
        )
        .wrap_err("Could not create the server certificate")?;
        log::debug!("Server's credentials created successfully");

        Ok(Self {
            private_key,
            certificate,
        })
    }

    /// Try loading the credentials from paths provided in the config
    ///
    /// # Returns:
    /// - `Ok(Some(credentials))` if loaded successfully
    /// - `Ok(None)` if could not find the credentials (e.g. files don't exist, are empty, or don't contain valid credentials)
    /// - `Err(error)` if there was an error while loading the credentials (e.g. no permissions to open the files)
    pub fn try_load(
        config: &Config<impl Mode>,
        ca_credentials: &CaCredentials,
    ) -> eyre::Result<Option<Self>> {
        log::debug!("Loading server credentials");

        let certificate = utils::load_certificate(&config.server_cert_path)?;
        let private_key = utils::load_private_key(&config.server_priv_path)?;

        let (Some(cert), Some(key)) = (certificate, private_key) else {
            log::debug!("Could not load server credentials");
            return Ok(None);
        };

        let cert_valid = utils::validate_credentials(&key, &cert, ca_credentials.private_key())
            .unwrap_or_else(|e| {
                log::warn!(
                    "There has been an error validating the certificate at {:?}: {e}",
                    config.server_cert_path
                );
                false
            });

        if !cert_valid {
            log::debug!("Loaded server credentials are invalid or expired");
            return Ok(None);
        }

        log::debug!("Loaded server credentials are valid, returning.");

        Ok(Some(Self {
            private_key: key,
            certificate: cert,
        }))
    }

    /// Writes the credentials to files specified in the config
    pub fn save(&self, config: &Config<impl Mode>) -> eyre::Result<()> {
        let inner = || -> eyre::Result<()> {
            log::debug!(
                "Saving server's private key to {:?}",
                config.server_priv_path
            );
            fs::write(
                &config.server_priv_path,
                self.private_key.private_key_to_pem_pkcs8()?,
            )?;
            log::debug!("Server's private key saved successfully");

            log::debug!(
                "Saving server's certificate to {:?}",
                config.server_cert_path
            );
            fs::write(&config.server_cert_path, self.certificate.to_pem()?)?;
            log::debug!("Server's certificate saved successfully");

            Ok(())
        };

        // this allows us to wrap both errors at the same time
        inner().wrap_err_with(|| eyre!("Could not save server credentials"))?;

        Ok(())
    }

    pub fn private_key(&self) -> &PKeyRef<Private> {
        &self.private_key
    }

    pub fn certificate(&self) -> &X509Ref {
        &self.certificate
    }
}
