use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    thread,
    time::Duration,
};

use chrono::{DateTime, Utc};
use color_eyre::eyre::{self, eyre, Context};
use once_cell::sync::Lazy;
use openssl::{
    asn1::{Asn1Integer, Asn1Time, Asn1TimeRef},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{HasPublic, PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{X509Name, X509NameRef, X509Ref, X509},
};
use uuid::Uuid;

use crate::config::subject_info::SubjectInfo;

pub static ASOCA_NAME: Lazy<X509Name> = Lazy::new(|| {
    let mut name_builder = X509Name::builder().expect("Could not create ASOCA name");
    name_builder
        .append_entry_by_text("CN", "ASoCA")
        .expect("Could not create ASOCA name");

    name_builder.build()
});

pub static ASN1_UNIX_EPOCH: Lazy<Asn1Time> =
    Lazy::new(|| Asn1Time::from_unix(0).expect("Could not construct Asn1Time from unix epoch"));

/// Common functionality used by `load_certificate` and `load_private_key`,
///
/// Returns Ok(None) if the file isn't found
fn load_from_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    const SIZE_LIMIT: u64 = 1024 * 1024; // 1 MiB
    const DEFAULT_INITIAL_BUF_CAPACITY: usize = 1024;

    log::trace!("loading data from {path:?}");

    // potential optimization: use a static/thread local buf;

    log::trace!("opening {path:?}");
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                log::trace!("File not found, returning `None`");
                return Ok(None);
            } else {
                log::error!("Encountered an error while reading from {:?}: {e}", path);
                return Err(e);
            }
        }
    };

    log::trace!("Getting file metadata of {path:?}");

    let buf_len = file
        .metadata()
        .map(|meta| meta.len() as usize)
        .unwrap_or_else(|_| {
            log::trace!(
                "Could not get metadata of {path:?}, falling back on default buffer length"
            );
            DEFAULT_INITIAL_BUF_CAPACITY
        })
        .min(SIZE_LIMIT as usize);

    let mut buf = Vec::<u8>::with_capacity(buf_len);

    let bytes_read = file.take(SIZE_LIMIT).read_to_end(&mut buf)?;
    log::trace!("Successfully read {bytes_read} bytes from {path:?}");
    if bytes_read == SIZE_LIMIT as usize {
        log::warn!("Provided file {path:?} is unusually large");
    }

    Ok(Some(buf))
}

/// Load a certificate from a file
///
/// Returns:
/// * `Ok(Some(certificate))` if the certificate was loaded successfully.
/// * `Ok(None)` if the file does not exist or does not contain a valid certificate.
/// * `Err(_)` in case of other errors.
pub fn load_certificate(path: impl AsRef<Path>) -> eyre::Result<Option<X509>> {
    log::debug!("Loading certificate from {:?}", path.as_ref());

    let Some(data) = load_from_file(path.as_ref())
        .wrap_err_with(|| eyre!("Could not load certificate from {:?}", path.as_ref()))?
    else {
        return Ok(None);
    };

    log::trace!("Certificate data loaded, parsing");
    let maybe_cert = X509::from_pem(&data)
        .inspect_err(|e| {
            log::warn!(
                "{:?} does not contain a valid certificate: {}",
                path.as_ref(),
                e
            )
        })
        .ok();
    log::debug!("Returning {:?}", maybe_cert);
    Ok(maybe_cert)
}

/// Load a private key from a file
///
/// Returns:
/// * `Ok(Some(key))` if the key was loaded successfully.
/// * `Ok(None)` if the file does not exist or does not contain a valid private key.
/// * `Err(_)` in case of other errors.
pub fn load_private_key(path: impl AsRef<Path>) -> eyre::Result<Option<PKey<Private>>> {
    log::debug!("Loading private key from {:?}", path.as_ref());

    let Some(data) = load_from_file(path.as_ref())
        .wrap_err_with(|| eyre!("Could not load certificate from {:?}", path.as_ref()))?
    else {
        return Ok(None);
    };

    log::trace!("Private key data loaded, parsing");
    let maybe_key = PKey::private_key_from_pem(&data)
        .inspect_err(|e| {
            log::warn!(
                "{:?} does not contain a valid private key: {}",
                path.as_ref(),
                e
            )
        })
        .ok();
    log::debug!("Returning private key");
    Ok(maybe_key)
}

/// Check if the certificate is issued by ASoCA, is not expired, and that the key inside the certificate matches the provided one
pub fn validate_credentials(
    key: &PKeyRef<impl HasPublic>,
    certificate: &X509Ref,
    // I personally don't like how it's possible to accidentally switch key and ca_key
    ca_key: &PKeyRef<impl HasPublic>,
) -> eyre::Result<bool> {
    let issuer_name_correct = || {
        certificate
            .issuer_name()
            .try_cmp(&ASOCA_NAME)
            .map(|ord| ord.is_eq())
    };

    let signature_correct = || certificate.verify(ca_key);

    let pub_key_matches = || {
        certificate
            .public_key()
            .map(|cert_key| cert_key.public_eq(key))
    };

    let not_expired = || -> Result<_, openssl::error::ErrorStack> {
        let now = Asn1Time::from_unix(Utc::now().timestamp())?;

        Ok(certificate
            .not_after()
            .compare(&now)
            .map(|ord| ord.is_ge())?
            && certificate
                .not_before()
                .compare(&now)
                .map(|ord| ord.is_le())?)
    };

    Ok(not_expired()? && issuer_name_correct()? && pub_key_matches()? && signature_correct()?)
}

/// Check if the given root certificate belongs to ASoCA and is signed with the given public key
pub fn validate_ca_credentials(
    key: &PKeyRef<impl HasPublic>,
    certificate: &X509Ref,
) -> eyre::Result<bool> {
    let subject_name_correct = || {
        certificate
            .subject_name()
            .try_cmp(&ASOCA_NAME)
            .map(|ord| ord.is_eq())
    };

    // using closures here to get short circuiting from &&
    Ok(subject_name_correct()? && validate_credentials(key, certificate, key)?)
}

pub fn create_server_certificate<T: HasPublic>(
    root_cert: &X509Ref,
    ca_private_key: &PKeyRef<Private>,
    server_public_key: &PKeyRef<T>,
    subject_info: &SubjectInfo,
    ttl: Duration,
) -> eyre::Result<X509> {
    log::trace!("Creating server certificate");

    let name = subject_info.subject_attributes.to_x509_name()?;

    let issue_time = Utc::now();
    let expiration_time = issue_time + ttl;
    let not_before = Asn1Time::from_unix(issue_time.timestamp())?;
    let not_after = Asn1Time::from_unix(expiration_time.timestamp())?;

    let serial_number = BigNum::from_slice(Uuid::now_v7().as_bytes())?;
    let serial_number = Asn1Integer::from_bn(&serial_number)?;

    let mut builder = X509::builder()?;

    builder.set_version(2)?;
    builder.set_issuer_name(root_cert.subject_name())?;
    builder.set_subject_name(&name)?;
    builder.set_serial_number(&serial_number)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&server_public_key)?;

    let extension_context = builder.x509v3_context(Some(root_cert), None);
    let extension = subject_info
        .alternative_names
        .to_x509_extension(&extension_context)?;
    builder.append_extension2(&extension)?;
    builder.sign(&ca_private_key, MessageDigest::sha256())?;

    let cert = builder.build();

    log::trace!("Created the server certificate: {:?}", cert);
    Ok(cert)
}

pub fn create_root_certificate(
    ca_private_key: &PKeyRef<Private>,
    ttl: Duration,
) -> eyre::Result<X509> {
    log::trace!("Creating root certificate");

    let name: &X509NameRef = &ASOCA_NAME;

    let issue_time = Utc::now();
    let expiration_time = issue_time + ttl;
    let not_before = Asn1Time::from_unix(issue_time.timestamp())?;
    let not_after = Asn1Time::from_unix(expiration_time.timestamp())?;

    let serial_number = BigNum::from_u32(0)?; // 0 for root cert
    let serial_number = Asn1Integer::from_bn(&serial_number)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?; // actually 3
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;
    builder.set_serial_number(&serial_number)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&ca_private_key)?;
    builder.sign(&ca_private_key, MessageDigest::sha256())?;

    let cert = builder.build();
    log::trace!("Created the root certificate: {:?}", cert);

    Ok(cert)
}

pub fn generate_key(bits: u32) -> eyre::Result<PKey<Private>> {
    log::trace!("Generating key with {bits} bits");

    let p = Rsa::generate(bits)?;
    let p = PKey::from_rsa(p)?;
    log::trace!("Key successfully generated");

    Ok(p)
}

pub fn sleep_until(datetime: DateTime<Utc>) {
    let duration = (datetime - Utc::now()).to_std().unwrap_or(Duration::ZERO);

    thread::sleep(duration);
}

/// Gets the time this certificate was issued at as a `chrono::DateTime<Utc>`
pub fn get_issued_datetime(certificate: &X509Ref) -> eyre::Result<DateTime<Utc>> {
    let issued_time = certificate.not_before();
    ans1_time_to_datetime(issued_time)
}

pub fn ans1_time_to_datetime(asn1_time: &Asn1TimeRef) -> eyre::Result<DateTime<Utc>> {
    // this will subtract ASN1_UNIX_EPOCH from asn1_time
    let diff = &ASN1_UNIX_EPOCH
        .diff(asn1_time)
        .wrap_err_with(|| eyre!("Could not construct a DateTime from Asn1Time {asn1_time}"))?;

    let days = chrono::Duration::try_days(diff.days as _)
        .expect("Asn1Time should not produce overflows when converting to chrono types");

    let secs = chrono::Duration::try_seconds(diff.secs as _)
        .expect("Asn1Time should not produce overflows when converting to chrono types");

    let diff = days + secs;

    Ok(DateTime::UNIX_EPOCH + diff)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_asn1_time_to_datetime() {
        let now = Utc::now();

        let now_timestamp = now.timestamp();

        let now_asn1 =
            Asn1Time::from_unix(now_timestamp).expect("Constructing Asn1Time should succeed");

        let converted =
            ans1_time_to_datetime(&now_asn1).expect("Converting back to DateTime should succeed");

        assert_eq!(
            now_timestamp,
            converted.timestamp(),
            "Timestamps must roundtrip"
        );
    }
}
