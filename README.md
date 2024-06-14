# ASoCA - Amazing Sophie's Certificate Authority

Simple and easy to use Certificate Authority.

Can be used to create "dummy" certificates for development and testing; or for small projects that might want to take advantage of TLS without having to register a domain name or compromise sercurity with self-signed certificates.

Will generate its own private key, a self-signed root certificate,
server private key and server certificate.

Can be used to create root and server certificates once, or to continuously renew them with "daemon mode".

## Notes
This project is not intended to be a fully featured Certificate Authority, rather, it provides a minimal set of functionality for easily creating X.509 certificates.

## Installation

```sh
cargo install --git https://github.com/SophieSilver/ASoCA
```

## Usage

`asoca [OPTIONS]`

### Options:

-   `--root-cert-ttl <TIMESPAN>`  
    How long should the root certificate be valid for

    [default: `10y`]

-   `--server-cert-ttl <TIMESPAN>`  
     How long should the server certificate be valid for

    [default: `1M`]

-   `--asoca-priv-path <PATH>`  
     Path where to save ASoCA's private signing key.

    Note that the key will only be saved in daemon mode.

    [default: `asoca_priv.pem`]

-   `--root-cert-path <PATH>`  
     Path where to save the root certificate

    [default: `root_cert.pem`]

-   `--server-priv-path <PATH>`  
     Path where to save the server's private key

    [default: `priv.pem`]

-   `--server-cert-path <PATH>`  
     Path where to save server's certificate  
     [default: `cert.pem`]

-   `--subject-info-path <PATH>`  
     Path to the JSON document with additional information to be included in the certificate.

    Currently only subject attributes and alternative names are supported. The local ip will be automatically appended to the list of alternative names, you can opt out of it with --no-local-ip or -n.

    If not specified, subject's CommonName will be set to "Certificate Holder".

    More about the structure of the JSON document can be read in the [Subject Info](#subject-info) section.

-   `-n`, `--no-local-ip`  
     Do not append the local ip to the list of alternative names in the server certificate

-   `--key-bits <INTEGER>`  
     Private key size in bits

    [default: `2048`]

-   `-d`, `--daemon-mode`  
     Run in daemon mode.

    In daemon mode, ASoCA will automatically renew server certificates

-   `--renew-server-after <TIMESPAN>`  
     After what period of time to renew the server certificate in daemon mode.

    Defaults to 90% of the value passed to `--server-cert-ttl`.

-   `-r`, `--renew-root`  
     Also renew the root certificate in daemon mode

-   `--renew-root-after <TIMESPAN>`  
     After what period of time to renew the server certificate in daemon mode.

    Defaults to 90% of the value passed to `--root-cert-ttl`.

-   `-v,` `--verbose`  
     Increase logging verbosity

-   `-q`, `--quiet`  
     Decrease logging verbosity

-   `-h`, `--help`  
     Print help (see a summary with `-h`)

-   `-V`, `--version`  
     Print version

### Subject Info

An example structure of the subject info JSON document:

```jsonc
{
    "subject_attributes": {
        // All subject attributes that x509 certificates support
        // are acceptable here
        "O": "My Organization",
        "CN": "My Server"
    },
    "alternative_names": {
        // both arrays and single values are supported
        "dns": ["example.com", "example.org"],
        "email": "JohnDoe@example.com",
        "uri": "https://example.com",
        // Your local IP will also be implicitly added here
        // You can disable that with `--no-local-ip`
        "ip": "127.0.0.1",
        "rid": "some-registered-id"
    }
}
```

## License

Licensed under either of

-   Apache License, Version 2.0
    ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
-   MIT license
    ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
