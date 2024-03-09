use std::{collections::HashMap, net::IpAddr};

use color_eyre::eyre::{self, eyre, Context};
use openssl::x509::{extension::SubjectAlternativeName, X509Extension, X509Name, X509v3Context};
use serde::{Deserialize, Serialize};
use serde_with::OneOrMany;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubjectAttributes(pub HashMap<String, String>);

impl SubjectAttributes {
    pub fn to_x509_name(&self) -> eyre::Result<X509Name> {
        let mut builder = X509Name::builder()?;

        for (field, value) in &self.0 {
            builder
                .append_entry_by_text(field, value)
                .wrap_err_with(|| eyre!("Error while appending {{\"{field}\": \"{value}\"}} to certificate attributes"))?;
        }

        Ok(builder.build())
    }
}

impl Default for SubjectAttributes {
    fn default() -> Self {
        Self(HashMap::from([(
            "CN".to_owned(),
            "Certificate Holder".to_owned(),
        )]))
    }
}

#[serde_with::apply(Vec => #[serde(default)] #[serde_as(deserialize_as = "OneOrMany<_>")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlternativeNames {
    pub dns: Vec<String>,
    pub email: Vec<String>,
    pub uri: Vec<String>,
    pub ip: Vec<IpAddr>,
    pub rid: Vec<String>,
}

impl AlternativeNames {
    pub fn to_x509_extension(&self, ctx: &X509v3Context<'_>) -> eyre::Result<X509Extension> {
        let mut builder = SubjectAlternativeName::new();

        // code duplication goes brrrr
        self.dns.iter().for_each(|value| {
            builder.dns(value);
        });

        self.email.iter().for_each(|value| {
            builder.email(value);
        });

        self.uri.iter().for_each(|value| {
            builder.uri(value);
        });

        self.ip.iter().for_each(|value| {
            builder.ip(&value.to_string());
        });

        self.rid.iter().for_each(|value| {
            builder.rid(value);
        });

        builder.build(ctx).wrap_err_with(|| {
            eyre!("Could not create x509 extension from subject alternative names")
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectInfo {
    #[serde(default)]
    pub subject_attributes: SubjectAttributes,
    #[serde(default)]
    pub alternative_names: AlternativeNames,
}
