// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PostgreSQL owns DSN interpretation, permitted authentication methods and SCRAM framing.
//! Password preprocessing occurs only during initial ingestion, before capture into SDK custody.

use busbar_contract::abi::sdk::cred::{redact_encoded_echoes, Cred};
use zeroize::Zeroizing;

mod capture;
mod decode;
mod policy;
mod saslprep;
mod wire;
pub(crate) use policy::{PgAuth, RequireAuth};
pub(crate) use wire::pg_scram_nonce;

type Bytes = Zeroizing<Vec<u8>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PasswordAt {
    Userinfo,
    Query(&'static str),
    Keyword,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Password {
    original: Cred,
    prepared: Cred,
    contains_nul: bool,
    floor: RequireAuth,
}

impl Password {
    fn capture(bytes: Bytes, secure: bool) -> Self {
        let contains_nul = bytes.contains(&0);
        let prepared = saslprep::password(&bytes)
            .map(|text| Zeroizing::new(text.as_bytes().to_vec()))
            .unwrap_or_else(|| bytes.clone());
        Self {
            original: Cred::captured(bytes).require_secure_if(secure),
            prepared: Cred::captured(prepared).require_secure_if(secure),
            contains_nul,
            floor: RequireAuth::DEFAULT,
        }
    }

    pub(crate) fn floor(&self) -> RequireAuth {
        self.floor
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.original.len()
    }

    #[cfg(test)]
    pub(crate) fn secure_required(&self) -> bool {
        self.original.secure_required()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredUrl {
    public: String,
    password: Option<Password>,
    echoes: Vec<Cred>,
    floor: RequireAuth,
}

impl CredUrl {
    pub(crate) fn parse_postgres(text: &str) -> Result<Self, &'static str> {
        capture::postgres(text)
    }
    pub(crate) fn public(&self) -> &str {
        &self.public
    }
    pub(crate) fn parsed(&self) -> Result<&str, &'static str> {
        Ok(self.public())
    }
    pub(crate) fn password(&self) -> Option<&Password> {
        self.password.as_ref()
    }
    pub(crate) fn floor(&self) -> RequireAuth {
        self.floor
    }
    pub(crate) fn redact_echo(&self, text: &str) -> String {
        let credentials: Vec<_> = self
            .password
            .iter()
            .map(|password| &password.original)
            .chain(self.echoes.iter())
            .collect();
        redact_encoded_echoes(text, &credentials)
    }
}

fn captured(public: String, found: Option<(Bytes, PasswordAt)>, echoes: Vec<Cred>) -> CredUrl {
    let secure = secure_requested(&public);
    CredUrl {
        public,
        password: found.map(|(bytes, _)| Password::capture(bytes, secure)),
        echoes,
        floor: RequireAuth::DEFAULT,
    }
}

fn secure_requested(public: &str) -> bool {
    let mut secure = false;
    let mut socket = false;
    let mut parameter = |key: &str, value: &[u8]| {
        if key == "host" && value.starts_with(b"/") {
            socket = true;
        }
        if key == "sslmode" {
            secure |= matches!(value, b"require" | b"verify-ca" | b"verify-full");
        }
    };
    if let Some((_, rest)) = public.split_once("://") {
        let (head, query) = rest.split_once('?').unwrap_or((rest, ""));
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key = decode::decode(key);
                let value = decode::decode(value);
                if let Ok(key) = core::str::from_utf8(&key) {
                    parameter(key, &value);
                }
            }
        }
        let authority = head.split('/').next().unwrap_or_default();
        let host = authority.rsplit('@').next().unwrap_or_default();
        socket |= decode::decode(host).starts_with(b"/");
    } else {
        let _ = capture::visit_postgres_keyword(public, |key, value, _| {
            parameter(key, &value);
            Ok(())
        });
    }
    secure && !socket
}

pub(crate) struct PostgresUrl(pub(crate) CredUrl);
impl<'de> serde::Deserialize<'de> for PostgresUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Capture;
        impl serde::de::Visitor<'_> for Capture {
            type Value = PostgresUrl;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<PostgresUrl, E> {
                CredUrl::parse_postgres(value.trim())
                    .map(PostgresUrl)
                    .map_err(|_| E::custom("invalid credential DSN"))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<PostgresUrl, E> {
                self.visit_str(&Zeroizing::new(value))
            }
        }
        deserializer.deserialize_string(Capture)
    }
}

#[cfg(test)]
mod capture_tests;
