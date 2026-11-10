// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH FLOOR (coordinator rulings S4 and S5): which auth methods weaker than the best a

/// A Postgres auth method, as libpq's `require_auth` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgAuth {
    /// `password`: AuthenticationCleartextPassword.
    Password,
    /// `md5`: AuthenticationMD5Password.
    Md5,
    /// `scram-sha-256`: SASL SCRAM-SHA-256.
    ScramSha256,
    /// `gss`: GSSAPI.
    Gss,
    /// `sspi`: SSPI.
    Sspi,
    /// `none`: the server asks for no authentication.
    None,
}

impl PgAuth {
    const ALL: [Self; 6] = [
        Self::Password,
        Self::Md5,
        Self::ScramSha256,
        Self::Gss,
        Self::Sspi,
        Self::None,
    ];

    /// The name `require_auth` uses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Md5 => "md5",
            Self::ScramSha256 => "scram-sha-256",
            Self::Gss => "gss",
            Self::Sspi => "sspi",
            Self::None => "none",
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }
}

/// The Postgres methods a connection string's `require_auth` allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequireAuth(u8);

impl RequireAuth {
    /// No `require_auth` written: busbar 1.6.0 allows SCRAM-SHA-256 and a server that asks for no
    pub const DEFAULT: Self = Self(PgAuth::ScramSha256.bit() | PgAuth::None.bit());

    /// Parse a `require_auth` value as libpq 16 does: a comma-separated list of method names, or a
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        const MIXED: &str = "require_auth mixes negated (`!`) and plain methods";
        let mut negated = None;
        let mut bits = 0_u8;
        for item in value.split(',') {
            let (neg, name) = match item.strip_prefix('!') {
                Some(n) => (true, n),
                None => (false, item),
            };
            if *negated.get_or_insert(neg) != neg {
                return Err(MIXED);
            }
            let m = PgAuth::named(name).ok_or(
                "require_auth names an unknown method (password, md5, scram-sha-256, gss, sspi \
                 or none)",
            )?;
            if bits & m.bit() != 0 {
                return Err("require_auth names a method twice");
            }
            bits |= m.bit();
        }
        let all = PgAuth::ALL.iter().fold(0, |a, m| a | m.bit());
        Ok(Self(if negated == Some(true) {
            all & !bits
        } else {
            bits
        }))
    }

    /// Whether `method` is allowed.
    #[must_use]
    pub const fn allows(self, method: PgAuth) -> bool {
        self.0 & method.bit() != 0
    }
}
