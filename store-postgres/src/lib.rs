// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PostgreSQL primitive persistence over the host connector, with a separate historical reader.
#![forbid(unsafe_code)]

mod credentials;
pub(crate) mod legacy;
mod pgwire;
mod settings;
pub(crate) mod v4;

use pgwire::Client;

/// Render a driver error with its CAUSE: `Display` for a server-side failure is just "db error".
fn render_pg_error(e: &pgwire::Error) -> String {
    let rendered = match e.as_db_error() {
        Some(db) => {
            let mut out = format!("{}: {}", db.code().code(), db.message());
            if let Some(constraint) = db.constraint() {
                out.push_str(&format!(" (constraint {constraint})"));
            }
            out
        }
        None => e.to_string(),
    };
    let mut safe = String::new();
    for ch in rendered.chars().take(4096) {
        if ch.is_control() {
            safe.extend(ch.escape_default());
        } else {
            safe.push(ch);
        }
    }
    if rendered.chars().count() > 4096 {
        safe.push_str(" [truncated]");
    }
    safe
}

/// Parsed connection settings and a bounded pool; no business schema or migration policy.
struct ConnectionSettings {
    shared: std::sync::Arc<Shared>,
}

/// How many connections an instance keeps: at most eight (1.5.5 kept one).
pub(crate) const KEPT_CONNECTIONS: usize = 8;

/// What every op of one instance shares.
pub(crate) struct Shared {
    /// The connection settings.
    pub(crate) config: pgwire::Config,
    /// The instance's kept connections, bounded at [`KEPT_CONNECTIONS`] (there is no pool setting).
    pub(crate) pool: std::sync::Arc<busbar_contract::abi::sdk::store::wire::Pool>,
    /// The endpoint (an index into the DSN's list) that last connected: the next connect tries it
    /// first.
    pub(crate) endpoint: std::sync::atomic::AtomicUsize,
}

/// One op's connection: the store's bodies run on it.
pub(crate) struct Session {
    client: Client,
    shared: std::sync::Arc<Shared>,
}

impl std::ops::Deref for Session {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.shared
    }
}

impl ConnectionSettings {
    /// Capture a borrowed DSN's password before parsing public connection options. Authentication
    /// and peer-error redaction use the sealed SDK credential; the store keeps no plaintext copy.
    #[cfg(test)]
    fn new(conn_str: &str) -> Result<Self, String> {
        let config = pgwire::Config::parse(conn_str).map_err(|e| e.to_string())?;
        Ok(Self::configured(config))
    }

    fn captured(captured: crate::credentials::CredUrl) -> Result<Self, String> {
        let config = pgwire::Config::captured(captured).map_err(|e| e.to_string())?;
        Ok(Self::configured(config))
    }

    fn configured(config: pgwire::Config) -> Self {
        Self {
            shared: std::sync::Arc::new(Shared {
                config,
                pool: busbar_contract::abi::sdk::store::wire::Pool::new(KEPT_CONNECTIONS),
                endpoint: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) fn shared(&self) -> std::sync::Arc<Shared> {
        self.shared.clone()
    }
}

impl Session {
    /// Open one op's connection over `wire`: connect through the host's connector, secure it when
    /// the settings ask, authenticate.
    pub(crate) async fn open(
        wire: busbar_contract::abi::sdk::store::wire::Wire,
        shared: std::sync::Arc<Shared>,
    ) -> Result<Self, String> {
        match Client::connect(wire, &shared.config, &shared.endpoint).await {
            Ok(client) => Ok(Self { client, shared }),
            Err(e) => Err(format!(
                "postgres store: failed to connect: {}",
                shared.config.redact(render_pg_error(&e))
            )),
        }
    }

    /// The op is done: its connection is kept for the next op if the session is idle, else
    /// discarded ([`Client::release`]).
    pub(crate) async fn close(mut self) {
        self.client.release().await;
    }

    fn client(&mut self) -> &mut Client {
        &mut self.client
    }
}

pub use v4::{door, MACRO_DOOR};
pub const NAME: &str = "busbar-store-postgres";

#[cfg(test)]
mod settings_schema_tests;
#[cfg(test)]
mod tests;

mod source_interpretation;

include!(concat!(env!("OUT_DIR"), "/context_test_source.rs"));
