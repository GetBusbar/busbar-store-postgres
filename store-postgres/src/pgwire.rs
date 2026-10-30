// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Postgres frontend protocol over the host's connector: a small async client whose every byte
//! goes through the op's one connection ([`Wire`], the store SDK's `wire`), so this store opens no
//! socket of its own. The codec is `postgres-protocol` (the messages, SCRAM-SHA-256 and md5) and
//! the value encodings are `postgres-types` (the same binary `ToSql`/`FromSql` the `postgres` crate
//! uses).
//!
//! The surface mirrors the `postgres` crate's (`Client`, `Transaction`, `Row`, `Error`) with every
//! call `async`. A statement is prepared under a name the first time its connection runs its text
//! (Parse/Describe/Sync for the parameter and column types) and kept with the connection (the
//! wire's session), so every later run of the same text is ONE round trip (Bind/Execute/Sync),
//! every parameter and column in the binary format. A `Transaction` dropped without `commit` is
//! rolled back before the connection's next statement.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use postgres_protocol::authentication::sasl::{self, ChannelBinding, ScramSha256};
use postgres_protocol::message::backend::{DataRowBody, ErrorResponseBody, Message};
use postgres_protocol::message::frontend;
use postgres_types::{FromSql, Kind, ToSql, Type};

use busbar_contract::abi::sdk::store::wire::Wire;

/// Whether the connection is secured (libpq's `sslmode`). `disable` and `allow` connect in
/// plaintext (no SSLRequest); `prefer` asks the server for TLS and secures the connection when it
/// accepts, without verifying its certificate, else goes on in plaintext; `require`, `verify-ca`
/// and `verify-full` ask for TLS and secure the connection through the host (its trust anchors),
/// refusing a server that declines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// Plaintext.
    Plain,
    /// TLS (unverified) when the server accepts it, else plaintext.
    Prefer,
    /// TLS, or no connection.
    Require,
}

/// Which kind of session a connect accepts (libpq's `target_session_attrs`): the others libpq has
/// (`primary`, `standby`, `prefer-standby`) are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAttrs {
    /// Any server.
    Any,
    /// A server that accepts writes (`transaction_read_only` is off).
    ReadWrite,
    /// A server that does not (`transaction_read_only` is on).
    ReadOnly,
}

/// One server to try: the name it is known by (the TLS check's server name, and what is shown), the
/// address the connector dials (libpq's `hostaddr` when given, else the name) and its port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    name: String,
    dial: String,
    port: u16,
}

/// A parsed connection string (the URL or the libpq keyword form).
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// The servers, in the order a connect tries them (libpq's multi-host list): a connect the
    /// first fails tries each in turn.
    endpoints: Vec<Endpoint>,
    pub user: String,
    pub password: Option<String>,
    pub dbname: Option<String>,
    pub application_name: Option<String>,
    pub options: Option<String>,
    pub ssl: SslMode,
    /// `connect_timeout` in milliseconds (whole seconds in the string, as the driver read it);
    /// `None` = no bound of the store's own.
    connect_timeout_ms: Option<u32>,
    target_session_attrs: SessionAttrs,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let first = self.endpoints.first();
        f.debug_struct("Config")
            .field("host", &first.map(|e| e.name.as_str()))
            .field("port", &first.map(|e| e.port))
            .field("user", &self.user)
            .field("dbname", &self.dbname)
            .finish_non_exhaustive()
    }
}

fn config_err(what: impl Into<String>) -> Error {
    Error::new(Kind_::Config(what.into()))
}

/// How long the host's connector lets a dialled socket sit idle before the OS probes it
/// (`busbar-core-connector`'s `KEEPALIVE_IDLE`, 1.5.5's `tcp_keepalive(60s)`), in seconds.
const KEEPALIVE_IDLE_SECS: i64 = 60;

/// Why a socket-tuning option has no effect.
const INERT_SOCKET: &str = "the host's connector dials every connection with TCP keepalive on, \
                            probing after 60 s idle at the OS's interval and count, and has no \
                            per-store setting for it";

/// Log, at debug (below the default level), that the accepted option `key=value` has no effect,
/// and why. `value` is a validated number or keyword, never a secret.
fn inert(key: &str, value: &str, why: &str) {
    tracing::debug!("postgres connection option {key}={value} has no effect: {why}");
}

/// Server-side bounds the store asks for at startup unless the DSN's `options` set them: a peer
/// stalled while holding a lock (the `store_revision` row, say) must not block the fleet forever.
const DEFAULT_SERVER_SETTINGS: [(&str, &str); 2] = [
    ("lock_timeout", "30s"),
    ("idle_in_transaction_session_timeout", "60s"),
];

impl Config {
    /// The startup `options` value: the DSN's, plus each of [`DEFAULT_SERVER_SETTINGS`] it does not
    /// name.
    fn startup_options(&self) -> Option<String> {
        let mut out = self.options.clone().unwrap_or_default();
        for (name, value) in DEFAULT_SERVER_SETTINGS {
            if !out.contains(name) {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&format!("-c {name}={value}"));
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// Parse a libpq connection string: `postgres[ql]://user:pass@host:port/db?key=value&...` or
    /// `host=... port=... user=... password=... dbname=... sslmode=...`.
    ///
    /// # Errors
    /// A malformed string, an unknown option, an option value the driver would refuse,
    /// `keepalives=0`, a Unix-socket host (this store reaches its server over the host's connector,
    /// which dials TCP) or no user.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(rest) = s
            .strip_prefix("postgresql://")
            .or_else(|| s.strip_prefix("postgres://"))
        {
            let (main, query) = match rest.split_once('?') {
                Some((m, q)) => (m, Some(q)),
                None => (rest, None),
            };
            let (authority, path) = match main.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (main, None),
            };
            let (userinfo, hostport) = match authority.rsplit_once('@') {
                Some((u, h)) => (Some(u), h),
                None => (None, authority),
            };
            if let Some(u) = userinfo {
                match u.split_once(':') {
                    Some((user, pass)) => {
                        pairs.push(("user".into(), decode(user)?));
                        pairs.push(("password".into(), decode(pass)?));
                    }
                    None => pairs.push(("user".into(), decode(u)?)),
                }
            }
            if !hostport.is_empty() {
                // libpq's multi-host list, `host1:port1,host2:port2`, kept as its keyword form's
                // comma lists (`host=a,b port=1,2`) for the option loop below.
                let (mut hosts, mut ports) = (Vec::new(), Vec::new());
                for one in hostport.split(',') {
                    let (host, port) = if let Some(v6) = one.strip_prefix('[') {
                        match v6.split_once(']') {
                            Some((h, rest)) => (h.to_string(), rest.strip_prefix(':')),
                            None => return Err(config_err("unterminated IPv6 host")),
                        }
                    } else {
                        match one.rsplit_once(':') {
                            Some((h, p)) => (h.to_string(), Some(p)),
                            None => (one.to_string(), None),
                        }
                    };
                    hosts.push(decode(&host)?);
                    ports.push(port.unwrap_or("").to_string());
                }
                if hosts.iter().any(|h| !h.is_empty()) {
                    pairs.push(("host".into(), hosts.join(",")));
                }
                if ports.iter().any(|p| !p.is_empty()) {
                    pairs.push(("port".into(), ports.join(",")));
                }
            }
            if let Some(db) = path.filter(|p| !p.is_empty()) {
                pairs.push(("dbname".into(), decode(db)?));
            }
            if let Some(q) = query {
                for kv in q.split('&').filter(|kv| !kv.is_empty()) {
                    // The malformed pair is NOT echoed: a password holding a `?` or `&` splits
                    // here, and its tail would land in the error (and the log).
                    let (k, v) = kv.split_once('=').ok_or_else(|| {
                        config_err("invalid query parameter (expected key=value)")
                    })?;
                    pairs.push((decode(k)?, decode(v)?));
                }
            }
        } else {
            pairs = keywords(s)?;
        }
        // Whether the string carries a password: an unknown option's key is then not named, since
        // a password that split on a space or `=` leaves its tail as a "key" here.
        let has_password =
            crate::dsn_password(s).is_some() || pairs.iter().any(|(k, _)| k == "password");
        let mut c = Config {
            endpoints: Vec::new(),
            user: String::new(),
            password: None,
            dbname: None,
            application_name: None,
            options: None,
            ssl: SslMode::Plain,
            connect_timeout_ms: None,
            target_session_attrs: SessionAttrs::Any,
        };
        let (mut hosts, mut hostaddrs, mut ports) = (None, None, String::new());
        for (k, v) in pairs {
            match k.as_str() {
                "host" => hosts = Some(v),
                "hostaddr" => hostaddrs = Some(v),
                "port" => ports = v,
                "user" => c.user = v,
                "password" => c.password = Some(v),
                "dbname" => c.dbname = Some(v),
                "application_name" => c.application_name = Some(v),
                "options" => c.options = Some(v),
                "sslmode" => {
                    c.ssl = match v.as_str() {
                        // `allow` would try plaintext first and TLS on refusal; this store goes
                        // straight to plaintext, as libpq does against a server that takes it.
                        "disable" | "allow" => SslMode::Plain,
                        "prefer" => SslMode::Prefer,
                        "require" | "verify-ca" | "verify-full" => SslMode::Require,
                        _ => {
                            return Err(config_err("invalid value for option `sslmode`"));
                        }
                    }
                }
                // Whole seconds: more than zero bounds the dial and
                // the handshake of a new connection, zero or less is no bound.
                "connect_timeout" => {
                    let secs: i64 = v.parse().map_err(|_| {
                        config_err(
                            "invalid value for option `connect_timeout` (a whole number of \
                             seconds; 0 or less means no bound)",
                        )
                    })?;
                    c.connect_timeout_ms = (secs > 0)
                        .then(|| u32::try_from(secs.saturating_mul(1000)).unwrap_or(u32::MAX));
                }
                "target_session_attrs" => {
                    c.target_session_attrs = match v.as_str() {
                        "any" => SessionAttrs::Any,
                        "read-write" => SessionAttrs::ReadWrite,
                        "read-only" => SessionAttrs::ReadOnly,
                        _ => {
                            return Err(config_err(
                                "invalid value for option `target_session_attrs` \
                                 (any, read-write or read-only)",
                            ));
                        }
                    }
                }
                // Refused rather than ignored: the store has no TLS client of its own, so no channel
                // binding, and a server that gets no binding could not be the one the operator
                // required.
                "channel_binding" => match v.as_str() {
                    "disable" | "prefer" => {}
                    "require" => {
                        return Err(config_err(
                            "channel_binding=require is not supported: this client has no \
                             SCRAM-SHA-256-PLUS, so it could not authenticate the way that asks \
                             (use prefer or disable)",
                        ));
                    }
                    _ => return Err(config_err("invalid value for option `channel_binding`")),
                },
                // Refused rather than ignored: the connection is verified against busbar's trust
                // anchors through the host, so a root certificate named here would never apply.
                "sslrootcert" => {
                    return Err(config_err(
                        "sslrootcert is not supported: the connection is verified against \
                         busbar's trust anchors, not a per-store root certificate",
                    ));
                }
                // The host's connector owns the sockets: it turns TCP keepalive on for every
                // connection it dials and offers no way to turn it off, so `keepalives=1` (any
                // non-zero, as the driver read it) is what happens and `keepalives=0` is refused.
                "keepalives" => {
                    let on: u64 = v
                        .parse()
                        .map_err(|_| config_err("invalid value for option `keepalives`"))?;
                    if on == 0 {
                        return Err(config_err(
                            "keepalives=0 is not supported: the host's connector keeps TCP \
                             keepalive on for every connection it dials and cannot turn it off \
                             for this store (remove the option, or set keepalives=1)",
                        ));
                    }
                }
                // Accepted as the driver accepted them; the ones the connector cannot apply are
                // logged at debug (once per option, naming why), never refused and never silent.
                "keepalives_idle" | "keepalives_interval" | "tcp_user_timeout" => {
                    let n: i64 = v
                        .parse()
                        .map_err(|_| config_err(format!("invalid value for option `{k}`")))?;
                    // Zero or less is the default (the driver's reading); the connector's own
                    // idle time is KEEPALIVE_IDLE_SECS.
                    let applied = n <= 0 || (k == "keepalives_idle" && n == KEEPALIVE_IDLE_SECS);
                    if !applied {
                        inert(&k, &v, INERT_SOCKET);
                    }
                }
                "keepalives_count" | "keepalives_retries" => {
                    let n: u32 = v
                        .parse()
                        .map_err(|_| config_err(format!("invalid value for option `{k}`")))?;
                    if n != 0 {
                        inert(&k, &v, INERT_SOCKET);
                    }
                }
                // `disable` is what this store does: the endpoints are tried in the order given.
                "load_balance_hosts" => match v.as_str() {
                    "disable" => {}
                    "random" => inert(
                        &k,
                        &v,
                        "the endpoints are tried in the order given, the one that last connected \
                         first; this store does not shuffle them",
                    ),
                    _ => return Err(config_err("invalid value for option `load_balance_hosts`")),
                },
                // `postgres` is what this store does: TLS is asked for with an SSLRequest.
                "sslnegotiation" => match v.as_str() {
                    "postgres" => {}
                    "direct" => inert(
                        &k,
                        &v,
                        "this store asks for TLS with an SSLRequest (sslnegotiation=postgres); \
                         sslmode still decides whether the connection is secured",
                    ),
                    _ => return Err(config_err("invalid value for option `sslnegotiation`")),
                },
                _ if has_password => {
                    return Err(config_err(
                        "unknown option (its name is withheld: the connection string carries a \
                         password)",
                    ));
                }
                _ => return Err(config_err(format!("unknown option `{k}`"))),
            }
        }
        c.endpoints = endpoints(hosts.as_deref(), hostaddrs.as_deref(), &ports)?;
        if c.endpoints.iter().any(|e| e.dial.starts_with('/')) {
            return Err(config_err(
                "a Unix-socket host is not supported: the store reaches its server over TCP",
            ));
        }
        if c.user.is_empty() {
            return Err(config_err("user missing"));
        }
        Ok(c)
    }

    /// Every endpoint, in the order a connect tries them: `(name, dial host:port)`.
    #[cfg(test)]
    #[must_use]
    pub fn targets(&self) -> Vec<(&str, String)> {
        self.endpoints
            .iter()
            .map(|e| (e.name.as_str(), target(&e.dial, e.port)))
            .collect()
    }
}

fn target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// libpq's host, hostaddr and port lists, paired by position: one port for every endpoint, or one
/// per endpoint; a hostaddr is the address to dial (an IP) and its host the name. An endpoint with
/// neither is `localhost`, an empty port 5432. A `host` list and a `hostaddr` list must be as long
/// as each other.
fn endpoints(
    hosts: Option<&str>,
    hostaddrs: Option<&str>,
    ports: &str,
) -> Result<Vec<Endpoint>, Error> {
    let names: Vec<&str> = hosts.map_or_else(Vec::new, |h| h.split(',').collect());
    let addrs: Vec<&str> = hostaddrs.map_or_else(Vec::new, |h| h.split(',').collect());
    if !names.is_empty() && !addrs.is_empty() && names.len() != addrs.len() {
        return Err(config_err(format!(
            "could not match {} host names to {} hostaddr values",
            names.len(),
            addrs.len()
        )));
    }
    let n = names.len().max(addrs.len()).max(1);
    let ports = ports
        .split(',')
        .map(|p| {
            if p.is_empty() {
                Ok(5432)
            } else {
                p.parse()
                    .map_err(|_| config_err("invalid value for option `port`"))
            }
        })
        .collect::<Result<Vec<u16>, Error>>()?;
    if ports.len() != 1 && ports.len() != n {
        return Err(config_err(format!(
            "could not match {} port numbers to {n} hosts",
            ports.len()
        )));
    }
    (0..n)
        .map(|i| {
            let name = names.get(i).copied().unwrap_or("");
            let addr = addrs.get(i).copied().unwrap_or("");
            if !addr.is_empty() && addr.parse::<std::net::IpAddr>().is_err() {
                return Err(config_err("invalid value for option `hostaddr`"));
            }
            let (name, dial) = match (name.is_empty(), addr.is_empty()) {
                (true, true) => ("localhost", "localhost"),
                (true, false) => (addr, addr),
                (false, true) => (name, name),
                (false, false) => (if name.starts_with('/') { addr } else { name }, addr),
            };
            Ok(Endpoint {
                name: name.to_string(),
                dial: dial.to_string(),
                port: ports[if ports.len() == 1 { 0 } else { i }],
            })
        })
        .collect()
}

fn decode(s: &str) -> Result<String, Error> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            match (
                b.get(i + 1).and_then(|c| hex(*c)),
                b.get(i + 2).and_then(|c| hex(*c)),
            ) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                _ => return Err(config_err("invalid percent encoding")),
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| config_err("invalid percent encoding"))
}

/// The libpq keyword form: `key=value` pairs, whitespace around `=` allowed, single-quoted values
/// with `\'` and `\\` escapes.
fn keywords(s: &str) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    loop {
        while it.peek().is_some_and(|c| c.is_whitespace()) {
            it.next();
        }
        if it.peek().is_none() {
            return Ok(out);
        }
        let mut key = String::new();
        while let Some(&c) = it.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            key.push(c);
            it.next();
        }
        while it.peek().is_some_and(|c| c.is_whitespace()) {
            it.next();
        }
        if it.next() != Some('=') {
            // The token is NOT echoed: it is not a well-formed `key=`, so it may be the tail of a
            // password that held a space, or a userinfo without its scheme.
            return Err(config_err(
                "unexpected EOF: a connection parameter without `=` (expected key=value)",
            ));
        }
        while it.peek().is_some_and(|c| c.is_whitespace()) {
            it.next();
        }
        let mut value = String::new();
        if it.peek() == Some(&'\'') {
            it.next();
            loop {
                match it.next() {
                    None => {
                        return Err(config_err("unterminated quoted connection parameter value"))
                    }
                    Some('\'') => break,
                    Some('\\') => match it.next() {
                        Some(c) => value.push(c),
                        None => {
                            return Err(config_err(
                                "unterminated quoted connection parameter value",
                            ))
                        }
                    },
                    Some(c) => value.push(c),
                }
            }
        } else {
            while let Some(&c) = it.peek() {
                if c.is_whitespace() {
                    break;
                }
                if c == '\\' {
                    it.next();
                    if let Some(n) = it.next() {
                        value.push(n);
                    }
                    continue;
                }
                value.push(c);
                it.next();
            }
        }
        out.push((key, value));
    }
}

/// A SQLSTATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlState(String);

impl SqlState {
    /// `42P01`, `undefined_table`.
    pub const UNDEFINED_TABLE: &'static str = "42P01";

    /// The five-character code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.0
    }
}

/// A server-side failure (an `ErrorResponse`).
#[derive(Debug, Clone)]
pub struct DbError {
    severity: String,
    code: SqlState,
    message: String,
    constraint: Option<String>,
}

impl DbError {
    fn parse(body: &ErrorResponseBody) -> Self {
        let mut e = DbError {
            severity: String::new(),
            code: SqlState(String::new()),
            message: String::new(),
            constraint: None,
        };
        let mut fields = body.fields();
        while let Ok(Some(f)) = fields.next() {
            let v = String::from_utf8_lossy(f.value_bytes()).into_owned();
            match f.type_() {
                b'S' => e.severity = v,
                b'C' => e.code = SqlState(v),
                b'M' => e.message = v,
                b'n' => e.constraint = Some(v),
                _ => {}
            }
        }
        e
    }

    /// The SQLSTATE.
    #[must_use]
    pub fn code(&self) -> &SqlState {
        &self.code
    }

    /// The primary message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The violated constraint, if one.
    #[must_use]
    pub fn constraint(&self) -> Option<&str> {
        self.constraint.as_deref()
    }
}

#[derive(Debug)]
enum Kind_ {
    Db(DbError),
    Connect(String),
    Io(String),
    Closed,
    Parse(String),
    Tls(String),
    Authentication(String),
    Config(String),
    ToSql(usize, String),
    FromSql(String, String),
    Column(String),
    RowCount,
    Parameters(usize, usize),
}

/// A driver error, in the `postgres` crate's words.
#[derive(Debug)]
pub struct Error(Box<Kind_>);

impl Error {
    fn new(k: Kind_) -> Self {
        Self(Box::new(k))
    }

    /// The server's failure, when it is one.
    #[must_use]
    pub fn as_db_error(&self) -> Option<&DbError> {
        match &*self.0 {
            Kind_::Db(d) => Some(d),
            _ => None,
        }
    }

    /// The server's SQLSTATE, when it is a server failure.
    #[must_use]
    pub fn code(&self) -> Option<&SqlState> {
        self.as_db_error().map(DbError::code)
    }

    /// A server failure with SQLSTATE `code` and `message`, as an `ErrorResponse` decodes.
    #[cfg(test)]
    #[must_use]
    pub fn server(code: &str, message: &str) -> Self {
        Self::new(Kind_::Db(DbError {
            severity: "ERROR".to_string(),
            code: SqlState(code.to_string()),
            message: message.to_string(),
            constraint: None,
        }))
    }

    /// A connect failure (the host's connector could not reach the server).
    #[must_use]
    pub fn connect(cause: impl fmt::Display) -> Self {
        Self::new(Kind_::Connect(cause.to_string()))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            Kind_::Db(d) => write!(f, "db error: {}: {}", d.severity, d.message),
            Kind_::Connect(c) => write!(f, "error connecting to server: {c}"),
            Kind_::Io(c) => write!(f, "error communicating with the server: {c}"),
            Kind_::Closed => f.write_str("connection closed"),
            Kind_::Parse(c) => write!(f, "error parsing response from server: {c}"),
            Kind_::Tls(c) => write!(f, "error performing TLS handshake: {c}"),
            Kind_::Authentication(c) => write!(f, "authentication error: {c}"),
            Kind_::Config(c) => write!(f, "invalid configuration: {c}"),
            Kind_::ToSql(i, c) => write!(f, "error serializing parameter {i}: {c}"),
            Kind_::FromSql(i, c) => write!(f, "error deserializing column `{i}`: {c}"),
            Kind_::Column(c) => write!(f, "invalid column `{c}`"),
            Kind_::RowCount => f.write_str("query returned an unexpected number of rows"),
            Kind_::Parameters(want, got) => {
                write!(f, "expected {want} parameters but got {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

fn parse_err(e: impl fmt::Display) -> Error {
    Error::new(Kind_::Parse(e.to_string()))
}

/// A result column.
#[derive(Debug, Clone)]
pub struct Column {
    name: String,
    type_: Type,
}

/// What names a column of a [`Row`]: its index or its name.
pub trait RowIndex: fmt::Display {
    #[doc(hidden)]
    fn index(&self, columns: &[Column]) -> Option<usize>;
}

impl RowIndex for usize {
    fn index(&self, columns: &[Column]) -> Option<usize> {
        (*self < columns.len()).then_some(*self)
    }
}

impl RowIndex for &str {
    fn index(&self, columns: &[Column]) -> Option<usize> {
        columns.iter().position(|c| c.name == *self)
    }
}

/// One result row.
#[derive(Debug)]
pub struct Row {
    columns: Arc<[Column]>,
    body: DataRowBody,
    ranges: Vec<Option<Range<usize>>>,
}

impl Row {
    /// Column `idx` as `T`.
    ///
    /// # Errors
    /// An unknown column, a type `T` does not accept, or a value that does not convert.
    pub fn try_get<'a, I: RowIndex, T: FromSql<'a>>(&'a self, idx: I) -> Result<T, Error> {
        let Some(i) = idx.index(&self.columns) else {
            return Err(Error::new(Kind_::Column(idx.to_string())));
        };
        let ty = &self.columns[i].type_;
        let name = &self.columns[i].name;
        if !T::accepts(ty) {
            return Err(Error::new(Kind_::FromSql(
                name.clone(),
                format!(
                    "cannot convert between the Rust type `{}` and the Postgres type `{}`",
                    std::any::type_name::<T>(),
                    ty
                ),
            )));
        }
        // A DataRow with fewer fields than the RowDescription named columns is the server's
        // protocol violation: an error on the missing column, never an out-of-bounds panic.
        let Some(range) = self.ranges.get(i) else {
            return Err(Error::new(Kind_::FromSql(
                name.clone(),
                format!(
                    "the server sent a row of {} fields for {} columns",
                    self.ranges.len(),
                    self.columns.len()
                ),
            )));
        };
        let raw = range.clone().map(|r| &self.body.buffer()[r]);
        T::from_sql_nullable(ty, raw)
            .map_err(|e| Error::new(Kind_::FromSql(name.clone(), e.to_string())))
    }
}

/// A statement prepared on the connection: its name there, and what its Describe answered.
struct Statement {
    name: String,
    types: Vec<Type>,
    columns: Arc<[Column]>,
}

/// How many statements a connection keeps prepared: past it, the least recently run is closed
/// (the store's variable-arity batches would otherwise prepare one per batch size, without end).
const STATEMENTS_KEPT: usize = 256;

/// The connection's prepared statements, by SQL text. Kept WITH the connection (the wire's session:
/// a kept connection hands it to the next op, a new connection starts empty and a closed one takes
/// it along), so an entry names a statement that exists on exactly that server session. An entry
/// goes in only once the server answered its Parse (a failed Parse prepares nothing), and stays
/// across a rolled-back transaction (a prepared statement is not transactional).
#[derive(Default)]
struct Cache {
    by_sql: HashMap<String, (Arc<Statement>, u64)>,
    /// The use clock (least recently run goes first) and the next statement's number.
    tick: u64,
    next: u64,
    /// Statements dropped from the cache whose Close goes out ahead of the next Parse.
    closing: Vec<String>,
}

/// [`Cache`], shared with the wire's session.
type Statements = Arc<Mutex<Cache>>;

impl Cache {
    fn get(&mut self, sql: &str) -> Option<Arc<Statement>> {
        self.tick += 1;
        let tick = self.tick;
        self.by_sql.get_mut(sql).map(|(s, used)| {
            *used = tick;
            s.clone()
        })
    }

    fn insert(&mut self, sql: &str, stmt: Arc<Statement>) {
        if self.by_sql.len() >= STATEMENTS_KEPT {
            let oldest = self
                .by_sql
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.forget(&k);
            }
        }
        self.by_sql.insert(sql.to_owned(), (stmt, self.tick));
    }

    fn forget(&mut self, sql: &str) {
        if let Some((s, _)) = self.by_sql.remove(sql) {
            self.closing.push(s.name.clone());
        }
    }

    fn forget_all(&mut self) {
        let names = self.by_sql.drain().map(|(_, (s, _))| s.name.clone());
        self.closing.extend(names);
    }
}

/// A cached statement's run failed because the server no longer has it as prepared: `26000`
/// (`invalid_sql_statement_name`, the session's statements were deallocated) or `0A000` (a schema
/// change altered its result type, "cached plan must not change result type").
fn is_stale_statement(e: &Error) -> bool {
    matches!(e.code().map(SqlState::code), Some("26000" | "0A000"))
}

/// One connection to the server, over the op's wire. The connection is KEPT for the instance's
/// next op (the store SDK's kept set) only when [`Client::release`] finds the session idle: the
/// last message read was `ReadyForQuery` with status `I` (no transaction open or failed), nothing
/// is left unread and no transaction awaits its rollback. Dropped any other way (an early return,
/// a protocol failure), it is discarded and the next op dials fresh.
pub struct Client {
    wire: Wire,
    buf: BytesMut,
    /// A `Transaction` was dropped uncommitted: roll it back before the next statement.
    rollback_pending: bool,
    /// The transaction status of the last `ReadyForQuery` (`I` idle, `T` in a transaction, `E` in
    /// a failed one).
    status: u8,
    /// The last message read was `ReadyForQuery` and nothing was sent after it.
    at_ready: bool,
    /// [`Client::release`] found the session idle: keep the connection.
    keep: bool,
    /// The statements prepared on this connection (the wire's session).
    statements: Statements,
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.keep {
            self.wire.discard();
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

/// A parameter.
pub type Param<'a> = &'a (dyn ToSql + Sync);

impl Client {
    /// Connect over `wire` (its need 0) to the server `cfg` names, secure the connection when
    /// `cfg` asks, and authenticate. The endpoints are tried in order (libpq's list), the one that
    /// last connected first (`preferred`, so a failover DSN does not evict the kept connection to
    /// try its first endpoint again on every op): any failure of one endpoint's connect (the dial,
    /// the TLS refusal, the server's startup error, a `target_session_attrs` mismatch) closes it
    /// and moves on to the next, and when all fail the last failure is the error (the driver's).
    ///
    /// # Errors
    /// The connector's failure (as a connect error), a TLS refusal, or the server's refusal.
    pub async fn connect(
        wire: Wire,
        cfg: &Config,
        preferred: &AtomicUsize,
    ) -> Result<Client, Error> {
        let n = cfg.endpoints.len();
        let first = preferred.load(Ordering::Relaxed);
        let first = if first < n { first } else { 0 };
        let mut last = None;
        for i in std::iter::once(first).chain((0..n).filter(|i| *i != first)) {
            match Self::attempt(&wire, cfg, &cfg.endpoints[i]).await {
                Ok(c) => {
                    preferred.store(i, Ordering::Relaxed);
                    return Ok(c);
                }
                Err(e) => {
                    // The bound comes off BEFORE the close: a bound that has passed answers every
                    // wire call with its timeout, the close included, which would leave this
                    // endpoint's socket in place under the next one's connect.
                    wire.unbound();
                    wire.close().await;
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| config_err("no server to connect to")))
    }

    /// One endpoint's connect: dial, secure, authenticate, check the session's kind.
    async fn attempt(wire: &Wire, cfg: &Config, endpoint: &Endpoint) -> Result<Client, Error> {
        // `connect_timeout` bounds a NEW connection's dial (the connector's own timeout for it) and
        // its handshake (`Wire::bound`); never the wait for one of the instance's kept connections,
        // which another op may hold for as long as its statement runs.
        let ms = cfg.connect_timeout_ms.unwrap_or(0);
        wire.connect_timed(0, Some(&target(&endpoint.dial, endpoint.port)), ms)
            .await
            .map_err(Error::connect)?;
        let reused = wire.reused();
        // A kept connection's statements come with it; a new connection's start empty and ride
        // with it from here on.
        let statements = match wire.session::<Statements>() {
            Some(s) if reused => s,
            _ => {
                let s = Statements::default();
                wire.set_session(s.clone());
                s
            }
        };
        let mut c = Client {
            wire: wire.clone(),
            buf: BytesMut::new(),
            rollback_pending: false,
            status: b'I',
            at_ready: true,
            keep: false,
            statements,
        };
        if reused {
            // A kept connection: secured and authenticated by the op that established it, and
            // idle when it was kept.
            return Ok(c);
        }
        if ms > 0 {
            wire.bound(ms);
        }
        c.handshake(cfg, endpoint).await?;
        wire.unbound();
        Ok(c)
    }

    async fn handshake(&mut self, cfg: &Config, endpoint: &Endpoint) -> Result<(), Error> {
        if cfg.ssl != SslMode::Plain {
            let mut out = BytesMut::new();
            frontend::ssl_request(&mut out);
            self.send(&out).await?;
            let answer = self.read_byte().await?;
            if answer != b'S' && cfg.ssl == SslMode::Require {
                return Err(Error::new(Kind_::Tls(
                    "server does not support TLS".to_string(),
                )));
            }
            if answer == b'S' {
                self.upgrade(cfg, endpoint).await?;
            } else if answer != b'N' {
                return Err(Error::new(Kind_::Tls(
                    "unexpected answer to the SSLRequest".to_string(),
                )));
            }
        }
        self.startup(cfg).await?;
        self.check_session_attrs(cfg).await
    }

    /// Secure the stream after the server's `S`: verified against the host's trust anchors for
    /// `require` and up, unverified for `prefer` (libpq).
    async fn upgrade(&mut self, cfg: &Config, endpoint: &Endpoint) -> Result<(), Error> {
        // Anything the server sent after its `S` went out in the clear, and would be parsed
        // after the upgrade as if the secured server had sent it (CVE-2021-23222, STARTTLS
        // response injection). The host's guard sees only the wire's input, which this
        // client's reads have already moved into its own buffer: the check is here.
        if !self.buf.is_empty() {
            return Err(Error::new(Kind_::Tls(
                "server sent unencrypted data after accepting TLS".to_string(),
            )));
        }
        let name = Some(endpoint.name.as_str());
        let secured = if cfg.ssl == SslMode::Prefer {
            self.wire.upgrade_secure_unverified(name).await
        } else {
            self.wire.upgrade_secure(name).await
        };
        secured.map_err(|e| Error::new(Kind_::Tls(e.to_string())))
    }

    async fn check_session_attrs(&mut self, cfg: &Config) -> Result<(), Error> {
        if cfg.target_session_attrs != SessionAttrs::Any {
            let row = self.query_one("SHOW transaction_read_only", &[]).await?;
            let read_only: &str = row.try_get(0)?;
            match (cfg.target_session_attrs, read_only) {
                (SessionAttrs::ReadWrite, "on") => {
                    return Err(Error::connect(
                        "target_session_attrs=read-write refused this server: it does not allow \
                         writes (transaction_read_only is on)",
                    ));
                }
                (SessionAttrs::ReadOnly, "off") => {
                    return Err(Error::connect(
                        "target_session_attrs=read-only refused this server: it is not read-only \
                         (transaction_read_only is off)",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn startup(&mut self, cfg: &Config) -> Result<(), Error> {
        let mut params: Vec<(&str, &str)> = vec![("client_encoding", "UTF8"), ("user", &cfg.user)];
        if let Some(db) = &cfg.dbname {
            params.push(("database", db));
        }
        let options = cfg.startup_options();
        if let Some(o) = &options {
            params.push(("options", o));
        }
        if let Some(a) = &cfg.application_name {
            params.push(("application_name", a));
        }
        let mut out = BytesMut::new();
        frontend::startup_message(params.iter().copied(), &mut out).map_err(parse_err)?;
        self.send(&out).await?;
        let password = || {
            cfg.password
                .as_deref()
                .map(str::as_bytes)
                .ok_or_else(|| Error::new(Kind_::Config("password missing".to_string())))
        };
        loop {
            match self.read().await? {
                Message::AuthenticationOk => break,
                Message::AuthenticationCleartextPassword => {
                    let mut out = BytesMut::new();
                    frontend::password_message(password()?, &mut out).map_err(parse_err)?;
                    self.send(&out).await?;
                }
                Message::AuthenticationMd5Password(b) => {
                    let hash = postgres_protocol::authentication::md5_hash(
                        cfg.user.as_bytes(),
                        password()?,
                        b.salt(),
                    );
                    let mut out = BytesMut::new();
                    frontend::password_message(hash.as_bytes(), &mut out).map_err(parse_err)?;
                    self.send(&out).await?;
                }
                Message::AuthenticationSasl(b) => {
                    let mut scram = false;
                    let mut mechs = b.mechanisms();
                    while let Some(m) = mechs.next().map_err(parse_err)? {
                        scram |= m == sasl::SCRAM_SHA_256;
                    }
                    if !scram {
                        return Err(Error::new(Kind_::Authentication(
                            "unsupported SASL mechanism".to_string(),
                        )));
                    }
                    let mut s = ScramSha256::new(password()?, ChannelBinding::unsupported());
                    let mut out = BytesMut::new();
                    frontend::sasl_initial_response(sasl::SCRAM_SHA_256, s.message(), &mut out)
                        .map_err(parse_err)?;
                    self.send(&out).await?;
                    let Message::AuthenticationSaslContinue(cont) = self.read_auth().await? else {
                        return Err(parse_err("unexpected message during SASL"));
                    };
                    s.update(cont.data())
                        .map_err(|e| Error::new(Kind_::Authentication(e.to_string())))?;
                    let mut out = BytesMut::new();
                    frontend::sasl_response(s.message(), &mut out).map_err(parse_err)?;
                    self.send(&out).await?;
                    let Message::AuthenticationSaslFinal(fin) = self.read_auth().await? else {
                        return Err(parse_err("unexpected message during SASL"));
                    };
                    s.finish(fin.data())
                        .map_err(|e| Error::new(Kind_::Authentication(e.to_string())))?;
                }
                Message::ErrorResponse(e) => return Err(Error::new(Kind_::Db(DbError::parse(&e)))),
                Message::NoticeResponse(_) => {}
                _ => {
                    return Err(Error::new(Kind_::Authentication(
                        "unsupported authentication method".to_string(),
                    )))
                }
            }
        }
        loop {
            match self.read().await? {
                Message::ReadyForQuery(_) => return Ok(()),
                Message::ErrorResponse(e) => return Err(Error::new(Kind_::Db(DbError::parse(&e)))),
                _ => {}
            }
        }
    }

    /// An authentication message, a server failure answered as one.
    async fn read_auth(&mut self) -> Result<Message, Error> {
        match self.read().await? {
            Message::ErrorResponse(e) => Err(Error::new(Kind_::Db(DbError::parse(&e)))),
            m => Ok(m),
        }
    }

    /// Whether the session is idle and whole: fit to be kept for the next op.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.at_ready && self.status == b'I' && !self.rollback_pending && self.buf.is_empty()
    }

    /// The op is done with the connection: keep it if the session is idle, else it is discarded
    /// when the client drops. A transaction the op dropped uncommitted (a replay, a conflict, a
    /// refusal: the common ends of a write) is rolled back first, when the connection is
    /// otherwise whole, so those ends keep the connection instead of costing the next op a fresh
    /// TCP, TLS and SCRAM handshake; a rollback that fails
    /// (even one the server answers and then returns to idle) is not kept.
    pub async fn release(&mut self) {
        if self.rollback_pending
            && self.at_ready
            && self.buf.is_empty()
            && self.settle().await.is_err()
        {
            return;
        }
        self.keep = self.is_idle();
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.at_ready = false;
        self.wire
            .write_all(bytes)
            .await
            .map_err(|e| Error::new(Kind_::Io(e.to_string())))
    }

    async fn more(&mut self) -> Result<(), Error> {
        let n = self
            .wire
            .fill()
            .await
            .map_err(|e| Error::new(Kind_::Io(e.to_string())))?;
        if n == 0 {
            return Err(Error::new(Kind_::Closed));
        }
        let buf = &mut self.buf;
        self.wire.input(|i| {
            buf.extend_from_slice(i);
            i.clear();
        });
        Ok(())
    }

    async fn read_byte(&mut self) -> Result<u8, Error> {
        while self.buf.is_empty() {
            self.more().await?;
        }
        let b = self.buf[0];
        let _ = self.buf.split_to(1);
        Ok(b)
    }

    /// The next message the server sent; asynchronous notices and parameter changes skipped.
    async fn read(&mut self) -> Result<Message, Error> {
        loop {
            match Message::parse(&mut self.buf).map_err(parse_err)? {
                Some(Message::ParameterStatus(_) | Message::NoticeResponse(_)) => {}
                Some(Message::NotificationResponse(_)) => {}
                Some(m) => {
                    if let Message::ReadyForQuery(b) = &m {
                        self.status = b.status();
                        self.at_ready = true;
                    }
                    return Ok(m);
                }
                None => self.more().await?,
            }
        }
    }

    /// Read to `ReadyForQuery`, after a failure.
    async fn drain(&mut self) -> Result<(), Error> {
        loop {
            if let Message::ReadyForQuery(_) = self.read().await? {
                return Ok(());
            }
        }
    }

    /// Roll back a transaction dropped uncommitted.
    async fn settle(&mut self) -> Result<(), Error> {
        if std::mem::take(&mut self.rollback_pending) {
            self.simple("ROLLBACK").await?;
        }
        Ok(())
    }

    async fn simple(&mut self, sql: &str) -> Result<(), Error> {
        let mut out = BytesMut::new();
        frontend::query(sql, &mut out).map_err(parse_err)?;
        self.send(&out).await?;
        let mut failed = None;
        loop {
            match self.read().await {
                Ok(Message::ReadyForQuery(_)) => break,
                Ok(Message::ErrorResponse(e)) if failed.is_none() => {
                    failed = Some(Error::new(Kind_::Db(DbError::parse(&e))));
                }
                Ok(_) => {}
                // A FATAL (57P01 admin shutdown, 53300) is followed by the server closing the
                // socket: the reason it gave is the error, not the close.
                Err(e) => return Err(failed.unwrap_or(e)),
            }
        }
        failed.map_or(Ok(()), Err)
    }

    /// Run `sql` (one or more statements, no parameters) through the simple query protocol.
    ///
    /// # Errors
    /// The first statement's failure.
    pub async fn batch_execute(&mut self, sql: &str) -> Result<(), Error> {
        self.settle().await?;
        self.simple(sql).await
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.statements
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Run one statement with `params`: its rows and the rows it affected. A statement the
    /// connection has prepared runs in one round trip; one it has not is prepared first. A cached
    /// statement the server no longer has ([`is_stale_statement`]) is dropped and, outside a
    /// transaction (nothing was aborted), prepared afresh and run once more.
    async fn run(&mut self, sql: &str, params: &[Param<'_>]) -> Result<(Vec<Row>, u64), Error> {
        self.settle().await?;
        let cached = self.cache().get(sql);
        let Some(stmt) = cached else {
            let stmt = self.prepare(sql).await?;
            return self.bind_execute(&stmt, params).await;
        };
        match self.bind_execute(&stmt, params).await {
            Err(e) if is_stale_statement(&e) => {
                if e.code().map(SqlState::code) == Some("26000") {
                    self.cache().forget_all();
                } else {
                    self.cache().forget(sql);
                }
                if !(self.at_ready && self.status == b'I') {
                    return Err(e);
                }
                let stmt = self.prepare(sql).await?;
                self.bind_execute(&stmt, params).await
            }
            r => r,
        }
    }

    /// Prepare `sql` under a new name (the parameter and column types: one round trip, which also
    /// closes the statements the cache dropped) and cache it.
    async fn prepare(&mut self, sql: &str) -> Result<Arc<Statement>, Error> {
        let name = {
            let mut c = self.cache();
            c.next += 1;
            format!("s{}", c.next)
        };
        let mut tail = BytesMut::new();
        frontend::parse(&name, sql, std::iter::empty(), &mut tail).map_err(parse_err)?;
        frontend::describe(b'S', &name, &mut tail).map_err(parse_err)?;
        frontend::sync(&mut tail);
        let mut out = BytesMut::new();
        for old in std::mem::take(&mut self.cache().closing) {
            frontend::close(b'S', &old, &mut out).map_err(parse_err)?;
        }
        out.extend_from_slice(&tail);
        self.send(&out).await?;
        let mut types: Vec<Type> = Vec::new();
        let mut columns: Vec<Column> = Vec::new();
        loop {
            match self.read().await? {
                Message::CloseComplete | Message::ParseComplete | Message::NoData => {}
                Message::ParameterDescription(p) => {
                    let mut it = p.parameters();
                    while let Some(oid) = it.next().map_err(parse_err)? {
                        types.push(type_of(oid));
                    }
                }
                Message::RowDescription(r) => {
                    let mut it = r.fields();
                    while let Some(f) = it.next().map_err(parse_err)? {
                        columns.push(Column {
                            name: f.name().to_string(),
                            type_: type_of(f.type_oid()),
                        });
                    }
                }
                Message::ErrorResponse(e) => {
                    let err = Error::new(Kind_::Db(DbError::parse(&e)));
                    // The connection is unusable when the drain fails (not idle, so not kept);
                    // the server's error is still the one to report.
                    let _ = self.drain().await;
                    return Err(err);
                }
                Message::ReadyForQuery(_) => break,
                _ => return Err(parse_err("unexpected message")),
            }
        }
        let stmt = Arc::new(Statement {
            name,
            types,
            columns: columns.into(),
        });
        self.cache().insert(sql, stmt.clone());
        Ok(stmt)
    }

    /// Run the prepared `stmt` with `params` (one round trip): its rows and the rows it affected.
    async fn bind_execute(
        &mut self,
        stmt: &Statement,
        params: &[Param<'_>],
    ) -> Result<(Vec<Row>, u64), Error> {
        let types = &stmt.types;
        if types.len() != params.len() {
            return Err(Error::new(Kind_::Parameters(types.len(), params.len())));
        }
        let mut out = BytesMut::new();
        let mut failed: Option<(usize, String)> = None;
        let mut index = 0;
        let bound = frontend::bind(
            "",
            &stmt.name,
            std::iter::repeat_n(1_i16, params.len()),
            params.iter().zip(types.iter()),
            |(p, ty), buf| {
                let i = index;
                index += 1;
                match p.to_sql_checked(ty, buf) {
                    Ok(postgres_types::IsNull::No) => Ok(postgres_protocol::IsNull::No),
                    Ok(postgres_types::IsNull::Yes) => Ok(postgres_protocol::IsNull::Yes),
                    Err(e) => {
                        failed = Some((i, e.to_string()));
                        Err(e)
                    }
                }
            },
            std::iter::once(1_i16),
            &mut out,
        );
        if let Err(e) = bound {
            return Err(match failed {
                Some((i, t)) => Error::new(Kind_::ToSql(i, t)),
                None => match e {
                    frontend::BindError::Conversion(e) => {
                        Error::new(Kind_::ToSql(0, e.to_string()))
                    }
                    frontend::BindError::Serialization(e) => parse_err(e),
                },
            });
        }
        frontend::execute("", 0, &mut out).map_err(parse_err)?;
        frontend::sync(&mut out);
        self.send(&out).await?;
        let columns = &stmt.columns;
        let mut rows = Vec::new();
        let mut affected = 0;
        let mut failed = None;
        loop {
            let message = match self.read().await {
                Ok(m) => m,
                Err(e) => return Err(failed.unwrap_or(e)),
            };
            match message {
                Message::BindComplete | Message::EmptyQueryResponse => {}
                Message::DataRow(body) => {
                    if failed.is_none() {
                        let mut ranges = Vec::with_capacity(columns.len());
                        let mut it = body.ranges();
                        while let Some(r) = it.next().map_err(parse_err)? {
                            ranges.push(r);
                        }
                        rows.push(Row {
                            columns: columns.clone(),
                            body,
                            ranges,
                        });
                    }
                }
                Message::CommandComplete(c) => {
                    let tag = c.tag().map_err(parse_err)?;
                    affected = tag
                        .rsplit(' ')
                        .next()
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                }
                Message::ErrorResponse(e) if failed.is_none() => {
                    failed = Some(Error::new(Kind_::Db(DbError::parse(&e))));
                }
                Message::ReadyForQuery(_) => break,
                _ => {}
            }
        }
        match failed {
            Some(e) => Err(e),
            None => Ok((rows, affected)),
        }
    }

    /// The rows `sql` answers.
    ///
    /// # Errors
    /// The statement's failure.
    pub async fn query(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Vec<Row>, Error> {
        self.run(sql, params).await.map(|(r, _)| r)
    }

    /// How many rows `sql` affected.
    ///
    /// # Errors
    /// The statement's failure.
    pub async fn execute(&mut self, sql: &str, params: &[Param<'_>]) -> Result<u64, Error> {
        self.run(sql, params).await.map(|(_, n)| n)
    }

    /// The one row `sql` answers.
    ///
    /// # Errors
    /// The statement's failure, or not exactly one row.
    pub async fn query_one(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Row, Error> {
        let mut rows = self.query(sql, params).await?;
        if rows.len() != 1 {
            return Err(Error::new(Kind_::RowCount));
        }
        Ok(rows.remove(0))
    }

    /// The row `sql` answers, if one.
    ///
    /// # Errors
    /// The statement's failure, or more than one row.
    pub async fn query_opt(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Option<Row>, Error> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows.remove(0))),
            _ => Err(Error::new(Kind_::RowCount)),
        }
    }

    /// Begin a READ COMMITTED transaction.
    ///
    /// # Errors
    /// The `BEGIN`'s failure.
    pub async fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        self.batch_execute(begin_sql(None)).await?;
        Ok(Transaction {
            client: self,
            done: false,
        })
    }

    /// A transaction with options.
    pub fn build_transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder {
            client: self,
            isolation: None,
        }
    }
}

fn type_of(oid: u32) -> Type {
    Type::from_oid(oid)
        .unwrap_or_else(|| Type::new(format!("{oid}"), oid, Kind::Simple, String::new()))
}

/// A transaction's isolation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    RepeatableRead,
}

/// The statement that begins a transaction at `isolation` (`None` = READ COMMITTED, stated, so a
/// DSN's `default_transaction_isolation` cannot change what the store's statements assume).
#[must_use]
pub fn begin_sql(isolation: Option<IsolationLevel>) -> &'static str {
    match isolation {
        None => "BEGIN ISOLATION LEVEL READ COMMITTED",
        Some(IsolationLevel::RepeatableRead) => "BEGIN ISOLATION LEVEL REPEATABLE READ",
    }
}

/// [`Client::build_transaction`].
pub struct TransactionBuilder<'a> {
    client: &'a mut Client,
    isolation: Option<IsolationLevel>,
}

impl<'a> TransactionBuilder<'a> {
    /// The isolation level.
    #[must_use]
    pub fn isolation_level(mut self, level: IsolationLevel) -> Self {
        self.isolation = Some(level);
        self
    }

    /// Begin it.
    ///
    /// # Errors
    /// The `BEGIN`'s failure.
    pub async fn start(self) -> Result<Transaction<'a>, Error> {
        self.client.batch_execute(begin_sql(self.isolation)).await?;
        Ok(Transaction {
            client: self.client,
            done: false,
        })
    }
}

/// A transaction; rolled back unless committed.
pub struct Transaction<'a> {
    client: &'a mut Client,
    done: bool,
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.client.rollback_pending = true;
        }
    }
}

impl Transaction<'_> {
    /// Commit.
    ///
    /// # Errors
    /// The `COMMIT`'s failure.
    pub async fn commit(mut self) -> Result<(), Error> {
        self.done = true;
        self.client.batch_execute("COMMIT").await
    }

    /// [`Client::batch_execute`] inside the transaction.
    ///
    /// # Errors
    /// As there.
    pub async fn batch_execute(&mut self, sql: &str) -> Result<(), Error> {
        self.client.batch_execute(sql).await
    }

    /// [`Client::query`] inside the transaction.
    ///
    /// # Errors
    /// As there.
    pub async fn query(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Vec<Row>, Error> {
        self.client.query(sql, params).await
    }

    /// [`Client::execute`] inside the transaction.
    ///
    /// # Errors
    /// As there.
    pub async fn execute(&mut self, sql: &str, params: &[Param<'_>]) -> Result<u64, Error> {
        self.client.execute(sql, params).await
    }

    /// [`Client::query_one`] inside the transaction.
    ///
    /// # Errors
    /// As there.
    pub async fn query_one(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Row, Error> {
        self.client.query_one(sql, params).await
    }

    /// [`Client::query_opt`] inside the transaction.
    ///
    /// # Errors
    /// As there.
    pub async fn query_opt(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Option<Row>, Error> {
        self.client.query_opt(sql, params).await
    }
}

#[cfg(test)]
#[path = "tests/pgwire.rs"]
mod tests;
