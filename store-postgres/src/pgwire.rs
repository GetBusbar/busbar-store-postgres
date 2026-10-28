// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE POSTGRES FRONTEND PROTOCOL OVER THE HOST'S CONNECTOR: a small async client whose every byte
//! goes through the op's one connection ([`Wire`], the store SDK's `wire`), so this store opens no
//! socket of its own (busbar THE DESIGN, the connections section). The codec is
//! `postgres-protocol` (the messages, SCRAM-SHA-256 and md5) and the value encodings are
//! `postgres-types` (the same binary `ToSql`/`FromSql` the `postgres` crate uses), so a parameter
//! or a column reads exactly as it did over the 1.5.5 driver.
//!
//! The surface mirrors the `postgres` crate's (`Client`, `Transaction`, `Row`, `Error`) with every
//! call `async`, so the store's SQL bodies are the 1.5.5 bodies with `.await`. A query is two round
//! trips (Parse/Describe/Sync for the parameter and column types, then Bind/Execute/Sync), every
//! parameter and column in the binary format. A `Transaction` dropped without `commit` is rolled
//! back before the connection's next statement, as the driver's was.

use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use postgres_protocol::authentication::sasl::{self, ChannelBinding, ScramSha256};
use postgres_protocol::message::backend::{DataRowBody, ErrorResponseBody, Message};
use postgres_protocol::message::frontend;
use postgres_types::{FromSql, Kind, ToSql, Type};

use busbar_contract::abi::sdk::store::wire::Wire;

// ── configuration ───────────────────────────────────────────────────────────────────────────

/// Whether the connection is secured (libpq's `sslmode`). `disable`, `allow` and `prefer` connect
/// in plaintext, as the 1.5.5 build (`NoTls`) did for every mode it accepted; `require`,
/// `verify-ca` and `verify-full` ask the server for TLS and secure the connection through the host
/// (its trust anchors), refusing a server that declines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// Plaintext.
    Plain,
    /// TLS, or no connection.
    Require,
}

/// Which kind of session a connect accepts (libpq's `target_session_attrs`, the 1.5.5 driver's
/// set): the others libpq has (`primary`, `standby`, `prefer-standby`) the driver refused too.
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

impl Config {
    /// Parse a libpq connection string: `postgres[ql]://user:pass@host:port/db?key=value&...` or
    /// `host=... port=... user=... password=... dbname=... sslmode=...`.
    ///
    /// # Errors
    /// A malformed string, an unknown option, a Unix-socket host (this store reaches its server
    /// over the host's connector, which dials TCP) or no user.
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
                        "disable" => SslMode::Plain,
                        // Refused rather than downgraded: these would try TLS or fall back to
                        // plaintext silently, and the operator asked for neither outcome by name.
                        m @ ("allow" | "prefer") => {
                            return Err(config_err(format!(
                                "sslmode={m} is not supported: this store never falls back \
                                 silently; use require/verify-ca/verify-full for TLS or disable \
                                 for plaintext"
                            )));
                        }
                        "require" | "verify-ca" | "verify-full" => SslMode::Require,
                        _ => {
                            return Err(config_err("invalid value for option `sslmode`"));
                        }
                    }
                }
                // Whole seconds, as the 1.5.5 driver read them: more than zero bounds the dial and
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
                // Refused rather than ignored: the 1.5.5 driver (no TLS client of its own, so no
                // channel binding) refused `require`, and a server that gets no binding could not
                // be the one the operator required.
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
                // Refused rather than ignored: the host's connector keeps the connection and its
                // sockets, so a per-store socket or balancing option could never apply.
                "keepalives"
                | "keepalives_idle"
                | "keepalives_interval"
                | "keepalives_count"
                | "keepalives_retries"
                | "load_balance_hosts"
                | "tcp_user_timeout"
                | "sslnegotiation" => {
                    return Err(config_err(format!(
                        "{k} is not supported by this store: the host's connector owns the \
                         connection and its sockets, so this option could never apply"
                    )));
                }
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

// ── errors ──────────────────────────────────────────────────────────────────────────────────

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
    FromSql(usize, String),
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
            Kind_::FromSql(i, c) => write!(f, "error deserializing column {i}: {c}"),
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

// ── rows ────────────────────────────────────────────────────────────────────────────────────

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
    /// # Panics
    /// An unknown column, or a value that does not convert (the `postgres` crate's `get`).
    pub fn get<'a, I: RowIndex, T: FromSql<'a>>(&'a self, idx: I) -> T {
        match self.try_get(idx) {
            Ok(v) => v,
            Err(e) => panic!("error retrieving column: {e}"),
        }
    }

    /// Column `idx` as `T`.
    ///
    /// # Errors
    /// An unknown column, a type `T` does not accept, or a value that does not convert.
    pub fn try_get<'a, I: RowIndex, T: FromSql<'a>>(&'a self, idx: I) -> Result<T, Error> {
        let Some(i) = idx.index(&self.columns) else {
            return Err(Error::new(Kind_::Column(idx.to_string())));
        };
        let ty = &self.columns[i].type_;
        if !T::accepts(ty) {
            return Err(Error::new(Kind_::FromSql(
                i,
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
                i,
                format!(
                    "the server sent a row of {} fields for {} columns",
                    self.ranges.len(),
                    self.columns.len()
                ),
            )));
        };
        let raw = range.clone().map(|r| &self.body.buffer()[r]);
        T::from_sql_nullable(ty, raw).map_err(|e| Error::new(Kind_::FromSql(i, e.to_string())))
    }
}

// ── the client ──────────────────────────────────────────────────────────────────────────────

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
        // its handshake (`Wire::bound`); never the wait for the instance's one kept connection,
        // which another op may hold for as long as its statement runs.
        let ms = cfg.connect_timeout_ms.unwrap_or(0);
        wire.connect_timed(0, Some(&target(&endpoint.dial, endpoint.port)), ms)
            .await
            .map_err(Error::connect)?;
        let mut c = Client {
            wire: wire.clone(),
            buf: BytesMut::new(),
            rollback_pending: false,
            status: b'I',
            at_ready: true,
            keep: false,
        };
        if wire.reused() {
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
        if cfg.ssl == SslMode::Require {
            let mut out = BytesMut::new();
            frontend::ssl_request(&mut out);
            self.send(&out).await?;
            let answer = self.read_byte().await?;
            if answer != b'S' {
                return Err(Error::new(Kind_::Tls(
                    "server does not support TLS".to_string(),
                )));
            }
            // Anything the server sent after its `S` went out in the clear, and would be parsed
            // after the upgrade as if the secured server had sent it (CVE-2021-23222, STARTTLS
            // response injection). The host's guard sees only the wire's input, which this
            // client's reads have already moved into its own buffer: the check is here.
            if !self.buf.is_empty() {
                return Err(Error::new(Kind_::Tls(
                    "server sent unencrypted data after accepting TLS".to_string(),
                )));
            }
            self.wire
                .upgrade_secure(Some(&endpoint.name))
                .await
                .map_err(|e| Error::new(Kind_::Tls(e.to_string())))?;
        }
        self.startup(cfg).await?;
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
        if let Some(o) = &cfg.options {
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

    /// Run one statement with `params`: its rows and the rows it affected.
    async fn run(&mut self, sql: &str, params: &[Param<'_>]) -> Result<(Vec<Row>, u64), Error> {
        self.settle().await?;
        // Round trip 1: the parameter and column types.
        let mut out = BytesMut::new();
        frontend::parse("", sql, std::iter::empty(), &mut out).map_err(parse_err)?;
        frontend::describe(b'S', "", &mut out).map_err(parse_err)?;
        frontend::sync(&mut out);
        self.send(&out).await?;
        let mut types: Vec<Type> = Vec::new();
        let mut columns: Vec<Column> = Vec::new();
        loop {
            match self.read().await? {
                Message::ParseComplete | Message::NoData => {}
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
        if types.len() != params.len() {
            return Err(Error::new(Kind_::Parameters(types.len(), params.len())));
        }
        // Round trip 2: bind, execute.
        let mut out = BytesMut::new();
        let mut failed: Option<(usize, String)> = None;
        let mut index = 0;
        let bound = frontend::bind(
            "",
            "",
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
        let columns: Arc<[Column]> = columns.into();
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

    /// Begin a transaction (the server's default isolation, READ COMMITTED).
    ///
    /// # Errors
    /// The `BEGIN`'s failure.
    pub async fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        self.batch_execute("BEGIN").await?;
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

/// The statement that begins a transaction at `isolation` (`None` = the server's default).
#[must_use]
pub fn begin_sql(isolation: Option<IsolationLevel>) -> &'static str {
    match isolation {
        None => "BEGIN",
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
mod tests {
    use super::{begin_sql, Config, IsolationLevel, SslMode};

    #[test]
    fn a_url_parses_into_its_parts() {
        let c = Config::parse(
            "postgres://u%40x:p%3Ass@db.internal:6543/busbar?sslmode=require&application_name=bb",
        )
        .unwrap();
        assert_eq!(c.user, "u@x");
        assert_eq!(c.password.as_deref(), Some("p:ss"));
        assert_eq!(c.targets()[0].1, "db.internal:6543");
        assert_eq!(c.dbname.as_deref(), Some("busbar"));
        assert_eq!(c.ssl, SslMode::Require);
        assert_eq!(c.application_name.as_deref(), Some("bb"));
        let c = Config::parse("postgresql://u@[::1]/d").unwrap();
        assert_eq!(c.targets()[0].1, "[::1]:5432");
        assert_eq!(c.password, None);
    }

    #[test]
    fn the_keyword_form_parses_with_spaces_and_quotes() {
        let c =
            Config::parse("host = db port=5433 user=u password='se cret' dbname=x sslmode=require")
                .unwrap();
        assert_eq!(c.targets()[0].1, "db:5433");
        assert_eq!(c.password.as_deref(), Some("se cret"));
        assert_eq!(c.ssl, SslMode::Require);
    }

    #[test]
    fn what_the_host_cannot_dial_is_refused() {
        assert!(Config::parse("host=/var/run/postgresql user=u").is_err());
        assert!(Config::parse("host=db").is_err(), "no user");
        assert!(Config::parse("host=db user=u bogus=1").is_err());
        assert!(Config::parse("host=db user=u sslmode=sometimes").is_err());
        assert!(Config::parse("host=a,b port=1,2,3 user=u").is_err());
    }

    /// libpq's MULTI-HOST list (busbar oracle store.boot|postgres|multi-host): every endpoint, in
    /// order, each with its own port or the one shared; a connect the first refuses tries the next.
    /// RED before: "multiple hosts are not supported".
    #[test]
    fn a_multi_host_list_names_every_endpoint_in_order() {
        let c = Config::parse("postgres://u:p@127.0.0.1:1,db:5433,[::1]/d").unwrap();
        let t: Vec<String> = c.targets().into_iter().map(|(_, t)| t).collect();
        assert_eq!(t, ["127.0.0.1:1", "db:5433", "[::1]:5432"]);
        let c = Config::parse("host=a,b port=6000 user=u").unwrap();
        let t: Vec<String> = c.targets().into_iter().map(|(_, t)| t).collect();
        assert_eq!(t, ["a:6000", "b:6000"]);
        let c = Config::parse("host=a,b port=1,2 user=u").unwrap();
        assert_eq!(c.targets()[1], ("b", "b:2".to_string()));
    }

    /// D11 (RED before: `host` and `hostaddr` shared one slot, the last won): `hostaddr` is the
    /// address that is dialled and `host` the name the TLS check and the errors use (libpq, and the
    /// 1.5.5 driver), paired by position; a hostaddr that is no IP, or a list of another length, is
    /// refused.
    #[test]
    fn hostaddr_is_dialled_and_host_is_the_name() {
        let c = Config::parse("host=db.internal hostaddr=10.1.2.3 port=6000 user=u").unwrap();
        assert_eq!(c.targets(), [("db.internal", "10.1.2.3:6000".to_string())]);
        let c = Config::parse("host=a,b hostaddr=10.0.0.1,::1 user=u").unwrap();
        assert_eq!(
            c.targets(),
            [
                ("a", "10.0.0.1:5432".to_string()),
                ("b", "[::1]:5432".to_string())
            ]
        );
        let c = Config::parse("hostaddr=10.1.2.3 user=u").unwrap();
        assert_eq!(c.targets(), [("10.1.2.3", "10.1.2.3:5432".to_string())]);
        let e = Config::parse("host=db hostaddr=not-an-ip user=u").unwrap_err();
        assert!(e.to_string().contains("hostaddr"), "{e}");
        assert!(Config::parse("host=a,b hostaddr=10.0.0.1 user=u").is_err());
        // The port list matches the longer of the two lists.
        let c = Config::parse("hostaddr=10.0.0.1,10.0.0.2 port=1,2 user=u").unwrap();
        assert_eq!(c.targets()[1].1, "10.0.0.2:2");
    }

    /// D10 (RED before: any value was accepted and ignored): `target_session_attrs` is `any`,
    /// `read-write` or `read-only` (the 1.5.5 driver's set); anything else is refused naming them.
    #[test]
    fn target_session_attrs_takes_the_drivers_values_only() {
        for ok in ["any", "read-write", "read-only"] {
            Config::parse(&format!("host=db user=u target_session_attrs={ok}")).unwrap();
        }
        let e = Config::parse("host=db user=u target_session_attrs=primary").unwrap_err();
        assert!(e.to_string().contains("target_session_attrs"), "{e}");
        assert!(
            e.to_string().contains("read-write"),
            "names the accepted values: {e}"
        );
    }

    /// D9 (RED before: both were accepted and silently ignored): this client has no SCRAM-PLUS, so
    /// `channel_binding=require` could not be honoured, and the connection is verified against
    /// busbar's trust anchors, so a per-store `sslrootcert` could not be. 1.5.5 refused both.
    #[test]
    fn what_this_client_cannot_honour_is_refused_not_ignored() {
        let e = Config::parse("host=db user=u channel_binding=require").unwrap_err();
        assert!(e.to_string().contains("channel_binding"), "{e}");
        Config::parse("host=db user=u channel_binding=prefer").unwrap();
        Config::parse("host=db user=u channel_binding=disable").unwrap();
        assert!(Config::parse("host=db user=u channel_binding=sometimes").is_err());
        let e = Config::parse("host=db user=u sslrootcert=/etc/ca.pem").unwrap_err();
        assert!(e.to_string().contains("sslrootcert"), "{e}");
        let e =
            Config::parse("postgres://u@db/d?sslmode=verify-full&sslrootcert=/ca.pem").unwrap_err();
        assert!(e.to_string().contains("sslrootcert"), "{e}");
    }

    /// A downgrade nobody asked for is refused: `prefer` and `allow` would fall back to plaintext
    /// silently, so they are errors that say what to use; `disable` is plaintext on request, and
    /// an ABSENT `sslmode` is plaintext too (documented in the README), not a refused request.
    /// The message never echoes the password.
    #[test]
    fn sslmode_prefer_and_allow_are_refused_not_downgraded() {
        for mode in ["prefer", "allow"] {
            for dsn in [
                format!("host=db user=u password=zq9pw sslmode={mode}"),
                format!("postgres://u:zq9pw@db/d?sslmode={mode}"),
            ] {
                let e = Config::parse(&dsn).unwrap_err().to_string();
                assert!(
                    e.contains(&format!("sslmode={mode} is not supported"))
                        && e.contains("never falls back silently")
                        && e.contains("verify-full")
                        && !e.contains("zq9pw"),
                    "{dsn}: {e}"
                );
            }
        }
        assert_eq!(
            Config::parse("host=db user=u sslmode=disable").unwrap().ssl,
            SslMode::Plain
        );
        assert_eq!(Config::parse("host=db user=u").unwrap().ssl, SslMode::Plain);
        for mode in ["require", "verify-ca", "verify-full"] {
            let c = Config::parse(&format!("host=db user=u sslmode={mode}")).unwrap();
            assert_eq!(c.ssl, SslMode::Require, "{mode}");
        }
    }

    /// Connect options this store neither applies nor can apply (the host's connector owns the
    /// sockets) are refused with an explanation, not accepted and ignored; the message never
    /// echoes the password.
    #[test]
    fn connect_options_the_store_cannot_apply_are_refused_not_ignored() {
        for opt in [
            "keepalives=1",
            "keepalives_idle=30",
            "keepalives_interval=10",
            "keepalives_count=3",
            "keepalives_retries=3",
            "load_balance_hosts=random",
            "tcp_user_timeout=5000",
            "sslnegotiation=direct",
        ] {
            let name = opt.split('=').next().unwrap();
            for dsn in [
                format!("host=db user=u password=zq9pw {opt}"),
                format!("postgres://u:zq9pw@db/d?{opt}"),
            ] {
                let e = Config::parse(&dsn).unwrap_err().to_string();
                assert!(
                    e.contains(&format!("{name} is not supported by this store"))
                        && !e.contains("zq9pw"),
                    "{dsn}: {e}"
                );
            }
        }
    }

    /// D37 (RED before: accepted and ignored): `connect_timeout` is whole seconds as the driver
    /// reads it, a number that is not one is refused.
    #[test]
    fn connect_timeout_is_whole_seconds() {
        for ok in ["5", "0", "-1"] {
            Config::parse(&format!("host=db user=u connect_timeout={ok}")).unwrap();
        }
        let e = Config::parse("host=db user=u connect_timeout=soon").unwrap_err();
        assert!(e.to_string().contains("connect_timeout"), "{e}");
        assert!(Config::parse("postgres://u@db/d?connect_timeout=2.5").is_err());
        // Zero or less is no bound (libpq's reading); more than zero is whole seconds.
        let ms = |v: &str| {
            Config::parse(&format!("host=db user=u connect_timeout={v}"))
                .unwrap()
                .connect_timeout_ms
        };
        assert_eq!((ms("5"), ms("0"), ms("-1")), (Some(5000), None, None));
        let e = Config::parse("host=db user=u connect_timeout=soon").unwrap_err();
        assert!(e.to_string().contains("whole number of seconds"), "{e}");
    }

    /// D26 (RED before: the unparsed fragment was echoed): a configuration error never repeats a
    /// token of the string that is not a well-formed `key=`, because a password with a space, a `?`
    /// or a missing `user:` prefix splits there and its tail would be echoed; an unknown option's
    /// key is named only when the string carries no password.
    #[test]
    fn a_config_error_never_echoes_a_password_tail() {
        for dsn in [
            "host=db user=u password=pa zq9tail",
            "postgres://u:pa?zq9tail@h/db",
            "u:zq9tail@h/db",
            "host=db user=u password='pa zq9tail' zq9tail",
        ] {
            let e = Config::parse(dsn).unwrap_err().to_string();
            assert!(
                !e.contains("zq9tail"),
                "{dsn}: the error echoed a fragment: {e}"
            );
        }
        // The key of an unknown option is the operator's, when no password rides along.
        let e = Config::parse("host=db user=u zq9key=1")
            .unwrap_err()
            .to_string();
        assert!(e.contains("zq9key"), "{e}");
        let e = Config::parse("host=db user=u password=s3 zq9key=1")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("zq9key") && e.contains("unknown option"), "{e}");
        let e = Config::parse("postgres://u:s3@db/d?zq9key=1")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("zq9key") && e.contains("unknown option"), "{e}");
    }

    /// B9: the store reaches its server over TCP, so a Unix-socket host is refused in the URL
    /// forms too (RED by mutation: drop the `starts_with('/')` refusal).
    #[test]
    fn a_unix_socket_host_is_refused_in_every_url_form() {
        let e = Config::parse("postgres://u@%2Fvar%2Frun%2Fpostgresql/d").unwrap_err();
        assert!(e.to_string().contains("Unix-socket"), "{e}");
        let e = Config::parse("postgres://u@/d?host=/tmp").unwrap_err();
        assert!(e.to_string().contains("Unix-socket"), "{e}");
        let e = Config::parse("postgres://u@db1,%2Ftmp/d").unwrap_err();
        assert!(e.to_string().contains("Unix-socket"), "{e}");
    }

    /// 1.5.5 dialled `hostaddr` and used `host` only as a name, so a socket-path host beside a
    /// hostaddr worked; the Unix-socket refusal is of what is DIALLED (RED before: refused).
    #[test]
    fn a_socket_path_host_beside_a_hostaddr_is_dialled_by_address() {
        let c = Config::parse("host=/tmp hostaddr=127.0.0.1 user=u").unwrap();
        assert_eq!(c.targets(), [("127.0.0.1", "127.0.0.1:5432".to_string())]);
        let c = Config::parse("postgres://u@%2Ftmp/d?hostaddr=127.0.0.1").unwrap();
        assert_eq!(c.targets(), [("127.0.0.1", "127.0.0.1:5432".to_string())]);
        assert!(Config::parse("host=/tmp user=u").is_err());
    }

    /// D28 (RED before: `ranges[i]` indexed out of bounds, a panic): a DataRow with fewer fields
    /// than the RowDescription named columns is an error on the missing column, not a panic.
    #[test]
    fn a_data_row_short_of_its_columns_is_an_error_not_a_panic() {
        use bytes::BytesMut;
        use fallible_iterator::FallibleIterator;
        use postgres_protocol::message::backend::Message;
        use postgres_types::Type;
        use std::sync::Arc;

        // A DataRow of ONE field ("ab") against a RowDescription of two columns.
        let mut raw = BytesMut::from(&b"D\0\0\0\x0c\0\x01\0\0\0\x02ab"[..]);
        let Some(Message::DataRow(body)) = Message::parse(&mut raw).unwrap() else {
            panic!("a data row");
        };
        let column = |name: &str| super::Column {
            name: name.to_string(),
            type_: Type::TEXT,
        };
        let columns: Arc<[super::Column]> = vec![column("a"), column("b")].into();
        let mut ranges = Vec::new();
        let mut it = body.ranges();
        while let Some(r) = it.next().unwrap() {
            ranges.push(r);
        }
        let row = super::Row {
            columns,
            body,
            ranges,
        };
        assert_eq!(row.try_get::<_, &str>(0).unwrap(), "ab");
        let e = row.try_get::<_, &str>(1).unwrap_err();
        assert!(e.to_string().contains("column 1"), "{e}");
    }

    #[test]
    fn a_snapshot_transaction_begins_repeatable_read() {
        assert_eq!(
            begin_sql(Some(IsolationLevel::RepeatableRead)),
            "BEGIN ISOLATION LEVEL REPEATABLE READ"
        );
        assert_eq!(begin_sql(None), "BEGIN");
    }
}
