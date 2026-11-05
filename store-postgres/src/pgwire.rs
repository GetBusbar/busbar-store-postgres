// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Postgres frontend protocol over the host's connector: a small async client whose every byte
//! goes through the op's one connection ([`Wire`], the store SDK's `wire`), so this store opens no
//! socket of its own.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use postgres_protocol::authentication::sasl;
use postgres_protocol::message::backend::{DataRowBody, ErrorResponseBody, Message};
use postgres_protocol::message::frontend;
use postgres_types::{FromSql, Kind, ToSql, Type};

use busbar_contract::abi::sdk::chip::pg_scram_nonce;
use busbar_contract::abi::sdk::cred::{CredUrl, PgAuth, RequireAuth, Seal};
use busbar_contract::abi::sdk::store::wire::Wire;

mod receive;
use receive::ReceiveBuffer;

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
    /// Public connection text and SDK-sealed passwords, including redaction aliases.
    credentials: CredUrl,
    pub dbname: Option<String>,
    pub application_name: Option<String>,
    pub options: Option<String>,
    pub ssl: SslMode,
    /// `connect_timeout` in milliseconds (whole seconds in the string, as the driver read it);
    /// `None` = unset (the default bound); `Some(0)` = no store handshake bound, host dial default.
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

/// Why a nondefault socket-tuning request cannot be honoured.
const FIXED_SOCKET_POLICY: &str =
    "the host's connector dials every connection with TCP keepalive on, \
                            probing after 60 s idle at the OS's interval and count, and has no \
                            per-store setting for it";

/// The most a message may declare: Postgres' own ceiling on a value (1 GiB) plus the four bytes
/// of the length word, which the declared length counts.
const MAX_MESSAGE_LEN: u32 = (1 << 30) + 4;
const MAX_CONTROL_MESSAGE_LEN: u32 = 30_000;

fn message_limit(tag: u8, authenticated: bool) -> u32 {
    if authenticated && matches!(tag, b'D' | b'E' | b'N' | b'A' | b'd') {
        MAX_MESSAGE_LEN
    } else {
        MAX_CONTROL_MESSAGE_LEN
    }
}

/// The handshake bound when the DSN has no `connect_timeout`.
const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 30_000;

impl Config {
    /// The store handshake/dial override, in milliseconds (0 = host dial default; no handshake bound).
    fn connect_bound_ms(&self) -> u32 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS)
    }

    /// Parse a libpq connection string: `postgres[ql]://user:pass@host:port/db?key=value&...` or
    /// `host=... port=... user=... password=... dbname=... sslmode=...`.
    pub fn parse(s: &str) -> Result<Self, Error> {
        Self::captured(CredUrl::parse_postgres(s).map_err(config_err)?)
    }

    /// Parse only public connection text, after the SDK has captured every password spelling.
    pub(crate) fn captured(captured: CredUrl) -> Result<Self, Error> {
        let public = captured.parsed().map_err(config_err)?.to_owned();
        let s = public.as_str();
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
                pairs.push(("user".into(), decode(u)?));
            }
            if !hostport.is_empty() {
                let (mut hosts, mut ports) = (Vec::new(), Vec::new());
                for one in hostport.split(',') {
                    let (host, port) = if let Some(v6) = one.strip_prefix('[') {
                        match v6.split_once(']') {
                            Some((h, rest)) => {
                                let port = if rest.is_empty() {
                                    None
                                } else {
                                    Some(rest.strip_prefix(':').ok_or_else(|| {
                                        config_err("unexpected text after bracketed IPv6 host")
                                    })?)
                                };
                                (h.to_string(), port)
                            }
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
                    let (k, v) = kv.split_once('=').ok_or_else(|| {
                        config_err("invalid query parameter (expected key=value)")
                    })?;
                    pairs.push((decode(k)?, decode(v)?));
                }
            }
        } else {
            pairs = keywords(s)?;
        }
        let has_password = captured.password().is_some();
        let mut c = Config {
            endpoints: Vec::new(),
            user: String::new(),
            credentials: captured,
            dbname: None,
            application_name: None,
            options: None,
            ssl: SslMode::Plain,
            connect_timeout_ms: None,
            target_session_attrs: SessionAttrs::Any,
        };
        let (mut hosts, mut hostaddrs, mut ports) = (None, None, String::new());
        for (k, v) in pairs {
            if matches!(
                k.as_str(),
                "user" | "dbname" | "application_name" | "options"
            ) && v.as_bytes().contains(&0)
            {
                return Err(config_err(format!("NUL byte in startup option `{k}`")));
            }
            match k.as_str() {
                "host" => hosts = Some(v),
                "hostaddr" => hostaddrs = Some(v),
                "port" => ports = v,
                "user" => c.user = v,

                "password" => return Err(config_err("password was not captured")),
                "require_auth" => {
                    RequireAuth::parse(&v).map_err(config_err)?;
                }
                "dbname" => c.dbname = Some(v),
                "application_name" => c.application_name = Some(v),
                "options" => c.options = Some(v),
                "sslmode" => {
                    c.ssl = match v.as_str() {
                        "disable" | "allow" => SslMode::Plain,
                        "prefer" => SslMode::Prefer,
                        "require" | "verify-ca" | "verify-full" => SslMode::Require,
                        _ => {
                            return Err(config_err("invalid value for option `sslmode`"));
                        }
                    }
                }

                "connect_timeout" => {
                    let secs: i64 = v.parse().map_err(|_| {
                        config_err(
                            "invalid value for option `connect_timeout` (a whole number of \
                             seconds; 0 or less means no bound)",
                        )
                    })?;

                    c.connect_timeout_ms = Some(if secs > 0 {
                        u32::try_from(secs.saturating_mul(1000)).unwrap_or(u32::MAX)
                    } else {
                        0
                    });
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

                "sslrootcert" => {
                    return Err(config_err(
                        "sslrootcert is not supported: the connection is verified against \
                         busbar's trust anchors, not a per-store root certificate",
                    ));
                }

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

                "keepalives_idle" | "keepalives_interval" | "tcp_user_timeout" => {
                    let n: i64 = v
                        .parse()
                        .map_err(|_| config_err(format!("invalid value for option `{k}`")))?;

                    let applied = n <= 0 || (k == "keepalives_idle" && n == KEEPALIVE_IDLE_SECS);
                    if !applied {
                        return Err(config_err(format!(
                            "nondefault `{k}` is not supported: {FIXED_SOCKET_POLICY}"
                        )));
                    }
                }
                "keepalives_count" | "keepalives_retries" => {
                    let n: u32 = v
                        .parse()
                        .map_err(|_| config_err(format!("invalid value for option `{k}`")))?;
                    if n != 0 {
                        return Err(config_err(format!(
                            "nondefault `{k}` is not supported: {FIXED_SOCKET_POLICY}"
                        )));
                    }
                }

                "load_balance_hosts" => match v.as_str() {
                    "disable" => {}
                    "random" => {
                        return Err(config_err(
                            "load_balance_hosts=random is not supported: the endpoints are tried \
                             in the order given, the one that last connected first; this store \
                             does not shuffle them",
                        ));
                    }
                    _ => return Err(config_err("invalid value for option `load_balance_hosts`")),
                },

                "sslnegotiation" => match v.as_str() {
                    "postgres" => {}
                    "direct" => {
                        return Err(config_err(
                            "sslnegotiation=direct is not supported: this store asks for TLS with \
                             an SSLRequest (sslnegotiation=postgres); sslmode still decides \
                             whether the connection is secured",
                        ));
                    }
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

    /// Scrub a peer's echoed password without exposing the sealed credential to the store.
    pub(crate) fn redact(&self, text: String) -> String {
        let text = zeroize::Zeroizing::new(text);
        self.credentials.redact_echo(&text)
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
/// per endpoint; a hostaddr is the address to dial (an IP) and its host the name.
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
pub(super) fn keywords(s: &str) -> Result<Vec<(String, String)>, Error> {
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
    fn parse(body: &ErrorResponseBody) -> Result<Self, Error> {
        let mut e = DbError {
            severity: String::new(),
            code: SqlState(String::new()),
            message: String::new(),
            constraint: None,
        };
        let mut has_message = false;
        let mut fields = body.fields();
        while let Some(f) = fields.next().map_err(parse_err)? {
            let v = String::from_utf8_lossy(f.value_bytes()).into_owned();
            match f.type_() {
                b'S' => e.severity = v,
                b'C' => e.code = SqlState(v),
                b'M' => {
                    has_message = true;
                    e.message = v;
                }
                b'n' => e.constraint = Some(v),
                _ => {}
            }
        }
        if e.code.0.len() != 5
            || !e
                .code
                .0
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || e.severity.is_empty()
            || !has_message
        {
            return Err(parse_err(
                "malformed ErrorResponse: missing or invalid required fields",
            ));
        }
        Ok(e)
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

    fn response(body: &ErrorResponseBody) -> Self {
        match DbError::parse(body) {
            Ok(error) => Self::new(Kind_::Db(error)),
            Err(error) => error,
        }
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
            Kind_::FromSql(name, c) => write!(f, "error deserializing column `{name}`: {c}"),
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
/// is left unread and no transaction awaits its rollback.
pub struct Client {
    wire: Wire,
    authenticated: bool,
    credentials: CredUrl,
    buf: ReceiveBuffer,
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

fn auth_err(why: impl fmt::Display) -> Error {
    Error::new(Kind_::Authentication(why.to_string()))
}

/// Keep postgres-protocol's ordered, extension-free server-first grammar and its 100,000
/// iteration ceiling.
fn scram_server_first(bytes: &[u8]) -> Result<&str, Error> {
    let bad = || auth_err("malformed SCRAM server-first message");
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let mut attrs = text.split(',');
    let nonce = attrs
        .next()
        .and_then(|a| a.strip_prefix("r="))
        .ok_or_else(bad)?;
    let salt = attrs
        .next()
        .and_then(|a| a.strip_prefix("s="))
        .ok_or_else(bad)?;
    let iterations = attrs
        .next()
        .and_then(|a| a.strip_prefix("i="))
        .ok_or_else(bad)?;
    if attrs.next().is_some()
        || !nonce
            .bytes()
            .all(|b| matches!(b, b'!'..=b'+' | b'-'..=b'~'))
        || !salt.bytes().all(scram_base64)
        || !iterations
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_digit() && *b != b'0')
        || !iterations.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    let iterations: u32 = iterations.parse().map_err(|_| bad())?;
    if iterations > 100_000 {
        return Err(auth_err(
            "SCRAM iteration count exceeds the maximum allowed",
        ));
    }
    Ok(text)
}

fn scram_base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'=')
}

/// No ambiguous attributes: the server-final is one verifier or one refusal. Peer-provided
/// refusal text is withheld because it may echo credential material.
fn scram_server_final(bytes: &[u8]) -> Result<&str, Error> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| auth_err("malformed SCRAM server-final message"))?;
    if let Some(error) = text.strip_prefix("e=") {
        if !error.contains(['\0', '=', ',']) {
            return Err(auth_err("the server refused SCRAM authentication"));
        }
    } else if text
        .strip_prefix("v=")
        .is_some_and(|v| v.bytes().all(scram_base64))
    {
        return Ok(text);
    }
    Err(auth_err("malformed SCRAM server-final message"))
}

/// A parameter.
pub type Param<'a> = &'a (dyn ToSql + Sync);

impl Client {
    fn response(&self, body: &ErrorResponseBody) -> Error {
        let mut error = Error::response(body);
        if let Kind_::Db(db) = &mut *error.0 {
            let message = zeroize::Zeroizing::new(std::mem::take(&mut db.message));
            db.message = self.credentials.redact_echo(&message);
            if let Some(constraint) = db.constraint.take() {
                let constraint = zeroize::Zeroizing::new(constraint);
                db.constraint = Some(self.credentials.redact_echo(&constraint));
            }
            let severity = zeroize::Zeroizing::new(std::mem::take(&mut db.severity));
            db.severity = self.credentials.redact_echo(&severity);
        }
        error
    }

    /// Connect over `wire` (its need 0) to the server `cfg` names, secure the connection when
    /// `cfg` asks, and authenticate.
    pub async fn connect(
        wire: Wire,
        cfg: &Config,
        preferred: &AtomicUsize,
    ) -> Result<Client, Error> {
        let n = cfg.endpoints.len();
        let first = preferred.load(Ordering::Relaxed);
        let first = if first < n { first } else { 0 };
        let mut failures: Vec<(usize, Error)> = Vec::new();
        for i in std::iter::once(first).chain((0..n).filter(|i| *i != first)) {
            match Self::attempt(&wire, cfg, &cfg.endpoints[i]).await {
                Ok(c) => {
                    preferred.store(i, Ordering::Relaxed);
                    return Ok(c);
                }
                Err(e) => {
                    wire.unbound();
                    wire.close().await;
                    failures.push((i, e));
                }
            }
        }

        if failures.len() > 1 {
            let joined: Vec<String> = failures
                .iter()
                .map(|(i, e)| {
                    let ep = &cfg.endpoints[*i];
                    format!("{}:{}: {}", ep.name, ep.port, crate::render_pg_error(e))
                })
                .collect();
            return Err(Error::connect(joined.join("; ")));
        }
        Err(failures
            .pop()
            .map_or_else(|| config_err("no server to connect to"), |(_, e)| e))
    }

    /// One endpoint's connect: dial, secure, authenticate, check the session's kind.
    async fn attempt(wire: &Wire, cfg: &Config, endpoint: &Endpoint) -> Result<Client, Error> {
        let ms = cfg.connect_bound_ms();
        wire.connect_timed(0, Some(&target(&endpoint.dial, endpoint.port)), ms)
            .await
            .map_err(Error::connect)?;
        let reused = wire.reused();

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
            authenticated: reused,
            credentials: cfg.credentials.clone(),
            buf: ReceiveBuffer::default(),
            rollback_pending: false,
            status: b'I',
            at_ready: true,
            keep: false,
            statements,
        };
        if reused {
            return Ok(c);
        }
        if ms > 0 {
            wire.bound(ms);
        }
        c.handshake(cfg, endpoint).await?;
        c.authenticated = true;
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
            cfg.credentials
                .password()
                .ok_or_else(|| config_err("password missing"))
        };
        let mut authenticated = false;
        loop {
            match self.read().await? {
                Message::AuthenticationOk => {
                    if !authenticated && !cfg.credentials.floor().pg().allows(PgAuth::None) {
                        return Err(auth_err(
                            "require_auth does not allow authentication method none",
                        ));
                    }
                    break;
                }
                Message::AuthenticationCleartextPassword => {
                    let message = password()?.pg_password_message().map_err(auth_err)?;
                    self.send_sealed(message).await?;
                    authenticated = true;
                }
                Message::AuthenticationMd5Password(b) => {
                    let message = password()?
                        .pg_md5_message(&cfg.user, b.salt())
                        .map_err(auth_err)?;
                    self.send_sealed(message).await?;
                    authenticated = true;
                }
                Message::AuthenticationSasl(b) => {
                    let mut scram = false;
                    let mut mechs = b.mechanisms();
                    while let Some(m) = mechs.next().map_err(parse_err)? {
                        scram |= m == sasl::SCRAM_SHA_256;
                    }
                    if !scram {
                        return Err(auth_err("unsupported SASL mechanism"));
                    }
                    let password = password()?;
                    if !password.floor().pg().allows(PgAuth::ScramSha256) {
                        return Err(auth_err("require_auth does not allow SCRAM-SHA-256"));
                    }

                    let first_bare = format!("n=,r={}", pg_scram_nonce().map_err(auth_err)?);
                    let first = format!("n,,{first_bare}");
                    let mut out = BytesMut::new();
                    frontend::sasl_initial_response(
                        sasl::SCRAM_SHA_256,
                        first.as_bytes(),
                        &mut out,
                    )
                    .map_err(parse_err)?;
                    self.send(&out).await?;
                    let Message::AuthenticationSaslContinue(cont) = self.read_auth().await? else {
                        return Err(parse_err("unexpected message during SASL"));
                    };
                    let server_first = scram_server_first(cont.data())?;
                    let (message, link) = password
                        .pg_scram_sha256_postgres(&first_bare, server_first, b"n,,")
                        .map_err(auth_err)?;
                    self.send_sealed(message).await?;
                    let Message::AuthenticationSaslFinal(fin) = self.read_auth().await? else {
                        return Err(parse_err("unexpected message during SASL"));
                    };
                    let server_final = scram_server_final(fin.data())?;
                    if !link.verify(server_final) {
                        return Err(auth_err("SCRAM verification error"));
                    }
                    authenticated = true;
                }
                Message::ErrorResponse(e) => return Err(self.response(&e)),
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
                Message::ErrorResponse(e) => return Err(self.response(&e)),
                _ => {}
            }
        }
    }

    /// An authentication message, a server failure answered as one.
    async fn read_auth(&mut self) -> Result<Message, Error> {
        match self.read().await? {
            Message::ErrorResponse(e) => Err(self.response(&e)),
            m => Ok(m),
        }
    }

    /// Whether the session is idle and whole: fit to be kept for the next op.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.at_ready && self.status == b'I' && !self.rollback_pending && self.buf.is_empty()
    }

    /// The op is done with the connection: keep it if the session is idle, else it is discarded
    /// when the client drops.
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

    /// A whole credential-bearing frame stays inside the SDK through partial writes and Pending.
    async fn send_sealed(&mut self, message: Seal) -> Result<(), Error> {
        self.at_ready = false;
        self.wire
            .write_sealed(message)
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
            buf.append(i);
            zeroize::Zeroize::zeroize(i);
        });
        Ok(())
    }

    async fn read_byte(&mut self) -> Result<u8, Error> {
        while self.buf.is_empty() {
            self.more().await?;
        }
        let b = self.buf[0];
        self.buf.consume(1);
        Ok(b)
    }

    /// The next message the server sent; asynchronous notices and parameter changes skipped.
    async fn read(&mut self) -> Result<Message, Error> {
        loop {
            if let Some(h) = self.buf.get(1..5) {
                let len = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
                if len > message_limit(self.buf[0], self.authenticated) {
                    return Err(Error::new(Kind_::Parse(format!(
                        "protocol error: the server declared a message of {len} bytes (over the protocol message limit)"
                    ))));
                }
            }
            match self.buf.message().map_err(parse_err)? {
                Some(
                    Message::ParameterStatus(_)
                    | Message::NoticeResponse(_)
                    | Message::NotificationResponse(_),
                ) => {}
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
                    failed = Some(self.response(&e));
                }
                Ok(_) => {}

                Err(e) => return Err(failed.unwrap_or(e)),
            }
        }
        failed.map_or(Ok(()), Err)
    }

    /// Run `sql` (one or more statements, no parameters) through the simple query protocol.
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
    /// connection has prepared runs in one round trip; one it has not is prepared first.
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
                    let err = self.response(&e);

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
                    failed = Some(self.response(&e));
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
    pub async fn query(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Vec<Row>, Error> {
        self.run(sql, params).await.map(|(r, _)| r)
    }

    /// How many rows `sql` affected.
    pub async fn execute(&mut self, sql: &str, params: &[Param<'_>]) -> Result<u64, Error> {
        self.run(sql, params).await.map(|(_, n)| n)
    }

    /// The one row `sql` answers.
    pub async fn query_one(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Row, Error> {
        let mut rows = self.query(sql, params).await?;
        if rows.len() != 1 {
            return Err(Error::new(Kind_::RowCount));
        }
        Ok(rows.remove(0))
    }

    /// The row `sql` answers, if one.
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

/// The one simple-query batch that begins a transaction at `isolation` (`None` = READ COMMITTED,
/// stated, so a DSN's `default_transaction_isolation` cannot change what the store's statements
/// assume).
#[must_use]
pub fn begin_sql(isolation: Option<IsolationLevel>) -> &'static str {
    match isolation {
        None => {
            "BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '30s'; \
             SET LOCAL idle_in_transaction_session_timeout = '60s'"
        }
        Some(IsolationLevel::RepeatableRead) => {
            "BEGIN ISOLATION LEVEL REPEATABLE READ; SET LOCAL lock_timeout = '30s'; \
             SET LOCAL idle_in_transaction_session_timeout = '60s'"
        }
    }
}

/// A Bind frame counts parameters in an unsigned 16-bit field.
pub(crate) const MAX_BIND_PARAMETERS: usize = u16::MAX as usize;

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
    pub async fn commit(mut self) -> Result<(), Error> {
        self.done = true;
        self.client.batch_execute("COMMIT").await
    }

    /// Roll back, awaiting the server's completion before releasing this transaction's locks.
    pub async fn rollback(mut self) -> Result<(), Error> {
        self.client.batch_execute("ROLLBACK").await?;
        self.done = true;
        Ok(())
    }

    /// [`Client::batch_execute`] inside the transaction.
    pub async fn batch_execute(&mut self, sql: &str) -> Result<(), Error> {
        self.client.batch_execute(sql).await
    }

    /// [`Client::query`] inside the transaction.
    pub async fn query(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Vec<Row>, Error> {
        self.client.query(sql, params).await
    }

    /// [`Client::execute`] inside the transaction.
    pub async fn execute(&mut self, sql: &str, params: &[Param<'_>]) -> Result<u64, Error> {
        self.client.execute(sql, params).await
    }

    /// [`Client::query_one`] inside the transaction.
    pub async fn query_one(&mut self, sql: &str, params: &[Param<'_>]) -> Result<Row, Error> {
        self.client.query_one(sql, params).await
    }

    /// [`Client::query_opt`] inside the transaction.
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
