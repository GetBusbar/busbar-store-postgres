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

/// A parsed connection string (the URL or the libpq keyword form).
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub dbname: Option<String>,
    pub application_name: Option<String>,
    pub options: Option<String>,
    pub ssl: SslMode,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
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
                if hostport.contains(',') {
                    return Err(config_err("multiple hosts are not supported"));
                }
                let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
                    match v6.split_once(']') {
                        Some((h, rest)) => (h.to_string(), rest.strip_prefix(':')),
                        None => return Err(config_err("unterminated IPv6 host")),
                    }
                } else {
                    match hostport.rsplit_once(':') {
                        Some((h, p)) => (h.to_string(), Some(p)),
                        None => (hostport.to_string(), None),
                    }
                };
                if !host.is_empty() {
                    pairs.push(("host".into(), decode(&host)?));
                }
                if let Some(p) = port.filter(|p| !p.is_empty()) {
                    pairs.push(("port".into(), p.to_string()));
                }
            }
            if let Some(db) = path.filter(|p| !p.is_empty()) {
                pairs.push(("dbname".into(), decode(db)?));
            }
            if let Some(q) = query {
                for kv in q.split('&').filter(|kv| !kv.is_empty()) {
                    let (k, v) = kv
                        .split_once('=')
                        .ok_or_else(|| config_err(format!("invalid query parameter `{kv}`")))?;
                    pairs.push((decode(k)?, decode(v)?));
                }
            }
        } else {
            pairs = keywords(s)?;
        }
        let mut c = Config {
            host: String::new(),
            port: 5432,
            user: String::new(),
            password: None,
            dbname: None,
            application_name: None,
            options: None,
            ssl: SslMode::Plain,
        };
        for (k, v) in pairs {
            match k.as_str() {
                "host" | "hostaddr" => c.host = v,
                "port" => {
                    c.port = v
                        .parse()
                        .map_err(|_| config_err("invalid value for option `port`"))?;
                }
                "user" => c.user = v,
                "password" => c.password = Some(v),
                "dbname" => c.dbname = Some(v),
                "application_name" => c.application_name = Some(v),
                "options" => c.options = Some(v),
                "sslmode" => {
                    c.ssl = match v.as_str() {
                        "disable" | "allow" | "prefer" => SslMode::Plain,
                        "require" | "verify-ca" | "verify-full" => SslMode::Require,
                        _ => {
                            return Err(config_err("invalid value for option `sslmode`"));
                        }
                    }
                }
                // Accepted and served by the host instead: its deadlines bound every connect, and
                // its connector keeps the connection.
                "connect_timeout"
                | "keepalives"
                | "keepalives_idle"
                | "target_session_attrs"
                | "channel_binding"
                | "load_balance_hosts"
                | "tcp_user_timeout"
                | "keepalives_interval"
                | "keepalives_retries"
                | "sslrootcert"
                | "sslnegotiation" => {}
                _ => return Err(config_err(format!("unknown option `{k}`"))),
            }
        }
        if c.host.is_empty() {
            c.host = "localhost".into();
        }
        if c.host.starts_with('/') {
            return Err(config_err(
                "a Unix-socket host is not supported: the store reaches its server over TCP",
            ));
        }
        if c.user.is_empty() {
            return Err(config_err("user missing"));
        }
        Ok(c)
    }

    /// The `host:port` the store's need dials.
    #[must_use]
    pub fn target(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
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
            return Err(config_err(format!("unexpected EOF after `{key}`")));
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
        let raw = self.ranges[i].clone().map(|r| &self.body.buffer()[r]);
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
    /// `cfg` asks, and authenticate.
    ///
    /// # Errors
    /// The connector's failure (as a connect error), a TLS refusal, or the server's refusal.
    pub async fn connect(wire: Wire, cfg: &Config) -> Result<Client, Error> {
        wire.connect(0, Some(&cfg.target()))
            .await
            .map_err(Error::connect)?;
        let reused = wire.reused();
        let mut c = Client {
            wire,
            buf: BytesMut::new(),
            rollback_pending: false,
            status: b'I',
            at_ready: true,
            keep: false,
        };
        if reused {
            // A kept connection: secured and authenticated by the op that established it, and
            // idle when it was kept.
            return Ok(c);
        }
        if cfg.ssl == SslMode::Require {
            let mut out = BytesMut::new();
            frontend::ssl_request(&mut out);
            c.send(&out).await?;
            let answer = c.read_byte().await?;
            if answer != b'S' {
                return Err(Error::new(Kind_::Tls(
                    "server does not support TLS".to_string(),
                )));
            }
            c.wire
                .upgrade_secure(Some(&cfg.host))
                .await
                .map_err(|e| Error::new(Kind_::Tls(e.to_string())))?;
        }
        c.startup(cfg).await?;
        Ok(c)
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
    /// when the client drops.
    pub fn release(&mut self) {
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
            match self.read().await? {
                Message::ReadyForQuery(_) => break,
                Message::ErrorResponse(e) if failed.is_none() => {
                    failed = Some(Error::new(Kind_::Db(DbError::parse(&e))));
                }
                _ => {}
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
                    self.drain().await?;
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
            match self.read().await? {
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
        assert_eq!(c.target(), "db.internal:6543");
        assert_eq!(c.dbname.as_deref(), Some("busbar"));
        assert_eq!(c.ssl, SslMode::Require);
        assert_eq!(c.application_name.as_deref(), Some("bb"));
        let c = Config::parse("postgresql://u@[::1]/d").unwrap();
        assert_eq!(c.target(), "[::1]:5432");
        assert_eq!(c.password, None);
    }

    #[test]
    fn the_keyword_form_parses_with_spaces_and_quotes() {
        let c =
            Config::parse("host = db port=5433 user=u password='se cret' dbname=x sslmode=prefer")
                .unwrap();
        assert_eq!(c.target(), "db:5433");
        assert_eq!(c.password.as_deref(), Some("se cret"));
        assert_eq!(c.ssl, SslMode::Plain);
    }

    #[test]
    fn what_the_host_cannot_dial_is_refused() {
        assert!(Config::parse("host=/var/run/postgresql user=u").is_err());
        assert!(Config::parse("host=db").is_err(), "no user");
        assert!(Config::parse("host=db user=u bogus=1").is_err());
        assert!(Config::parse("host=db user=u sslmode=sometimes").is_err());
        assert!(Config::parse("postgres://u@a,b/d").is_err());
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
