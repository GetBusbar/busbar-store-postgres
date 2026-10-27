// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres** backend for busbar's durable governance store: the shared, multi-node store.
//! Serves the store kind's table (`StoreSlots`) over the HOST'S CONNECTOR: every op runs on the
//! instance's kept connection as straight-line async code (`pgwire`, the Postgres frontend protocol
//! over the store SDK's `wire`), so the store opens no socket of its own and no op blocks a thread.
//! It depends only on `busbar-contract` (plus the sans-IO `postgres-protocol`/`postgres-types`
//! codec). One door (`store_door!` in `v3`): linked into a build as `door`, or dropped in as the
//! sibling plugin cdylib. Schema history: see `SCHEMA_VERSION`.
//!
//! ## Connections
//!
//! One kept connection ([`KEPT_CONNECTIONS`] = 1), so ops take turns on it as they took 1.5.x's
//! mutex. `open`'s connect step dials through the host (one declared `tcp` need), authenticates
//! (SCRAM-SHA-256, md5 or cleartext) and ensures the schema, so an unreachable or refusing server
//! fails the load. A connection is kept only while its session is idle; one that failed or was left
//! mid-transaction is closed and the next op connects afresh.
//!
//! ## Known limitations
//!
//! - `sslmode=require` / `verify-ca` / `verify-full` secure the connection through the host's
//!   connector and ALWAYS verify the certificate and name (libpq's `require` would not); a server
//!   answering the `SSLRequest` with `N` fails the load. `disable`, `allow` and `prefer` connect in
//!   plaintext, as 1.5.x did.
//! - No partitioning, LISTEN/NOTIFY-accelerated hydration or column-level secret grants: all three
//!   are internal and can be added without a schema bump.

#![forbid(unsafe_code)]

mod pgwire;

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStoreError,
    RecordStoreResult, ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey, UNIT_CACHE_READ,
    UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use pgwire::{Client, Row, Transaction};
use postgres_types::ToSql;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;

// postgres driver error -> the api's backend-agnostic `RecordStoreError` (the contract crate stays
// storage-free, so the `From` impl that powers `?` cannot live there).
trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, pgwire::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(render_pg_error(&e)))
    }
}

/// Render a driver error with its CAUSE: `Display` for a server-side failure is just "db error".
/// The server's `detail` is deliberately omitted (on a unique violation it holds ROW VALUES).
fn render_pg_error(e: &pgwire::Error) -> String {
    match e.as_db_error() {
        Some(db) => {
            let mut out = format!("{}: {}", db.code().code(), db.message());
            if let Some(constraint) = db.constraint() {
                out.push_str(&format!(" (constraint {constraint})"));
            }
            out
        }
        None => e.to_string(),
    }
}

/// True when a postgres error is SQLSTATE 42P01 (`undefined_table`), the ONE case `migrate()` reads
/// as an unversioned database; any other class must never be read as "fresh" and drop a populated one.
fn is_undefined_table(e: &pgwire::Error) -> bool {
    e.code().map(pgwire::SqlState::code) == Some(pgwire::SqlState::UNDEFINED_TABLE)
}

/// Extract the PASSWORD from a Postgres DSN. Supports both the URL form
/// (`postgres://user:pass@host:5432/db`) and the libpq keyword form (`... password=secret ...`), so
/// a connect-error string can be scrubbed of the secret regardless of which shape the operator used.
fn dsn_password(dsn: &str) -> Option<String> {
    if let Some(rest) = dsn.split("://").nth(1) {
        if let Some((userinfo, _)) = rest.rsplit_once('@') {
            if let Some((_, pass)) = userinfo.split_once(':') {
                if !pass.is_empty() {
                    return Some(pass.to_string());
                }
            }
        }
    }
    // The URL QUERY-PARAMETER form (`?password=secret`) skips the userinfo branch above.
    if let Some((_, query)) = dsn.split_once('?') {
        for param in query.split('&') {
            if let Some(v) = param.strip_prefix("password=") {
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    // The libpq KEYWORD form tolerates whitespace around `=` and single-quoted values, so collapse
    // the whitespace first and match the key only at a token boundary (`sslpassword=` is another option).
    let normalized = collapse_around_equals(dsn);
    let mut search = normalized.as_str();
    while let Some(at) = search.find("password=") {
        let at_token_start = at == 0
            || search[..at]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace);
        let rest = &search[at + "password=".len()..];
        if at_token_start {
            let value = match rest.strip_prefix('\'') {
                Some(quoted) => quoted.split('\'').next().unwrap_or(""),
                None => rest.split_whitespace().next().unwrap_or(""),
            };
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        search = rest;
    }
    None
}

/// Remove whitespace immediately before and after every `=`, so `key = value` and `key=value`
/// scan identically. Only used by `dsn_password`.
fn collapse_around_equals(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            // Whitespace that only separates a key from its `=` is not a token boundary.
            if !(j < chars.len() && chars[j] == '=') {
                out.push(' ');
            }
            i = j;
            continue;
        }
        if c == '=' {
            out.push('=');
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Percent-DECODE a URL component (`%40` -> `@`). A malformed escape is left verbatim. So the scrub
/// redacts BOTH the raw and decoded forms of a URL-embedded password.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Replace every occurrence of `secret` (in BOTH raw and percent-decoded forms) with `<redacted>`.
fn scrub(msg: String, secret: Option<&str>) -> String {
    let Some(s) = secret.filter(|s| !s.is_empty()) else {
        return msg;
    };
    let mut out = msg;
    if out.contains(s) {
        out = out.replace(s, "<redacted>");
    }
    let decoded = percent_decode(s);
    if decoded != s && !decoded.is_empty() && out.contains(&decoded) {
        out = out.replace(&decoded, "<redacted>");
    }
    out
}

/// Store schema version. The last release (1.5.x) is v6; a pre-v5 database is dropped and recreated
/// (1.5.0 was unreleased).
/// - v6: one-time backfill of `usage_windows.billable_requests` where it is 0 beside nonzero
///   `requests`, gated on the crossing: the shape is also what a fully refunded window looks like,
///   so repeating it would re-bill refunds.
/// - v7-v9 (dev builds only): typed task/mcp tables, never read or dropped by v10.
/// - v10 (1.6.0), in place and additive: `keys` gains `idp_subject`/`binding_mode`/`minted_by`/
///   `idp_provider`/`allowed_scopes_by_kind`; open usage units get `usage_ledger_units` and
///   `usage_metering_units`; `usage_metering.priced_from_ms` joins its key; the kind-tagged
///   `plane_records`, `plane_chain` and `plane_tokens`.
/// - v11: `store_ops` (the durable `op_id` dedupe log) and `store_records`.
/// - v13: the tables of the deleted money, journal and session slots go, with their dedupe rows.
const SCHEMA_VERSION: i64 = 13;

/// The plane-record kinds whose retention is TERMINAL-ONLY: `purge_plane_records_before` drops a
/// row of one only once its `disposition` is `Terminal` (an interrupted task waiting on a human sits
/// still longest). Every other kind drops any row older than the cutoff.
const TERMINAL_ONLY_RETENTION_KINDS: [&str; 1] = ["task"];

/// `(parent kind, child kind)`: purging a parent takes the child CHAIN hanging off it in the same
/// transaction (a task's event chain has no retention path of its own).
const PLANE_CHILD_KINDS: [(&str, &str); 1] = [("task", "task_event")];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS busbar_schema (
    version BIGINT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS store_revision (
    only_row BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (only_row),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
INSERT INTO store_revision (only_row, revision) VALUES (TRUE, 0) ON CONFLICT (only_row) DO NOTHING;

CREATE TABLE IF NOT EXISTS keys (
    id              TEXT PRIMARY KEY,
    -- Rotation fingerprint, not a lookup key: deliberately not UNIQUE.
    generation_hash TEXT NOT NULL,
    name            TEXT NOT NULL,
    -- NULL = pool grant omitted = all pools; a JSON array (even empty) = exhaustive.
    allowed_pools   TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      BIGINT NOT NULL,
    key_group       TEXT,
    labels          TEXT NOT NULL DEFAULT '{}',
    expires_at      BIGINT,
    -- Tombstone marker; NULL = live.
    deleted_at      BIGINT,
    revision        BIGINT NOT NULL DEFAULT 0,
    idp_subject     TEXT,
    binding_mode    TEXT,
    minted_by       TEXT,
    idp_provider    TEXT,
    -- Non-pool scope grants, {kind: [value, ...]}; NULL in BOTH grant columns is the wildcard.
    allowed_scopes_by_kind TEXT,
    CONSTRAINT keys_tombstone_disabled CHECK (deleted_at IS NULL OR enabled = FALSE)
);
CREATE INDEX IF NOT EXISTS idx_keys_revision ON keys (revision);

-- Row-looked-up credentials only (sigv4); slot allows two rows per (key_id, kind) for rotation.
CREATE TABLE IF NOT EXISTS credentials (
    id            TEXT PRIMARY KEY,
    key_id        TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('sigv4')),
    slot          SMALLINT NOT NULL CHECK (slot IN (0, 1)),
    public_id     TEXT NOT NULL,
    secret        TEXT,
    secret_form   TEXT NOT NULL CHECK (secret_form IN ('none', 'recoverable', 'digest')),
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    expires_at    BIGINT,
    revoked_at    BIGINT,
    revoke_reason TEXT,
    revision      BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT credentials_public_id_uniq UNIQUE (kind, public_id),
    CONSTRAINT credentials_slot_uniq UNIQUE (key_id, kind, slot),
    CONSTRAINT credentials_secret_form_matches CHECK ((secret_form = 'none') = (secret IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_credentials_revision ON credentials (revision);
CREATE INDEX IF NOT EXISTS idx_credentials_key_id ON credentials (key_id);

CREATE TABLE IF NOT EXISTS usage_windows (
    bucket_id    TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    requests     BIGINT NOT NULL DEFAULT 0,
    billable_requests BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start)
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    bucket_id          TEXT NOT NULL,
    window_start       BIGINT NOT NULL,
    model              TEXT NOT NULL,
    tokens_input       BIGINT NOT NULL DEFAULT 0,
    tokens_output      BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read  BIGINT NOT NULL DEFAULT 0,
    tokens_cache_write BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start, model)
);
-- Open unit classes of a ledger row (the four reserved token classes keep their columns).
CREATE TABLE IF NOT EXISTS usage_ledger_units (
    bucket_id    TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    model        TEXT NOT NULL,
    unit         TEXT COLLATE \"C\" NOT NULL,
    count        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start, model, unit)
);
CREATE TABLE IF NOT EXISTS usage_metering (
    key_id             TEXT NOT NULL,
    bucket             BIGINT NOT NULL,
    model              TEXT NOT NULL,
    provider           TEXT NOT NULL,
    tokens_input       BIGINT NOT NULL DEFAULT 0,
    tokens_output      BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read  BIGINT NOT NULL DEFAULT 0,
    tokens_cache_write BIGINT NOT NULL DEFAULT 0,
    requests           BIGINT NOT NULL DEFAULT 0,
    billable_requests  BIGINT NOT NULL DEFAULT 0,
    key_group_at_use   TEXT NOT NULL DEFAULT '',
    pricing_version    TEXT NOT NULL DEFAULT '',
    -- Start of the rate-card entry this row accrued under; part of the key.
    priced_from_ms     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms)
);
CREATE INDEX IF NOT EXISTS idx_usage_metering_bucket ON usage_metering (bucket);
-- Open unit classes of a metering row.
CREATE TABLE IF NOT EXISTS usage_metering_units (
    key_id         TEXT NOT NULL,
    bucket         BIGINT NOT NULL,
    model          TEXT NOT NULL,
    provider       TEXT NOT NULL,
    priced_from_ms BIGINT NOT NULL DEFAULT 0,
    unit           TEXT COLLATE \"C\" NOT NULL,
    count          BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms, unit)
);
CREATE INDEX IF NOT EXISTS idx_usage_metering_units_bucket ON usage_metering_units (bucket);
CREATE TABLE IF NOT EXISTS audit_log (
    seq       BIGINT PRIMARY KEY,
    ts        BIGINT NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    principal TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS denylist (
    sub        TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0
);

-- The kind-tagged plane records: an OPAQUE body plus the typed sidecar columns (kind, id, parent,
-- seq, ts, disposition) this store keys, orders and sweeps on; it never decodes a body.
-- COLLATE \"C\" on every identity column is byte-exact comparison: a non-deterministic ICU collation
-- would otherwise collide ids differing only in case and fold a single-use token onto its variant.

-- UPSERTED records (a task, a demotion, a push configuration, ...): one current row per (kind, id).
CREATE TABLE IF NOT EXISTS plane_records (
    kind        TEXT COLLATE \"C\" NOT NULL,
    id          TEXT COLLATE \"C\" NOT NULL,
    parent      TEXT COLLATE \"C\",
    seq         BIGINT NOT NULL DEFAULT 0,
    ts          BIGINT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('active', 'terminal')),
    body        BYTEA NOT NULL,
    PRIMARY KEY (kind, id)
);
-- The retention sweep's access path: purge_plane_records_before filters on (kind, ts).
CREATE INDEX IF NOT EXISTS plane_records_kind_ts_idx ON plane_records (kind, ts);
CREATE INDEX IF NOT EXISTS plane_records_kind_parent_idx ON plane_records (kind, parent);

-- APPENDED chains, append-only by (kind, parent, seq): identical is a retry, different is a fork.
CREATE TABLE IF NOT EXISTS plane_chain (
    kind        TEXT COLLATE \"C\" NOT NULL,
    parent      TEXT COLLATE \"C\" NOT NULL,
    seq         BIGINT NOT NULL,
    id          TEXT COLLATE \"C\" NOT NULL,
    ts          BIGINT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('active', 'terminal')),
    body        BYTEA NOT NULL,
    PRIMARY KEY (kind, parent, seq)
);
CREATE INDEX IF NOT EXISTS plane_chain_kind_ts_idx ON plane_chain (kind, ts);

-- The single-use token ledger behind redeem_plane_token, one for the whole fleet.
CREATE TABLE IF NOT EXISTS plane_tokens (
    kind       TEXT COLLATE \"C\" NOT NULL,
    token      TEXT COLLATE \"C\" NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (kind, token)
);

-- The durable op_id dedupe log (abi::store S1-S4). Every u64 is kept bit-for-bit in a BIGINT.
CREATE TABLE IF NOT EXISTS store_ops (
    op_id       BYTEA PRIMARY KEY,
    body        TEXT NOT NULL,
    answer      TEXT NOT NULL,
    recorded_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS store_ops_recorded_at_idx ON store_ops (recorded_at);
-- A plane's kernel-held records, scanned in key (byte) order.
CREATE TABLE IF NOT EXISTS store_records (
    schema_id TEXT COLLATE \"C\" NOT NULL,
    key       BYTEA NOT NULL,
    value     BYTEA NOT NULL,
    PRIMARY KEY (schema_id, key)
);
";

/// The v10 column additions on tables a 1.5.x database already has (idempotent).
const MIGRATE_V10_COLUMNS: &str = "
ALTER TABLE keys ADD COLUMN IF NOT EXISTS idp_subject TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS binding_mode TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS minted_by TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS idp_provider TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS allowed_scopes_by_kind TEXT;
ALTER TABLE usage_metering ADD COLUMN IF NOT EXISTS priced_from_ms BIGINT NOT NULL DEFAULT 0;
";

/// Postgres `Store` backend (durable, shared across a cluster): the parsed connection settings and
/// the kept connection, reached over the host's connector, so the store opens no socket of its own.
/// The schema is ensured once, by `open`'s connect step.
pub struct PostgresStore {
    shared: std::sync::Arc<Shared>,
}

/// How many connections an instance keeps: the 1.5.5 store held exactly one.
pub const KEPT_CONNECTIONS: usize = 1;

/// What every op of one instance shares.
pub(crate) struct Shared {
    /// The connection settings.
    pub(crate) config: pgwire::Config,
    /// The DSN's password, scrubbed from every connect-error text.
    pub(crate) secret: Option<String>,
    /// When this instance last swept `store_ops` past its retention (`v3`).
    pub(crate) ops_swept_at: AtomicU64,
    /// The instance's KEPT connections (ARCHITECT ruling 2026-10-03, STORE-KEEP): bounded at ONE,
    /// the 1.5.5 store's one mutex-guarded connection (it had no pool setting). An op waits for it
    /// while another holds it, as 1.5.5's ops waited on the mutex.
    pub(crate) pool: std::sync::Arc<busbar_contract::abi::sdk::store::wire::Pool>,
    /// The endpoint (an index into the DSN's list) that last connected: the next connect tries it
    /// first, so a failover DSN keeps asking for the kept connection's own endpoint.
    pub(crate) endpoint: std::sync::atomic::AtomicUsize,
}

/// ONE OP'S CONNECTION: the 1.5.5 bodies run on it, as they ran on the mutex-guarded client.
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

/// Clamp a `u64` into `i64` for a BIGINT column (a value above `i64::MAX` pins to `i64::MAX`, never
/// wraps).
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed BIGINT back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as`.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// The four RESERVED unit classes, in the order of the `usage_ledger` token columns
/// (`tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`). Every other unit
/// class is an OPEN one and lives in `usage_ledger_units`.
const RESERVED_COLUMNS: [&str; 4] = [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE];

fn is_reserved_unit(unit: &str) -> bool {
    RESERVED_COLUMNS.contains(&unit)
}

/// Current Unix time in seconds (0 before the epoch): the one source of wall-clock stamps, so no
/// write path binds a nearby BIGINT such as `revision` to a timestamp column.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl PostgresStore {
    /// The store on the connection string `conn_str`: parsed here, connected by the connect step. A
    /// string the driver refuses is refused in its words, scrubbed of the DSN password.
    pub fn new(conn_str: &str) -> RecordStoreResult<Self> {
        let secret = dsn_password(conn_str);
        let config = pgwire::Config::parse(conn_str)
            .map_err(|e| RecordStoreError(scrub(e.to_string(), secret.as_deref())))?;
        Ok(Self {
            shared: std::sync::Arc::new(Shared {
                config,
                secret,
                ops_swept_at: AtomicU64::new(0),
                pool: busbar_contract::abi::sdk::store::wire::Pool::new(KEPT_CONNECTIONS),
                endpoint: std::sync::atomic::AtomicUsize::new(0),
            }),
        })
    }

    pub(crate) fn shared(&self) -> std::sync::Arc<Shared> {
        self.shared.clone()
    }
}

impl Session {
    /// Open one op's connection over `wire`: connect through the host's connector, secure it when
    /// the settings ask, authenticate. A failure is the driver's words (`error connecting to
    /// server: ...`, or the server's SQLSTATE and message), scrubbed of the DSN password.
    pub(crate) async fn open(
        wire: busbar_contract::abi::sdk::store::wire::Wire,
        shared: std::sync::Arc<Shared>,
    ) -> Result<Self, String> {
        match Client::connect(wire, &shared.config, &shared.endpoint).await {
            Ok(client) => Ok(Self { client, shared }),
            Err(e) => Err(scrub(render_pg_error(&e), shared.secret.as_deref())),
        }
    }

    /// The op is done: its connection is kept for the next op if the session is idle, else
    /// discarded ([`Client::release`]).
    pub(crate) async fn close(mut self) {
        self.client.release().await;
    }

    fn lock(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Open a transaction with ONE consistent snapshot (REPEATABLE READ, not READ COMMITTED's
    /// per-statement snapshot, which tears multi-statement reads like `get_usage`).
    pub(crate) async fn snapshot_consistent_tx<'a>(
        client: &'a mut Client,
    ) -> RecordStoreResult<Transaction<'a>> {
        client
            .build_transaction()
            .isolation_level(pgwire::IsolationLevel::RepeatableRead)
            .start()
            .await
            .store()
    }

    const MIGRATE_LOCK_KEY: i64 = 0x6275_7362_6172_5f70; // ASCII "busbar_p"

    pub(crate) async fn migrate(&mut self) -> RecordStoreResult<()> {
        let client = self.lock();
        client
            .batch_execute(&format!(
                "SELECT pg_advisory_lock({})",
                Self::MIGRATE_LOCK_KEY
            ))
            .await
            .store()?;
        let result = Self::migrate_locked(client).await;
        let unlocked = client
            .batch_execute(&format!(
                "SELECT pg_advisory_unlock({})",
                Self::MIGRATE_LOCK_KEY
            ))
            .await;
        // Report a migration failure first; but an unlock failure after a successful migration must
        // not be swallowed: a held session advisory lock can hang a sibling node's connect.
        match (result, unlocked) {
            (Ok(()), Err(e)) => Err(RecordStoreError(format!(
                "migrate: schema migration succeeded but releasing the advisory lock failed ({e}); \
                 a sibling node's own migrate() may now hang waiting for this lock"
            ))),
            (result, _) => result,
        }
    }

    async fn migrate_locked(client: &mut Client) -> RecordStoreResult<()> {
        client
            .batch_execute("CREATE TABLE IF NOT EXISTS busbar_schema (version BIGINT PRIMARY KEY)")
            .await
            .store()?;
        let version: i64 = match client
            .query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
            .await
        {
            Ok(Some(r)) => r.get(0),
            Ok(None) => 0,
            Err(e) if is_undefined_table(&e) => 0,
            Err(e) => return Err(RecordStoreError(render_pg_error(&e))),
        };
        // ALREADY CURRENT: run no DDL. Every node migrates on connect, and `CREATE INDEX IF NOT EXISTS`
        // takes a SHARE lock before it finds the index exists, in the opposite order to `delete_key`
        // (observed: `40P01` deadlock against a node merely connecting).
        if version > SCHEMA_VERSION {
            // A newer build owns this database: this one would ignore its newer rules (the epoch
            // fence among them), so it must not serve it.
            return Err(RecordStoreError(format!(
                "postgres store: database schema v{version} is newer than this build \
                 (v{SCHEMA_VERSION}); refusing to open"
            )));
        }
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        let mut tx = client.transaction().await.store()?;
        if version < 5 {
            let legacy: bool = tx
                .query_one(
                    "SELECT to_regclass('usage_counters') IS NOT NULL
                        OR to_regclass('virtual_keys') IS NOT NULL
                        OR to_regclass('aws_credentials') IS NOT NULL",
                    &[],
                )
                .await
                .store()?
                .get(0);
            if legacy {
                tx.batch_execute(
                    "DROP TABLE IF EXISTS virtual_keys;
                     DROP TABLE IF EXISTS aws_credentials;
                     DROP TABLE IF EXISTS keys CASCADE;
                     DROP TABLE IF EXISTS credentials;
                     DROP TABLE IF EXISTS usage_counters;
                     DROP TABLE IF EXISTS usage_windows;
                     DROP TABLE IF EXISTS usage_ledger;
                     DROP TABLE IF EXISTS usage_metering;
                     DROP TABLE IF EXISTS audit_log;
                     DROP TABLE IF EXISTS denylist;
                     DROP TABLE IF EXISTS store_revision;",
                )
                .await
                .store()?;
            }
        }
        tx.batch_execute(SCHEMA).await.store()?;
        // v6 one-time backfill — see SCHEMA_VERSION's doc comment for why this is safe as a
        // gated-once value backfill and would NOT be safe as a repeated/per-boot heuristic. Only
        // fires when crossing INTO v6 (a store already at v6+ never re-runs this).
        if version < 6 {
            tx.execute(
                "UPDATE usage_windows SET billable_requests = requests \
                 WHERE billable_requests = 0 AND requests > 0",
                &[],
            )
            .await
            .store()?;
        }
        // v10: `SCHEMA`'s `CREATE TABLE IF NOT EXISTS` never alters an existing table, so on a v6
        // database these statements ARE the upgrade. Gated on crossing INTO v10 because `ALTER TABLE`
        // takes an ACCESS EXCLUSIVE lock even as a no-op, and every node's connect runs `migrate()`.
        // One transaction with the version stamp, so a crash re-runs it from the start.
        if version < 10 {
            tx.batch_execute(MIGRATE_V10_COLUMNS).await.store()?;
            // `priced_from_ms` joins the metering primary key; every existing row carries 0, so the
            // old key was already unique and the widened key admits every row unchanged.
            tx.batch_execute(
                "ALTER TABLE usage_metering DROP CONSTRAINT IF EXISTS usage_metering_pkey;
                 ALTER TABLE usage_metering ADD CONSTRAINT usage_metering_pkey
                     PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms);",
            )
            .await
            .store()?;
        }
        // v13 — see SCHEMA_VERSION. The deleted slots' tables and dedupe rows go in the same
        // transaction as the version stamp, so a crash part-way re-runs it whole.
        if version < 13 {
            tx.batch_execute(
                "DROP TABLE IF EXISTS money_slices;
                 DROP TABLE IF EXISTS money_slots;
                 DROP TABLE IF EXISTS money_epoch;
                 DROP TABLE IF EXISTS store_journal;
                 DROP TABLE IF EXISTS store_sessions;
                 DELETE FROM store_ops WHERE split_part(body, ':', 1) NOT IN
                     ('append_plane_record', 'add_usage_batch', 'add_metering_batch');",
            )
            .await
            .store()?;
        }
        tx.execute(
            "INSERT INTO busbar_schema (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
            &[&SCHEMA_VERSION],
        )
        .await
        .store()?;
        tx.commit().await.store()?;
        Ok(())
    }

    /// Bump and return the store-global revision inside the caller's open transaction. Must be the
    /// FIRST statement of any transaction that mutates `keys`/`credentials`: it fixes one lock order
    /// (`store_revision` row, then the rest) across every mutating method, so they cannot deadlock.
    async fn next_revision(tx: &mut Transaction<'_>) -> RecordStoreResult<i64> {
        tx.query_one(
            "UPDATE store_revision SET revision = revision + 1 WHERE only_row RETURNING revision",
            &[],
        )
        .await
        .store()?
        .try_get(0)
        .store()
    }
}

fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}
fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

// SCOPE STORAGE. `allowed_pools` holds the `pool` grants as a JSON array of names, or NULL; the v10
// `allowed_scopes_by_kind` holds every NON-pool grant as `{kind: [value, ...]}`, NULL when none, so a
// pool-only key is stored as 1.5.x wrote it. `None` (grant omitted = all) -> both NULL; `Some(list)`
// -> `allowed_pools` is ALWAYS an array (possibly `[]`), so `Some([])` never collapses into `None`
// and a non-pool-only grant never reads back as "every pool".
type ScopeColumns = (Option<String>, Option<String>);

fn scopes_to_storage(scopes: &Option<Vec<ScopeRef>>) -> ScopeColumns {
    let Some(list) = scopes else {
        return (None, None);
    };
    let mut pools: Vec<&str> = Vec::new();
    let mut by_kind: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for s in list {
        if s.kind == "pool" {
            pools.push(s.value.as_str());
        } else {
            by_kind
                .entry(s.kind.as_str())
                .or_default()
                .push(s.value.as_str());
        }
    }
    let pools = serde_json::to_string(&pools).unwrap_or_else(|_| "[]".to_string());
    let by_kind = if by_kind.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&by_kind).unwrap_or_else(|_| "{}".to_string()))
    };
    (Some(pools), by_kind)
}

/// The inverse of [`scopes_to_storage`]: pools first, then every other kind in kind order — the
/// same canonical order the VirtualKey wire reassembles in.
fn scopes_from_storage(pools: Option<String>, by_kind: Option<String>) -> Option<Vec<ScopeRef>> {
    if pools.is_none() && by_kind.is_none() {
        return None;
    }
    let mut out: Vec<ScopeRef> = pools
        .map(|p| serde_json::from_str::<Vec<String>>(p.trim()).unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .map(ScopeRef::pool)
        .collect();
    if let Some(by_kind) = by_kind {
        let map: BTreeMap<String, Vec<String>> =
            serde_json::from_str(by_kind.trim()).unwrap_or_default();
        for (kind, values) in map {
            out.extend(values.into_iter().map(|value| ScopeRef {
                kind: kind.clone(),
                value,
            }));
        }
    }
    Some(out)
}

fn row_to_key(r: &Row) -> VirtualKey {
    VirtualKey {
        id: r.get(0),
        generation_hash: r.get(1),
        name: r.get(2),
        allowed_scopes: scopes_from_storage(
            r.get::<_, Option<String>>(3),
            r.get::<_, Option<String>>(14),
        ),
        enabled: r.get(4),
        created_at: read_u64(r.get::<_, i64>(5)),
        group: r.get(6),
        labels: labels_from_storage(&r.get::<_, String>(7)),
        expires_at: r.get::<_, Option<i64>>(8).map(read_u64),
        deleted_at: r.get::<_, Option<i64>>(9).map(read_u64),
        revision: read_u64(r.get::<_, i64>(10)),
        idp_subject: r.get(11),
        binding_mode: r.get(12),
        minted_by: r.get(13),
        idp_provider: r.get(15),
    }
}

const KEY_COLUMNS: &str = "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,idp_subject,binding_mode,minted_by,allowed_scopes_by_kind,idp_provider";

fn secret_form_to_storage(f: SecretForm) -> &'static str {
    match f {
        SecretForm::None => "none",
        SecretForm::Recoverable => "recoverable",
        SecretForm::Digest => "digest",
    }
}
fn secret_form_from_storage(s: &str) -> SecretForm {
    match s {
        "recoverable" => SecretForm::Recoverable,
        "digest" => SecretForm::Digest,
        _ => SecretForm::None,
    }
}

const CRED_META_COLUMNS: &str = "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";
/// The row index of `secret` in `SELECT {CRED_META_COLUMNS},secret ...`: the column count of
/// CRED_META_COLUMNS. Guarded by `cred_secret_column_index_matches_cred_meta_columns_count`.
const CRED_SECRET_COLUMN_INDEX: usize = 12;

fn row_to_cred_meta(r: &Row) -> CredentialMeta {
    CredentialMeta {
        id: r.get(0),
        key_id: r.get(1),
        kind: r.get(2),
        slot: r.get::<_, i16>(3) as u8,
        public_id: r.get(4),
        secret_form: secret_form_from_storage(r.get::<_, &str>(5)),
        created_at: read_u64(r.get::<_, i64>(6)),
        updated_at: read_u64(r.get::<_, i64>(7)),
        expires_at: r.get::<_, Option<i64>>(8).map(read_u64),
        revoked_at: r.get::<_, Option<i64>>(9).map(read_u64),
        revoke_reason: r.get(10),
        revision: read_u64(r.get::<_, i64>(11)),
    }
}

impl Session {
    pub(crate) async fn put_key(&mut self, key: &VirtualKey) -> RecordStoreResult<()> {
        let (pools, by_kind) = scopes_to_storage(&key.allowed_scopes);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let expires = key.expires_at.map(clamp);
        let deleted = key.deleted_at.map(clamp);
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        let rev = Self::next_revision(&mut tx).await?;
        // The conflict branch's `WHERE` is the TOMBSTONE PRECONDITION: a live-shaped write must not
        // overwrite a tombstoned row (that would reissue a never-reissued id and revive its tokens).
        // It rides on the statement, not a prior SELECT, so under READ COMMITTED it closes the TOCTOU
        // window. A write that CARRIES a tombstone still applies.
        let changed = tx.execute(
            "INSERT INTO keys
                (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,
                 idp_subject,binding_mode,minted_by,allowed_scopes_by_kind,idp_provider)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
             ON CONFLICT (id) DO UPDATE SET
                generation_hash=EXCLUDED.generation_hash, name=EXCLUDED.name,
                allowed_pools=EXCLUDED.allowed_pools, enabled=EXCLUDED.enabled,
                key_group=EXCLUDED.key_group, labels=EXCLUDED.labels,
                expires_at=EXCLUDED.expires_at, deleted_at=EXCLUDED.deleted_at,
                revision=EXCLUDED.revision, idp_subject=EXCLUDED.idp_subject,
                binding_mode=EXCLUDED.binding_mode, minted_by=EXCLUDED.minted_by,
                allowed_scopes_by_kind=EXCLUDED.allowed_scopes_by_kind,
                idp_provider=EXCLUDED.idp_provider
             WHERE EXCLUDED.deleted_at IS NOT NULL OR keys.deleted_at IS NULL",
            &[
                &key.id, &key.generation_hash, &key.name, &pools, &key.enabled, &created,
                &key.group, &labels, &expires, &deleted, &rev, &key.idp_subject,
                &key.binding_mode, &key.minted_by, &by_kind, &key.idp_provider,
            ],
        ).await
        .store()?;
        if changed == 0 {
            // The conflict branch matched a row but its WHERE rejected the write: the stored row is
            // tombstoned and this one is not. That is the only way to reach 0 here.
            return Err(RecordStoreError(format!(
                "put_key: '{}' is tombstoned and its id is never reissued; refusing to clear the \
                 tombstone",
                key.id
            )));
        }
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn get_key(&mut self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys WHERE id=$1");
        let row = self.lock().query_opt(&sql, &[&id]).await.store()?;
        Ok(row.map(|r| row_to_key(&r)))
    }

    pub(crate) async fn list_keys(&mut self) -> RecordStoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED (tombstoned rows included) -- see the trait doc: this serves both
        // the admin-listing caller (which filters deleted_at.is_none() itself) and list_keys_since's
        // default fallback, which needs tombstones visible to drive credential eviction downstream.
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys ORDER BY created_at");
        let rows = self.lock().query(&sql, &[]).await.store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    pub(crate) async fn list_keys_since(
        &mut self,
        since: u64,
    ) -> RecordStoreResult<Vec<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys WHERE revision > $1 ORDER BY revision");
        let rows = self.lock().query(&sql, &[&clamp(since)]).await.store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    pub(crate) async fn delete_key(&mut self, id: &str) -> RecordStoreResult<()> {
        // TOMBSTONE: the `keys` row survives (attribution keeps resolving) and every credential row
        // is destroyed, in ONE transaction under the SAME revision, so a REPEATABLE READ hydration
        // snapshot never sees the tombstoned key with its credentials still live.
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        let already_deleted: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NOT NULL FROM keys WHERE id=$1",
                &[&id],
            )
            .await
            .store()?
            .map(|r| r.get(0));
        match already_deleted {
            None => {
                // Unknown id is an ERROR, unlike already-tombstoned: answering Ok would tell an operator
                // who typo'd an id that a key was revoked when none was.
                return Err(RecordStoreError(format!("delete_key: unknown id '{id}'")));
            }
            Some(true) => {
                // Already tombstoned: no-op, not an error.
                tx.commit().await.store()?;
                return Ok(());
            }
            Some(false) => {}
        }
        let rev = Self::next_revision(&mut tx).await?;
        // `deleted_at` is a wall-clock stamp and `revision` a counter; both BIGINT, so binding one
        // value to both would compile and pass every "is tombstoned" check. Bound separately
        // (`delete_key_stamps_deleted_at_with_a_wall_clock_time_not_the_revision`).
        let now = clamp(now_secs());
        tx.execute("DELETE FROM credentials WHERE key_id=$1", &[&id])
            .await
            .store()?;
        // `AND deleted_at IS NULL` restates the guard in the UPDATE's own WHERE: under READ COMMITTED
        // the UPDATE re-checks it after taking the row lock, so two concurrent deletes serialize
        // (the loser matches 0 rows) instead of both overwriting `deleted_at`/`revision`.
        tx.execute(
            "UPDATE keys SET enabled=FALSE, deleted_at=$2, revision=$3 \
                 WHERE id=$1 AND deleted_at IS NULL",
            &[&id, &now, &rev],
        )
        .await
        .store()?;
        // A concurrent delete_key committed between our SELECT and this UPDATE: idempotent no-op,
        // same as the `Some(true)` branch above -- not an error.
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn get_usage(
        &mut self,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let ws = clamp(window_start);
        let client = self.lock();
        let mut tx = Self::snapshot_consistent_tx(client).await?;
        let (requests, billable_requests): (u64, u64) = tx
            .query_opt(
                "SELECT requests, billable_requests
                 FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
                &[&bucket_id, &ws],
            )
            .await
            .store()?
            .map(|r| (read_u64(r.get::<_, i64>(0)), read_u64(r.get::<_, i64>(1))))
            .unwrap_or((0, 0));
        let rows = tx
            .query(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                 FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2 ORDER BY model",
                &[&bucket_id, &ws],
            )
            .await
            .store()?;
        let unit_rows = tx
            .query(
                "SELECT model, unit, count FROM usage_ledger_units
                 WHERE bucket_id=$1 AND window_start=$2 ORDER BY model, unit",
                &[&bucket_id, &ws],
            )
            .await
            .store()?;
        tx.commit().await.store()?;
        // One ModelTokens per model, in model order. The four reserved classes come off their
        // columns and every open class off `usage_ledger_units`, all into the one name-keyed map.
        // Zero counts are left out, so the map stays sparse the way busbar's own ledger keeps it.
        let mut models: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for r in &rows {
            let units = models.entry(r.get::<_, String>(0)).or_default();
            for (i, unit) in RESERVED_COLUMNS.iter().enumerate() {
                let v = read_u64(r.get::<_, i64>(i + 1));
                if v != 0 {
                    units.insert(unit.to_string(), v);
                }
            }
        }
        for r in &unit_rows {
            let v = read_u64(r.get::<_, i64>(2));
            let units = models.entry(r.get::<_, String>(0)).or_default();
            if v != 0 {
                units.insert(r.get::<_, String>(1), v);
            }
        }
        Ok(UsageLedger {
            requests,
            billable_requests,
            models: models
                .into_iter()
                .map(|(model, usage_units)| ModelTokens { model, usage_units })
                .collect(),
        })
    }

    pub(crate) async fn put_usage(
        &mut self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let ws = clamp(window_start);
        let rq = clamp(ledger.requests);
        let brq = clamp(ledger.billable_requests);
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket_id, &ws],
        )
        .await
        .store()?;
        tx.execute(
            "DELETE FROM usage_ledger_units WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket_id, &ws],
        )
        .await
        .store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = EXCLUDED.requests,
                billable_requests = EXCLUDED.billable_requests",
            &[&bucket_id, &ws, &rq, &brq],
        )
        .await
        .store()?;
        if !ledger.models.is_empty() {
            let rows: Vec<[i64; 4]> = ledger
                .models
                .iter()
                .map(|m| RESERVED_COLUMNS.map(|u| clamp(m.tier(u))))
                .collect();
            let mut sql = String::from(
                "INSERT INTO usage_ledger \
                 (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) \
                 VALUES ",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(2 + rows.len() * 5);
            params.push(&bucket_id);
            params.push(&ws);
            for (i, (m, row)) in ledger.models.iter().zip(rows.iter()).enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                let base = 3 + i * 5;
                sql.push_str(&format!(
                    "($1,$2,${},${},${},${},${})",
                    base,
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4
                ));
                params.push(&m.model);
                for v in row {
                    params.push(v);
                }
            }
            tx.execute(&sql, &params).await.store()?;

            // The OPEN unit classes: an absolute set too (the window's rows were cleared above).
            let opens: Vec<(&String, &String, i64)> = ledger
                .models
                .iter()
                .flat_map(|m| {
                    m.usage_units
                        .iter()
                        .filter(|(u, v)| !is_reserved_unit(u) && **v != 0)
                        .map(move |(u, v)| (&m.model, u, clamp(*v)))
                })
                .collect();
            if !opens.is_empty() {
                let mut sql = String::from(
                    "INSERT INTO usage_ledger_units (bucket_id, window_start, model, unit, count) VALUES ",
                );
                let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(2 + opens.len() * 3);
                params.push(&bucket_id);
                params.push(&ws);
                for (i, (model, unit, count)) in opens.iter().enumerate() {
                    if i > 0 {
                        sql.push(',');
                    }
                    let base = 3 + i * 3;
                    sql.push_str(&format!("($1,$2,${},${},${})", base, base + 1, base + 2));
                    params.push(*model);
                    params.push(*unit);
                    params.push(count);
                }
                // Two ModelTokens entries for one model never reach this statement: the
                // reserved-column INSERT above has no ON CONFLICT, so it refuses them (23505)
                // first, as 1.5.5's put_usage did.
                sql.push_str(
                    " ON CONFLICT (bucket_id, window_start, model, unit) DO UPDATE SET \
                     count = usage_ledger_units.count + EXCLUDED.count",
                );
                tx.execute(&sql, &params).await.store()?;
            }
        }
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn list_metering(
        &mut self,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let b = clamp(bucket);
        let client = self.lock();
        // ONE snapshot for both reads, so a row's open classes are never read from a different
        // moment than its token columns.
        let mut tx = Self::snapshot_consistent_tx(client).await?;
        let rows = tx
            .query(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
                    requests, billable_requests, key_group_at_use, pricing_version, priced_from_ms
                 FROM usage_metering WHERE bucket=$1
                 ORDER BY key_id, model, provider, priced_from_ms",
                &[&b],
            )
            .await
            .store()?;
        let unit_rows = tx
            .query(
                "SELECT key_id, model, provider, priced_from_ms, unit, count
                 FROM usage_metering_units WHERE bucket=$1",
                &[&b],
            )
            .await
            .store()?;
        tx.commit().await.store()?;
        type RowKey = (String, String, String, i64);
        let mut units: std::collections::HashMap<RowKey, BTreeMap<String, u64>> =
            std::collections::HashMap::new();
        for r in &unit_rows {
            let v = read_u64(r.get::<_, i64>(5));
            if v == 0 {
                continue;
            }
            units
                .entry((r.get(0), r.get(1), r.get(2), r.get(3)))
                .or_default()
                .insert(r.get(4), v);
        }
        Ok(rows
            .iter()
            .map(|r| {
                let key: RowKey = (r.get(0), r.get(1), r.get(2), r.get(11));
                MeteringRow {
                    usage_units: units.remove(&key).unwrap_or_default(),
                    key_id: key.0,
                    model: key.1,
                    provider: key.2,
                    tokens_input: read_u64(r.get::<_, i64>(3)),
                    tokens_output: read_u64(r.get::<_, i64>(4)),
                    tokens_cache_read: read_u64(r.get::<_, i64>(5)),
                    tokens_cache_write: read_u64(r.get::<_, i64>(6)),
                    requests: read_u64(r.get::<_, i64>(7)),
                    billable_requests: read_u64(r.get::<_, i64>(8)),
                    key_group_at_use: r.get(9),
                    pricing_version: r.get(10),
                    priced_from_ms: read_u64(key.3),
                }
            })
            .collect())
    }

    pub(crate) async fn put_credential(
        &mut self,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        Self::put_credential_tx(&mut tx, secret).await?;
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn put_key_with_credential(
        &mut self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        // ATOMIC mint: the bearer key and its credential commit together or not at all.
        let (pools, by_kind) = scopes_to_storage(&key.allowed_scopes);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let expires = key.expires_at.map(clamp);
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        let rev = Self::next_revision(&mut tx).await?;
        // Same TOMBSTONE PRECONDITION as `put_key`, where it matters most: re-minting over a
        // tombstoned id must be REFUSED, not clear the tombstone and revive every earlier token. The
        // insert supplies `deleted_at = NULL`, so the guard is "the stored row must not be a tombstone".
        let changed = tx.execute(
            "INSERT INTO keys
                (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,
                 idp_subject,binding_mode,minted_by,allowed_scopes_by_kind,idp_provider)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (id) DO UPDATE SET
                generation_hash=EXCLUDED.generation_hash, name=EXCLUDED.name,
                allowed_pools=EXCLUDED.allowed_pools, enabled=EXCLUDED.enabled,
                key_group=EXCLUDED.key_group, labels=EXCLUDED.labels,
                expires_at=EXCLUDED.expires_at, revision=EXCLUDED.revision,
                idp_subject=EXCLUDED.idp_subject, binding_mode=EXCLUDED.binding_mode,
                minted_by=EXCLUDED.minted_by, allowed_scopes_by_kind=EXCLUDED.allowed_scopes_by_kind,
                idp_provider=EXCLUDED.idp_provider
             WHERE keys.deleted_at IS NULL",
            &[
                &key.id, &key.generation_hash, &key.name, &pools, &key.enabled, &created,
                &key.group, &labels, &expires, &rev, &key.idp_subject, &key.binding_mode,
                &key.minted_by, &by_kind, &key.idp_provider,
            ],
        ).await
        .store()?;
        if changed == 0 {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: '{}' is tombstoned and its id is never reissued; \
                 refusing to clear the tombstone",
                key.id
            )));
        }
        Self::put_credential_tx(&mut tx, secret).await?;
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn list_credentials(
        &mut self,
        key_id: &str,
    ) -> RecordStoreResult<Vec<CredentialMeta>> {
        let sql = format!("SELECT {CRED_META_COLUMNS} FROM credentials WHERE key_id=$1");
        let rows = self.lock().query(&sql, &[&key_id]).await.store()?;
        Ok(rows.iter().map(row_to_cred_meta).collect())
    }

    pub(crate) async fn revoke_credential(
        &mut self,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                &[&id],
            )
            .await
            .store()?
            .get(0);
        if !exists {
            // NOT idempotent-success: a silent no-op lets an operator believe a leaked secret was
            // killed. Minting into a revoked slot rewrites the row's primary key, so an id from an
            // earlier `list_credentials` can stop resolving; success there would leave the credential
            // authenticating with the audit trail saying it was revoked.
            return Err(RecordStoreError(format!(
                "revoke_credential: unknown credential id {id}; nothing was revoked"
            )));
        }
        let rev = Self::next_revision(&mut tx).await?;
        let now = now_secs();
        // `AND revoked_at IS NULL` in the UPDATE's own WHERE: a repeat revoke is a true no-op (no
        // revision bump, no rewritten reason) and, under READ COMMITTED's row-lock re-check, safe
        // against a concurrent revoke of the same id.
        let changed = tx
            .execute(
                "UPDATE credentials SET revoked_at=$2, revoke_reason=$3, updated_at=$2, revision=$4
                 WHERE id=$1 AND revoked_at IS NULL",
                &[&id, &clamp(now), &reason, &rev],
            )
            .await
            .store()?;
        if changed == 0 {
            // Zero rows is ambiguous: a concurrent mint into the freed slot can rewrite this row's
            // PRIMARY KEY (`put_credential_tx` sets `id=EXCLUDED.id`) between the EXISTS above and
            // this UPDATE, and reporting success then is "revoked, yet still authenticating". So ask
            // again, inside this transaction.
            let still_exists: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                    &[&id],
                )
                .await
                .store()?
                .get(0);
            if !still_exists {
                return Err(RecordStoreError(format!(
                    "revoke_credential: credential id {id} existed when this call started and \
                     names no row by the time the revocation was written (a concurrent mint into \
                     the same slot rewrites the row's id); nothing was revoked"
                )));
            }
            // The row is there and was already revoked: a true idempotent no-op, exactly what the
            // trait promises. The revision bump above goes unused, which its own doc allows (a
            // monotonic counter with gaps).
        }
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn list_credentials_since(
        &mut self,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE revision > $1 ORDER BY revision"
        );
        let rows = self.lock().query(&sql, &[&clamp(since)]).await.store()?;
        Ok(rows
            .iter()
            .map(|r| CredentialSecret {
                meta: row_to_cred_meta(r),
                secret: r
                    .get::<_, Option<String>>(CRED_SECRET_COLUMN_INDEX)
                    .unwrap_or_default(),
            })
            .collect())
    }

    pub(crate) async fn list_audit(&mut self) -> RecordStoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq");
        let rows = self.lock().query(&sql, &[]).await.store()?;
        Ok(rows.iter().map(row_to_audit).collect())
    }

    pub(crate) async fn list_audit_tail(
        &mut self,
        limit: u64,
    ) -> RecordStoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq DESC LIMIT $1");
        let rows = self
            .lock()
            .query(&sql, &[&i64::try_from(limit).unwrap_or(i64::MAX)])
            .await
            .store()?;
        let mut out: Vec<AuditRecord> = rows.iter().map(row_to_audit).collect();
        out.reverse();
        Ok(out)
    }

    pub(crate) async fn add_denylist(&mut self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        // `created_at` is a clock read, not the literal 0 (as store-sqlite writes).
        self.lock()
            .execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (sub) DO UPDATE SET reason = EXCLUDED.reason",
                &[&sub, &reason, &clamp(now_secs())],
            )
            .await
            .store()?;
        Ok(())
    }

    pub(crate) async fn list_denylist(&mut self) -> RecordStoreResult<Vec<String>> {
        let rows = self
            .lock()
            .query("SELECT sub FROM denylist", &[])
            .await
            .store()?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    // ── THE KIND-TAGGED PLANE-RECORD VERBS (busbar 1.6.0) ──
    //
    // Generic over `kind`: an UPSERTED record lives in `plane_records` keyed `(kind, id)`, an
    // APPENDED one in `plane_chain` keyed `(kind, parent, seq)`. Identity, ordering and retention
    // read only the typed sidecar columns, never the body.

    pub(crate) async fn upsert_plane_record(
        &mut self,
        record: PlaneRecordRef<'_>,
    ) -> RecordStoreResult<()> {
        // This store binds owned rows: the one copy of the borrowed view happens here.
        let record = &record.to_record();
        // REFUSED rather than clamped: `clamp` pins a value above i64::MAX, so the row read back
        // would not be the row written and nothing would ever report it.
        let seq = as_storable_i64("upsert_plane_record", "seq", record.seq)?;
        let ts = as_storable_i64("upsert_plane_record", "ts", record.ts)?;
        // UPSERT BY (kind, id): the engine writes through on EVERY transition, so a second write
        // for one id REPLACES the row — the sidecar columns included, which is how a terminal
        // transition reaches the retention sweep and the liveness check.
        self.lock()
            .execute(
                "INSERT INTO plane_records (kind, id, parent, seq, ts, disposition, body)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT (kind, id) DO UPDATE SET
                    parent=EXCLUDED.parent, seq=EXCLUDED.seq, ts=EXCLUDED.ts,
                    disposition=EXCLUDED.disposition, body=EXCLUDED.body",
                &[
                    &record.kind,
                    &record.id,
                    &record.parent,
                    &seq,
                    &ts,
                    &disposition_to_storage(record.disposition),
                    &record.body,
                ],
            )
            .await
            .store()?;
        Ok(())
    }

    pub(crate) async fn get_plane_record(
        &mut self,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<Option<Vec<u8>>> {
        // No principal filter, deliberately: caller scoping is ENGINE-side, because an
        // authorization check living in the backend is one an unauthorized reader bypasses by
        // configuring a different backend.
        let row = self
            .lock()
            .query_opt(
                "SELECT body FROM plane_records WHERE kind=$1 AND id=$2",
                &[&kind, &id],
            )
            .await
            .store()?;
        Ok(row.map(|r| r.get(0)))
    }

    pub(crate) async fn list_plane_records(
        &mut self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let client = self.lock();
        // One snapshot across both tables.
        let mut tx = Self::snapshot_consistent_tx(client).await?;
        let (records, chain) = match selector {
            PlaneSelector::All => (
                tx.query(
                    "SELECT body FROM plane_records WHERE kind=$1 ORDER BY seq, id",
                    &[&kind],
                )
                .await
                .store()?,
                tx.query(
                    "SELECT body FROM plane_chain WHERE kind=$1 ORDER BY parent, seq",
                    &[&kind],
                )
                .await
                .store()?,
            ),
            // Oldest-first by seq — the order the engine's chain verifier reads a parent's chain.
            PlaneSelector::Parent(p) => {
                let p: &str = p;
                (
                    tx.query(
                        "SELECT body FROM plane_records WHERE kind=$1 AND parent=$2 ORDER BY seq, id",
                        &[&kind, &p],
                    ).await
                    .store()?,
                    tx.query(
                        "SELECT body FROM plane_chain WHERE kind=$1 AND parent=$2 ORDER BY seq",
                        &[&kind, &p],
                    ).await
                    .store()?,
                )
            }
        };
        tx.commit().await.store()?;
        Ok(records
            .iter()
            .chain(chain.iter())
            .map(|r| r.get::<_, Vec<u8>>(0))
            .collect())
    }

    pub(crate) async fn list_plane_record_parents(
        &mut self,
        kind: &str,
    ) -> RecordStoreResult<Vec<String>> {
        // The boot enumeration a restart resumes chains from: every parent holding a record of
        // `kind`, each exactly once.
        let rows = self
            .lock()
            .query(
                "SELECT parent FROM plane_chain WHERE kind=$1
                 UNION
                 SELECT parent FROM plane_records WHERE kind=$1 AND parent IS NOT NULL
                 ORDER BY 1",
                &[&kind],
            )
            .await
            .store()?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    pub(crate) async fn purge_plane_records_before(
        &mut self,
        kind: &str,
        before: u64,
    ) -> RecordStoreResult<u64> {
        // STRICTLY older than the cutoff: a row exactly at `before` is kept. WHICH rows go is the
        // kind's own contract, read off the typed `disposition` column and never out of the body —
        // see TERMINAL_ONLY_RETENTION_KINDS.
        let cutoff = clamp(before);
        let terminal_only = TERMINAL_ONLY_RETENTION_KINDS.contains(&kind);
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        let purged: Vec<String> = tx
            .query(
                "DELETE FROM plane_records
                 WHERE kind=$1 AND ts < $2 AND (NOT $3 OR disposition = 'terminal')
                 RETURNING id",
                &[&kind, &cutoff, &terminal_only],
            )
            .await
            .store()?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let chain = tx
            .execute(
                "DELETE FROM plane_chain WHERE kind=$1 AND ts < $2",
                &[&kind, &cutoff],
            )
            .await
            .store()?;
        // CASCADE, in the SAME transaction: a purged parent's child chain goes with it, and only
        // the chains under a record that actually went — so this can never be a second, wider
        // retention rule in disguise.
        if !purged.is_empty() {
            for (_, child) in PLANE_CHILD_KINDS.iter().filter(|(p, _)| *p == kind) {
                tx.execute(
                    "DELETE FROM plane_chain WHERE kind=$1 AND parent = ANY($2)",
                    &[child, &purged],
                )
                .await
                .store()?;
            }
        }
        tx.commit().await.store()?;
        // `execute`/`RETURNING` report the rows actually removed, so the count is one performed.
        Ok(purged.len() as u64 + chain)
    }

    pub(crate) async fn delete_plane_record(
        &mut self,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<()> {
        // Absent is a NO-OP, not an error: the engine clears on every observation that agrees with
        // the operator rather than tracking whether it had written one. A chain whose parent is
        // `id` goes too, so deleting a record cannot leave part of its chain behind.
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        tx.execute(
            "DELETE FROM plane_records WHERE kind=$1 AND id=$2",
            &[&kind, &id],
        )
        .await
        .store()?;
        tx.execute(
            "DELETE FROM plane_chain WHERE kind=$1 AND parent=$2",
            &[&kind, &id],
        )
        .await
        .store()?;
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn redeem_plane_token(
        &mut self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // `now` is REFUSED, not clamped: clamped to i64::MAX it would sweep the kind's entire ledger
        // and report the insert as a first redemption, reopening every spent token. `expires_at`
        // alone saturates: minting claims pass `u64::MAX` for "never expires", and the column is only
        // compared against `now` by the sweep, so `i64::MAX` is the same answer.
        let expires = i64::try_from(expires_at).unwrap_or(i64::MAX);
        let cutoff = as_storable_i64("redeem_plane_token", "now", now)?;
        let client = self.lock();
        let mut tx = client.transaction().await.store()?;
        // The eviction sweep, STRICTLY less-than (an entry expiring exactly at `now` is kept) and
        // BEFORE the insert, so it never deletes the row this call records.
        tx.execute(
            "DELETE FROM plane_tokens WHERE kind=$1 AND expires_at < $2",
            &[&kind, &cutoff],
        )
        .await
        .store()?;
        // THE TEST AND SET, as ONE statement: 1 row written means THIS call recorded the redemption,
        // 0 means it was already there. A read then a write would tell both halves of a race they
        // were first.
        let inserted = tx
            .execute(
                "INSERT INTO plane_tokens (kind, token, expires_at) VALUES ($1,$2,$3)
                 ON CONFLICT (kind, token) DO NOTHING",
                &[&kind, &token, &expires],
            )
            .await
            .store()?;
        tx.commit().await.store()?;
        Ok(inserted == 1)
    }

    pub(crate) async fn plane_token_live(
        &mut self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // MULTI-use and SPENDS NOTHING: a plain read of the `(kind, token)` upserted record, live only
        // while present, `Active`, and before `expires_at`. Asking twice answers the same twice.
        if now > expires_at {
            return Ok(false);
        }
        let row = self
            .lock()
            .query_opt(
                "SELECT disposition FROM plane_records WHERE kind=$1 AND id=$2",
                &[&kind, &token],
            )
            .await
            .store()?;
        Ok(row.is_some_and(|r| r.get::<_, &str>(0) == "active"))
    }
}

const AUDIT_COLUMNS: &str = "seq, ts, action, resource, outcome, principal, prev_hash, hash";

fn disposition_to_storage(d: PlaneDisposition) -> &'static str {
    match d {
        PlaneDisposition::Active => "active",
        PlaneDisposition::Terminal => "terminal",
    }
}

/// Reject a `u64` a signed BIGINT cannot hold, naming the method and the field. `clamp` would pin
/// it to `i64::MAX`, so the row read back would not be the row written: tolerable on counters, not
/// on a plane record's chain position or a token ledger's clock.
fn as_storable_i64(method: &str, field: &str, v: u64) -> RecordStoreResult<i64> {
    i64::try_from(v).map_err(|_| {
        RecordStoreError(format!(
            "{method}: {field} {v} exceeds the storable range (i64::MAX); refusing to store a row \
             that would not read back as itself"
        ))
    })
}

fn row_to_audit(r: &Row) -> AuditRecord {
    AuditRecord {
        seq: read_u64(r.get::<_, i64>(0)),
        ts: read_u64(r.get::<_, i64>(1)),
        action: r.get(2),
        resource: r.get(3),
        outcome: r.get(4),
        principal: r.get(5),
        prev_hash: r.get(6),
        hash: r.get(7),
    }
}

impl Session {
    /// Shared body of `put_credential`/`put_key_with_credential`: upsert on `(key_id, kind, slot)`.
    /// Minting into an OCCUPIED LIVE slot must fail rather than destroy a working credential
    /// mid-overlap-window: the `DO UPDATE`'s `WHERE credentials.revoked_at IS NOT NULL` makes the
    /// upsert not apply, and the `changed` check turns that into an error.
    async fn put_credential_tx(
        tx: &mut Transaction<'_>,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let m = &secret.meta;
        let rev = Self::next_revision(tx).await?;
        // The owning key must EXIST and be LIVE. Checked AFTER `next_revision`, which is what makes it
        // atomic: every mutating transaction takes the single `store_revision` row lock first, so a
        // concurrent `delete_key` has either committed before this read (and this sees the tombstone)
        // or cannot start its cascade until this mint commits (and then removes it).
        let owner_live: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NULL FROM keys WHERE id=$1",
                &[&m.key_id],
            )
            .await
            .store()?
            .map(|r| r.get(0));
        match owner_live {
            None => {
                return Err(RecordStoreError(format!(
                    "put_credential: owning key '{}' does not exist; refusing a credential that \
                     hangs off nothing",
                    m.key_id
                )))
            }
            Some(false) => {
                return Err(RecordStoreError(format!(
                    "put_credential: owning key '{}' is tombstoned; refusing to mint a credential \
                     under a revoked key",
                    m.key_id
                )))
            }
            Some(true) => {}
        }
        let form = secret_form_to_storage(m.secret_form);
        let secret_val = if m.secret_form == SecretForm::None {
            None
        } else {
            Some(secret.secret.as_str())
        };
        let expires = m.expires_at.map(clamp);
        let changed = tx
            .execute(
                "INSERT INTO credentials
                    (id,key_id,kind,slot,public_id,secret,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,$11)
                 ON CONFLICT (key_id, kind, slot) DO UPDATE SET
                    id=EXCLUDED.id, public_id=EXCLUDED.public_id, secret=EXCLUDED.secret,
                    secret_form=EXCLUDED.secret_form, updated_at=EXCLUDED.updated_at,
                    expires_at=EXCLUDED.expires_at, revoked_at=NULL, revoke_reason=NULL,
                    revision=EXCLUDED.revision
                 WHERE credentials.revoked_at IS NOT NULL",
                &[
                    &m.id,
                    &m.key_id,
                    &m.kind,
                    &(m.slot as i16),
                    &m.public_id,
                    &secret_val,
                    &form,
                    &clamp(m.created_at),
                    &clamp(m.updated_at),
                    &expires,
                    &rev,
                ],
            ).await
            .store()?;
        if changed == 0 {
            // Either the slot is occupied by a LIVE credential (the WHERE guard blocked it), or this
            // is a genuine first insert into a free slot that the ON CONFLICT branch didn't need --
            // distinguish by checking existence.
            let exists: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE key_id=$1 AND kind=$2 AND slot=$3)",
                    &[&m.key_id, &m.kind, &(m.slot as i16)],
                ).await
                .store()?
                .get(0);
            if exists {
                return Err(RecordStoreError(format!(
                    "put_credential: slot {} for key {} kind {} holds a LIVE credential; revoke it first",
                    m.slot, m.key_id, m.kind
                )));
            }
            // Free slot, first insert -- the INSERT branch of the upsert should have applied. If we
            // get here with changed==0 and no existing row, something else rejected the write (e.g.
            // a UNIQUE(kind, public_id) violation on a DIFFERENT key/slot) -- surface plainly.
            return Err(RecordStoreError(
                "put_credential: insert did not apply (public_id may already be in use by another credential)".to_string(),
            ));
        }
        Ok(())
    }
}

/// The writes the store v3 `op_id` slots run inside their dedupe transaction ([`v3`]).
impl Session {
    /// `add_usage` inside the caller's transaction (the store v3 `op_id` writes and batches run
    /// it with their dedupe record, in one transaction).
    pub(crate) async fn add_usage_in(
        tx: &mut Transaction<'_>,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let ws = clamp(window_start);
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,GREATEST(0,$3::bigint),GREATEST(0,$4::bigint))
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = GREATEST(0, usage_windows.requests + $3::bigint),
                billable_requests = GREATEST(0, usage_windows.billable_requests + $4::bigint)",
            &[&bucket_id, &ws, &delta.requests, &delta.billable_requests],
        )
        .await
        .store()?;
        // `UsageDelta.models` may name one model twice and `apply_delta` folds the entries in order,
        // flooring after each; one `UPDATE .. FROM (VALUES ..)` applies only one joined row per target.
        // So apply in ROUNDS: round k holds the k-th occurrence of each model, and a delta without
        // duplicates is exactly one round.
        let mut rounds: Vec<Vec<&busbar_contract::records::ModelTokensDelta>> = Vec::new();
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for m in &delta.models {
            let n = seen.entry(m.model.as_str()).or_insert(0);
            if rounds.len() <= *n {
                rounds.push(Vec::new());
            }
            rounds[*n].push(m);
            *n += 1;
        }
        for models in &rounds {
            // TWO batched statements, so a NEGATIVE delta (a refund) lands: `INSERT .. ON CONFLICT DO
            // UPDATE` can only add `EXCLUDED.col`, which is floored at 0 for a first-seen model, so a
            // refund was lost. Instead ensure every model's row exists at zero, then apply the SIGNED
            // deltas in one UPDATE floored at 0, as `UsageLedger::apply_model_delta` does.
            let deltas: Vec<[i64; 4]> = models
                .iter()
                .map(|m| RESERVED_COLUMNS.map(|u| m.usage_units.get(u).copied().unwrap_or(0)))
                .collect();
            let mut ensure =
                String::from("INSERT INTO usage_ledger (bucket_id, window_start, model) VALUES ");
            let mut update = String::from(
                "UPDATE usage_ledger u SET \
                    tokens_input       = GREATEST(0, u.tokens_input + v.di), \
                    tokens_output      = GREATEST(0, u.tokens_output + v.do_), \
                    tokens_cache_read  = GREATEST(0, u.tokens_cache_read + v.dcr), \
                    tokens_cache_write = GREATEST(0, u.tokens_cache_write + v.dcw) \
                 FROM (VALUES ",
            );
            let mut ensure_params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(2 + models.len());
            let mut update_params: Vec<&(dyn ToSql + Sync)> =
                Vec::with_capacity(2 + models.len() * 5);
            ensure_params.push(&bucket_id);
            ensure_params.push(&ws);
            update_params.push(&bucket_id);
            update_params.push(&ws);
            for (i, (m, d)) in models.iter().zip(deltas.iter()).enumerate() {
                if i > 0 {
                    ensure.push(',');
                    update.push(',');
                }
                ensure.push_str(&format!("($1,$2,${})", 3 + i));
                ensure_params.push(&m.model);
                let base = 3 + i * 5;
                update.push_str(&format!(
                    "(${}::text,${}::bigint,${}::bigint,${}::bigint,${}::bigint)",
                    base,
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4
                ));
                update_params.push(&m.model);
                for v in d {
                    update_params.push(v);
                }
            }
            ensure.push_str(" ON CONFLICT (bucket_id, window_start, model) DO NOTHING");
            update.push_str(
                ") AS v(model, di, do_, dcr, dcw) \
                 WHERE u.bucket_id = $1 AND u.window_start = $2 AND u.model = v.model",
            );
            tx.execute(&ensure, &ensure_params).await.store()?;
            tx.execute(&update, &update_params).await.store()?;

            // The OPEN unit classes, the same ensure-then-signed-update shape.
            let opens: Vec<(&String, &String, i64)> = models
                .iter()
                .flat_map(|m| {
                    m.usage_units
                        .iter()
                        .filter(|(u, _)| !is_reserved_unit(u))
                        .map(move |(u, d)| (&m.model, u, *d))
                })
                .collect();
            if !opens.is_empty() {
                let mut ensure = String::from(
                    "INSERT INTO usage_ledger_units (bucket_id, window_start, model, unit) VALUES ",
                );
                let mut update = String::from(
                    "UPDATE usage_ledger_units u SET count = GREATEST(0, u.count + v.d) FROM (VALUES ",
                );
                let mut ensure_params: Vec<&(dyn ToSql + Sync)> =
                    Vec::with_capacity(2 + opens.len() * 2);
                let mut update_params: Vec<&(dyn ToSql + Sync)> =
                    Vec::with_capacity(2 + opens.len() * 3);
                ensure_params.push(&bucket_id);
                ensure_params.push(&ws);
                update_params.push(&bucket_id);
                update_params.push(&ws);
                for (i, (model, unit, d)) in opens.iter().enumerate() {
                    if i > 0 {
                        ensure.push(',');
                        update.push(',');
                    }
                    let eb = 3 + i * 2;
                    ensure.push_str(&format!("($1,$2,${},${})", eb, eb + 1));
                    ensure_params.push(*model);
                    ensure_params.push(*unit);
                    let ub = 3 + i * 3;
                    update.push_str(&format!(
                        "(${}::text,${}::text,${}::bigint)",
                        ub,
                        ub + 1,
                        ub + 2
                    ));
                    update_params.push(*model);
                    update_params.push(*unit);
                    update_params.push(d);
                }
                ensure.push_str(" ON CONFLICT (bucket_id, window_start, model, unit) DO NOTHING");
                update.push_str(
                    ") AS v(model, unit, d) \
                     WHERE u.bucket_id = $1 AND u.window_start = $2 \
                       AND u.model = v.model AND u.unit = v.unit",
                );
                tx.execute(&ensure, &ensure_params).await.store()?;
                tx.execute(&update, &update_params).await.store()?;
            }
        }
        Ok(())
    }

    /// `add_metering` inside the caller's transaction.
    pub(crate) async fn add_metering_in(
        tx: &mut Transaction<'_>,
        d: &MeteringDelta,
    ) -> RecordStoreResult<()> {
        let (bucket, ti, to, tcr, tcw) = (
            clamp(d.bucket),
            clamp(d.tokens_input),
            clamp(d.tokens_output),
            clamp(d.tokens_cache_read),
            clamp(d.tokens_cache_write),
        );
        let requests = clamp(d.requests);
        let brequests = clamp(d.billable_requests);
        let priced_from = clamp(d.priced_from_ms);
        // `priced_from_ms` is part of the accrual key (DECISION #79): a rate-card edit inside the
        // UTC day opens a SECOND row for that day so each half keeps the card it was earned under,
        // rather than folding counts earned under two prices into one row readable against one.
        tx.execute(
            "INSERT INTO usage_metering (key_id, bucket, model, provider,
                 tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
                 requests, billable_requests, key_group_at_use, pricing_version, priced_from_ms)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (key_id, bucket, model, provider, priced_from_ms) DO UPDATE SET
                 tokens_input       = usage_metering.tokens_input + EXCLUDED.tokens_input,
                 tokens_output      = usage_metering.tokens_output + EXCLUDED.tokens_output,
                 tokens_cache_read  = usage_metering.tokens_cache_read + EXCLUDED.tokens_cache_read,
                 tokens_cache_write = usage_metering.tokens_cache_write + EXCLUDED.tokens_cache_write,
                 requests           = usage_metering.requests + EXCLUDED.requests,
                 billable_requests  = usage_metering.billable_requests + EXCLUDED.billable_requests",
            &[
                &d.key_id, &bucket, &d.model, &d.provider, &ti, &to, &tcr, &tcw, &requests,
                &brequests, &d.key_group_at_use, &d.pricing_version, &priced_from,
            ],
        ).await
        .store()?;
        // Every ledgered class the token columns do not hold, additive like them, in the SAME
        // transaction so a metering row never shows its tokens without its other classes.
        let units: Vec<(&String, i64)> = d
            .usage_units
            .iter()
            .filter(|(_, v)| **v != 0)
            .map(|(u, v)| (u, clamp(*v)))
            .collect();
        if !units.is_empty() {
            let mut sql = String::from(
                "INSERT INTO usage_metering_units \
                 (key_id, bucket, model, provider, priced_from_ms, unit, count) VALUES ",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(5 + units.len() * 2);
            params.push(&d.key_id);
            params.push(&bucket);
            params.push(&d.model);
            params.push(&d.provider);
            params.push(&priced_from);
            for (i, (unit, count)) in units.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                let base = 6 + i * 2;
                sql.push_str(&format!("($1,$2,$3,$4,$5,${},${})", base, base + 1));
                params.push(*unit);
                params.push(count);
            }
            sql.push_str(
                " ON CONFLICT (key_id, bucket, model, provider, priced_from_ms, unit) DO UPDATE SET \
                 count = usage_metering_units.count + EXCLUDED.count",
            );
            tx.execute(&sql, &params).await.store()?;
        }
        Ok(())
    }

    /// `append_plane_record` inside the caller's transaction: `Ok(true)` once the record is stored
    /// (or an identical one already was), `Ok(false)` when the conflicting row vanished before the
    /// share lock held it (retry in a fresh transaction), `Err` on a fork.
    pub(crate) async fn append_plane_record_in(
        tx: &mut Transaction<'_>,
        record: &PlaneRecord,
    ) -> RecordStoreResult<bool> {
        let seq = as_storable_i64("append_plane_record", "seq", record.seq)?;
        let ts = as_storable_i64("append_plane_record", "ts", record.ts)?;
        // The chain a child record hangs off: its parent, or (a parentless append) its own id —
        // the same identity busbar's reference backends key a chain by.
        let parent = record.parent.as_deref().unwrap_or(record.id.as_str());
        let disposition = disposition_to_storage(record.disposition);
        // APPEND-ONLY. A record on an occupied (kind, parent, seq) is IDENTICAL (the write-through
        // retrying: Ok) or DIFFERENT (a forked chain: an error), as `append_audit` settles a duplicate
        // seq. The INSERT and the `FOR SHARE` read-back share one transaction so the conflicting row
        // cannot be purged under the comparison; if it vanishes first this returns `Ok(false)`, never
        // success, and the v3 caller turns that into a failure the kernel retries.
        let inserted = tx
            .execute(
                "INSERT INTO plane_chain (kind, parent, seq, id, ts, disposition, body)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT (kind, parent, seq) DO NOTHING",
                &[
                    &record.kind,
                    &parent,
                    &seq,
                    &record.id,
                    &ts,
                    &disposition,
                    &record.body,
                ],
            )
            .await
            .store()?;
        if inserted == 1 {
            return Ok(true);
        }
        let stored = tx
            .query_opt(
                "SELECT id, ts, disposition, body FROM plane_chain
                 WHERE kind=$1 AND parent=$2 AND seq=$3 FOR SHARE",
                &[&record.kind, &parent, &seq],
            )
            .await
            .store()?;
        match stored {
            Some(r) => {
                let identical = r.get::<_, String>(0) == record.id
                    && r.get::<_, i64>(1) == ts
                    && r.get::<_, String>(2) == disposition
                    && r.get::<_, Vec<u8>>(3) == record.body;
                if identical {
                    return Ok(true);
                }
                // Names the position and nothing else — it must not echo stored (or caller)
                // content back.
                Err(RecordStoreError(format!(
                    "append_plane_record: kind '{}' parent '{}' seq {} is already occupied by \
                     another record; the chain has forked",
                    record.kind, parent, record.seq
                )))
            }
            None => Ok(false),
        }
    }
}

// ── THE PLUGIN DOOR ──
// `v3` invokes `store_door!` over this store, which expands to `door`: a build that links this crate
// registers it, and the sibling `busbar-store-postgres-plugin` cdylib exports it.

mod v3;
pub use v3::door;

/// The package name the door's Statement states for this store.
pub const NAME: &str = "busbar-store-postgres";

#[cfg(test)]
mod tests;
