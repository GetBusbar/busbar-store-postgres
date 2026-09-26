// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres** backend for busbar's durable governance store — the shared, multi-node `db`
//! plugin. Implements `busbar_contract::records::RecordStore` over a mutex-guarded synchronous `postgres` client,
//! depending only on the `busbar-contract` crate (plus the `postgres` driver), never on the engine.
//!
//! Schema v10 (busbar 1.6.0): the kind-tagged plane-record tables, the name-keyed usage ledger and
//! the dated metering key, upgraded IN PLACE from a 1.5.x (v6) database — see `SCHEMA_VERSION`.
//!
//! Schema v5 (1.5.0, the generic-credentials redesign): `virtual_keys`/`aws_credentials` are
//! replaced by `keys` (pure principal attributes, `generation_hash` instead of `key_hash`,
//! `expires_at`/`deleted_at`/`revision`) and `credentials` (kind-polymorphic row-looked-up
//! credentials — today only `kind='sigv4'`). `DELETE` is a TOMBSTONE, not a hard delete: the `keys`
//! row survives (so `usage_metering.key_id` keeps resolving forever) while every credential row for
//! it is destroyed and `enabled`/`deleted_at` are set, atomically, in the same transaction and the
//! same `revision` stamp — this is what makes revision-delta hydration observe the tombstone AND
//! the credential disappearance as one atomic delta (see `delete_key`'s doc comment for why this
//! matters: a naive implementation that tombstoned the key in one transaction and deleted
//! credentials in another would let a `REPEATABLE READ` hydration snapshot land between them and
//! observe a "deleted" key whose credential is still live).
//!
//! Like the prior schema, this is a **single mutex-guarded connection** used off the request hot
//! path (key CRUD + the write-behind usage flush) — governance is off the reactor entirely.
//!
//! ## Known limitations (documented honestly, not papered over)
//!
//! - **No TLS in this build (`NoTls`).** Run the connection over a trusted network segment, a local
//!   socket, or a TLS-terminating proxy (pgbouncer/stunnel).
//! - **No automatic reconnect.** A persistently dropped connection surfaces as store errors; a
//!   permanently broken connection requires a process restart.
//! - **No partitioning, no LISTEN/NOTIFY-accelerated hydration, no column-level secret grants in
//!   this pass.** The design session that produced this schema recommended all three as scale/perf
//!   layers on top of this contract — deliberately deferred here in favor of getting the
//!   correctness-critical surface (tombstone semantics, revoke fan-out via `revoke_credential`,
//!   hydration-delta soundness, slot-safe credential minting) right first. None of the three change
//!   the `Store` trait's observable behavior; they're purely internal to this crate and can be
//!   added later without another schema bump.

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult,
    ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey, UNIT_CACHE_READ, UNIT_CACHE_WRITE,
    UNIT_INPUT, UNIT_OUTPUT,
};
use postgres::types::ToSql;
use postgres::{Client, NoTls, Row, Transaction};
use std::collections::BTreeMap;
use std::sync::Mutex;

// postgres driver error -> the api's backend-agnostic `RecordStoreError` (the contract crate stays
// storage-free, so the `From` impl that powers `?` cannot live there).
trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, postgres::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(render_pg_error(&e)))
    }
}

/// Render a driver error with its CAUSE attached. `postgres::Error`'s own `Display` for a
/// server-side failure is the literal string "db error" and nothing else: the SQLSTATE, the server
/// message and the violated constraint all live behind `as_db_error()`. Mapping straight through
/// `to_string()` therefore handed operators (and this crate's own callers) a two-word error for
/// every constraint violation, permission failure and bad statement alike, which is unactionable
/// and indistinguishable between causes.
///
/// The server's `detail` field is deliberately NOT included: on a unique violation Postgres puts
/// the offending ROW VALUES in it, and this string reaches logs. The SQLSTATE, the primary message
/// and the constraint name identify the failure without echoing data.
fn render_pg_error(e: &postgres::Error) -> String {
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

/// True when a postgres error is SQLSTATE 42P01 (`undefined_table`) - the ONE case migrate() treats
/// as an unversioned (version 0) database. Every other error class (connection, timeout, permission)
/// is transient/fatal and must never be read as "fresh DB": treating a connection or permission
/// failure as version 0 would drop and recreate a populated database.
fn is_undefined_table(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE)
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
    // The URL QUERY-PARAMETER form (`postgres://user@host/db?password=secret`). libpq accepts it,
    // the README tells operators to use the query string for other options, and it does not go
    // through the userinfo branch above, so without this it reached the keyword scan below and was
    // never redacted.
    if let Some((_, query)) = dsn.split_once('?') {
        for param in query.split('&') {
            if let Some(v) = param.strip_prefix("password=") {
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    // The libpq KEYWORD form. libpq allows whitespace around the separator (`password = secret`)
    // and single-quoted values (`password='se cret'`); a plain `strip_prefix("password=")` over
    // whitespace tokens sees neither, returns None, and `scrub` then passes the connect error
    // through with the secret intact. Collapse the whitespace around every `=` first, then match
    // the key only at a token boundary so `sslpassword=` (a different libpq option) is not mistaken
    // for it.
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

/// Store schema version. v5 (1.5.0 generic-credentials redesign): `virtual_keys`/`aws_credentials`
/// -> `keys`/`credentials` (kind-polymorphic, slot-bounded, tombstone-delete, revision-stamped for
/// incremental hydration). 1.5.0 is unreleased, so a pre-v5 database is dropped and recreated - a
/// bump, never a migration.
///
/// v6: ONE-TIME, DURABLE backfill of `usage_windows.billable_requests` for any row still shaped
/// `billable_requests=0, requests>0` at the moment this migration runs. Exists to retire a bug in
/// busbar core's `governance::state::hydrate_budgets`, which used to infer "legacy pre-split
/// row" from that exact counter shape at EVERY boot - but a fully-refunded window (every request
/// in it non-2xx; `refund_bucket` decrements `billable_requests` but deliberately never
/// `requests`) produces the identical shape, so hydrate_budgets could not tell "never migrated"
/// from "correctly refunded to zero" and silently re-billed refunded fees on restart. Doing the
/// value-based backfill HERE, ONCE, gated on the version crossing, is safe ONLY because 1.5.0 has
/// never shipped to a real customer - there is no genuine "currently, legitimately refunded to
/// zero" row in existence anywhere to accidentally re-bill at the moment this migration ships.
/// This would NOT be safe to run again, or to run as a per-boot heuristic (that was the bug) -
/// which is exactly why it is gated on `version < 6` and will never fire a second time on any
/// store that has already crossed into v6. `hydrate_budgets` itself drops the heuristic entirely
/// once every store it reads from has passed through this migration.
///
/// v7-v9 (never released — dev builds of 1.5.x only): the protocol-NAMED durable tables
/// `mcp_calls`, `tasks`/`task_events`, `mcp_demotions` and `spent_ask_states`, one per typed trait
/// method busbar 1.6.0 has since deleted. v10 no longer creates, reads or writes them. A database a
/// dev build carried to v9 keeps them exactly as they were — NOTHING is dropped or rewritten — so
/// the rows remain on disk for an operator who wants them; the 1.6.0 engine writes its plane records
/// in its own opaque body format through the tables below instead, and guessing that format for a
/// row written under the old typed shape would be inventing data, not migrating it.
///
/// v10 (busbar 1.6.0 store interface), an IN-PLACE, ADDITIVE upgrade of a v6 (released 1.5.x)
/// database — no table is dropped and no existing row changes meaning:
///   * `keys` gains `idp_subject`/`binding_mode`/`minted_by` (NULL for every pre-existing key, which
///     is exactly what `VirtualKey` reads for a key minted before those fields existed) and
///     `allowed_scopes_by_kind`, the non-`pool` scope grants (`mcp_server`, `agent`, …) keyed by
///     kind. `allowed_pools` keeps holding the pool grants byte-for-byte as before, so a pool-only
///     key reads back unchanged; NULL in both columns is still the omitted-grant wildcard.
///   * the usage ledger keeps the four reserved token classes in its existing columns and carries
///     every OPEN unit class (1.6.0 M1b `usage_units`) in the new `usage_ledger_units` table.
///   * `usage_metering` gains `priced_from_ms` (DEFAULT 0 — the opening rate-card entry, which is
///     how busbar reads an undated 1.5.x row) and it JOINS the primary key, so a rate-card edit
///     inside a UTC day opens a second row rather than folding two prices into one (#79). Open unit
///     classes ride in the new `usage_metering_units` table.
///   * the kind-tagged PLANE-RECORD verbs get `plane_records` (upserted, keyed `(kind, id)`),
///     `plane_chain` (appended, keyed `(kind, parent, seq)`) and `plane_tokens` (the single-use
///     token ledger, keyed `(kind, token)`).
const SCHEMA_VERSION: i64 = 10;

/// The plane-record kinds whose retention is TERMINAL-ONLY: `purge_plane_records_before` drops a row
/// of one of these kinds only once its `disposition` sidecar says `Terminal`. An interrupted task
/// waiting on a human is exactly the row that sits still longest, and sweeping it is losing the
/// work. Every other kind drops any row older than the cutoff — the same split busbar's reference
/// backends (`store-memory`, `store-example-plugin`) draw.
const TERMINAL_ONLY_RETENTION_KINDS: [&str; 1] = ["task"];

/// `(parent kind, child kind)`: purging a parent record takes the child CHAIN hanging off it in the
/// same transaction. A task's event chain has no retention path of its own, so leaving it behind
/// would let it grow forever under tasks that no longer exist — the cascade busbar's
/// `store-example-plugin` makes, and this store made before 1.6.0.
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
    -- Rotation fingerprint (VirtualKey::generation_hash), NOT a lookup key -- deliberately no
    -- UNIQUE constraint, see the type's own doc for why.
    generation_hash TEXT NOT NULL,
    name            TEXT NOT NULL,
    -- NULL = the pool grant was OMITTED at mint = ALL pools; a JSON array (possibly empty) = the
    -- exhaustive grant. NULL and '[]' must never collapse into each other.
    allowed_pools   TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      BIGINT NOT NULL,
    key_group       TEXT,
    labels          TEXT NOT NULL DEFAULT '{}',
    expires_at      BIGINT,
    -- TOMBSTONE marker. NULL = live. The row is never removed once tombstoned; see delete_key.
    deleted_at      BIGINT,
    revision        BIGINT NOT NULL DEFAULT 0,
    -- v10 (busbar 1.6.0): attribution/provenance, NULL for every key minted before they existed.
    idp_subject     TEXT,
    binding_mode    TEXT,
    minted_by       TEXT,
    -- v10: the NON-pool scope grants, a JSON object {kind: [value, ...]}. NULL = none. Pool grants
    -- stay in allowed_pools; NULL in BOTH columns is the omitted-grant wildcard.
    allowed_scopes_by_kind TEXT,
    CONSTRAINT keys_tombstone_disabled CHECK (deleted_at IS NULL OR enabled = FALSE)
);
CREATE INDEX IF NOT EXISTS idx_keys_revision ON keys (revision);

-- Row-looked-up credentials ONLY (today: sigv4). Bearer/signed-token auth is never represented
-- here -- verify_token never looks up a row, it only compares VirtualKey::generation_hash. Slot
-- bounds cardinality to exactly 2 rows per (key_id, kind), for safe overlap-window rotation.
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
-- v10: every OPEN unit class of a (bucket, window, model) ledger row — the 1.6.0 M1b `usage_units`
-- keys that are not one of the four reserved token classes above (which keep their columns, so a
-- 1.5.x ledger row needs no rewrite). Additive on the flush path like the token columns.
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
    -- v10: the instant this row's price started (#79). Part of the accrual key.
    priced_from_ms     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms)
);
CREATE INDEX IF NOT EXISTS idx_usage_metering_bucket ON usage_metering (bucket);
-- v10: every ledgered class the token columns do not hold (MeteringRow::usage_units), per metering
-- row. Additive like the token columns.
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

-- THE KIND-TAGGED PLANE RECORDS (v10, busbar 1.6.0). The typed per-protocol tables of v7-v9 are
-- replaced by one neutral surface: a plane record is an OPAQUE body the engine serialized plus the
-- typed sidecar columns (kind, id, parent, seq, ts, disposition) that let this store key, order and
-- retention-sweep without ever decoding the body. This store NEVER decodes a body and never
-- computes or recomputes a digest inside one: it persists what it was handed and returns it
-- verbatim.
--
-- COLLATE \"C\" on every identity column is BYTE-EXACT comparison, stated rather than inherited.
-- Postgres's default collations are deterministic, so this changes nothing on a normally-created
-- database — but one created with a NON-DETERMINISTIC ICU collation (case- and accent-insensitive)
-- would otherwise make two task ids differing only in case COLLIDE on the primary key and silently
-- upsert onto one row, fold a single-use token onto its case-variant, and let `vk_alice` read
-- `vk_Alice`'s call chain. A kind, an id, a parent and a token are opaque strings, never words.

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

-- APPENDED chains (a task's event chain, a principal's call log): append-only, keyed by the chain
-- position (kind, parent, seq). A second record at an occupied position is either the write-through
-- retrying (identical: Ok) or a fork (different: refused) — never an overwrite.
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

-- THE SINGLE-USE TOKEN LEDGER behind redeem_plane_token (an `ask` approval nonce, ...). A sealed
-- single-use token verifies identically on its second presentation; only a RECORD THAT THE FIRST
-- HAPPENED tells them apart, and it has to be one ledger for the whole fleet to be true of every
-- node. Every redemption is a point INSERT on the primary key; expires_at bounds the table.
CREATE TABLE IF NOT EXISTS plane_tokens (
    kind       TEXT COLLATE \"C\" NOT NULL,
    token      TEXT COLLATE \"C\" NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (kind, token)
);
";

/// The v10 column additions on tables a 1.5.x database already has. `IF NOT EXISTS`, so a re-run
/// after a crash part-way through is harmless; `migrate_locked` runs it only when crossing into v10.
const MIGRATE_V10_COLUMNS: &str = "
ALTER TABLE keys ADD COLUMN IF NOT EXISTS idp_subject TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS binding_mode TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS minted_by TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS allowed_scopes_by_kind TEXT;
ALTER TABLE usage_metering ADD COLUMN IF NOT EXISTS priced_from_ms BIGINT NOT NULL DEFAULT 0;
";

/// Postgres `Store` backend (durable, shared across a cluster). A single mutex-guarded connection —
/// governance is off the request hot path, so serializing access is fine.
pub struct PostgresStore {
    client: Mutex<Client>,
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

/// Current Unix time in seconds, 0 if the system clock is before the epoch. The ONE source of
/// wall-clock stamps in this crate (`deleted_at`, `revoked_at`), so no write path can reach for a
/// convenient nearby integer instead: `revision` is also a BIGINT and binding it to a timestamp
/// column type-checks, round-trips, and satisfies every "is it set" assertion while recording a
/// time a few seconds after 1970.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl PostgresStore {
    /// Connect to Postgres with the given libpq connection string / URL and ensure the schema. TLS
    /// is not wired in this build (`NoTls`); front the database with a TLS-terminating proxy or a
    /// local socket.
    pub fn connect(conn_str: &str) -> RecordStoreResult<Self> {
        let secret = dsn_password(conn_str);
        // `render_pg_error`, not `e.to_string()`. A server-side refusal (bad database name, failed
        // authentication, an unavailable extension) is a `db_error` whose Display is the literal
        // two words "db error" — so the ONE error an operator hits before anything else works
        // rendered as the least actionable string in the crate, while every query error had already
        // been fixed to carry its SQLSTATE and message. Still scrubbed of the DSN password.
        let client = Client::connect(conn_str, NoTls)
            .map_err(|e| RecordStoreError(scrub(render_pg_error(&e), secret.as_deref())))?;
        let store = Self {
            client: Mutex::new(client),
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Open a transaction that gives every statement inside it ONE consistent snapshot, taken at the
    /// transaction's first statement — REPEATABLE READ, not the default READ COMMITTED (which gives
    /// each statement its own fresh snapshot, a torn-read hazard for any multi-statement read like
    /// `get_usage` or the hydration delta queries).
    pub(crate) fn snapshot_consistent_tx<'a>(
        client: &'a mut Client,
    ) -> RecordStoreResult<postgres::Transaction<'a>> {
        client
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .start()
            .store()
    }

    const MIGRATE_LOCK_KEY: i64 = 0x6275_7362_6172_5f70; // ASCII "busbar_p"

    fn migrate(&self) -> RecordStoreResult<()> {
        let mut client = self.lock();
        client
            .batch_execute(&format!(
                "SELECT pg_advisory_lock({})",
                Self::MIGRATE_LOCK_KEY
            ))
            .store()?;
        let result = Self::migrate_locked(&mut client);
        let unlocked = client.batch_execute(&format!(
            "SELECT pg_advisory_unlock({})",
            Self::MIGRATE_LOCK_KEY
        ));
        // A migration failure is the more important thing to report; don't mask it with an unlock
        // failure. But if the migration itself SUCCEEDED and the unlock did not, that must not be
        // swallowed: an un-released session-held advisory lock can hang a sibling node's connect()
        // (which takes the same lock before its own migrate) for the remaining lifetime of this
        // process's connection, with previously zero trace that it happened.
        match (result, unlocked) {
            (Ok(()), Err(e)) => Err(RecordStoreError(format!(
                "migrate: schema migration succeeded but releasing the advisory lock failed ({e}); \
                 a sibling node's own migrate() may now hang waiting for this lock"
            ))),
            (result, _) => result,
        }
    }

    fn migrate_locked(client: &mut Client) -> RecordStoreResult<()> {
        client
            .batch_execute("CREATE TABLE IF NOT EXISTS busbar_schema (version BIGINT PRIMARY KEY)")
            .store()?;
        let version: i64 =
            match client.query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[]) {
                Ok(Some(r)) => r.get(0),
                Ok(None) => 0,
                Err(e) if is_undefined_table(&e) => 0,
                Err(e) => return Err(RecordStoreError(e.to_string())),
            };
        // ALREADY CURRENT: run no DDL at all. Every node runs `migrate()` on every connect, and
        // `SCHEMA`'s `CREATE INDEX IF NOT EXISTS` takes a SHARE lock on its table before it
        // discovers the index exists — first on `keys`, then on `credentials`. A `delete_key` on
        // another node writes them in the OTHER order (credentials, then keys), so re-running the
        // no-op DDL on a current database deadlocked a live key delete against a node merely
        // connecting (observed: `40P01` on `UPDATE keys ... deleted_at`). A database at (or past)
        // this build's version has every table and index this build creates.
        if version >= SCHEMA_VERSION {
            return Ok(());
        }
        let mut tx = client.transaction().store()?;
        if version < 5 {
            let legacy: bool = tx
                .query_one(
                    "SELECT to_regclass('usage_counters') IS NOT NULL
                        OR to_regclass('virtual_keys') IS NOT NULL
                        OR to_regclass('aws_credentials') IS NOT NULL",
                    &[],
                )
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
                .store()?;
            }
        }
        tx.batch_execute(SCHEMA).store()?;
        // v6 one-time backfill — see SCHEMA_VERSION's doc comment for why this is safe as a
        // gated-once value backfill and would NOT be safe as a repeated/per-boot heuristic. Only
        // fires when crossing INTO v6 (a store already at v6+ never re-runs this).
        if version < 6 {
            tx.execute(
                "UPDATE usage_windows SET billable_requests = requests \
                 WHERE billable_requests = 0 AND requests > 0",
                &[],
            )
            .store()?;
        }
        // v10 — see SCHEMA_VERSION. `SCHEMA`'s `CREATE TABLE IF NOT EXISTS` never alters a table
        // that already exists, so on a 1.5.x (v6) database these statements ARE the upgrade.
        // Nothing is dropped and no existing value is rewritten.
        //
        // Crossing INTO v10 only, and that gate is load-bearing rather than tidy: `ALTER TABLE`
        // takes an ACCESS EXCLUSIVE lock on the table even when `IF NOT EXISTS` turns it into a
        // no-op, and every node's connect runs `migrate()` — so an unconditional ALTER here locks
        // `keys` out from under every other node's in-flight transaction on every connect (and
        // deadlocks against one holding the `store_revision` row this transaction's `SCHEMA` insert
        // also touches). The whole migration is ONE transaction with the version stamp, so a crash
        // part-way leaves `version < 10` and the next connect re-runs it from the start.
        if version < 10 {
            tx.batch_execute(MIGRATE_V10_COLUMNS).store()?;
            // The one v10 step that is not a pure addition: `priced_from_ms` joins the metering
            // primary key. Every existing row carries `priced_from_ms = 0` (the column default),
            // so the old key `(key_id, bucket, model, provider)` was already unique and the widened
            // key admits every existing row unchanged.
            tx.batch_execute(
                "ALTER TABLE usage_metering DROP CONSTRAINT IF EXISTS usage_metering_pkey;
                 ALTER TABLE usage_metering ADD CONSTRAINT usage_metering_pkey
                     PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms);",
            )
            .store()?;
        }
        tx.execute(
            "INSERT INTO busbar_schema (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
            &[&SCHEMA_VERSION],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    /// Bump and return the store-global revision INSIDE the caller's already-open transaction. Must
    /// be the FIRST statement of any transaction that mutates `keys`/`credentials`/`denylist` (not
    /// `denylist` directly — `add_denylist` doesn't take a revision param on the trait — but keys
    /// and credentials do): calling it first fixes a single lock-acquisition order
    /// (`store_revision` row, then whatever else the transaction touches) across every mutating
    /// method, which is what makes cross-method deadlock structurally impossible.
    fn next_revision(tx: &mut Transaction<'_>) -> RecordStoreResult<i64> {
        tx.query_one(
            "UPDATE store_revision SET revision = revision + 1 WHERE only_row RETURNING revision",
            &[],
        )
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

// SCOPE STORAGE. `allowed_pools` is unchanged since 1.5.x: a JSON array of bare pool names, or
// NULL. The v10 `allowed_scopes_by_kind` column carries every NON-pool grant as a JSON object
// `{kind: [value, ...]}` (NULL when there are none), so a pool-only key is stored byte-identically
// to what a 1.5.x build wrote, and a pre-v10 row (NULL in the new column) reads back exactly as it
// did. The partition mirrors the VirtualKey wire (`allowed_pools` + one field per kind):
//   * `None` (grant omitted = every scope of every kind) -> both columns NULL;
//   * `Some(list)` (exhaustive across ALL kinds, possibly empty) -> `allowed_pools` is ALWAYS a
//     JSON array (possibly `[]`), so `Some([])` = no scopes never collapses into `None` = all, and
//     a grant of only non-pool kinds never reads back as "every pool".
// A non-pool kind is NEVER folded into `allowed_pools`: that is the pre-1.6.0 defect where an
// `mcp_server` grant became a POOL grant on a store round-trip.
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
    }
}

const KEY_COLUMNS: &str = "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,idp_subject,binding_mode,minted_by,allowed_scopes_by_kind";

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
/// The row index of `secret` in `SELECT {CRED_META_COLUMNS},secret FROM credentials ...` -- always
/// exactly the column COUNT of CRED_META_COLUMNS (12: id,key_id,kind,slot,public_id,secret_form,
/// created_at,updated_at,expires_at,revoked_at,revoke_reason,revision -- indices 0-11), since every
/// query that reads `secret` builds its SELECT by appending it right after that column list. Named
/// here instead of a bare `12` at each call site. The drift guard is a test, not an inline
/// assertion: `cred_secret_column_index_matches_cred_meta_columns_count` in this crate's `tests`
/// module fails if CRED_META_COLUMNS' column count ever changes without this constant being
/// updated to match, which is as close as stable Rust gets while `str::split` is not
/// const-evaluable.
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

impl RecordStore for PostgresStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        let (pools, by_kind) = scopes_to_storage(&key.allowed_scopes);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let expires = key.expires_at.map(clamp);
        let deleted = key.deleted_at.map(clamp);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let rev = Self::next_revision(&mut tx)?;
        // The `WHERE` on the conflict branch is the TOMBSTONE PRECONDITION (see `Store::put_key`):
        // a live-shaped write (`EXCLUDED.deleted_at IS NULL`) must not overwrite a tombstoned row,
        // which would reissue an id the contract says is never reissued and revive every token
        // minted before the delete. It rides on the statement rather than a preceding SELECT for
        // the same reason `delete_key`'s `AND deleted_at IS NULL` does: under READ COMMITTED the
        // conflict branch re-evaluates its WHERE against post-lock committed data, so this actually
        // closes the TOCTOU window a separate SELECT leaves wide open.
        // A write that CARRIES a tombstone is unaffected and still applies.
        let changed = tx.execute(
            "INSERT INTO keys
                (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,
                 idp_subject,binding_mode,minted_by,allowed_scopes_by_kind)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (id) DO UPDATE SET
                generation_hash=EXCLUDED.generation_hash, name=EXCLUDED.name,
                allowed_pools=EXCLUDED.allowed_pools, enabled=EXCLUDED.enabled,
                key_group=EXCLUDED.key_group, labels=EXCLUDED.labels,
                expires_at=EXCLUDED.expires_at, deleted_at=EXCLUDED.deleted_at,
                revision=EXCLUDED.revision, idp_subject=EXCLUDED.idp_subject,
                binding_mode=EXCLUDED.binding_mode, minted_by=EXCLUDED.minted_by,
                allowed_scopes_by_kind=EXCLUDED.allowed_scopes_by_kind
             WHERE EXCLUDED.deleted_at IS NOT NULL OR keys.deleted_at IS NULL",
            &[
                &key.id, &key.generation_hash, &key.name, &pools, &key.enabled, &created,
                &key.group, &labels, &expires, &deleted, &rev, &key.idp_subject,
                &key.binding_mode, &key.minted_by, &by_kind,
            ],
        )
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
        tx.commit().store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys WHERE id=$1");
        let row = self.lock().query_opt(&sql, &[&id]).store()?;
        Ok(row.map(|r| row_to_key(&r)))
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED (tombstoned rows included) -- see the trait doc: this serves both
        // the admin-listing caller (which filters deleted_at.is_none() itself) and list_keys_since's
        // default fallback, which needs tombstones visible to drive credential eviction downstream.
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys ORDER BY created_at");
        let rows = self.lock().query(&sql, &[]).store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys WHERE revision > $1 ORDER BY revision");
        let rows = self.lock().query(&sql, &[&clamp(since)]).store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        // TOMBSTONE, not a hard delete: the `keys` row survives (billing/audit attribution keeps
        // resolving it forever) while every credential row for it is destroyed. Both happen in ONE
        // transaction stamped with the SAME revision, which is the load-bearing property for
        // hydration soundness: a REPEATABLE READ hydration snapshot can never observe the
        // tombstoned key without the credentials already being gone, so a delta-consumer that
        // reacts to "this key's revision-delta shows deleted_at newly set" by evicting all its
        // cached credentials is provably correct -- there is no window where the credential rows'
        // own (now-nonexistent) deltas would have been needed to convey the deletion.
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let already_deleted: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NOT NULL FROM keys WHERE id=$1",
                &[&id],
            )
            .store()?
            .map(|r| r.get(0));
        match already_deleted {
            None => {
                // Unknown id: an ERROR, and deliberately NOT the same case as the already-tombstoned
                // one below. The trait settles them apart because "already tombstoned" means the
                // operator's intent is satisfied and the evidence is on disk, while "no such id"
                // means nothing was touched - and answering Ok there tells an operator who typo'd
                // an id that a key was revoked when none was.
                return Err(RecordStoreError(format!("delete_key: unknown id '{id}'")));
            }
            Some(true) => {
                // Already tombstoned: no-op, not an error.
                tx.commit().store()?;
                return Ok(());
            }
            Some(false) => {}
        }
        let rev = Self::next_revision(&mut tx)?;
        // `deleted_at` is a WALL-CLOCK stamp and `revision` is the store-global counter. They are
        // both BIGINT, so binding one value to both columns compiles, round-trips and satisfies
        // every "is this key tombstoned" check -- while telling every operator, retention job and
        // cross-backend comparison that the key was deleted a few seconds after 1970. Bound
        // separately, and pinned by
        // `delete_key_stamps_deleted_at_with_a_wall_clock_time_not_the_revision`.
        let now = clamp(now_secs());
        tx.execute("DELETE FROM credentials WHERE key_id=$1", &[&id])
            .store()?;
        // `AND deleted_at IS NULL` re-states the guard the SELECT above already checked, IN the
        // UPDATE's own WHERE clause: under Postgres' READ COMMITTED semantics, an UPDATE takes a row
        // lock and re-evaluates its WHERE against the post-lock committed data, so this closes the
        // TOCTOU window the plain `SELECT` above cannot -- two concurrent delete_key calls on the
        // same id now genuinely serialize (the loser's UPDATE matches 0 rows) instead of both
        // unconditionally overwriting `deleted_at`/`revision` regardless of which committed first.
        let changed = tx
            .execute(
                "UPDATE keys SET enabled=FALSE, deleted_at=$2, revision=$3 \
                 WHERE id=$1 AND deleted_at IS NULL",
                &[&id, &now, &rev],
            )
            .store()?;
        // A concurrent delete_key committed between our SELECT and this UPDATE: idempotent no-op,
        // same as the `Some(true)` branch above -- not an error.
        if changed == 0 {
            tx.commit().store()?;
            return Ok(());
        }
        tx.commit().store()?;
        Ok(())
    }

    fn scrub_key(&self, id: &str) -> RecordStoreResult<()> {
        // PII-erasure only: null name/labels on an ALREADY-tombstoned key. Errors if unknown or
        // still live -- scrubbing a live key would be silent, un-auditable data loss on an active
        // principal (the trait doc's own guard: go through delete_key first).
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let deleted: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NOT NULL FROM keys WHERE id=$1",
                &[&id],
            )
            .store()?
            .map(|r| r.get(0));
        match deleted {
            None => return Err(RecordStoreError(format!("scrub_key: unknown key {id}"))),
            Some(false) => {
                return Err(RecordStoreError(format!(
                    "scrub_key: key {id} is not tombstoned -- call delete_key first"
                )))
            }
            Some(true) => {}
        }
        let rev = Self::next_revision(&mut tx)?;
        // `AND deleted_at IS NOT NULL` re-states the "must already be tombstoned" guard IN the
        // UPDATE's own WHERE clause, closing the same TOCTOU class as delete_key above: the SELECT
        // this function just ran is not atomic with this write, so without the re-check here a
        // concurrent put_key/put_key_with_credential resurrecting the key between the SELECT and
        // this UPDATE would let scrub_key silently erase name/labels on what is, by the time this
        // statement lands, a LIVE key -- exactly the un-auditable-data-loss-on-an-active-principal
        // this method's own doc comment says it must never do.
        let changed = tx
            .execute(
                "UPDATE keys SET name='', labels='{}', revision=$2 \
                 WHERE id=$1 AND deleted_at IS NOT NULL",
                &[&id, &rev],
            )
            .store()?;
        if changed == 0 {
            return Err(RecordStoreError(format!(
                "scrub_key: key {id} was resurrected (deleted_at cleared) concurrently with this \
                 call -- refusing to scrub a key that is live by the time the write landed"
            )));
        }
        tx.commit().store()?;
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = Self::snapshot_consistent_tx(&mut client)?;
        let (requests, billable_requests): (u64, u64) = tx
            .query_opt(
                "SELECT requests, billable_requests
                 FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
                &[&bucket_id, &ws],
            )
            .store()?
            .map(|r| (read_u64(r.get::<_, i64>(0)), read_u64(r.get::<_, i64>(1))))
            .unwrap_or((0, 0));
        let rows = tx
            .query(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                 FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2 ORDER BY model",
                &[&bucket_id, &ws],
            )
            .store()?;
        let unit_rows = tx
            .query(
                "SELECT model, unit, count FROM usage_ledger_units
                 WHERE bucket_id=$1 AND window_start=$2 ORDER BY model, unit",
                &[&bucket_id, &ws],
            )
            .store()?;
        tx.commit().store()?;
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

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let ws = clamp(window_start);
        let rq = clamp(ledger.requests);
        let brq = clamp(ledger.billable_requests);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket_id, &ws],
        )
        .store()?;
        tx.execute(
            "DELETE FROM usage_ledger_units WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket_id, &ws],
        )
        .store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = EXCLUDED.requests,
                billable_requests = EXCLUDED.billable_requests",
            &[&bucket_id, &ws, &rq, &brq],
        )
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
            tx.execute(&sql, &params).store()?;

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
                // Two ModelTokens entries for one model would name the same unit twice; summed,
                // the same way `UsageLedger::apply_delta` folds them, rather than a key violation.
                sql.push_str(
                    " ON CONFLICT (bucket_id, window_start, model, unit) DO UPDATE SET \
                     count = usage_ledger_units.count + EXCLUDED.count",
                );
                tx.execute(&sql, &params).store()?;
            }
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,GREATEST(0,$3::bigint),GREATEST(0,$4::bigint))
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = GREATEST(0, usage_windows.requests + $3::bigint),
                billable_requests = GREATEST(0, usage_windows.billable_requests + $4::bigint)",
            &[&bucket_id, &ws, &delta.requests, &delta.billable_requests],
        )
        .store()?;
        if !delta.models.is_empty() {
            // TWO statements, both batched over every model, and the split is what makes a
            // NEGATIVE delta (a refund) land. An `INSERT … ON CONFLICT DO UPDATE` can only add
            // `EXCLUDED.col` on conflict, and EXCLUDED is the row the INSERT would have written —
            // which has to be floored at 0 for a first-seen model — so a refund against an existing
            // row added 0 and was silently lost. Instead: make sure every model's row exists (at
            // zero), then apply the SIGNED deltas to it in one UPDATE, floored at 0 there. A refund
            // against a fresh row floors to 0, exactly as `UsageLedger::apply_model_delta` does.
            let deltas: Vec<[i64; 4]> = delta
                .models
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
            let mut ensure_params: Vec<&(dyn ToSql + Sync)> =
                Vec::with_capacity(2 + delta.models.len());
            let mut update_params: Vec<&(dyn ToSql + Sync)> =
                Vec::with_capacity(2 + delta.models.len() * 5);
            ensure_params.push(&bucket_id);
            ensure_params.push(&ws);
            update_params.push(&bucket_id);
            update_params.push(&ws);
            for (i, (m, d)) in delta.models.iter().zip(deltas.iter()).enumerate() {
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
            tx.execute(&ensure, &ensure_params).store()?;
            tx.execute(&update, &update_params).store()?;

            // The OPEN unit classes, the same ensure-then-signed-update shape.
            let opens: Vec<(&String, &String, i64)> = delta
                .models
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
                tx.execute(&ensure, &ensure_params).store()?;
                tx.execute(&update, &update_params).store()?;
            }
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> RecordStoreResult<()> {
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
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
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
        )
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
            tx.execute(&sql, &params).store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        let b = clamp(bucket);
        let mut client = self.lock();
        // ONE snapshot for both reads, so a row's open classes are never read from a different
        // moment than its token columns.
        let mut tx = Self::snapshot_consistent_tx(&mut client)?;
        let rows = tx
            .query(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
                    requests, billable_requests, key_group_at_use, pricing_version, priced_from_ms
                 FROM usage_metering WHERE bucket=$1
                 ORDER BY key_id, model, provider, priced_from_ms",
                &[&b],
            )
            .store()?;
        let unit_rows = tx
            .query(
                "SELECT key_id, model, provider, priced_from_ms, unit, count
                 FROM usage_metering_units WHERE bucket=$1",
                &[&b],
            )
            .store()?;
        tx.commit().store()?;
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

    fn purge_windows_before(&self, before: u64) -> RecordStoreResult<u64> {
        let b = clamp(before);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let n1 = tx
            .execute("DELETE FROM usage_windows WHERE window_start < $1", &[&b])
            .store()?;
        tx.execute("DELETE FROM usage_ledger WHERE window_start < $1", &[&b])
            .store()?;
        tx.execute(
            "DELETE FROM usage_ledger_units WHERE window_start < $1",
            &[&b],
        )
        .store()?;
        tx.commit().store()?;
        Ok(n1)
    }

    fn purge_metering_before(&self, bucket: &str) -> RecordStoreResult<u64> {
        // The trait's purge_metering_before takes `bucket: &str` while list_metering/add_metering
        // use `bucket: u64` -- an inconsistency in the core trait itself, not introduced here.
        // usage_metering.bucket is genuinely BIGINT, so this parses the string form.
        let b: i64 = bucket.parse().map_err(|_| {
            RecordStoreError(format!(
                "purge_metering_before: invalid bucket {bucket:?}, expected an integer"
            ))
        })?;
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let n = tx
            .execute("DELETE FROM usage_metering WHERE bucket=$1", &[&b])
            .store()?;
        tx.execute("DELETE FROM usage_metering_units WHERE bucket=$1", &[&b])
            .store()?;
        tx.commit().store()?;
        Ok(n)
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        Self::put_credential_tx(&mut tx, secret)?;
        tx.commit().store()?;
        Ok(())
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        // ATOMIC mint: the bearer key and its credential commit together or not at all.
        let (pools, by_kind) = scopes_to_storage(&key.allowed_scopes);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let expires = key.expires_at.map(clamp);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let rev = Self::next_revision(&mut tx)?;
        // Same TOMBSTONE PRECONDITION as `put_key`, and this is the path where it MATTERS MOST: the
        // conflict branch used to set `deleted_at=NULL` outright, so re-minting over a tombstoned id
        // deliberately cleared the tombstone. That was written to avoid leaving a row both enabled
        // and deleted (which a CHECK constraint forbids), but the contract's answer to that is to
        // REFUSE the write, not to reissue an id `VirtualKey::deleted_at` says is never reissued and
        // revive every token minted before the delete.
        //
        // The insert always supplies `deleted_at = NULL` (a mint is live by construction), so the
        // guard here is simply "the stored row must not be a tombstone".
        let changed = tx.execute(
            "INSERT INTO keys
                (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,
                 idp_subject,binding_mode,minted_by,allowed_scopes_by_kind)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$11,$12,$13,$14)
             ON CONFLICT (id) DO UPDATE SET
                generation_hash=EXCLUDED.generation_hash, name=EXCLUDED.name,
                allowed_pools=EXCLUDED.allowed_pools, enabled=EXCLUDED.enabled,
                key_group=EXCLUDED.key_group, labels=EXCLUDED.labels,
                expires_at=EXCLUDED.expires_at, revision=EXCLUDED.revision,
                idp_subject=EXCLUDED.idp_subject, binding_mode=EXCLUDED.binding_mode,
                minted_by=EXCLUDED.minted_by, allowed_scopes_by_kind=EXCLUDED.allowed_scopes_by_kind
             WHERE keys.deleted_at IS NULL",
            &[
                &key.id, &key.generation_hash, &key.name, &pools, &key.enabled, &created,
                &key.group, &labels, &expires, &rev, &key.idp_subject, &key.binding_mode,
                &key.minted_by, &by_kind,
            ],
        )
        .store()?;
        if changed == 0 {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: '{}' is tombstoned and its id is never reissued; \
                 refusing to clear the tombstone",
                key.id
            )));
        }
        Self::put_credential_tx(&mut tx, secret)?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        let sql = format!("SELECT {CRED_META_COLUMNS} FROM credentials WHERE key_id=$1");
        let rows = self.lock().query(&sql, &[&key_id]).store()?;
        Ok(rows.iter().map(row_to_cred_meta).collect())
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE kind=$1 AND public_id=$2"
        );
        let row = self.lock().query_opt(&sql, &[&kind, &public_id]).store()?;
        Ok(row.map(|r| CredentialSecret {
            meta: row_to_cred_meta(&r),
            secret: r
                .get::<_, Option<String>>(CRED_SECRET_COLUMN_INDEX)
                .unwrap_or_default(),
        }))
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                &[&id],
            )
            .store()?
            .get(0);
        if !exists {
            // NOT idempotent-success: the trait's idempotency covers an ALREADY-REVOKED row, and it
            // defaults this method to a loud error because a silent no-op lets an operator believe a
            // leaked secret was killed when it was not. An id naming no row is the shape that
            // matters -- minting into a revoked slot rewrites that row's primary key, so an id from
            // an earlier `list_credentials` can stop resolving while a caller still holds it, and
            // reporting success there leaves the live credential authenticating with the audit trail
            // saying it was revoked. store-mysql and store-memory both fail loud here.
            return Err(RecordStoreError(format!(
                "revoke_credential: unknown credential id {id}; nothing was revoked"
            )));
        }
        let rev = Self::next_revision(&mut tx)?;
        let now = now_secs();
        // `AND revoked_at IS NULL`: mirrors delete_key's `already_deleted` idempotency (see above) --
        // a repeat revoke_credential call on an already-revoked row must be a true no-op, not bump
        // the global revision / rewrite revoke_reason+updated_at every time it's called. Stated IN
        // the UPDATE's own WHERE clause (not just the `exists` SELECT above) so this is also
        // TOCTOU-safe: two concurrent revoke_credential calls on the same id now genuinely
        // serialize under Postgres' READ COMMITTED row-lock re-check, and only the first to commit
        // actually changes anything.
        let changed = tx
            .execute(
                "UPDATE credentials SET revoked_at=$2, revoke_reason=$3, updated_at=$2, revision=$4
                 WHERE id=$1 AND revoked_at IS NULL",
                &[&id, &clamp(now), &reason, &rev],
            )
            .store()?;
        if changed == 0 {
            // Zero rows means one of two very different things, and the row count alone cannot tell
            // them apart. Discarding it would put the unknown-id case straight back: the `EXISTS`
            // above takes no row lock and runs before `next_revision`, so between the check and this
            // UPDATE a concurrent mint into the freed slot can rewrite this row's PRIMARY KEY
            // (`put_credential_tx` sets `id=EXCLUDED.id`), leaving the id naming nothing. Reported
            // as success, that is the same "revoked, and yet still authenticating" outcome the
            // unknown-id error above exists to prevent, just reached by a race instead of a typo.
            // So ask again, inside this transaction, which of the two it was.
            let still_exists: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                    &[&id],
                )
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
        tx.commit().store()?;
        Ok(())
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE revision > $1 ORDER BY revision"
        );
        let rows = self.lock().query(&sql, &[&clamp(since)]).store()?;
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

    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        // A `seq`/`ts` past `i64::MAX` cannot be stored faithfully: `clamp` pins it, so the record
        // read back is NOT the record written. Two consequences, both bad, and neither acceptable
        // silently — an identical retry compares unequal and is reported as "the audit chain has
        // forked" (naming the same action on both sides, the worst possible page to hand an
        // operator), and two genuinely distinct seqs collapse onto one row. Rejected outright
        // instead. Comparing the CLAMPED form would fix the false alarm by causing the silent loss,
        // which is the wrong half to give up.
        if entry.seq > i64::MAX as u64 || entry.ts > i64::MAX as u64 {
            return Err(RecordStoreError(format!(
                "append_audit: seq {} / ts {} exceeds the storable range (i64::MAX); refusing to \
                 store a record that would not read back as itself",
                entry.seq, entry.ts
            )));
        }
        let (seq, ts) = (clamp(entry.seq), clamp(entry.ts));
        // ON CONFLICT DO NOTHING, not DO UPDATE: the trait's own contract is "append-only... a store
        // never rewrites or recomputes the digest" (busbar_contract::records::RecordStore::append_audit doc). `seq` is a
        // per-process counter (see the engine's own known caveat about clustered nodes), so a
        // collision here means either a real caller bug or two nodes racing on the same seq -- in
        // BOTH cases silently overwriting a prior entry's hash/prev_hash would corrupt the hash chain
        // without any trace. Failing loudly on a collision is strictly safer than the alternative:
        // the caller (or an operator) finds out immediately, instead of the audit log quietly losing
        // integrity guarantees it claims to hold.
        // A collision has TWO causes and they are not the same event. Erroring on both (which this
        // used to do) makes the engine's own write-through look like a corrupt chain the first time
        // a commit ACK is lost to a timeout or a reconnect and it retries. Compare the records and
        // let the difference decide, per the trait contract:
        //   identical -> the retry. Benign, and the common one. Ok.
        //   different -> two records claiming one chain position: forked or tampered. Error.
        //
        // The INSERT and the read-back run in ONE transaction, and the read takes `FOR SHARE`, so
        // the row that caused the conflict cannot be deleted out from under the comparison. Without
        // that (an autocommit INSERT then a separate autocommit SELECT), an out-of-band deleter —
        // operator SQL, an external retention job — could remove the conflicting row in between,
        // leaving the seq empty and this method with nothing to compare. The obvious-looking answer
        // there, "nothing occupies the seq, so no fork: return Ok", REPORTS SUCCESS FOR A RECORD IT
        // NEVER STORED. That is the same silent-loss shape the whole comparison exists to prevent,
        // just inverted, and an audit entry is the last thing that should vanish quietly.
        //
        // The loop covers the one case the lock cannot: the row disappearing BEFORE the read takes
        // its share lock. Then the seq is genuinely free again and the right move is to insert,
        // which is what the next iteration does. Bounded, and exhausting the bound is an error
        // rather than a success, so no path here returns Ok without the record being stored.
        const MAX_ATTEMPTS: u32 = 3;
        for _ in 0..MAX_ATTEMPTS {
            let mut client = self.lock();
            let mut tx = client.transaction().store()?;
            let inserted = tx
                .execute(
                    "INSERT INTO audit_log
                        (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                     ON CONFLICT (seq) DO NOTHING",
                    &[
                        &seq,
                        &ts,
                        &entry.action,
                        &entry.resource,
                        &entry.outcome,
                        &entry.principal,
                        &entry.prev_hash,
                        &entry.hash,
                    ],
                )
                .store()?;
            if inserted == 1 {
                tx.commit().store()?;
                return Ok(());
            }
            let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log WHERE seq=$1 FOR SHARE");
            let stored = tx
                .query_opt(&sql, &[&seq])
                .store()?
                .map(|r| row_to_audit(&r));
            match stored {
                Some(stored) if &stored == entry => {
                    tx.commit().store()?;
                    return Ok(());
                }
                Some(stored) => {
                    return Err(RecordStoreError(format!(
                        "append_audit: seq {} already holds a DIFFERENT record; the audit chain \
                         has forked (stored action '{}', incoming '{}')",
                        entry.seq, stored.action, entry.action
                    )));
                }
                // Gone before the share lock could hold it. Drop the transaction and try again:
                // the seq is free, so the insert should now land.
                None => {
                    drop(tx);
                }
            }
        }
        Err(RecordStoreError(format!(
            "append_audit: seq {} kept being freed between the insert and the read-back after \
             {MAX_ATTEMPTS} attempts; something is deleting audit rows concurrently and the record \
             was NOT stored",
            entry.seq
        )))
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq");
        let rows = self.lock().query(&sql, &[]).store()?;
        Ok(rows.iter().map(row_to_audit).collect())
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq DESC LIMIT $1");
        let rows = self
            .lock()
            .query(&sql, &[&i64::try_from(limit).unwrap_or(i64::MAX)])
            .store()?;
        let mut out: Vec<AuditRecord> = rows.iter().map(row_to_audit).collect();
        out.reverse();
        Ok(out)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        // `created_at` is a clock read, not the literal 0 it used to be. Same shape as the
        // `deleted_at` defect: the row lands, every "is this subject denied" check keeps working,
        // and only a question about WHEN it was denied reads back the epoch. store-sqlite writes
        // `now_secs()` into the identical column.
        self.lock()
            .execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (sub) DO UPDATE SET reason = EXCLUDED.reason",
                &[&sub, &reason, &clamp(now_secs())],
            )
            .store()?;
        Ok(())
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        let rows = self.lock().query("SELECT sub FROM denylist", &[]).store()?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    // ── THE KIND-TAGGED PLANE-RECORD VERBS (busbar 1.6.0) ────────────────────────────────────
    //
    // Generic over `kind`: this store names no plane and decodes no body. An UPSERTED record lives
    // in `plane_records` keyed `(kind, id)`; an APPENDED one in `plane_chain` keyed
    // `(kind, parent, seq)`. Identity, ordering and retention read only the typed sidecar columns.

    fn upsert_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()> {
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
            .store()?;
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        // No principal filter, deliberately: caller scoping is ENGINE-side, because an
        // authorization check living in the backend is one an unauthorized reader bypasses by
        // configuring a different backend.
        let row = self
            .lock()
            .query_opt(
                "SELECT body FROM plane_records WHERE kind=$1 AND id=$2",
                &[&kind, &id],
            )
            .store()?;
        Ok(row.map(|r| r.get(0)))
    }

    fn append_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()> {
        let seq = as_storable_i64("append_plane_record", "seq", record.seq)?;
        let ts = as_storable_i64("append_plane_record", "ts", record.ts)?;
        // The chain a child record hangs off: its parent, or (a parentless append) its own id —
        // the same identity busbar's reference backends key a chain by.
        let parent = record.parent.as_deref().unwrap_or(record.id.as_str());
        let disposition = disposition_to_storage(record.disposition);
        // APPEND-ONLY, never an overwrite. A record arriving on an occupied (kind, parent, seq) is
        // settled by comparing the two, the same way `append_audit` settles a duplicate seq:
        // IDENTICAL is the write-through retrying after a timeout (Ok, the common case), DIFFERENT
        // is a forked or tampered chain (an error — overwriting would destroy exactly the case
        // worth reporting, and this store never restates a digest it was handed).
        //
        // The INSERT and the read-back share ONE transaction and the read takes `FOR SHARE`, so the
        // conflicting row cannot be purged out from under the comparison; the bounded loop covers
        // the row vanishing before the share lock lands (the position is then free, so insert). No
        // path returns Ok without the record being stored.
        const MAX_ATTEMPTS: u32 = 3;
        for _ in 0..MAX_ATTEMPTS {
            let mut client = self.lock();
            let mut tx = client.transaction().store()?;
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
                .store()?;
            if inserted == 1 {
                tx.commit().store()?;
                return Ok(());
            }
            let stored = tx
                .query_opt(
                    "SELECT id, ts, disposition, body FROM plane_chain
                     WHERE kind=$1 AND parent=$2 AND seq=$3 FOR SHARE",
                    &[&record.kind, &parent, &seq],
                )
                .store()?;
            match stored {
                Some(r) => {
                    let identical = r.get::<_, String>(0) == record.id
                        && r.get::<_, i64>(1) == ts
                        && r.get::<_, String>(2) == disposition
                        && r.get::<_, Vec<u8>>(3) == record.body;
                    if identical {
                        tx.commit().store()?;
                        return Ok(());
                    }
                    // Names the position and nothing else — it must not echo stored (or caller)
                    // content back.
                    return Err(RecordStoreError(format!(
                        "append_plane_record: kind '{}' parent '{}' seq {} is already occupied by \
                         another record; the chain has forked",
                        record.kind, parent, record.seq
                    )));
                }
                None => drop(tx),
            }
        }
        Err(RecordStoreError(format!(
            "append_plane_record: kind '{}' seq {} kept being freed between the insert and the \
             read-back after {MAX_ATTEMPTS} attempts; something is deleting chain rows \
             concurrently and the record was NOT stored",
            record.kind, record.seq
        )))
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let mut client = self.lock();
        // One snapshot across both tables.
        let mut tx = Self::snapshot_consistent_tx(&mut client)?;
        let (records, chain) = match selector {
            PlaneSelector::All => (
                tx.query(
                    "SELECT body FROM plane_records WHERE kind=$1 ORDER BY seq, id",
                    &[&kind],
                )
                .store()?,
                tx.query(
                    "SELECT body FROM plane_chain WHERE kind=$1 ORDER BY parent, seq",
                    &[&kind],
                )
                .store()?,
            ),
            // Oldest-first by seq — the order the engine's chain verifier reads a parent's chain.
            PlaneSelector::Parent(p) => (
                tx.query(
                    "SELECT body FROM plane_records WHERE kind=$1 AND parent=$2 ORDER BY seq, id",
                    &[&kind, p],
                )
                .store()?,
                tx.query(
                    "SELECT body FROM plane_chain WHERE kind=$1 AND parent=$2 ORDER BY seq",
                    &[&kind, p],
                )
                .store()?,
            ),
        };
        tx.commit().store()?;
        Ok(records
            .iter()
            .chain(chain.iter())
            .map(|r| r.get::<_, Vec<u8>>(0))
            .collect())
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
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
            .store()?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        // STRICTLY older than the cutoff: a row exactly at `before` is kept. WHICH rows go is the
        // kind's own contract, read off the typed `disposition` column and never out of the body —
        // see TERMINAL_ONLY_RETENTION_KINDS.
        let cutoff = clamp(before);
        let terminal_only = TERMINAL_ONLY_RETENTION_KINDS.contains(&kind);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let purged: Vec<String> = tx
            .query(
                "DELETE FROM plane_records
                 WHERE kind=$1 AND ts < $2 AND (NOT $3 OR disposition = 'terminal')
                 RETURNING id",
                &[&kind, &cutoff, &terminal_only],
            )
            .store()?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let chain = tx
            .execute(
                "DELETE FROM plane_chain WHERE kind=$1 AND ts < $2",
                &[&kind, &cutoff],
            )
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
                .store()?;
            }
        }
        tx.commit().store()?;
        // `execute`/`RETURNING` report the rows actually removed, so the count is one performed.
        Ok(purged.len() as u64 + chain)
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        // Absent is a NO-OP, not an error: the engine clears on every observation that agrees with
        // the operator rather than tracking whether it had written one. A chain whose parent is
        // `id` goes too, so deleting a record cannot leave part of its chain behind.
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "DELETE FROM plane_records WHERE kind=$1 AND id=$2",
            &[&kind, &id],
        )
        .store()?;
        tx.execute(
            "DELETE FROM plane_chain WHERE kind=$1 AND parent=$2",
            &[&kind, &id],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // REFUSED rather than clamped, and this is the sharpest instance of that choice in the
        // crate: a `now` clamped to i64::MAX would sweep the kind's ENTIRE ledger below and then
        // report the insert as a first redemption — one out-of-range argument silently reopening
        // every spent token. An error is refused by the engine, so it is the direction to fail in.
        let expires = as_storable_i64("redeem_plane_token", "expires_at", expires_at)?;
        let cutoff = as_storable_i64("redeem_plane_token", "now", now)?;
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        // The eviction sweep the redemption carries, bounding the ledger by one validity window: an
        // entry recording a token that can no longer be presented protects nothing. STRICTLY
        // less-than (an entry expiring exactly at `now` is kept), and BEFORE the insert, so it can
        // never delete the row this very call records.
        tx.execute(
            "DELETE FROM plane_tokens WHERE kind=$1 AND expires_at < $2",
            &[&kind, &cutoff],
        )
        .store()?;
        // THE TEST AND SET, as ONE statement: `execute` returns the rows this INSERT wrote, so 1
        // means THIS call recorded the redemption and 0 means it was already there. A read then a
        // write would tell BOTH halves of a race — two nodes, or two requests to one — they were
        // first.
        let inserted = tx
            .execute(
                "INSERT INTO plane_tokens (kind, token, expires_at) VALUES ($1,$2,$3)
                 ON CONFLICT (kind, token) DO NOTHING",
                &[&kind, &token, &expires],
            )
            .store()?;
        tx.commit().store()?;
        Ok(inserted == 1)
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // MULTI-use and SPENDS NOTHING: a plain read of the `(kind, token)` upserted record. Live
        // only while the record is present AND its disposition is still Active AND `now` has not
        // passed `expires_at`; a missing record, a terminal one and a lapsed deadline each answer
        // false. Asking twice answers the same twice.
        if now > expires_at {
            return Ok(false);
        }
        let row = self
            .lock()
            .query_opt(
                "SELECT disposition FROM plane_records WHERE kind=$1 AND id=$2",
                &[&kind, &token],
            )
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

/// Reject a `u64` a signed BIGINT cannot hold, naming the method and the field. The crate-wide
/// `clamp` would pin it to `i64::MAX` instead, so the row read back would not be the row written and
/// nothing would ever have reported an error — tolerable on the counters `clamp` still serves, not on
/// a plane record's chain position or a token ledger's clock.
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

impl PostgresStore {
    /// Shared body of `put_credential`/`put_key_with_credential`: upsert on `(key_id, kind, slot)`.
    /// Minting into an OCCUPIED LIVE slot (revoked_at IS NULL) MUST fail rather than silently
    /// destroy a working credential mid-overlap-window -- the `WHERE credentials.revoked_at IS NOT
    /// NULL` guard on the `DO UPDATE` makes that structural: the upsert simply does not apply if
    /// the existing row is live, and the subsequent `changed` check turns that into a real error
    /// instead of a silent no-op.
    fn put_credential_tx(
        tx: &mut Transaction<'_>,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let m = &secret.meta;
        let rev = Self::next_revision(tx)?;
        // The owning key must EXIST and be LIVE (`put_credential`'s precondition, pinned by the
        // conformance suite). `delete_key` cascades a key's credentials away precisely so the
        // secret material stops resolving; accepting a mint afterwards puts it back under a key an
        // operator just revoked. Checked AFTER `next_revision`, and that ordering is what makes it
        // atomic rather than a read-then-write: every mutating transaction (delete_key included)
        // takes the single `store_revision` row lock first and holds it to commit, so a concurrent
        // `delete_key` has either fully committed before this read — which then sees the tombstone
        // — or cannot start its cascade until this mint has committed, and then removes it.
        let owner_live: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NULL FROM keys WHERE id=$1",
                &[&m.key_id],
            )
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
            )
            .store()?;
        if changed == 0 {
            // Either the slot is occupied by a LIVE credential (the WHERE guard blocked it), or this
            // is a genuine first insert into a free slot that the ON CONFLICT branch didn't need --
            // distinguish by checking existence.
            let exists: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE key_id=$1 AND kind=$2 AND slot=$3)",
                    &[&m.key_id, &m.kind, &(m.slot as i16)],
                )
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

const _: fn() = || {
    fn assert_tosql<T: ToSql>() {}
    assert_tosql::<i64>();
    assert_tosql::<Option<i64>>();
    assert_tosql::<bool>();
};

// ── THE PLUGIN DOOR ─────────────────────────────────────────────────────────────────────────────
// One registration, both doors (DECISIONS #2 rule (1)): `export_store_plugin!(open)` emits
// `BUSBAR_COLD_ENTRY` — the boundary a busbar build that LINKS this crate hands the loader (see
// [`linked::STORE`]) — and registers that same entry as the image's door, through which the SDK's
// frozen symbols answer when the sibling `busbar-store-postgres-plugin` cdylib is dropped in.

/// The package name both doors state for this store.
pub const NAME: &str = "busbar-store-postgres";
/// The name `store.module` selects this store by.
pub const ALIAS: &str = "postgres";

/// Construct a Postgres store from the JSON config the engine passes through `open`:
///
/// ```json
/// { "url": "postgres://user:pass@host:5432/busbar" }
/// ```
pub fn open(cfg: &str) -> Result<Box<dyn RecordStore>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid postgres plugin config: {e}"))?
    };
    let url = v
        .get("url")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "postgres plugin config requires a \"url\" (a libpq connection string)".to_string()
        })?;
    let store = PostgresStore::connect(url).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_contract::abi::sdk::export_store_plugin!(open);

/// THE LINKED ENTRY (DECISIONS #2 rule (1)): what a busbar build that links this store registers
/// onto the cold-kind axis — the same statement and boundary the dropped-in tarball carries.
pub mod linked {
    /// `(name, alias, boundary)`.
    pub const STORE: (&str, &str, &busbar_contract::abi::sdk::ColdEntry) =
        (super::NAME, super::ALIAS, &super::BUSBAR_COLD_ENTRY);
}

#[cfg(test)]
mod tests;
