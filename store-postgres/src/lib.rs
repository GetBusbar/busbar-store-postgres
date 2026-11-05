// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres** backend for busbar's durable governance store: the shared, multi-node store.

#![forbid(unsafe_code)]

#[cfg(not(test))]
#[path = "database_clock.rs"]
mod database_clock;
#[cfg(test)]
#[path = "tests/database_clock.rs"]
mod database_clock;
mod pgwire;

use busbar_contract::abi::sdk::store::column::{
    clamp, read_u64, scope_columns, scopes_from_columns, storable_i64,
};
use busbar_contract::abi::sdk::store::fork;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStoreError,
    RecordStoreResult, Retention, SecretForm, UsageDelta, UsageLedger, VirtualKey, UNIT_CACHE_READ,
    UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use pgwire::{Client, Row, Transaction};
use postgres_types::ToSql;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;

trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, pgwire::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(render_pg_error(&e)))
    }
}

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

/// True when a postgres error is SQLSTATE 42P01 (`undefined_table`), the ONE case `migrate()` reads
/// as an unversioned database; any other class must never be read as "fresh" and drop a populated one.
fn is_undefined_table(e: &pgwire::Error) -> bool {
    e.code().map(pgwire::SqlState::code) == Some(pgwire::SqlState::UNDEFINED_TABLE)
}

/// Store schema version. v6 is the oldest released schema; v8 converts quantity aggregates
/// to checked micro-units without changing request counters.
pub const SCHEMA_VERSION: i64 = 8;

const TICKET_RECORD_KIND: &str = "ticket";

/// How many times the migration transaction runs when it is chosen as a deadlock victim.
const MIGRATE_ATTEMPTS: u32 = 3;

/// The oldest schema any release wrote.
const FIRST_RELEASED_SCHEMA: i64 = 6;

/// The plane-record kinds whose retention is TERMINAL-ONLY: `purge_plane_records_before` drops a
/// row of one only once its `disposition` is `Terminal` (an interrupted task waiting on a human sits
/// still longest).
const TERMINAL_ONLY_RETENTION_KINDS: [&str; 1] = ["task"];

/// Rows one purge statement removes (and the ids it holds).
const PURGE_BATCH: i64 = 1000;

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
    -- FALSE: the record carried no parent and is keyed by its own id (never listed as a parent).
    has_parent  BOOLEAN NOT NULL DEFAULT TRUE,
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
CREATE INDEX IF NOT EXISTS plane_tokens_kind_expires ON plane_tokens (kind, expires_at);

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

/// The v7 column additions on tables an older database already has (idempotent).
const MIGRATE_V7_COLUMNS: &str = "
ALTER TABLE keys ADD COLUMN IF NOT EXISTS idp_subject TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS binding_mode TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS minted_by TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS idp_provider TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS allowed_scopes_by_kind TEXT;
ALTER TABLE usage_metering ADD COLUMN IF NOT EXISTS priced_from_ms BIGINT NOT NULL DEFAULT 0;
";

/// Postgres `Store` backend (durable, shared across a cluster): the parsed connection settings and
pub struct PostgresStore {
    shared: std::sync::Arc<Shared>,
}

/// How many connections an instance keeps: at most eight (1.5.5 kept one).
pub const KEPT_CONNECTIONS: usize = 8;

/// What every op of one instance shares.
pub(crate) struct Shared {
    /// The connection settings.
    pub(crate) config: pgwire::Config,
    /// When this instance last swept `store_ops` past its retention (`v3`).
    pub(crate) ops_swept_at: AtomicU64,
    /// The instance's kept connections, bounded at [`KEPT_CONNECTIONS`] (there is no pool setting).
    pub(crate) pool: std::sync::Arc<busbar_contract::abi::sdk::store::wire::Pool>,
    /// The endpoint (an index into the DSN's list) that last connected: the next connect tries it
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

/// The four RESERVED unit classes, in the order of the `usage_ledger` token columns
/// (`tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`).
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
    /// Capture a borrowed DSN's password before parsing public connection options. Authentication
    /// and peer-error redaction use the sealed SDK credential; the store keeps no plaintext copy.
    pub fn new(conn_str: &str) -> RecordStoreResult<Self> {
        let config =
            pgwire::Config::parse(conn_str).map_err(|e| RecordStoreError(e.to_string()))?;
        Ok(Self::configured(config))
    }

    fn captured(captured: busbar_contract::abi::sdk::cred::CredUrl) -> RecordStoreResult<Self> {
        let config =
            pgwire::Config::captured(captured).map_err(|e| RecordStoreError(e.to_string()))?;
        Ok(Self::configured(config))
    }

    fn configured(config: pgwire::Config) -> Self {
        Self {
            shared: std::sync::Arc::new(Shared {
                config,
                ops_swept_at: AtomicU64::new(0),
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

    const MIGRATE_LOCK_KEY: i64 = 0x6275_7362_6172_5f70;

    pub(crate) async fn migrate(&mut self) -> RecordStoreResult<()> {
        let client = self.client();
        client
            .batch_execute(&format!(
                "SET lock_timeout = '30s'; SELECT pg_advisory_lock({}); RESET lock_timeout",
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
            Ok(Some(r)) => r.try_get(0).store()?,
            Ok(None) => 0,
            Err(e) if is_undefined_table(&e) => 0,
            Err(e) => return Err(RecordStoreError(render_pg_error(&e))),
        };

        if version > SCHEMA_VERSION {
            return Err(RecordStoreError(format!(
                "postgres store: database schema v{version} is newer than this build \
                 (v{SCHEMA_VERSION}); refusing to open"
            )));
        }
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        if version != 0 && version < FIRST_RELEASED_SCHEMA {
            return Err(RecordStoreError(format!(
                "postgres store: database schema v{version} predates v{FIRST_RELEASED_SCHEMA}, the \
                 oldest released schema; refusing to open"
            )));
        }

        let mut attempt = 1;
        loop {
            match Self::migrate_tx(client, version).await {
                Err(e) if attempt < MIGRATE_ATTEMPTS && e.0.starts_with("40P01") => attempt += 1,
                result => return result,
            }
        }
    }

    async fn migrate_tx(client: &mut Client, version: i64) -> RecordStoreResult<()> {
        let mut tx = client.transaction().await.store()?;
        tx.batch_execute(SCHEMA).await.store()?;
        if version < 7 {
            let incompatible: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM usage_windows WHERE window_start < 0)
                     OR EXISTS(SELECT 1 FROM usage_ledger WHERE window_start < 0)
                     OR EXISTS(SELECT 1 FROM usage_ledger_units WHERE window_start < 0)
                     OR EXISTS(SELECT 1 FROM usage_metering WHERE bucket < 0)
                     OR EXISTS(SELECT 1 FROM usage_metering_units WHERE bucket < 0)",
                    &[],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if incompatible {
                return Err(RecordStoreError(
                    "postgres store: negative usage key in a released-v6 database; \
                     refusing to infer its encoding"
                        .into(),
                ));
            }
        }
        if version < 7 {
            let incompatible: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE created_at < 0 OR updated_at < 0
                     OR expires_at < 0 OR revoked_at < 0)",
                    &[],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if incompatible {
                return Err(RecordStoreError(
                    "postgres store: negative credential timestamp in a released-v6 database; \
                     refusing to infer its encoding"
                        .into(),
                ));
            }
        }

        if version < 7 {
            tx.batch_execute(MIGRATE_V7_COLUMNS).await.store()?;

            tx.batch_execute(
                "ALTER TABLE usage_metering DROP CONSTRAINT IF EXISTS usage_metering_pkey;
                 ALTER TABLE usage_metering ADD CONSTRAINT usage_metering_pkey
                     PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms);",
            )
            .await
            .store()?;
        }

        if version < 7 {
            let ambiguous: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM plane_chain WHERE parent = id)",
                    &[],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if ambiguous {
                return Err(RecordStoreError(
                    "postgres store: released-v6 plane_chain parent presence is ambiguous; \
                     refusing to infer it; repair requires authoritative envelope provenance \
                     or a verified backup"
                        .into(),
                ));
            }
            tx.batch_execute(
                "ALTER TABLE plane_chain ADD COLUMN IF NOT EXISTS has_parent BOOLEAN NOT NULL DEFAULT TRUE",
            )
            .await
            .store()?;
        }
        if version < 7 {
            let dirty: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE revoked_at IS NOT NULL
                     AND (secret IS NOT NULL OR secret_form <> 'none'))",
                    &[],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if dirty {
                let rev = Self::next_revision(&mut tx).await?;
                tx.execute(
                    "UPDATE credentials SET secret=NULL, secret_form='none', revision=$1
                     WHERE revoked_at IS NOT NULL
                     AND (secret IS NOT NULL OR secret_form <> 'none')",
                    &[&rev],
                )
                .await
                .store()?;
            }
        }
        if version < 7 {
            let orphan: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM usage_metering_units u
                 LEFT JOIN usage_metering m ON m.key_id=u.key_id AND m.bucket=u.bucket
                 AND m.model=u.model AND m.provider=u.provider AND m.priced_from_ms=u.priced_from_ms
                 WHERE m.key_id IS NULL)",
                    &[],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if orphan {
                return Err(RecordStoreError(
                    "postgres store: metering unit attribution has no parent".into(),
                ));
            }
            tx.batch_execute(
                "ALTER TABLE usage_metering_units
                    ADD COLUMN IF NOT EXISTS key_group_at_use TEXT COLLATE \"C\" NOT NULL DEFAULT '',
                    ADD COLUMN IF NOT EXISTS pricing_version TEXT COLLATE \"C\" NOT NULL DEFAULT '';
                 UPDATE usage_metering_units u SET key_group_at_use=m.key_group_at_use,
                    pricing_version=m.pricing_version FROM usage_metering m
                 WHERE m.key_id=u.key_id AND m.bucket=u.bucket AND m.model=u.model
                    AND m.provider=u.provider AND m.priced_from_ms=u.priced_from_ms;
                 ALTER TABLE usage_metering_units DROP CONSTRAINT IF EXISTS usage_metering_units_pkey;
                 CREATE INDEX IF NOT EXISTS idx_metering_units_identity
                    ON usage_metering_units (key_id,bucket,model,provider,priced_from_ms,unit);
                 ALTER TABLE usage_metering DROP CONSTRAINT IF EXISTS usage_metering_pkey;
                 ALTER TABLE usage_metering
                    ALTER COLUMN key_group_at_use TYPE TEXT COLLATE \"C\",
                    ALTER COLUMN pricing_version TYPE TEXT COLLATE \"C\";
                 CREATE INDEX IF NOT EXISTS idx_metering_identity
                    ON usage_metering (key_id,bucket,model,provider,priced_from_ms);"
            ).await.store()?;
        }
        if version < 7 {
            tx.batch_execute(
                "ALTER TABLE usage_windows
                    ALTER COLUMN requests TYPE NUMERIC(20,0),
                    ALTER COLUMN billable_requests TYPE NUMERIC(20,0);
                 ALTER TABLE usage_ledger
                    ALTER COLUMN tokens_input TYPE NUMERIC(20,0),
                    ALTER COLUMN tokens_output TYPE NUMERIC(20,0),
                    ALTER COLUMN tokens_cache_read TYPE NUMERIC(20,0),
                    ALTER COLUMN tokens_cache_write TYPE NUMERIC(20,0);
                 ALTER TABLE usage_ledger_units ALTER COLUMN count TYPE NUMERIC(20,0);",
            )
            .await
            .store()?;
        }
        // Quantity conversion and its version stamp share one transaction. Lock every
        // quantity table before preflight so no counter can change between check and update.
        tx.batch_execute("LOCK TABLE usage_ledger, usage_ledger_units, usage_metering, usage_metering_units IN ACCESS EXCLUSIVE MODE")
            .await.store()?;
        for (table, columns) in [
            (
                "usage_ledger",
                &[
                    "tokens_input",
                    "tokens_output",
                    "tokens_cache_read",
                    "tokens_cache_write",
                ][..],
            ),
            ("usage_ledger_units", &["count"][..]),
            (
                "usage_metering",
                &[
                    "tokens_input",
                    "tokens_output",
                    "tokens_cache_read",
                    "tokens_cache_write",
                ][..],
            ),
            ("usage_metering_units", &["count"][..]),
        ] {
            let invalid = columns
                .iter()
                .map(|column| format!("{column} < 0 OR {column} > 9223372036854"))
                .collect::<Vec<_>>()
                .join(" OR ");
            let invalid: bool = tx
                .query_one(
                    &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {invalid})"),
                    &[],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if invalid {
                return Err(RecordStoreError(format!(
                    "exact count migration: {table} contains a quantity outside the scale-6 range; nothing was converted"
                )));
            }
        }
        for (table, columns) in [
            (
                "usage_ledger",
                &[
                    "tokens_input",
                    "tokens_output",
                    "tokens_cache_read",
                    "tokens_cache_write",
                ][..],
            ),
            ("usage_ledger_units", &["count"][..]),
            (
                "usage_metering",
                &[
                    "tokens_input",
                    "tokens_output",
                    "tokens_cache_read",
                    "tokens_cache_write",
                ][..],
            ),
            ("usage_metering_units", &["count"][..]),
        ] {
            let assignments = columns
                .iter()
                .map(|column| format!("{column} = {column} * 1000000"))
                .collect::<Vec<_>>()
                .join(", ");
            tx.batch_execute(&format!("UPDATE {table} SET {assignments}"))
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

    /// Lock the store-global revision inside the caller's open transaction. Acquire this
    async fn lock_revision(tx: &mut Transaction<'_>) -> RecordStoreResult<()> {
        tx.query_one(
            "SELECT revision FROM store_revision WHERE only_row FOR UPDATE",
            &[],
        )
        .await
        .store()?;
        Ok(())
    }

    /// Bump and return the store-global revision inside the caller's transaction.
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
fn labels_from_storage(stored: &str) -> RecordStoreResult<BTreeMap<String, String>> {
    serde_json::from_str(stored).map_err(|_| RecordStoreError("invalid stored key labels".into()))
}

fn row_to_key(r: &Row) -> RecordStoreResult<VirtualKey> {
    Ok(VirtualKey {
        id: r.try_get(0).store()?,
        generation_hash: r.try_get(1).store()?,
        name: r.try_get(2).store()?,
        allowed_scopes: scopes_from_columns(
            r.try_get::<_, Option<String>>(3).store()?,
            r.try_get::<_, Option<String>>(14).store()?,
        ),
        enabled: r.try_get(4).store()?,
        created_at: read_u64(r.try_get::<_, i64>(5).store()?),
        group: r.try_get(6).store()?,
        labels: labels_from_storage(&r.try_get::<_, String>(7).store()?)?,
        expires_at: r.try_get::<_, Option<i64>>(8).store()?.map(read_u64),
        deleted_at: r.try_get::<_, Option<i64>>(9).store()?.map(read_u64),
        revision: read_u64(r.try_get::<_, i64>(10).store()?),
        idp_subject: r.try_get(11).store()?,
        binding_mode: r.try_get(12).store()?,
        minted_by: r.try_get(13).store()?,
        idp_provider: r.try_get(15).store()?,
    })
}

/// `a + b` in SQL, pinned at `i64::MAX` instead of failing 22003 (rule 8); `floor` also keeps it >= 0.
fn sat_add(a: &str, b: &str, floor: bool) -> String {
    let sum = format!("LEAST(9223372036854775807, ({a})::numeric + ({b})::numeric)");
    if floor {
        format!("GREATEST(0, {sum})::bigint")
    } else {
        format!("({sum})::bigint")
    }
}

/// Raw usage has an exact unsigned domain; numeric arithmetic must never narrow through BIGINT.
fn usage_add(a: &str, b: &str) -> String {
    format!(
        "GREATEST(0, LEAST({}, ({a})::numeric + ({b})::numeric))",
        u64::MAX
    )
}

fn usage_count(row: &Row, column: usize) -> RecordStoreResult<u64> {
    let text: String = row.try_get(column).store()?;

    if text.starts_with('-') {
        return Ok(0);
    }
    text.parse()
        .map_err(|_| RecordStoreError("invalid unsigned usage counter".into()))
}

fn usage_key(value: u64) -> i64 {
    value as i64
}

const KEY_COLUMNS: &str = "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision,idp_subject,binding_mode,minted_by,allowed_scopes_by_kind,idp_provider";

fn secret_form_to_storage(f: SecretForm) -> &'static str {
    match f {
        SecretForm::None => "none",
        SecretForm::Recoverable => "recoverable",
        SecretForm::Digest => "digest",
    }
}
fn secret_form_from_storage(s: &str) -> RecordStoreResult<SecretForm> {
    match s {
        "none" => Ok(SecretForm::None),
        "recoverable" => Ok(SecretForm::Recoverable),
        "digest" => Ok(SecretForm::Digest),
        _ => Err(RecordStoreError(
            "invalid stored credential secret form".into(),
        )),
    }
}

const CRED_META_COLUMNS: &str = "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";
/// The row index of `secret` in `SELECT {CRED_META_COLUMNS},secret ...`: the column count of
/// CRED_META_COLUMNS.
const CRED_SECRET_COLUMN_INDEX: usize = 12;

fn credential_timestamp(value: u64) -> i64 {
    value as i64
}

fn read_credential_timestamp(value: i64) -> u64 {
    value as u64
}

fn row_to_cred_meta(r: &Row) -> RecordStoreResult<CredentialMeta> {
    Ok(CredentialMeta {
        id: r.try_get(0).store()?,
        key_id: r.try_get(1).store()?,
        kind: r.try_get(2).store()?,
        slot: r.try_get::<_, i16>(3).store()? as u8,
        public_id: r.try_get(4).store()?,
        secret_form: secret_form_from_storage(r.try_get::<_, &str>(5).store()?)?,
        created_at: read_credential_timestamp(r.try_get::<_, i64>(6).store()?),
        updated_at: read_credential_timestamp(r.try_get::<_, i64>(7).store()?),
        expires_at: r
            .try_get::<_, Option<i64>>(8)
            .store()?
            .map(read_credential_timestamp),
        revoked_at: r
            .try_get::<_, Option<i64>>(9)
            .store()?
            .map(read_credential_timestamp),
        revoke_reason: r.try_get(10).store()?,
        revision: read_u64(r.try_get::<_, i64>(11).store()?),
    })
}

/// The `keys` upsert both key writes run; the conflict branch's `WHERE` is the tombstone
/// precondition (a write not carrying a tombstone never overwrites one).
const KEY_UPSERT: &str = "INSERT INTO keys
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
     WHERE EXCLUDED.deleted_at IS NOT NULL OR keys.deleted_at IS NULL";

/// The derived column values of a [`KEY_UPSERT`], owned so its parameters can borrow them.
struct KeyColumns {
    pools: Option<String>,
    by_kind: Option<String>,
    labels: String,
    created: i64,
    expires: Option<i64>,
    deleted: Option<i64>,
}

impl KeyColumns {
    fn of(key: &VirtualKey, deleted: Option<i64>) -> Self {
        let (pools, by_kind) = scope_columns(key.allowed_scopes.as_deref());
        Self {
            pools,
            by_kind,
            labels: labels_to_storage(&key.labels),
            created: clamp(key.created_at),
            expires: key.expires_at.map(clamp),
            deleted,
        }
    }

    /// The statement's parameters, `$1..$16` in order.
    fn params<'a>(&'a self, key: &'a VirtualKey, rev: &'a i64) -> [&'a (dyn ToSql + Sync); 16] {
        [
            &key.id,
            &key.generation_hash,
            &key.name,
            &self.pools,
            &key.enabled,
            &self.created,
            &key.group,
            &self.labels,
            &self.expires,
            &self.deleted,
            rev,
            &key.idp_subject,
            &key.binding_mode,
            &key.minted_by,
            &self.by_kind,
            &key.idp_provider,
        ]
    }
}

impl Session {
    pub(crate) async fn put_key(&mut self, key: &VirtualKey) -> RecordStoreResult<()> {
        let cols = KeyColumns::of(key, key.deleted_at.map(clamp));
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        let rev = Self::next_revision(&mut tx).await?;

        let changed = tx
            .execute(KEY_UPSERT, &cols.params(key, &rev))
            .await
            .store()?;
        if changed == 0 {
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
        let row = self.client().query_opt(&sql, &[&id]).await.store()?;
        row.map(|r| row_to_key(&r)).transpose()
    }

    pub(crate) async fn list_keys(&mut self) -> RecordStoreResult<Vec<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys ORDER BY created_at, id");
        let rows = self.client().query(&sql, &[]).await.store()?;
        rows.iter().map(row_to_key).collect()
    }

    pub(crate) async fn list_keys_since(
        &mut self,
        since: u64,
    ) -> RecordStoreResult<Vec<VirtualKey>> {
        let sql = format!(
            "SELECT {KEY_COLUMNS} FROM keys WHERE revision > $1 OR revision = 0 ORDER BY revision, id"
        );
        let rows = self.client().query(&sql, &[&clamp(since)]).await.store()?;
        rows.iter().map(row_to_key).collect()
    }

    pub(crate) async fn delete_key(&mut self, id: &str) -> RecordStoreResult<()> {
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        Self::lock_revision(&mut tx).await?;
        let already_deleted: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NOT NULL FROM keys WHERE id=$1",
                &[&id],
            )
            .await
            .store()?
            .map(|r| r.try_get(0).store())
            .transpose()?;
        match already_deleted {
            None => {
                return Err(RecordStoreError(format!("delete_key: unknown id '{id}'")));
            }
            Some(true) => {
                tx.commit().await.store()?;
                return Ok(());
            }
            Some(false) => {}
        }
        let rev = Self::next_revision(&mut tx).await?;

        let now = clamp(now_secs());
        tx.execute("DELETE FROM credentials WHERE key_id=$1", &[&id])
            .await
            .store()?;

        tx.execute(
            "UPDATE keys SET enabled=FALSE, deleted_at=$2, revision=$3 \
                 WHERE id=$1 AND deleted_at IS NULL",
            &[&id, &now, &rev],
        )
        .await
        .store()?;
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn get_usage(
        &mut self,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let client = self.client();
        let mut tx = Self::snapshot_consistent_tx(client).await?;
        let ledger = Self::get_usage_in(&mut tx, bucket_id, window_start).await?;
        tx.commit().await.store()?;
        Ok(ledger)
    }

    async fn get_usage_in(
        tx: &mut Transaction<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let ws = usage_key(window_start);
        let (requests, billable_requests): (u64, u64) = match tx
            .query_opt(
                "SELECT requests::text, billable_requests::text
                 FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
                &[&bucket_id, &ws],
            )
            .await
            .store()?
        {
            Some(r) => (usage_count(&r, 0)?, usage_count(&r, 1)?),
            None => (0, 0),
        };
        let rows = tx
            .query(
                "SELECT model, tokens_input::text, tokens_output::text, tokens_cache_read::text, tokens_cache_write::text
                 FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2 ORDER BY model",
                &[&bucket_id, &ws],
            )
            .await
            .store()?;
        let unit_rows = tx
            .query(
                "SELECT model, unit, count::text FROM usage_ledger_units
                 WHERE bucket_id=$1 AND window_start=$2 ORDER BY model, unit",
                &[&bucket_id, &ws],
            )
            .await
            .store()?;

        let mut models: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for r in &rows {
            let units = models
                .entry(r.try_get::<_, String>(0).store()?)
                .or_default();
            for (i, unit) in RESERVED_COLUMNS.iter().enumerate() {
                let v = usage_count(r, i + 1)?;
                if v != 0 {
                    units.insert(unit.to_string(), v);
                }
            }
        }
        for r in &unit_rows {
            let v = usage_count(r, 2)?;
            let units = models
                .entry(r.try_get::<_, String>(0).store()?)
                .or_default();
            if v != 0 {
                units.insert(r.try_get::<_, String>(1).store()?, v);
            }
        }
        Ok(UsageLedger {
            requests,
            billable_requests,
            models: models
                .into_iter()
                .map(|(model, usage_units)| ModelTokens {
                    scale: 6,
                    model,
                    usage_units,
                })
                .collect(),
        })
    }

    pub(crate) async fn purge_usage_before(&mut self, before: u64) -> RecordStoreResult<u64> {
        if before == 0 {
            return Ok(0);
        }
        let cutoff = usage_key(before);
        let mut tx = self.client().transaction().await.store()?;
        Self::lock_revision(&mut tx).await?;
        tx.batch_execute(
            "LOCK TABLE usage_windows, usage_ledger, usage_ledger_units \
             IN SHARE ROW EXCLUSIVE MODE",
        )
        .await
        .store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE window_start <> 0 AND
             (($1::bigint >= 0 AND window_start >= 0 AND window_start < $1) OR
              ($1 < 0 AND (window_start >= 0 OR window_start < $1)))",
            &[&cutoff],
        )
        .await
        .store()?;
        tx.execute(
            "DELETE FROM usage_ledger_units WHERE window_start <> 0 AND
             (($1::bigint >= 0 AND window_start >= 0 AND window_start < $1) OR
              ($1 < 0 AND (window_start >= 0 OR window_start < $1)))",
            &[&cutoff],
        )
        .await
        .store()?;
        let removed = tx
            .execute(
                "DELETE FROM usage_windows WHERE window_start <> 0 AND
                 (($1::bigint >= 0 AND window_start >= 0 AND window_start < $1) OR
                  ($1 < 0 AND (window_start >= 0 OR window_start < $1)))",
                &[&cutoff],
            )
            .await
            .store()?;
        tx.commit().await.store()?;
        Ok(removed)
    }

    pub(crate) async fn put_usage(
        &mut self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let mut ledger = ledger.clone();
        ledger
            .normalize_scale6()
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        let ledger = &ledger;

        if busbar_contract::abi::sdk::store::correction::reserved_bucket(bucket_id) {
            return Err(RecordStoreError(
                "reserved usage adjustment requires atomic correction".into(),
            ));
        }
        let ws = usage_key(window_start);
        let rq = ledger.requests.to_string();
        let brq = ledger.billable_requests.to_string();
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        Self::lock_revision(&mut tx).await?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,$3::text::numeric,$4::text::numeric)
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = EXCLUDED.requests,
                billable_requests = EXCLUDED.billable_requests",
            &[&bucket_id, &ws, &rq, &brq],
        )
        .await
        .store()?;
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

        if !ledger.models.is_empty() {
            let rows: Vec<[String; 4]> = ledger
                .models
                .iter()
                .map(|m| RESERVED_COLUMNS.map(|u| m.tier(u).to_string()))
                .collect();
            for (models, rows) in ledger
                .models
                .chunks((pgwire::MAX_BIND_PARAMETERS - 2) / 5)
                .zip(rows.chunks((pgwire::MAX_BIND_PARAMETERS - 2) / 5))
            {
                let mut sql = String::from(
                    "INSERT INTO usage_ledger \
                 (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) \
                 VALUES ",
                );
                let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(2 + rows.len() * 5);
                params.push(&bucket_id);
                params.push(&ws);
                for (i, (m, row)) in models.iter().zip(rows.iter()).enumerate() {
                    if i > 0 {
                        sql.push(',');
                    }
                    let base = 3 + i * 5;
                    sql.push_str(&format!(
                        "($1,$2,${},${}::text::numeric,${}::text::numeric,${}::text::numeric,${}::text::numeric)",
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
            }

            let opens: Vec<(&String, &String, String)> = ledger
                .models
                .iter()
                .flat_map(|m| {
                    m.usage_units
                        .iter()
                        .filter(|(u, v)| !is_reserved_unit(u) && **v != 0)
                        .map(move |(u, v)| (&m.model, u, v.to_string()))
                })
                .collect();
            if !opens.is_empty() {
                for opens in opens.chunks((pgwire::MAX_BIND_PARAMETERS - 2) / 3) {
                    let mut sql = String::from(
                        "INSERT INTO usage_ledger_units (bucket_id, window_start, model, unit, count) VALUES ",
                    );
                    let mut params: Vec<&(dyn ToSql + Sync)> =
                        Vec::with_capacity(2 + opens.len() * 3);
                    params.push(&bucket_id);
                    params.push(&ws);
                    for (i, (model, unit, count)) in opens.iter().enumerate() {
                        if i > 0 {
                            sql.push(',');
                        }
                        let base = 3 + i * 3;
                        sql.push_str(&format!(
                            "($1,$2,${},${},${}::text::numeric)",
                            base,
                            base + 1,
                            base + 2
                        ));
                        params.push(*model);
                        params.push(*unit);
                        params.push(count);
                    }

                    sql.push_str(
                        " ON CONFLICT (bucket_id, window_start, model, unit) DO UPDATE SET \
                     count = usage_ledger_units.count + EXCLUDED.count",
                    );
                    tx.execute(&sql, &params).await.store()?;
                }
            }
        }
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn list_metering(
        &mut self,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let client = self.client();

        let mut tx = Self::snapshot_consistent_tx(client).await?;
        let rows = Self::list_metering_in(&mut tx, bucket).await?;
        tx.commit().await.store()?;
        Ok(rows)
    }

    async fn list_metering_in(
        tx: &mut Transaction<'_>,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        Self::list_metering_for_key_in(tx, bucket, None).await
    }

    async fn list_metering_for_key_in(
        tx: &mut Transaction<'_>,
        bucket: u64,
        key: Option<&str>,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let b = usage_key(bucket);
        let rows = tx
            .query(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
                    requests, billable_requests, key_group_at_use, pricing_version, priced_from_ms
                 FROM usage_metering WHERE bucket=$1 AND ($2::text IS NULL OR key_id=$2)
                 ORDER BY key_id, model, provider, priced_from_ms, key_group_at_use, pricing_version",
                &[&b, &key],
            )
            .await
            .store()?;
        let unit_rows = tx
            .query(
                "SELECT key_id, model, provider, priced_from_ms, unit, count, key_group_at_use, pricing_version
                 FROM usage_metering_units WHERE bucket=$1 AND ($2::text IS NULL OR key_id=$2)",
                &[&b, &key],
            )
            .await
            .store()?;
        type RowKey = (String, String, String, i64, String, String);
        let mut units: std::collections::HashMap<RowKey, BTreeMap<String, u64>> =
            std::collections::HashMap::new();
        for r in &unit_rows {
            let v = read_u64(r.try_get::<_, i64>(5).store()?);
            if v == 0 {
                continue;
            }
            units
                .entry((
                    r.try_get(0).store()?,
                    r.try_get(1).store()?,
                    r.try_get(2).store()?,
                    r.try_get(3).store()?,
                    r.try_get(6).store()?,
                    r.try_get(7).store()?,
                ))
                .or_default()
                .insert(r.try_get(4).store()?, v);
        }
        rows.iter()
            .map(|r| {
                let key: RowKey = (
                    r.try_get(0).store()?,
                    r.try_get(1).store()?,
                    r.try_get(2).store()?,
                    r.try_get(11).store()?,
                    r.try_get(9).store()?,
                    r.try_get(10).store()?,
                );
                Ok(MeteringRow {
                    scale: 6,
                    usage_units: units.remove(&key).unwrap_or_default(),
                    key_id: key.0,
                    model: key.1,
                    provider: key.2,
                    tokens_input: read_u64(r.try_get::<_, i64>(3).store()?),
                    tokens_output: read_u64(r.try_get::<_, i64>(4).store()?),
                    tokens_cache_read: read_u64(r.try_get::<_, i64>(5).store()?),
                    tokens_cache_write: read_u64(r.try_get::<_, i64>(6).store()?),
                    requests: read_u64(r.try_get::<_, i64>(7).store()?),
                    billable_requests: read_u64(r.try_get::<_, i64>(8).store()?),
                    key_group_at_use: r.try_get(9).store()?,
                    pricing_version: r.try_get(10).store()?,
                    priced_from_ms: read_u64(key.3),
                })
            })
            .collect()
    }

    pub(crate) async fn put_credential(
        &mut self,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        if Self::put_credential_tx(&mut tx, "put_credential", secret).await? {
            tx.commit().await.store()?;
        }
        Ok(())
    }

    pub(crate) async fn rewrap_credential(
        &mut self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        if expected.meta.revoked_at.is_some()
            || expected.meta.secret_form != SecretForm::Recoverable
            || expected.secret == replacement
        {
            return Ok(false);
        }
        let client = self.client();
        let mut tx = client.transaction().await.store()?;

        Self::lock_revision(&mut tx).await?;
        let owner_live: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM keys WHERE id=$1 AND deleted_at IS NULL)",
                &[&expected.meta.key_id],
            )
            .await
            .store()?
            .try_get(0)
            .store()?;
        if !owner_live {
            tx.commit().await.store()?;
            return Ok(false);
        }
        let row = tx
            .query_opt(
                &format!(
                    "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE id=$1 FOR UPDATE"
                ),
                &[&expected.meta.id],
            )
            .await
            .store()?;
        let matches = if let Some(row) = row {
            let mut current = CredentialSecret {
                meta: row_to_cred_meta(&row)?,
                secret: row
                    .try_get::<_, Option<String>>(CRED_SECRET_COLUMN_INDEX)
                    .store()?
                    .unwrap_or_default(),
            };
            let matches = &current == expected;
            zeroize::Zeroize::zeroize(&mut current.secret);
            matches
        } else {
            false
        };
        if !matches {
            tx.commit().await.store()?;
            return Ok(false);
        }
        let revision = Self::next_revision(&mut tx).await?;
        let changed = tx
            .execute(
                "UPDATE credentials SET secret=$2, revision=$3 WHERE id=$1",
                &[&expected.meta.id, &replacement, &revision],
            )
            .await
            .store()?;
        if changed != 1 {
            return Err(RecordStoreError(
                "credential rewrap lost its locked row".into(),
            ));
        }
        tx.commit().await.store()?;
        Ok(true)
    }

    pub(crate) async fn put_key_with_credential(
        &mut self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        if key.deleted_at.is_some() {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: key '{}' is tombstoned; a credential is never minted \
                 onto it",
                key.id
            )));
        }
        if secret.meta.key_id != key.id {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: the credential names key '{}', not the key '{}' being \
                 minted with it",
                secret.meta.key_id, key.id
            )));
        }
        let cols = KeyColumns::of(key, None);
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        let rev = Self::next_revision(&mut tx).await?;

        let changed = tx
            .execute(KEY_UPSERT, &cols.params(key, &rev))
            .await
            .store()?;
        if changed == 0 {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: '{}' is tombstoned and its id is never reissued; \
                 refusing to clear the tombstone",
                key.id
            )));
        }
        Self::put_credential_tx(&mut tx, "put_key_with_credential", secret).await?;
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn list_credentials(
        &mut self,
        key_id: &str,
    ) -> RecordStoreResult<Vec<CredentialMeta>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS} FROM credentials WHERE key_id=$1 ORDER BY kind, slot"
        );
        let rows = self.client().query(&sql, &[&key_id]).await.store()?;
        rows.iter().map(row_to_cred_meta).collect()
    }

    pub(crate) async fn revoke_credential(
        &mut self,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                &[&id],
            )
            .await
            .store()?
            .try_get(0)
            .store()?;
        if !exists {
            return Err(RecordStoreError(format!(
                "revoke_credential: unknown id '{id}'"
            )));
        }
        let rev = Self::next_revision(&mut tx).await?;
        let now = credential_timestamp(now_secs());

        let changed = tx
            .execute(
                "UPDATE credentials SET revoked_at=$2, revoke_reason=$3, updated_at=$2, revision=$4,
                    secret=NULL, secret_form='none'
                 WHERE id=$1 AND revoked_at IS NULL",
                &[&id, &now, &reason, &rev],
            )
            .await
            .store()?;
        if changed == 0 {
            tx.execute(
                "UPDATE credentials SET secret=NULL, secret_form='none', revision=$2
                 WHERE id=$1 AND revoked_at IS NOT NULL
                 AND (secret IS NOT NULL OR secret_form <> 'none')",
                &[&id, &rev],
            )
            .await
            .store()?;

            let still_exists: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                    &[&id],
                )
                .await
                .store()?
                .try_get(0)
                .store()?;
            if !still_exists {
                return Err(RecordStoreError(format!(
                    "revoke_credential: unknown id '{id}'"
                )));
            }
        }
        tx.commit().await.store()?;
        Ok(())
    }

    pub(crate) async fn list_credentials_since(
        &mut self,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE revision > $1 OR revision = 0 ORDER BY revision, id"
        );
        let rows = self.client().query(&sql, &[&clamp(since)]).await.store()?;
        rows.iter()
            .map(|r| {
                Ok(CredentialSecret {
                    meta: row_to_cred_meta(r)?,
                    secret: r
                        .try_get::<_, Option<String>>(CRED_SECRET_COLUMN_INDEX)
                        .store()?
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    pub(crate) async fn list_audit(&mut self) -> RecordStoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq");
        let rows = self.client().query(&sql, &[]).await.store()?;
        rows.iter().map(row_to_audit).collect()
    }

    pub(crate) async fn list_audit_tail(
        &mut self,
        limit: u64,
    ) -> RecordStoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq DESC LIMIT $1");
        let rows = self
            .client()
            .query(&sql, &[&i64::try_from(limit).unwrap_or(i64::MAX)])
            .await
            .store()?;
        let mut out: Vec<AuditRecord> = rows
            .iter()
            .map(row_to_audit)
            .collect::<RecordStoreResult<_>>()?;
        out.reverse();
        Ok(out)
    }

    pub(crate) async fn add_denylist(&mut self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.client()
            .execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (sub) DO NOTHING",
                &[&sub, &reason, &clamp(now_secs())],
            )
            .await
            .store()?;
        Ok(())
    }

    pub(crate) async fn list_denylist(&mut self) -> RecordStoreResult<Vec<String>> {
        let rows = self
            .client()
            .query("SELECT sub FROM denylist", &[])
            .await
            .store()?;
        rows.iter().map(|r| r.try_get(0).store()).collect()
    }

    pub(crate) async fn upsert_plane_record(
        &mut self,
        record: PlaneRecordRef<'_>,
    ) -> RecordStoreResult<()> {
        let record = &record.to_record();

        let seq = storable_i64("upsert_plane_record", "seq", record.seq)?;
        let ts = storable_i64("upsert_plane_record", "ts", record.ts)?;

        self.client()
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
        let row = self
            .client()
            .query_opt(
                "SELECT body FROM (
                     SELECT body, 0 AS src FROM plane_records WHERE kind=$1 AND id=$2
                     UNION ALL
                     SELECT body, 1 AS src FROM plane_chain
                      WHERE kind=$1 AND parent=$2 AND seq=0 AND NOT has_parent
                 ) r ORDER BY src LIMIT 1",
                &[&kind, &id],
            )
            .await
            .store()?;
        row.map(|r| r.try_get(0).store()).transpose()
    }

    pub(crate) async fn list_plane_records(
        &mut self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let rows = match selector {
            PlaneSelector::All => {
                self.client()
                    .query(
                        "SELECT body FROM (
                             SELECT body, seq, id AS identity, id FROM plane_records WHERE kind=$1
                             UNION ALL
                             SELECT body, seq, parent AS identity, id FROM plane_chain WHERE kind=$1
                         ) r ORDER BY seq, identity, id",
                        &[&kind],
                    )
                    .await
            }

            PlaneSelector::Parent(p) => {
                let p: &str = p;
                self.client()
                    .query(
                        "SELECT body FROM (
                             SELECT body, seq, id AS identity, id FROM plane_records
                              WHERE kind=$1 AND parent=$2
                             UNION ALL
                             SELECT body, seq, parent AS identity, id FROM plane_chain
                              WHERE kind=$1 AND parent=$2 AND has_parent
                         ) r ORDER BY seq, identity, id",
                        &[&kind, &p],
                    )
                    .await
            }
        }
        .store()?;
        rows.iter()
            .map(|r| r.try_get::<_, Vec<u8>>(0).store())
            .collect()
    }

    pub(crate) async fn list_plane_record_parents(
        &mut self,
        kind: &str,
    ) -> RecordStoreResult<Vec<String>> {
        let rows = self
            .client()
            .query(
                "SELECT parent FROM plane_chain WHERE kind=$1 AND has_parent
                 UNION
                 SELECT parent FROM plane_records WHERE kind=$1 AND parent IS NOT NULL
                 ORDER BY 1",
                &[&kind],
            )
            .await
            .store()?;
        rows.iter().map(|r| r.try_get(0).store()).collect()
    }

    pub(crate) async fn purge_plane_records_before(
        &mut self,
        kind: &str,
        before: u64,
    ) -> RecordStoreResult<u64> {
        let retention = if TERMINAL_ONLY_RETENTION_KINDS.contains(&kind) {
            Retention::TerminalOnly
        } else {
            Retention::Age
        };
        self.purge_plane_records(kind, before, retention).await
    }

    pub(crate) async fn purge_plane_records(
        &mut self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        let terminal_only = retention == Retention::TerminalOnly;
        let client = self.client();
        let mut tx = client.transaction().await.store()?;
        let before = if kind == TICKET_RECORD_KIND {
            before.min(Self::database_now(&mut tx).await?)
        } else {
            before
        };
        let cutoff = clamp(before);
        let above_sql_maximum = before > i64::MAX as u64;

        let mut purged = 0_u64;
        loop {
            let ids: Vec<String> = tx
                .query(
                    "DELETE FROM plane_records
                     WHERE kind=$1 AND ($5 OR ts < $2) AND (NOT $3 OR disposition = 'terminal')
                       AND (kind, id) IN
                         (SELECT kind, id FROM plane_records
                          WHERE kind=$1 AND ($5 OR ts < $2) AND (NOT $3 OR disposition = 'terminal')
                          LIMIT $4)
                     RETURNING id",
                    &[
                        &kind,
                        &cutoff,
                        &terminal_only,
                        &PURGE_BATCH,
                        &above_sql_maximum,
                    ],
                )
                .await
                .store()?
                .iter()
                .map(|r| r.try_get(0).store())
                .collect::<RecordStoreResult<_>>()?;

            if !ids.is_empty() {
                for (_, child) in PLANE_CHILD_KINDS.iter().filter(|(p, _)| *p == kind) {
                    tx.execute(
                        "DELETE FROM plane_chain WHERE kind=$1 AND parent = ANY($2)",
                        &[child, &ids],
                    )
                    .await
                    .store()?;
                }
            }
            purged += ids.len() as u64;
            if (ids.len() as i64) < PURGE_BATCH {
                break;
            }
        }
        let mut chain = 0_u64;
        loop {
            let n = tx
                .execute(
                    "DELETE FROM plane_chain WHERE ctid IN
                         (SELECT ctid FROM plane_chain
                          WHERE kind=$1 AND ($5 OR ts < $2) AND (NOT $3 OR disposition = 'terminal')
                          LIMIT $4)",
                    &[
                        &kind,
                        &cutoff,
                        &terminal_only,
                        &PURGE_BATCH,
                        &above_sql_maximum,
                    ],
                )
                .await
                .store()?;
            chain += n;
            if (n as i64) < PURGE_BATCH {
                break;
            }
        }
        tx.commit().await.store()?;

        Ok(purged + chain)
    }

    pub(crate) async fn delete_plane_record(
        &mut self,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<()> {
        let client = self.client();
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

        for (_, child) in PLANE_CHILD_KINDS.iter().filter(|(p, _)| *p == kind) {
            tx.execute(
                "DELETE FROM plane_chain WHERE kind=$1 AND parent=$2",
                &[child, &id],
            )
            .await
            .store()?;
        }
        tx.commit().await.store()?;
        Ok(())
    }

    async fn database_now(tx: &mut Transaction<'_>) -> RecordStoreResult<u64> {
        database_clock::now(tx).await
    }

    pub(crate) async fn redeem_plane_token(
        &mut self,
        kind: &str,
        token: &str,
        expires_at: u64,
        _caller_now: u64,
    ) -> RecordStoreResult<bool> {
        const REPLAY_TOKEN_LOCK_DOMAIN: &str = "busbar:replay-token";
        let mut tx = self.client().transaction().await.store()?;

        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(ROW($1::text,$2::text)::text,0))",
            &[&REPLAY_TOKEN_LOCK_DOMAIN, &kind],
        )
        .await
        .store()?;
        let store_now = Self::database_now(&mut tx).await?;
        let cutoff = store_now as i64;
        if expires_at < store_now {
            tx.rollback().await.store()?;
            return Ok(false);
        }

        let expires = i64::try_from(expires_at).unwrap_or(i64::MAX);
        tx.execute(
            "DELETE FROM plane_tokens WHERE kind=$1 AND expires_at < $2",
            &[&kind, &cutoff],
        )
        .await
        .store()?;
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
        if kind == TICKET_RECORD_KIND {
            let Ok(deadline) = i64::try_from(expires_at) else {
                return Ok(false);
            };
            let mut tx = Self::snapshot_consistent_tx(self.client()).await?;
            let store_now = Self::database_now(&mut tx).await?;
            let row = tx
                .query_opt(
                    "SELECT disposition FROM plane_records WHERE kind=$1 AND id=$2 AND ts=$3",
                    &[&kind, &token, &deadline],
                )
                .await
                .store()?;
            let terminal = row
                .as_ref()
                .map(|r| r.try_get::<_, &str>(0).store())
                .transpose()?;
            let live = expires_at >= store_now
                && terminal == Some(disposition_to_storage(PlaneDisposition::Terminal));
            tx.commit().await.store()?;
            return Ok(live);
        }

        if now > expires_at {
            return Ok(false);
        }
        let row = self
            .client()
            .query_opt(
                "SELECT disposition FROM plane_records WHERE kind=$1 AND id=$2",
                &[&kind, &token],
            )
            .await
            .store()?;
        match row {
            Some(r) => Ok(r.try_get::<_, &str>(0).store()? == "active"),
            None => Ok(false),
        }
    }
}

const AUDIT_COLUMNS: &str = "seq, ts, action, resource, outcome, principal, prev_hash, hash";

fn disposition_to_storage(d: PlaneDisposition) -> &'static str {
    match d {
        PlaneDisposition::Active => "active",
        PlaneDisposition::Terminal => "terminal",
    }
}

fn row_to_audit(r: &Row) -> RecordStoreResult<AuditRecord> {
    Ok(AuditRecord {
        seq: read_u64(r.try_get::<_, i64>(0).store()?),
        ts: read_u64(r.try_get::<_, i64>(1).store()?),
        action: r.try_get(2).store()?,
        resource: r.try_get(3).store()?,
        outcome: r.try_get(4).store()?,
        principal: r.try_get(5).store()?,
        prev_hash: r.try_get(6).store()?,
        hash: r.try_get(7).store()?,
    })
}

impl Session {
    /// Shared body of `put_credential`/`put_key_with_credential` (`op` names the caller in every
    /// refusal): upsert on `(key_id, kind, slot)`.
    async fn put_credential_tx(
        tx: &mut Transaction<'_>,
        op: &str,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<bool> {
        let m = &secret.meta;
        let rev = Self::next_revision(tx).await?;

        let owner_live: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NULL FROM keys WHERE id=$1",
                &[&m.key_id],
            )
            .await
            .store()?
            .map(|r| r.try_get(0).store())
            .transpose()?;
        match owner_live {
            None => {
                return Err(RecordStoreError(format!(
                    "{op}: key '{}' does not exist; a credential must hang off a real key",
                    m.key_id
                )));
            }
            Some(false) => {
                return Err(RecordStoreError(format!(
                    "{op}: key '{}' is tombstoned; its credentials were revoked with it and are \
                     never reissued",
                    m.key_id
                )));
            }
            Some(true) => {}
        }
        let form = secret_form_to_storage(m.secret_form);
        let secret_val = if m.secret_form == SecretForm::None {
            None
        } else {
            Some(secret.secret.as_str())
        };
        let slot = m.slot as i16;
        let created = credential_timestamp(m.created_at);
        let updated = credential_timestamp(m.updated_at);
        let expires = m.expires_at.map(credential_timestamp);
        let live_refused = |key_id: &str, kind: &str, slot: i16| {
            RecordStoreError(format!(
                "{op}: slot {slot} for key '{key_id}' kind '{kind}' holds a live credential; \
                 revoke it first"
            ))
        };

        if let Some(r) = tx
            .query_opt(
                "SELECT key_id, kind, slot, public_id, secret, secret_form, created_at, updated_at,
                        expires_at, revoked_at IS NOT NULL
                 FROM credentials WHERE id=$1",
                &[&m.id],
            )
            .await
            .store()?
        {
            if r.try_get::<_, bool>(9).store()? {
                return Err(RecordStoreError(format!(
                    "{op}: credential '{}' is revoked; a revoked credential is never re-minted",
                    m.id
                )));
            }
            let stored: (&str, &str, i16, &str, Option<&str>, &str) = (
                r.try_get(0).store()?,
                r.try_get(1).store()?,
                r.try_get(2).store()?,
                r.try_get(3).store()?,
                r.try_get(4).store()?,
                r.try_get(5).store()?,
            );
            let same = stored
                == (
                    m.key_id.as_str(),
                    m.kind.as_str(),
                    slot,
                    m.public_id.as_str(),
                    secret_val,
                    form,
                )
                && r.try_get::<_, i64>(6).store()? == created
                && r.try_get::<_, i64>(7).store()? == updated
                && r.try_get::<_, Option<i64>>(8).store()? == expires;
            if same {
                return Ok(false);
            }
            return Err(live_refused(stored.0, stored.1, stored.2));
        }

        let occupant: Option<bool> = tx
            .query_opt(
                "SELECT revoked_at IS NOT NULL FROM credentials
                 WHERE key_id=$1 AND kind=$2 AND slot=$3",
                &[&m.key_id, &m.kind, &slot],
            )
            .await
            .store()?
            .map(|r| r.try_get(0).store())
            .transpose()?;
        if occupant == Some(false) {
            return Err(live_refused(&m.key_id, &m.kind, slot));
        }

        let holder = tx
            .query_opt(
                "SELECT key_id, slot FROM credentials WHERE kind=$1 AND public_id=$2",
                &[&m.kind, &m.public_id],
            )
            .await
            .store()?;
        if let Some(h) = holder {
            let (hk, hs): (String, i16) = (h.try_get(0).store()?, h.try_get(1).store()?);
            if !(hk == m.key_id && hs == slot) {
                return Err(RecordStoreError(format!(
                    "{op}: public_id '{}' is already in use for kind '{}'",
                    m.public_id, m.kind
                )));
            }
        }
        tx.execute(
            "INSERT INTO credentials
                (id,key_id,kind,slot,public_id,secret,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,$11)
             ON CONFLICT (key_id, kind, slot) DO UPDATE SET
                id=EXCLUDED.id, public_id=EXCLUDED.public_id, secret=EXCLUDED.secret,
                secret_form=EXCLUDED.secret_form, created_at=EXCLUDED.created_at,
                updated_at=EXCLUDED.updated_at,
                expires_at=EXCLUDED.expires_at, revoked_at=NULL, revoke_reason=NULL,
                revision=EXCLUDED.revision
             WHERE credentials.revoked_at IS NOT NULL",
            &[
                &m.id,
                &m.key_id,
                &m.kind,
                &slot,
                &m.public_id,
                &secret_val,
                &form,
                &created,
                &updated,
                &expires,
                &rev,
            ],
        )
        .await
        .store()?;
        Ok(true)
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
        let mut delta = delta.clone();
        delta
            .normalize_scale6()
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        let delta = &delta;
        let mut checked = Self::get_usage_in(tx, bucket_id, window_start).await?;
        checked
            .checked_apply_delta(delta)
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;

        let ws = usage_key(window_start);
        let window_sql = format!(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,GREATEST(0,$3::bigint),GREATEST(0,$4::bigint))
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = {},
                billable_requests = {}",
            usage_add("usage_windows.requests", "$3::bigint"),
            usage_add("usage_windows.billable_requests", "$4::bigint"),
        );
        tx.execute(
            &window_sql,
            &[&bucket_id, &ws, &delta.requests, &delta.billable_requests],
        )
        .await
        .store()?;

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
        for models in rounds
            .iter()
            .flat_map(|models| models.chunks((pgwire::MAX_BIND_PARAMETERS - 2) / 5))
        {
            let deltas: Vec<[i64; 4]> = models
                .iter()
                .map(|m| RESERVED_COLUMNS.map(|u| m.usage_units.get(u).copied().unwrap_or(0)))
                .collect();
            let mut ensure =
                String::from("INSERT INTO usage_ledger (bucket_id, window_start, model) VALUES ");
            let mut update = format!(
                "UPDATE usage_ledger u SET \
                    tokens_input       = {}, \
                    tokens_output      = {}, \
                    tokens_cache_read  = {}, \
                    tokens_cache_write = {} \
                 FROM (VALUES ",
                usage_add("u.tokens_input", "v.di"),
                usage_add("u.tokens_output", "v.do_"),
                usage_add("u.tokens_cache_read", "v.dcr"),
                usage_add("u.tokens_cache_write", "v.dcw"),
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
                for opens in opens.chunks((pgwire::MAX_BIND_PARAMETERS - 2) / 3) {
                    let mut ensure = String::from(
                        "INSERT INTO usage_ledger_units (bucket_id, window_start, model, unit) VALUES ",
                    );
                    let mut update = format!(
                        "UPDATE usage_ledger_units u SET count = {} FROM (VALUES ",
                        usage_add("u.count", "v.d")
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
                    ensure
                        .push_str(" ON CONFLICT (bucket_id, window_start, model, unit) DO NOTHING");
                    update.push_str(
                        ") AS v(model, unit, d) \
                     WHERE u.bucket_id = $1 AND u.window_start = $2 \
                       AND u.model = v.model AND u.unit = v.unit",
                    );
                    tx.execute(&ensure, &ensure_params).await.store()?;
                    tx.execute(&update, &update_params).await.store()?;
                }
            }
        }
        Ok(())
    }

    /// `add_metering` inside the caller's transaction.
    pub(crate) async fn add_metering_in(
        tx: &mut Transaction<'_>,
        d: &MeteringDelta,
    ) -> RecordStoreResult<()> {
        let mut d = d.clone();
        d.normalize_scale6()
            .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        let d = &d;
        if let Some(mut checked) = Self::list_metering_for_key_in(tx, d.bucket, Some(&d.key_id))
            .await?
            .into_iter()
            .find(|row| {
                row.model == d.model
                    && row.provider == d.provider
                    && row.priced_from_ms == d.priced_from_ms
                    && row.key_group_at_use == d.key_group_at_use
                    && row.pricing_version == d.pricing_version
            })
        {
            checked
                .checked_add_delta(d)
                .map_err(|e| RecordStoreError(format!("exact count: {e}")))?;
        }

        let (bucket, ti, to, tcr, tcw) = (
            usage_key(d.bucket),
            clamp(d.tokens_input),
            clamp(d.tokens_output),
            clamp(d.tokens_cache_read),
            clamp(d.tokens_cache_write),
        );
        let requests = clamp(d.requests);
        let brequests = clamp(d.billable_requests);
        let priced_from = clamp(d.priced_from_ms);

        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(ROW($1::text,$2::bigint,$3::text,$4::text,$5::bigint)::text,0))",
            &[&d.key_id, &bucket, &d.model, &d.provider, &priced_from],
        ).await.store()?;
        let params: &[&(dyn ToSql + Sync)] = &[
            &d.key_id,
            &bucket,
            &d.model,
            &d.provider,
            &ti,
            &to,
            &tcr,
            &tcw,
            &requests,
            &brequests,
            &d.key_group_at_use,
            &d.pricing_version,
            &priced_from,
        ];
        let updated = tx
            .execute(
                &format!(
                "UPDATE usage_metering SET tokens_input={}, tokens_output={}, tokens_cache_read={},
                 tokens_cache_write={}, requests={}, billable_requests={}
                 WHERE key_id=$1 AND bucket=$2 AND model=$3 AND provider=$4
                 AND key_group_at_use=$11 AND pricing_version=$12 AND priced_from_ms=$13",
                sat_add("tokens_input", "$5::bigint", false),
                sat_add("tokens_output", "$6::bigint", false),
                sat_add("tokens_cache_read", "$7::bigint", false),
                sat_add("tokens_cache_write", "$8::bigint", false),
                sat_add("requests", "$9::bigint", false),
                sat_add("billable_requests", "$10::bigint", false),
            ),
                params,
            )
            .await
            .store()?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO usage_metering (key_id,bucket,model,provider,tokens_input,tokens_output,
                 tokens_cache_read,tokens_cache_write,requests,billable_requests,key_group_at_use,
                 pricing_version,priced_from_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                params,
            ).await.store()?;
        }
        let units: Vec<(&String, i64)> = d
            .usage_units
            .iter()
            .filter(|(_, v)| **v != 0)
            .map(|(u, v)| (u, clamp(*v)))
            .collect();
        for units in units.chunks((pgwire::MAX_BIND_PARAMETERS - 7) / 2) {
            let mut sql = String::from("WITH incoming(unit,count) AS (VALUES ");
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(7 + units.len() * 2);
            params.extend_from_slice(&[
                &d.key_id,
                &bucket,
                &d.model,
                &d.provider,
                &priced_from,
                &d.key_group_at_use,
                &d.pricing_version,
            ]);
            for (i, (unit, count)) in units.iter().enumerate() {
                if i != 0 {
                    sql.push(',');
                }
                let base = 8 + i * 2;
                sql.push_str(&format!("(${}::text,${}::bigint)", base, base + 1));
                params.push(*unit);
                params.push(count);
            }
            sql.push_str(&format!(
                "), updated AS (UPDATE usage_metering_units u SET count={}
                 FROM incoming v WHERE u.key_id=$1 AND u.bucket=$2 AND u.model=$3
                 AND u.provider=$4 AND u.priced_from_ms=$5 AND u.key_group_at_use=$6
                 AND u.pricing_version=$7 AND u.unit=v.unit RETURNING u.unit)
                 INSERT INTO usage_metering_units
                 (key_id,bucket,model,provider,priced_from_ms,key_group_at_use,pricing_version,unit,count)
                 SELECT $1,$2,$3,$4,$5,$6,$7,v.unit,v.count FROM incoming v
                 WHERE NOT EXISTS (SELECT 1 FROM updated u WHERE u.unit=v.unit)",
                sat_add("u.count","v.count",false),
            ));
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
        let seq = storable_i64("append_plane_record", "seq", record.seq)?;
        let ts = storable_i64("append_plane_record", "ts", record.ts)?;

        let parent = record.parent.as_deref().unwrap_or(record.id.as_str());
        let has_parent = record.parent.is_some();
        let disposition = disposition_to_storage(record.disposition);

        let inserted = tx
            .execute(
                "INSERT INTO plane_chain (kind, parent, seq, id, ts, disposition, body, has_parent)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (kind, parent, seq) DO NOTHING",
                &[
                    &record.kind,
                    &parent,
                    &seq,
                    &record.id,
                    &ts,
                    &disposition,
                    &record.body,
                    &has_parent,
                ],
            )
            .await
            .store()?;
        if inserted == 1 {
            return Ok(true);
        }
        let stored = tx
            .query_opt(
                "SELECT id, ts, disposition, body, has_parent FROM plane_chain
                 WHERE kind=$1 AND parent=$2 AND seq=$3 FOR SHARE",
                &[&record.kind, &parent, &seq],
            )
            .await
            .store()?;
        match stored {
            Some(r) => {
                let identical = r.try_get::<_, String>(0).store()? == record.id
                    && r.try_get::<_, i64>(1).store()? == ts
                    && r.try_get::<_, String>(2).store()? == disposition
                    && r.try_get::<_, Vec<u8>>(3).store()? == record.body
                    && r.try_get::<_, bool>(4).store()? == has_parent;
                if identical {
                    return Ok(true);
                }

                Err(fork::chain_fork(&record.kind, parent, record.seq))
            }
            None => Ok(false),
        }
    }
}

mod v3;
pub use v3::door;

/// The package name the door's Statement states for this store.
pub const NAME: &str = "busbar-store-postgres";

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
