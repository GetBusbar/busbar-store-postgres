-- SPDX-License-Identifier: Apache-2.0
-- Test DDL extracted verbatim from 0283f54^:store-postgres/src/lib.rs::SCHEMA.
-- Same physical fresh DDL in schema8 at0283f54. Synthetic test databases only;
-- this is not a published historical data fixture.

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
    unit         TEXT COLLATE "C" NOT NULL,
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
    unit           TEXT COLLATE "C" NOT NULL,
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
-- COLLATE "C" on every identity column is byte-exact comparison: a non-deterministic ICU collation
-- would otherwise collide ids differing only in case and fold a single-use token onto its variant.

-- UPSERTED records (a task, a demotion, a push configuration, ...): one current row per (kind, id).
CREATE TABLE IF NOT EXISTS plane_records (
    kind        TEXT COLLATE "C" NOT NULL,
    id          TEXT COLLATE "C" NOT NULL,
    parent      TEXT COLLATE "C",
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
    kind        TEXT COLLATE "C" NOT NULL,
    parent      TEXT COLLATE "C" NOT NULL,
    seq         BIGINT NOT NULL,
    id          TEXT COLLATE "C" NOT NULL,
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
    kind       TEXT COLLATE "C" NOT NULL,
    token      TEXT COLLATE "C" NOT NULL,
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
    schema_id TEXT COLLATE "C" NOT NULL,
    key       BYTEA NOT NULL,
    value     BYTEA NOT NULL,
    PRIMARY KEY (schema_id, key)
);