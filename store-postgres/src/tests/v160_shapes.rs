// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar 1.6.0 record shapes against a live Postgres — the kind-tagged `VirtualKey` scopes and

use super::*;
use busbar_contract::records::{ScopeRef, UsageDelta};

/// The schema a RELEASED 1.5.x build (store-postgres v1.0.0-v1.0.6, schema v6) created, verbatim
const V6_SCHEMA: &str = "
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
    generation_hash TEXT NOT NULL,
    name            TEXT NOT NULL,
    allowed_pools   TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      BIGINT NOT NULL,
    key_group       TEXT,
    labels          TEXT NOT NULL DEFAULT '{}',
    expires_at      BIGINT,
    deleted_at      BIGINT,
    revision        BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT keys_tombstone_disabled CHECK (deleted_at IS NULL OR enabled = FALSE)
);
CREATE INDEX IF NOT EXISTS idx_keys_revision ON keys (revision);
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
    PRIMARY KEY (key_id, bucket, model, provider)
);
CREATE INDEX IF NOT EXISTS idx_usage_metering_bucket ON usage_metering (bucket);
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

";

fn units(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn signed(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

/// A database stamped below the oldest released schema (v6) is refused at open, with the reason.
#[test]
fn a_database_stamped_below_v6_is_refused() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_v5");
    let iso_url = tmp.url();
    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(
            "CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             INSERT INTO busbar_schema (version) VALUES (5);",
        )
        .unwrap();
    }
    let err = TestStore::open(&iso_url)
        .err()
        .expect("a pre-release schema is refused");
    assert!(
        err.ends_with(
            "postgres store: database schema v5 predates v6, the oldest released schema; \
             refusing to open"
        ),
        "{err}"
    );
}

/// A released 1.5.x database upgrades IN PLACE. Nothing is dropped, every existing row reads back
#[test]
fn a_released_v6_database_upgrades_in_place_without_losing_a_row() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_v6up");
    let iso_url = tmp.url();
    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(V6_SCHEMA).unwrap();
        c.batch_execute(
            "INSERT INTO busbar_schema (version) VALUES (5), (6);
             UPDATE store_revision SET revision = 7;
             INSERT INTO keys (id, generation_hash, name, allowed_pools, enabled, created_at,
                               key_group, labels, expires_at, deleted_at, revision)
             VALUES ('vk_pools', 'binding:vk_pools:g1', 'pools key', '[\"fast\",\"cheap\"]', TRUE,
                     100, 'growth', '{\"team\":\"a\"}', 999, NULL, 3),
                    ('vk_all', 'binding:vk_all:g1', 'wildcard key', NULL, TRUE, 101,
                     NULL, '{}', NULL, NULL, 4),
                    ('vk_none', 'binding:vk_none:g1', 'no-pools key', '[]', TRUE, 102,
                     NULL, '{}', NULL, NULL, 5),
                    ('vk_dead', 'binding:vk_dead:g1', 'dead key', NULL, FALSE, 103,
                     NULL, '{}', NULL, 1700000000, 6);
             INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form,
                                      created_at, updated_at, revision)
             VALUES ('cred_v6', 'vk_pools', 'sigv4', 0, 'AKIAV6', 'v1:plain:s3cret',
                     'recoverable', 100, 100, 7);
             INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ('vk_pools', 86400, 12, 10);
             INSERT INTO usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output,
                                       tokens_cache_read, tokens_cache_write)
             VALUES ('vk_pools', 86400, 'model-a', 100, 200, 0, 7);
             INSERT INTO usage_metering (key_id, bucket, model, provider, tokens_input,
                                         tokens_output, tokens_cache_read, tokens_cache_write,
                                         requests, billable_requests, key_group_at_use,
                                         pricing_version)
             VALUES ('vk_pools', 86400, 'model-a', 'prov', 100, 200, 0, 7, 12, 10, 'growth', 'v1');
             INSERT INTO audit_log VALUES (1, 100, 'hook.register', 'hook:x', 'applied', 'vk_admin',
                                           '', 'h1');
             INSERT INTO denylist (sub, reason, created_at) VALUES ('vk_revoked', 'leak', 5);",
        )
        .unwrap();
    }

    let store = connect_store_with_retry(&iso_url).expect("this build connects to a v6 database");

    let mut check = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let version: i64 = check
        .query_one("SELECT MAX(version) FROM busbar_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(version, SCHEMA_VERSION);

    let pools = store
        .get_key("vk_pools")
        .unwrap()
        .expect("the v6 key survives");
    assert_eq!(
        pools.allowed_scopes,
        Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("cheap")])
    );
    assert_eq!(pools.name, "pools key");
    assert_eq!(pools.group.as_deref(), Some("growth"));
    assert_eq!(pools.labels.get("team").map(String::as_str), Some("a"));
    assert_eq!(pools.expires_at, Some(999));
    assert_eq!(pools.revision, 3);
    assert_eq!(
        (pools.idp_subject, pools.binding_mode, pools.minted_by),
        (None, None, None),
        "a key minted before the 1.6.0 fields existed reads them as None"
    );
    assert_eq!(
        store.get_key("vk_all").unwrap().unwrap().allowed_scopes,
        None,
        "a v6 NULL grant is still the omitted-grant wildcard"
    );
    assert_eq!(
        store.get_key("vk_none").unwrap().unwrap().allowed_scopes,
        Some(vec![]),
        "a v6 '[]' grant is still NO scopes, never widened to all"
    );
    assert!(store
        .get_key("vk_dead")
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
    assert_eq!(store.list_keys().unwrap().len(), 4);
    assert_eq!(
        store
            .list_keys_since(4)
            .unwrap()
            .iter()
            .map(|k| k.id.as_str())
            .collect::<Vec<_>>(),
        vec!["vk_none", "vk_dead"],
        "the revision delta still works off the v6 revisions"
    );

    let cred = store
        .lookup_credential_secret("sigv4", "AKIAV6")
        .unwrap()
        .expect("the v6 credential still resolves");
    assert_eq!(cred.plaintext(), Some("s3cret"));
    assert_eq!(store.list_audit().unwrap().len(), 1);
    assert_eq!(
        store.list_denylist().unwrap(),
        vec!["vk_revoked".to_string()]
    );

    let ledger = store.get_usage("vk_pools", 86_400).unwrap();
    assert_eq!((ledger.requests, ledger.billable_requests), (12, 10));
    assert_eq!(
        ledger.models,
        vec![ModelTokens {
            model: "model-a".into(),
            usage_units: units(&[(UNIT_INPUT, 100), (UNIT_OUTPUT, 200), (UNIT_CACHE_WRITE, 7)]),
        }]
    );

    let rows = store.list_metering(86_400).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].priced_from_ms, 0);
    assert_eq!(rows[0].tokens_input, 100);
    assert_eq!(rows[0].requests, 12);
    assert_eq!(rows[0].key_group_at_use, "growth");
    assert_eq!(rows[0].pricing_version, "v1");
    assert!(rows[0].usage_units.is_empty());

    store
        .add_metering(&MeteringDelta {
            key_id: "vk_pools".into(),
            bucket: 86_400,
            model: "model-a".into(),
            provider: "prov".into(),
            tokens_input: 1,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "growth".into(),
            pricing_version: "v2".into(),
            priced_from_ms: 43_200_000,
            usage_units: Default::default(),
        })
        .unwrap();
    let mut rows = store.list_metering(86_400).unwrap();
    rows.sort_by_key(|r| r.priced_from_ms);
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[0].tokens_input, rows[1].tokens_input), (100, 1));

    let mut k = store.get_key("vk_all").unwrap().unwrap();
    k.minted_by = Some("vk_admin".into());
    k.allowed_scopes = Some(vec![ScopeRef {
        kind: "mcp_server".into(),
        value: "files".into(),
    }]);
    store.put_key(&k).unwrap();
    let back = store.get_key("vk_all").unwrap().unwrap();
    assert_eq!(back.minted_by.as_deref(), Some("vk_admin"));
    assert_eq!(back.allowed_scopes, k.allowed_scopes);

    drop(store);
    let again = connect_store_with_retry(&iso_url).expect("reconnect");
    assert_eq!(again.get_key("vk_all").unwrap().unwrap(), back);
    assert_eq!(again.list_metering(86_400).unwrap().len(), 2);
    drop(again);
    drop(check);
}

/// Every scope KIND round-trips as itself. The pre-1.6.0 storage kept bare pool names only, so an
#[test]
fn scope_grants_of_every_kind_round_trip_without_collapsing_into_pools() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let store = connect_store_with_retry(&url).expect("connect");
    let (mixed, mcp_only) = ("vk_scope_mixed", "vk_scope_mcp_only");
    hard_reset(&store, mixed);
    hard_reset(&store, mcp_only);

    let scope = |kind: &str, value: &str| ScopeRef {
        kind: kind.into(),
        value: value.into(),
    };
    let mut k = sample_key(mixed);
    k.allowed_scopes = Some(vec![
        ScopeRef::pool("fast"),
        scope("agent", "planner"),
        scope("mcp_server", "files"),
        scope("mcp_server", "search"),
        scope("mcp_tool", "files_read"),
    ]);
    store.put_key(&k).unwrap();
    let back = store.get_key(mixed).unwrap().unwrap();
    assert_eq!(back.allowed_scopes, k.allowed_scopes);
    assert!(back.scope_allowed("mcp_server", "files"));
    assert!(
        !back.scope_allowed("pool", "files"),
        "an MCP grant must never become a pool grant"
    );
    let stored_pools: Option<String> = store
        .lock()
        .query_one("SELECT allowed_pools FROM keys WHERE id=$1", &[&mixed])
        .unwrap()
        .get(0);
    assert_eq!(
        stored_pools.as_deref(),
        Some("[\"fast\"]"),
        "pools stay in their 1.5.x column"
    );

    let mut m = sample_key(mcp_only);
    m.allowed_scopes = Some(vec![scope("mcp_server", "files")]);
    store.put_key(&m).unwrap();
    let back = store.get_key(mcp_only).unwrap().unwrap();
    assert_eq!(back.allowed_scopes, m.allowed_scopes);
    assert!(
        !back.scope_allowed("pool", "fast"),
        "an MCP-only key must grant no pool at all"
    );

    m.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    store.put_key(&m).unwrap();
    assert_eq!(
        store.get_key(mcp_only).unwrap().unwrap().allowed_scopes,
        m.allowed_scopes
    );
    hard_reset(&store, mixed);
    hard_reset(&store, mcp_only);
}

/// The three 1.6.0 attribution fields round-trip through every write path.
#[test]
fn the_attribution_fields_round_trip_through_every_key_write() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let store = connect_store_with_retry(&url).expect("connect");
    let (a, b) = ("vk_attr_put", "vk_attr_mint");
    hard_reset(&store, a);
    hard_reset(&store, b);

    let mut k = sample_key(a);
    k.idp_subject = Some("user@example.com".into());
    k.binding_mode = Some("user-bound".into());
    k.minted_by = Some("vk_admin".into());
    store.put_key(&k).unwrap();
    let back = store.get_key(a).unwrap().unwrap();
    assert_eq!(back.idp_subject.as_deref(), Some("user@example.com"));
    assert_eq!(back.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(back.minted_by.as_deref(), Some("vk_admin"));

    let mut m = sample_key(b);
    m.binding_mode = Some("time-bound".into());
    m.minted_by = Some("vk_app_admin".into());
    store
        .put_key_with_credential(&m, &sample_cred(b, 0, "AKIA_ATTR_MINT"))
        .unwrap();
    let back = store.get_key(b).unwrap().unwrap();
    assert_eq!(back.binding_mode.as_deref(), Some("time-bound"));
    assert_eq!(back.minted_by.as_deref(), Some("vk_app_admin"));
    assert_eq!(back.idp_subject, None);

    store.delete_key(b).unwrap();
    assert_eq!(
        store.get_key(b).unwrap().unwrap().minted_by.as_deref(),
        Some("vk_app_admin")
    );
    hard_reset(&store, a);
    hard_reset(&store, b);
}

/// `idp_provider` is persisted with the row and read back.
#[test]
fn idp_provider_round_trips() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_idp_provider";
    hard_reset(&store, id);
    let mut k = sample_key(id);
    k.idp_provider = Some("github".into());
    store.put_key(&k).unwrap();
    let back = store.get_key(id).unwrap().unwrap();
    assert_eq!(back.idp_provider.as_deref(), Some("github"));
    hard_reset(&store, id);
}

/// The usage ledger is name-keyed (1.6.0 M1b): the four reserved classes AND every open class
#[test]
fn the_usage_ledger_carries_open_units_and_applies_refunds() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket = "vk_units_ledger";
    hard_reset(&store, bucket);
    let ws = 500u64;

    let ledger = UsageLedger {
        requests: 4,
        billable_requests: 3,
        models: vec![
            ModelTokens {
                model: "model-a".into(),
                usage_units: units(&[(UNIT_INPUT, 10), (UNIT_OUTPUT, 20), ("search_units", 3)]),
            },
            ModelTokens {
                model: "model-b".into(),
                usage_units: units(&[("tool_calls", 5)]),
            },
        ],
    };
    store.put_usage(bucket, ws, &ledger).unwrap();
    assert_eq!(store.get_usage(bucket, ws).unwrap(), ledger);

    let smaller = UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: "model-a".into(),
            usage_units: units(&[(UNIT_INPUT, 1)]),
        }],
    };
    store.put_usage(bucket, ws, &smaller).unwrap();
    assert_eq!(store.get_usage(bucket, ws).unwrap(), smaller);

    store
        .add_usage(
            bucket,
            ws,
            &UsageDelta {
                requests: 2,
                billable_requests: 1,
                models: vec![
                    ModelTokensDelta {
                        model: "model-a".into(),
                        usage_units: signed(&[(UNIT_INPUT, 4), ("search_units", 7)]),
                    },
                    ModelTokensDelta {
                        model: "model-c".into(),
                        usage_units: signed(&[(UNIT_OUTPUT, 9)]),
                    },
                ],
            },
        )
        .unwrap();
    store
        .add_usage(
            bucket,
            ws,
            &UsageDelta {
                requests: 0,
                billable_requests: -1,
                models: vec![
                    ModelTokensDelta {
                        model: "model-a".into(),
                        usage_units: signed(&[(UNIT_INPUT, -2), ("search_units", -100)]),
                    },
                    // A refund against a model the window never saw floors to 0.
                    ModelTokensDelta {
                        model: "model-d".into(),
                        usage_units: signed(&[(UNIT_OUTPUT, -5)]),
                    },
                ],
            },
        )
        .unwrap();

    let got = store.get_usage(bucket, ws).unwrap();
    let mut expect = smaller.clone();
    expect.apply_delta(&UsageDelta {
        requests: 2,
        billable_requests: 1,
        models: vec![
            ModelTokensDelta {
                model: "model-a".into(),
                usage_units: signed(&[(UNIT_INPUT, 4), ("search_units", 7)]),
            },
            ModelTokensDelta {
                model: "model-c".into(),
                usage_units: signed(&[(UNIT_OUTPUT, 9)]),
            },
        ],
    });
    expect.apply_delta(&UsageDelta {
        requests: 0,
        billable_requests: -1,
        models: vec![
            ModelTokensDelta {
                model: "model-a".into(),
                usage_units: signed(&[(UNIT_INPUT, -2), ("search_units", -100)]),
            },
            ModelTokensDelta {
                model: "model-d".into(),
                usage_units: signed(&[(UNIT_OUTPUT, -5)]),
            },
        ],
    });

    for m in &mut expect.models {
        m.usage_units.retain(|_, v| *v != 0);
    }
    expect.models.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(got, expect);
    assert_eq!(
        got.models[0].tier(UNIT_INPUT),
        3,
        "1 + 4 - 2: the refund landed"
    );
    assert!(
        !got.models[0].usage_units.contains_key("search_units"),
        "7 - 100 floors at 0 rather than going negative"
    );

    hard_reset(&store, bucket);
}

/// Metering: `priced_from_ms` is part of the accrual key (a card edit mid-day opens a second row,
#[test]
fn metering_splits_on_priced_from_ms_and_carries_open_classes() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let store = connect_store_with_retry(&url).expect("connect");
    let key_id = format!("vk_meter_units_{}", unique_suffix());
    let bucket = 20_270_611u64;
    let delta = |priced_from_ms: u64, input: u64, classes: &[(&str, u64)]| MeteringDelta {
        key_id: key_id.clone(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: input,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms,
        usage_units: units(classes),
    };
    store
        .add_metering(&delta(0, 10, &[("tool_calls", 2)]))
        .unwrap();
    store
        .add_metering(&delta(0, 5, &[("tool_calls", 3), ("bytes", 100)]))
        .unwrap();
    store.add_metering(&delta(1_000, 7, &[])).unwrap();

    let mut rows: Vec<MeteringRow> = store
        .list_metering(bucket)
        .unwrap()
        .into_iter()
        .filter(|r| r.key_id == key_id)
        .collect();
    rows.sort_by_key(|r| r.priced_from_ms);
    assert_eq!(rows.len(), 2, "a second price instant opens a second row");
    assert_eq!(rows[0].tokens_input, 15);
    assert_eq!(rows[0].requests, 2);
    assert_eq!(
        rows[0].usage_units,
        units(&[("bytes", 100), ("tool_calls", 5)])
    );
    assert_eq!(rows[1].priced_from_ms, 1_000);
    assert_eq!(rows[1].tokens_input, 7);
    assert!(rows[1].usage_units.is_empty());

    hard_reset(&store, &key_id);
}

/// A delete holds the revision transaction while both mints reach that real lock. Once the
#[test]
fn a_mint_racing_a_delete_never_leaves_a_credential_under_the_tombstone() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let setup = connect_store_with_retry(&url).expect("connect");
    setup
        .lock()
        .batch_execute(
            "CREATE FUNCTION hold_key_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
           PERFORM pg_advisory_xact_lock(hashtext(current_database()), 1);
           RETURN NEW;
         END $$;
         CREATE TRIGGER hold_key_delete BEFORE UPDATE OF deleted_at ON keys
         FOR EACH ROW WHEN (NEW.deleted_at IS NOT NULL) EXECUTE FUNCTION hold_key_delete();",
        )
        .unwrap();
    let mut holder = connect_client_with_retry(&url);
    let holder_pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let mut observer = connect_client_with_retry(&url);
    for round in 0..5u32 {
        let id = format!("vk_race_mint_{}_{round}", std::process::id());
        hard_reset(&setup, &id);
        setup.put_key(&sample_key(&id)).unwrap();

        let mint_nodes: Vec<_> = (0..2u8)
            .map(|slot| {
                (
                    slot,
                    connect_store_with_retry(&url).expect("mint node connects"),
                )
            })
            .collect();
        let delete_node = connect_store_with_retry(&url).expect("delete node connects");
        holder
            .query_one(
                "SELECT pg_advisory_lock(hashtext(current_database()), 1)",
                &[],
            )
            .unwrap();
        let (delete_wait, mint_wait, released, deleted, mints) = std::thread::scope(|scope| {
            let delete_id = id.clone();
            let delete = scope.spawn(move || delete_node.delete_key(&delete_id));
            let delete_wait =
                super::plane_records::wait_for_blocked_backends(&mut observer, holder_pid, 1);
            let delete_pid = delete_wait
                .as_ref()
                .ok()
                .and_then(|pids| pids.first())
                .copied();
            let workers: Vec<_> = mint_nodes
                .into_iter()
                .map(|(slot, node)| {
                    let id = id.clone();
                    scope.spawn(move || {
                        node.put_credential(&sample_cred(
                            &id,
                            slot,
                            &format!("AKIA_RACE_{}_{slot}", id.to_uppercase()),
                        ))
                    })
                })
                .collect();
            let mint_wait = delete_pid
                .map(|pid| super::plane_records::wait_for_blocked_backends(&mut observer, pid, 2));

            let released = holder.query_one(
                "SELECT pg_advisory_unlock(hashtext(current_database()), 1)",
                &[],
            );
            let deleted = delete.join().unwrap();
            let mints: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
            (delete_wait, mint_wait, released, deleted, mints)
        });
        assert!(released
            .expect("release the paused delete")
            .get::<_, bool>(0));
        deleted.expect("the observed delete commits");
        assert_eq!(delete_wait.expect("observe the delete backend").len(), 1);
        assert_eq!(
            mint_wait
                .expect("delete must have reached its trigger")
                .expect("observe both mint backends")
                .len(),
            2,
            "both mints must actually wait on the deletion transaction"
        );
        for r in mints {
            let e = r.expect_err("a mint blocked behind the delete must see its tombstone");
            assert!(e.0.contains("is tombstoned"), "round {round}: {e:?}");
        }
        assert!(setup.get_key(&id).unwrap().unwrap().deleted_at.is_some());

        let late = setup
            .put_credential(&sample_cred(
                &id,
                0,
                &format!("AKIA_LATE_{}", id.to_uppercase()),
            ))
            .expect_err("a mint under a tombstone is refused");
        assert!(late.0.contains("is tombstoned"), "{late:?}");
        assert!(
            setup.list_credentials(&id).unwrap().is_empty(),
            "round {round}: a credential survived under a tombstoned key"
        );
        hard_reset(&setup, &id);
    }
}

const FIXTURE_DUMP_1_5_5: &str = include_str!("../../tests/fixtures/1.5.5/dump.sql");
const FIXTURE_ROWS_1_5_5: &str = include_str!("../../tests/fixtures/1.5.5/rows.json");

fn fixture_rows(table: &str) -> Vec<serde_json::Value> {
    let all: serde_json::Value = serde_json::from_str(FIXTURE_ROWS_1_5_5).unwrap();
    all[table]
        .as_array()
        .unwrap_or_else(|| panic!("rows.json has no table {table}"))
        .clone()
}

fn fx_u64(row: &serde_json::Value, col: &str) -> u64 {
    row[col]
        .as_u64()
        .unwrap_or_else(|| panic!("{col} is not an unsigned integer in {row}"))
}

fn fx_str<'a>(row: &'a serde_json::Value, col: &str) -> &'a str {
    row[col]
        .as_str()
        .unwrap_or_else(|| panic!("{col} is not a string in {row}"))
}

/// A fresh database holding exactly what the 1.5.5 binary left. `dump.sql` is executed whole by
fn restore_1_5_5(url: &str) -> TempDb {
    let tmp = TempDb::create(url, "spg_155");
    let mut c = postgres::Client::connect(&tmp.url(), postgres::NoTls).unwrap();
    c.batch_execute(FIXTURE_DUMP_1_5_5)
        .expect("the 1.5.5 dump restores");
    tmp
}

fn reserved_units(row: &serde_json::Value) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for (unit, col) in [
        (UNIT_INPUT, "tokens_input"),
        (UNIT_OUTPUT, "tokens_output"),
        (UNIT_CACHE_READ, "tokens_cache_read"),
        (UNIT_CACHE_WRITE, "tokens_cache_write"),
    ] {
        let v = fx_u64(row, col);
        if v != 0 {
            m.insert(unit.to_string(), v);
        }
    }
    m
}

/// Recorded admin counts must survive independently of the raw-row comparison below.
fn assert_recorded_1_5_5_admin_counts(store: &TestStore) {
    let usage: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/1.5.5/readback/usage.json"
    ))
    .unwrap();
    let metering = store
        .list_metering(usage["window"]["start"].as_u64().unwrap())
        .unwrap();
    for expected in usage["by_key"].as_array().unwrap() {
        let rows: Vec<_> = metering
            .iter()
            .filter(|row| row.key_id == expected["id"].as_str().unwrap())
            .collect();
        let actual = [
            rows.iter().map(|row| row.requests).sum::<u64>(),
            rows.iter().map(|row| row.tokens_input).sum(),
            rows.iter().map(|row| row.tokens_output).sum(),
            rows.iter().map(|row| row.tokens_cache_read).sum(),
            rows.iter().map(|row| row.tokens_cache_write).sum(),
        ];
        let expected = [
            "requests",
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_creation",
        ]
        .map(|field| expected[field].as_u64().unwrap());
        assert_eq!(
            actual, expected,
            "migrated metering preserves the recorded fleet usage counts"
        );
    }
    for text in [
        include_str!("../../tests/fixtures/1.5.5/readback/key-fixture-grouped.json"),
        include_str!("../../tests/fixtures/1.5.5/readback/key-fixture-ungrouped.json"),
    ] {
        let expected: serde_json::Value = serde_json::from_str(text).unwrap();
        let id = expected["id"].as_str().unwrap();
        let got = store
            .get_usage(id, expected["window_start"].as_u64().unwrap())
            .unwrap();
        assert_eq!(got.requests, expected["requests"].as_u64().unwrap(), "preserve the independently recorded key-window count, including historical differences from metering");
        let tokens: u64 = got
            .models
            .iter()
            .map(|model| {
                [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE]
                    .iter()
                    .map(|unit| model.usage_units.get(*unit).copied().unwrap_or(0))
                    .sum::<u64>()
            })
            .sum();
        assert_eq!(tokens, expected["tokens"].as_u64().unwrap());
    }
}

/// Every row of `rows.json` read back through the 1.6.0 surface, and no extra rows.
fn assert_1_5_5_rows_read_back(store: &TestStore) {
    assert_recorded_1_5_5_admin_counts(store);
    assert!(
        store.list_credentials_since(0).unwrap().is_empty(),
        "migration must not invent credentials absent from this recording"
    );
    assert!(
        store.list_denylist().unwrap().is_empty(),
        "migration must not invent denylist rows absent from this recording"
    );
    let expected_revision = fixture_rows("store_revision")[0]["revision"]
        .as_u64()
        .unwrap();
    let actual_revision: i64 = store
        .lock()
        .query_one("SELECT revision FROM store_revision WHERE only_row", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        actual_revision as u64, expected_revision,
        "migration preserves the recorded global revision"
    );

    let metering = fixture_rows("usage_metering");
    assert!(!metering.is_empty(), "the fixture carries metering rows");
    let buckets: std::collections::BTreeSet<u64> =
        metering.iter().map(|r| fx_u64(r, "bucket")).collect();
    let mut seen = 0;
    for bucket in &buckets {
        let got = store.list_metering(*bucket).unwrap();
        let want: Vec<&serde_json::Value> = metering
            .iter()
            .filter(|r| fx_u64(r, "bucket") == *bucket)
            .collect();
        assert_eq!(got.len(), want.len(), "metering rows in bucket {bucket}");
        for w in want {
            let row = got
                .iter()
                .find(|g| {
                    g.key_id == fx_str(w, "key_id")
                        && g.model == fx_str(w, "model")
                        && g.provider == fx_str(w, "provider")
                })
                .unwrap_or_else(|| panic!("metering row missing after migrate: {w}"));
            assert_eq!(row.requests, fx_u64(w, "requests"), "{w}");
            assert_eq!(row.billable_requests, fx_u64(w, "billable_requests"), "{w}");
            assert_eq!(row.key_group_at_use, fx_str(w, "key_group_at_use"), "{w}");
            assert_eq!(row.pricing_version, fx_str(w, "pricing_version"), "{w}");
            assert_eq!(row.tokens_input, fx_u64(w, "tokens_input"), "{w}");
            assert_eq!(row.tokens_output, fx_u64(w, "tokens_output"), "{w}");
            assert_eq!(row.tokens_cache_read, fx_u64(w, "tokens_cache_read"), "{w}");
            assert_eq!(
                row.tokens_cache_write,
                fx_u64(w, "tokens_cache_write"),
                "{w}"
            );
            assert_eq!(row.priced_from_ms, 0, "a 1.5.5 row is undated: {w}");
            assert!(row.usage_units.is_empty(), "{w}");
            seen += 1;
        }
    }
    assert_eq!(seen, metering.len());

    let windows = fixture_rows("usage_windows");
    assert!(!windows.is_empty(), "the fixture carries usage windows");
    let ledger = fixture_rows("usage_ledger");
    for w in &windows {
        let bucket = fx_str(w, "bucket_id");
        let start = fx_u64(w, "window_start");
        let got = store.get_usage(bucket, start).unwrap();
        assert_eq!(got.requests, fx_u64(w, "requests"), "{w}");
        assert_eq!(got.billable_requests, fx_u64(w, "billable_requests"), "{w}");
        let mut want: Vec<ModelTokens> = ledger
            .iter()
            .filter(|l| fx_str(l, "bucket_id") == bucket && fx_u64(l, "window_start") == start)
            .map(|l| ModelTokens {
                model: fx_str(l, "model").to_string(),
                usage_units: reserved_units(l),
            })
            .collect();
        let mut have = got.models.clone();
        want.sort_by(|a, b| a.model.cmp(&b.model));
        have.sort_by(|a, b| a.model.cmp(&b.model));
        assert_eq!(have, want, "ledger of {bucket}@{start}");
    }
    let ledger_windows: std::collections::BTreeSet<(String, u64)> = ledger
        .iter()
        .map(|l| {
            (
                fx_str(l, "bucket_id").to_string(),
                fx_u64(l, "window_start"),
            )
        })
        .collect();
    for (bucket, start) in ledger_windows {
        assert!(
            windows
                .iter()
                .any(|w| fx_str(w, "bucket_id") == bucket && fx_u64(w, "window_start") == start),
            "ledger rows of {bucket}@{start} have a usage_windows row"
        );
    }

    let keys = fixture_rows("keys");
    assert!(!keys.is_empty(), "the fixture carries keys");
    assert_eq!(store.list_keys().unwrap().len(), keys.len());
    for k in &keys {
        let got = store
            .get_key(fx_str(k, "id"))
            .unwrap()
            .unwrap_or_else(|| panic!("key missing after migrate: {k}"));
        assert_eq!(got.name, fx_str(k, "name"), "{k}");
        assert_eq!(got.generation_hash, fx_str(k, "generation_hash"), "{k}");
        assert_eq!(got.enabled, k["enabled"].as_bool().unwrap(), "{k}");
        assert_eq!(got.group.as_deref(), k["key_group"].as_str(), "{k}");
        assert_eq!(got.created_at, fx_u64(k, "created_at"), "{k}");
        assert_eq!(got.revision, fx_u64(k, "revision"), "{k}");
        assert_eq!(got.expires_at, k["expires_at"].as_u64(), "{k}");
        assert_eq!(got.deleted_at, k["deleted_at"].as_u64(), "{k}");
        assert!(k["allowed_pools"].is_null() && got.allowed_scopes.is_none());
        assert_eq!(
            (got.idp_subject, got.binding_mode, got.minted_by),
            (None, None, None),
            "{k}"
        );
    }

    let audit = fixture_rows("audit_log");
    assert!(!audit.is_empty(), "the fixture carries audit rows");
    let got = store.list_audit().unwrap();
    assert_eq!(got.len(), audit.len());
    for (g, w) in got.iter().zip(&audit) {
        assert_eq!(g.seq, fx_u64(w, "seq"), "{w}");
        assert_eq!(g.ts, fx_u64(w, "ts"), "{w}");
        assert_eq!(g.action, fx_str(w, "action"), "{w}");
        assert_eq!(g.resource, fx_str(w, "resource"), "{w}");
        assert_eq!(g.outcome, fx_str(w, "outcome"), "{w}");
        assert_eq!(g.principal, fx_str(w, "principal"), "{w}");
        assert_eq!(g.prev_hash, fx_str(w, "prev_hash"), "{w}");
        assert_eq!(g.hash, fx_str(w, "hash"), "{w}");
    }
}

/// Every read the assertions above make, as sorted text, so two opens compare whole.
fn read_everything_1_5_5(store: &TestStore) -> Vec<String> {
    let mut out = vec![
        format!("{:?}", store.list_keys().unwrap()),
        format!("{:?}", store.list_audit().unwrap()),
    ];
    for r in fixture_rows("usage_metering") {
        out.push(format!(
            "{:?}",
            store.list_metering(fx_u64(&r, "bucket")).unwrap()
        ));
    }
    for w in fixture_rows("usage_windows") {
        out.push(format!(
            "{:?}",
            store
                .get_usage(fx_str(&w, "bucket_id"), fx_u64(&w, "window_start"))
                .unwrap()
        ));
    }
    out
}

fn schema_version_of(url: &str) -> i64 {
    let mut c = postgres::Client::connect(url, postgres::NoTls).unwrap();
    c.query_one("SELECT MAX(version) FROM busbar_schema", &[])
        .unwrap()
        .get(0)
}

/// Rows written by the 1.5.5 binary read back through this build's migrate, field for field.
#[test]
fn the_1_5_5_binarys_rows_read_back_through_migrate() {
    let Some(url) = live_url() else { return };
    let tmp = restore_1_5_5(&url);
    let iso_url = tmp.url();
    let store = connect_store_with_retry(&iso_url).expect("this build opens the 1.5.5 database");
    assert_eq!(schema_version_of(&iso_url), SCHEMA_VERSION);
    assert_1_5_5_rows_read_back(&store);
}

/// A second open over the migrated 1.5.5 database changes nothing.
#[test]
fn migrate_over_the_1_5_5_rows_is_idempotent() {
    let Some(url) = live_url() else { return };
    let tmp = restore_1_5_5(&url);
    let iso_url = tmp.url();
    let first = {
        let store = connect_store_with_retry(&iso_url).expect("first open");
        assert_eq!(schema_version_of(&iso_url), SCHEMA_VERSION);
        assert_1_5_5_rows_read_back(&store);
        read_everything_1_5_5(&store)
    };
    let store = connect_store_with_retry(&iso_url).expect("second open");
    assert_eq!(schema_version_of(&iso_url), SCHEMA_VERSION);
    assert_1_5_5_rows_read_back(&store);
    assert_eq!(read_everything_1_5_5(&store), first);
}

/// `UsageDelta.models` may name one model twice. `add_usage` must fold the entries sequentially,
#[test]
fn add_usage_folds_a_model_named_twice_sequentially() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_shapes");
    let url = database.url();
    let store = connect_store_with_retry(&url).expect("connect");
    let ws = 20_270_601u64;
    let entry = |m: &str, u: &[(&str, i64)]| ModelTokensDelta {
        model: m.into(),
        usage_units: signed(u),
    };

    let bucket = "vk_dup_models_sum";
    hard_reset(&store, bucket);
    store
        .add_usage(
            bucket,
            ws,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![
                    entry("m", &[(UNIT_INPUT, 100)]),
                    entry("m", &[(UNIT_INPUT, 50)]),
                ],
            },
        )
        .unwrap();
    let got = store.get_usage(bucket, ws).unwrap();
    assert_eq!(got.models.len(), 1);
    assert_eq!(got.models[0].usage_units.get(UNIT_INPUT), Some(&150));

    let bucket = "vk_dup_models_refund";
    hard_reset(&store, bucket);
    let start = UsageLedger {
        requests: 0,
        billable_requests: 0,
        models: vec![ModelTokens {
            model: "m".into(),
            usage_units: units(&[(UNIT_INPUT, 20)]),
        }],
    };
    store.put_usage(bucket, ws, &start).unwrap();
    let refund = UsageDelta {
        requests: 0,
        billable_requests: 0,
        models: vec![
            entry("m", &[(UNIT_INPUT, -150)]),
            entry("m", &[(UNIT_INPUT, 100)]),
        ],
    };
    store.add_usage(bucket, ws, &refund).unwrap();
    let mut expect = start.clone();
    expect.apply_delta(&refund);
    let got = store.get_usage(bucket, ws).unwrap();
    assert_eq!(got, expect);
    assert_eq!(got.models[0].usage_units.get(UNIT_INPUT), Some(&100));

    let bucket = "vk_dup_models_open";
    hard_reset(&store, bucket);
    let d = UsageDelta {
        requests: 0,
        billable_requests: 0,
        models: vec![
            entry("m", &[("search_units", 3), (UNIT_OUTPUT, 1)]),
            entry("n", &[("search_units", 9)]),
            entry("m", &[("search_units", 4)]),
        ],
    };
    store.add_usage(bucket, ws, &d).unwrap();
    let mut expect = UsageLedger::default();
    expect.apply_delta(&d);
    let got = store.get_usage(bucket, ws).unwrap();
    assert_eq!(got, expect);
    let m = got.models.iter().find(|x| x.model == "m").unwrap();
    assert_eq!(m.usage_units.get("search_units"), Some(&7));

    hard_reset(&store, "vk_dup_models_sum");
    hard_reset(&store, "vk_dup_models_refund");
    hard_reset(&store, "vk_dup_models_open");
}
