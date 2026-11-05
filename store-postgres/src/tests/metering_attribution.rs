// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{MeteringDelta, MeteringRow};
use std::collections::BTreeMap;
fn attributed_meter(bucket: u64, group: &str, version: &str, n: u64) -> MeteringDelta {
    MeteringDelta {
        scale: 6,
        key_id: "attribution-key".into(),
        bucket,
        model: "model".into(),
        provider: "provider".into(),
        tokens_input: n,
        tokens_output: n + 1,
        tokens_cache_read: n + 2,
        tokens_cache_write: n + 3,
        requests: n,
        billable_requests: n,
        key_group_at_use: group.into(),
        pricing_version: version.into(),
        priced_from_ms: 17,
        usage_units: BTreeMap::from([("audio_seconds".into(), n)]),
    }
}

fn assert_attributed_rows(rows: Vec<MeteringRow>) {
    let rows: BTreeMap<_, _> = rows
        .into_iter()
        .map(|r| ((r.key_group_at_use.clone(), r.pricing_version.clone()), r))
        .collect();
    let expected = [
        ("", "", 6),
        ("group", "v1", 9),
        ("other", "v1", 12),
        ("group", "V1", 15),
        ("group", "v1 ", 18),
        ("group", "", 21),
        ("", "v1", 24),
    ];
    assert_eq!(rows.len(), expected.len());
    for (group, version, n) in expected {
        let row = &rows[&(group.into(), version.into())];
        assert_eq!(row.key_id, "attribution-key");
        assert_eq!(row.priced_from_ms, 17);
        assert_eq!(row.tokens_input, n);
        assert_eq!(row.tokens_output, n + 3);
        assert_eq!(row.tokens_cache_read, n + 6);
        assert_eq!(row.tokens_cache_write, n + 9);
        assert_eq!(row.requests, n);
        assert_eq!(row.billable_requests, n);
        assert_eq!(
            row.usage_units,
            BTreeMap::from([("audio_seconds".into(), n)])
        );
    }
}

#[test]
fn historical_attribution_survives_batch_replay_and_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_attribution");
    let store = TestStore::open(&db.url()).unwrap();
    let bucket = u64::MAX - 1;
    let mut deltas: Vec<_> = [
        ("", ""),
        ("group", "v1"),
        ("other", "v1"),
        ("group", "V1"),
        ("group", "v1 "),
        ("group", ""),
        ("", "v1"),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (g, v))| attributed_meter(bucket, g, v, i as u64 + 2))
    .collect();
    for d in &deltas {
        store.add_metering(d).unwrap();
    }
    deltas.extend(deltas.clone());
    let op = OpId::from_parts(601, 3);
    store.add_metering_batch_op(op, &deltas).unwrap();
    store.add_metering_batch_op(op, &deltas).unwrap();
    let mut changed = deltas.clone();
    changed[0].pricing_version = "changed".into();
    assert_eq!(
        store.add_metering_batch_op(op, &changed),
        Err(OpRefused::Conflict)
    );
    assert_attributed_rows(store.list_metering(bucket).unwrap());
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    reopened.add_metering_batch_op(op, &deltas).unwrap();
    assert_attributed_rows(reopened.list_metering(bucket).unwrap());
}

fn legacy_metering(raw: &mut postgres::Client) {
    raw.batch_execute(
        "CREATE TABLE legacy_metering_units AS SELECT key_id,bucket,model,provider,priced_from_ms,unit,count FROM usage_metering_units;
         DROP TABLE usage_metering_units;
         ALTER TABLE legacy_metering_units RENAME TO usage_metering_units;
         ALTER TABLE usage_metering_units ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms,unit);
         ALTER TABLE usage_metering DROP CONSTRAINT IF EXISTS usage_metering_pkey;
         ALTER TABLE usage_metering ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms);
         DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES (6);"
    ).unwrap();
}

#[test]
fn migration_preserves_legacy_attribution_units_and_replay() {
    let Some(url) = live_url() else { return };
    for (group, version) in [("", ""), ("historical", "old-version ")] {
        let db = TempDb::create(&url, "spg_meter_history");
        let store = TestStore::open(&db.url()).unwrap();
        let old = attributed_meter(u64::MAX, group, version, 7);
        let op = OpId::from_parts(601, 5);
        store
            .add_metering_batch_op(op, std::slice::from_ref(&old))
            .unwrap();
        let expected = store.list_metering(old.bucket).unwrap();
        drop(store);
        let mut raw = connect_client_with_retry(&db.url());
        legacy_metering(&mut raw);
        drop(raw);
        let migrated = TestStore::open(&db.url()).unwrap();
        migrated
            .add_metering_batch_op(op, std::slice::from_ref(&old))
            .unwrap();
        assert_eq!(migrated.list_metering(old.bucket).unwrap(), expected);
        let new = MeteringDelta {
            scale: 6,
            key_group_at_use: "new-group".into(),
            pricing_version: "new-version".into(),
            ..old.clone()
        };
        migrated.add_metering(&new).unwrap();
        let rows = migrated.list_metering(old.bucket).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&expected[0]));
        for row in rows {
            assert_eq!(row.usage_units, old.usage_units);
        }
    }
}

#[test]
fn migration_refuses_orphan_metering_units_without_inventing_attribution() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_meter_orphan");
    let store = TestStore::open(&db.url()).unwrap();
    store
        .add_metering(&attributed_meter(17, "group", "version", 7))
        .unwrap();
    drop(store);
    let mut raw = connect_client_with_retry(&db.url());
    legacy_metering(&mut raw);
    raw.batch_execute("DELETE FROM usage_metering").unwrap();
    for _ in 0..2 {
        let error = TestStore::open(&db.url())
            .err()
            .expect("orphan must refuse migration");
        assert!(
            error.contains("metering unit attribution has no parent"),
            "{error}"
        );
        let count: i64 = raw
            .query_one("SELECT count FROM usage_metering_units", &[])
            .unwrap()
            .get(0);
        assert_eq!(count, 7);
    }
}

#[test]
fn long_historical_attribution_migrates_and_accumulates_without_an_index_limit() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_long_attribution");
    let store = TestStore::open(&db.url()).unwrap();
    let group: String = (0..1024_u64)
        .map(|i| {
            format!(
                "{:016x}",
                i.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(17)
            )
        })
        .collect();
    let version: String = group.chars().rev().collect();
    let old = attributed_meter(u64::MAX, &group, &version, 7);
    store.add_metering(&old).unwrap();
    let expected = store.list_metering(old.bucket).unwrap();
    drop(store);
    let mut raw = connect_client_with_retry(&db.url());
    legacy_metering(&mut raw);
    drop(raw);
    let migrated = TestStore::open(&db.url()).unwrap();
    assert_eq!(migrated.list_metering(old.bucket).unwrap(), expected);
    migrated.add_metering(&old).unwrap();
    let new = MeteringDelta {
        scale: 6,
        pricing_version: format!("{version}changed"),
        ..old.clone()
    };
    migrated.add_metering(&new).unwrap();
    let rows = migrated.list_metering(old.bucket).unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.key_group_at_use, group);
        let n = if row.pricing_version == version {
            14
        } else {
            assert_eq!(row.pricing_version, new.pricing_version);
            7
        };
        assert_eq!(row.requests, n);
        assert_eq!(row.tokens_input, n);
        assert_eq!(
            row.usage_units,
            BTreeMap::from([("audio_seconds".into(), n)])
        );
    }
}

#[test]
fn concurrent_first_metering_writes_share_one_attributed_cell_and_unit_count() {
    use std::time::{Duration, Instant};
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_meter_insert_race");
    let first = TestStore::open(&db.url()).unwrap();
    let second = TestStore::open(&db.url()).unwrap();
    let reader = TestStore::open(&db.url()).unwrap();
    let mut holder = connect_client_with_retry(&db.url());
    holder
        .batch_execute(
            "CREATE FUNCTION hold_meter_insert() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_advisory_xact_lock(601713); RETURN NEW; END $$;
        CREATE TRIGGER hold_meter_insert BEFORE INSERT ON usage_metering
        FOR EACH ROW EXECUTE FUNCTION hold_meter_insert();
        BEGIN; SELECT pg_advisory_xact_lock(601713);",
        )
        .unwrap();
    let d = attributed_meter(17, "group", "version", 7);
    let e = d.clone();
    let a = std::thread::spawn(move || first.add_metering(&d));
    let b = std::thread::spawn(move || second.add_metering(&e));
    let until = Instant::now() + Duration::from_secs(5);
    let blocked = loop {
        if let Err(error) = holder.batch_execute("SELECT pg_stat_clear_snapshot()") {
            break Err(error);
        }
        match holder.query_one(
            "SELECT count(*) FROM pg_stat_activity
            WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock'",
            &[],
        ) {
            Ok(row) if row.get::<_, i64>(0) >= 2 => break Ok(true),
            Ok(_) if Instant::now() >= until => break Ok(false),
            Ok(_) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => break Err(error),
        }
    };
    let released = holder.batch_execute("ROLLBACK");
    drop(holder);
    let a = a.join();
    let b = b.join();
    released.unwrap();
    assert!(
        blocked.unwrap(),
        "both writes reached the real database lock boundary"
    );
    a.unwrap().unwrap();
    b.unwrap().unwrap();
    let rows = reader.list_metering(17).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 14);
    assert_eq!(rows[0].tokens_input, 14);
    assert_eq!(
        rows[0].usage_units,
        BTreeMap::from([("audio_seconds".into(), 14)])
    );
}
