// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    MeteringDelta, ModelTokens, ModelTokensDelta, RecordStore, UsageDelta, UsageLedger,
};
use std::collections::BTreeMap;

fn delta(scale: u32, amount: i128, requests: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            scale,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([
                ("input".into(), amount),
                ("audio_seconds".into(), amount),
            ]),
        }],
    }
}

fn meter(key: &str, scale: u32, amount: i128, requests: u64) -> MeteringDelta {
    MeteringDelta {
        scale,
        key_id: key.into(),
        bucket: 0,
        model: "exact-model".into(),
        provider: "provider".into(),
        tokens_input: amount,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: requests,
        key_group_at_use: "group".into(),
        pricing_version: "opening".into(),
        priced_from_ms: 0,
        usage_units: BTreeMap::from([("audio_seconds".into(), amount)]),
    }
}

fn exercise(store: &dyn RecordStore, key: &str) {
    store.add_usage(key, 0, &delta(0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 1);
    let cells = [(key, 0, delta(6, 123_456, 2))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    let got = store.get_usage(key, 0).unwrap();
    assert_eq!((got.requests, got.billable_requests), (3, 3));
    assert_eq!(got.models[0].scale, 6);
    assert_eq!(got.models[0].usage_units["input"], 2_123_456);
    assert_eq!(got.models[0].usage_units["audio_seconds"], 2_123_456);
    store.add_usage(key, 0, &delta(6, -123_455, 0)).unwrap();
    assert_eq!(
        store.get_usage(key, 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 0, delta(6, 1, 2))])
        .is_err());

    store.add_metering(&meter(key, 0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 2);
    let meters = [meter(key, 6, 123_456, 2)];
    store.add_metering_batch_deduped(op, &meters).unwrap();
    store.add_metering_batch_deduped(op, &meters).unwrap();
    let before = store.list_metering(0).unwrap();
    let got = before.iter().find(|row| row.key_id == key).unwrap();
    assert_eq!(
        (
            got.scale,
            got.tokens_input,
            got.requests,
            got.billable_requests
        ),
        (6, 2_123_456, 3, 3)
    );
    assert_eq!(got.usage_units["audio_seconds"], 2_123_456);
    let op = OpId::from_parts(0xe81, 3);
    assert!(store
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1), meter(key, 6, i128::MAX, 1)])
        .is_err());
    assert_eq!(
        store.list_metering(0).unwrap(),
        before,
        "overflow rolls the entire batch back"
    );
    store
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1)])
        .unwrap();

    let max = UsageLedger {
        requests: 7,
        billable_requests: 5,
        models: vec![ModelTokens {
            scale: 6,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([("input".into(), i128::MAX)]),
        }],
    };
    store.put_usage(key, 0, &max).unwrap();
    let op = OpId::from_parts(0xe81, 4);
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1)), (key, 0, delta(6, 1, 1))])
        .is_err());
    assert_eq!(store.get_usage(key, 0).unwrap(), max);
    assert_eq!(store.get_usage(key, 1).unwrap(), UsageLedger::default());
    // A refused operation leaves no receipt; the same id can now commit another body.
    store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1))])
        .unwrap();
    assert_eq!(
        store.get_usage(key, 1).unwrap().models[0].usage_units["input"],
        1
    );
    assert!(store.add_usage(key, 2, &delta(3, 1, 1)).is_err());
    assert_eq!(store.get_usage(key, 2).unwrap(), UsageLedger::default());
}

#[test]
fn exact_counts_decimal_legacy_replay_and_atomic_overflow() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "exactcounts");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("exact-counts")).unwrap();
    exercise(&*store, "exact-counts");
}

fn migrated(store: &dyn RecordStore) {
    let row = store.get_usage("legacy", 0).unwrap();
    assert_eq!((row.requests, row.billable_requests), (7, 5));
    let model = row
        .models
        .iter()
        .find(|row| row.model == "exact-model")
        .unwrap();
    assert_eq!(model.scale, 6);
    assert_eq!(model.usage_units["input"], 2_000_000);
    assert_eq!(model.usage_units["audio_seconds"], 3_000_000);
    let rows = store.list_metering(0).unwrap();
    let row = rows.iter().find(|row| row.key_id == "legacy").unwrap();
    assert_eq!(
        (row.scale, row.tokens_input, row.requests),
        (6, 4_000_000, 9)
    );
    assert_eq!(row.usage_units["audio_seconds"], 5_000_000);
}

#[test]
fn exact_counts_legacy_migration_preflight_reopen_idempotent() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "exactmigration");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("legacy")).unwrap();
    drop(store);
    let mut raw = postgres::Client::connect(&db.url(), postgres::NoTls).unwrap();
    raw.batch_execute("DELETE FROM busbar_schema; INSERT INTO busbar_schema VALUES(7);
        INSERT INTO usage_windows(bucket_id,window_start,requests,billable_requests) VALUES('legacy',0,7,5);
        INSERT INTO usage_ledger(bucket_id,window_start,model,tokens_input) VALUES('legacy',0,'exact-model',2);
        INSERT INTO usage_ledger_units(bucket_id,window_start,model,unit,count) VALUES('legacy',0,'exact-model','audio_seconds',170141183460469231731687303715885);
        INSERT INTO usage_metering(key_id,bucket,model,provider,tokens_input,requests) VALUES('legacy',0,'exact-model','provider',4,9);
        INSERT INTO usage_metering_units(key_id,bucket,model,provider,unit,count) VALUES('legacy',0,'exact-model','provider','audio_seconds',5);").unwrap();
    assert!(TestStore::open(&db.url()).is_err());
    let value: String = raw
        .query_one("SELECT tokens_input::text FROM usage_ledger", &[])
        .unwrap()
        .get(0);
    assert_eq!(value, "2", "preflight leaves every table unchanged");
    let version: i64 = raw
        .query_one("SELECT MAX(version) FROM busbar_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(version, 7);
    raw.batch_execute("UPDATE usage_ledger_units SET count=3")
        .unwrap();
    drop(raw);
    for _ in 0..2 {
        let store = TestStore::open(&db.url()).unwrap();
        migrated(&*store);
    }
    let store = TestStore::open(&db.url()).unwrap();
    store.add_usage("legacy", 0, &delta(6, 1, 0)).unwrap();
    drop(store);
    let store = TestStore::open(&db.url()).unwrap();
    assert_eq!(
        store.get_usage("legacy", 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
}

#[test]
fn full_range_quantities_replay_refund_and_unsigned_request_counters() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "fullrange");
    let store = TestStore::open(&db.url()).unwrap();
    let wide = (1_i128 << 100) + 123_456;
    let op = OpId::from_parts(0xe82, 1);
    let cells = [("wide", 0, delta(6, wide, 1))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    assert_eq!(
        store.get_usage("wide", 0).unwrap().models[0].tier("input"),
        wide
    );
    assert!(store
        .add_usage_batch_deduped(op, &[("wide", 0, delta(6, wide + 1, 1))])
        .is_err());

    store.add_usage("wide", 0, &delta(6, i128::MIN, 0)).unwrap();
    let refunded = store.get_usage("wide", 0).unwrap();
    assert_eq!(refunded.requests, 1);
    assert_eq!(
        refunded.models[0].tier("input"),
        0,
        "ordinary refunds floor at zero"
    );
    assert_eq!(refunded.models[0].tier("audio_seconds"), 0);

    let op = OpId::from_parts(0xe82, 2);
    let meters = [meter("wide", 6, wide, u64::MAX)];
    store.add_metering_batch_deduped(op, &meters).unwrap();
    store.add_metering_batch_deduped(op, &meters).unwrap();
    store.add_metering(&meter("wide", 6, 1, 1)).unwrap();
    drop(store);
    let store = TestStore::open(&db.url()).unwrap();
    let rows = store.list_metering(0).unwrap();
    let row = rows.iter().find(|row| row.key_id == "wide").unwrap();
    assert_eq!(row.tokens_input, wide + 1);
    assert_eq!(row.usage_units["audio_seconds"], wide + 1);
    assert_eq!((row.requests, row.billable_requests), (u64::MAX, u64::MAX));
}

/// Recreate the physical v7/v8 quantity columns, then verify conversion and widening separately.
#[test]
fn schema_nine_widens_before_scaling_and_never_rescales_micro_units() {
    let Some(url) = live_url() else { return };
    for old_version in [7, 8] {
        let db = TempDb::create(&url, "wideupgrade");
        drop(TestStore::open(&db.url()).unwrap());
        let mut raw = postgres::Client::connect(&db.url(), postgres::NoTls).unwrap();
        raw.batch_execute(&format!(
            "DELETE FROM busbar_schema; INSERT INTO busbar_schema VALUES({old_version});
             ALTER TABLE usage_ledger ALTER COLUMN tokens_input TYPE NUMERIC(20,0),
                ALTER COLUMN tokens_output TYPE NUMERIC(20,0),
                ALTER COLUMN tokens_cache_read TYPE NUMERIC(20,0),
                ALTER COLUMN tokens_cache_write TYPE NUMERIC(20,0);
             ALTER TABLE usage_ledger_units ALTER COLUMN count TYPE NUMERIC(20,0);
             ALTER TABLE usage_metering ALTER COLUMN tokens_input TYPE BIGINT,
                ALTER COLUMN tokens_output TYPE BIGINT, ALTER COLUMN tokens_cache_read TYPE BIGINT,
                ALTER COLUMN tokens_cache_write TYPE BIGINT, ALTER COLUMN requests TYPE BIGINT,
                ALTER COLUMN billable_requests TYPE BIGINT;
             ALTER TABLE usage_metering_units ALTER COLUMN count TYPE BIGINT;
             INSERT INTO usage_windows(bucket_id,window_start,requests,billable_requests) VALUES('wide',0,7,5);
             INSERT INTO usage_ledger(bucket_id,window_start,model,tokens_input) VALUES('wide',0,'exact-model',9223372036854775807);
             INSERT INTO usage_ledger_units(bucket_id,window_start,model,unit,count) VALUES('wide',0,'exact-model','audio_seconds',9223372036854775807);
             INSERT INTO usage_metering(key_id,bucket,model,provider,tokens_input,requests,billable_requests) VALUES('wide',0,'exact-model','provider',9223372036854775807,7,5);
             INSERT INTO usage_metering_units(key_id,bucket,model,provider,unit,count) VALUES('wide',0,'exact-model','provider','audio_seconds',9223372036854775807);"
        )).unwrap();
        let expected = i128::from(i64::MAX) * if old_version == 7 { 1_000_000 } else { 1 };
        for _ in 0..2 {
            let store = TestStore::open(&db.url()).unwrap();
            let usage = store.get_usage("wide", 0).unwrap();
            assert_eq!(usage.models[0].tier("input"), expected);
            assert_eq!(usage.models[0].tier("audio_seconds"), expected);
            assert_eq!((usage.requests, usage.billable_requests), (7, 5));
            let row = &store.list_metering(0).unwrap()[0];
            assert_eq!(row.tokens_input, expected);
            assert_eq!(row.usage_units["audio_seconds"], expected);
            assert_eq!((row.requests, row.billable_requests), (7, 5));
        }
        assert_eq!(
            raw.query_one("SELECT MAX(version) FROM busbar_schema", &[])
                .unwrap()
                .get::<_, i64>(0),
            9
        );
        let count: i64 = raw.query_one(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
             AND table_name IN ('usage_ledger','usage_ledger_units','usage_metering','usage_metering_units')
             AND column_name IN ('tokens_input','tokens_output','tokens_cache_read','tokens_cache_write','count')
             AND data_type='numeric' AND numeric_precision=39 AND numeric_scale=0", &[]
        ).unwrap().get(0);
        assert_eq!(count, 10);
    }
}

#[test]
fn schema_nine_invalid_preflight_rolls_back_widening_and_version() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "widerefusal");
    drop(TestStore::open(&db.url()).unwrap());
    let mut raw = postgres::Client::connect(&db.url(), postgres::NoTls).unwrap();
    raw.batch_execute(
        "DELETE FROM busbar_schema; INSERT INTO busbar_schema VALUES(8);
         ALTER TABLE usage_ledger ALTER COLUMN tokens_input TYPE NUMERIC(20,0);
         INSERT INTO usage_ledger(bucket_id,window_start,model,tokens_input)
             VALUES('bad',0,'model',-1);",
    )
    .unwrap();
    assert!(TestStore::open(&db.url()).is_err());
    assert_eq!(
        raw.query_one("SELECT MAX(version) FROM busbar_schema", &[])
            .unwrap()
            .get::<_, i64>(0),
        8
    );
    assert_eq!(
        raw.query_one("SELECT tokens_input::text FROM usage_ledger", &[])
            .unwrap()
            .get::<_, String>(0),
        "-1"
    );
    assert_eq!(raw.query_one(
        "SELECT numeric_precision::int FROM information_schema.columns
         WHERE table_schema=current_schema() AND table_name='usage_ledger' AND column_name='tokens_input'", &[]
    ).unwrap().get::<_, i32>(0), 20);
}
