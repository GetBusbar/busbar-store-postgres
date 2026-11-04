// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;

const KEYS: [u64; 8] = [
    0,
    1,
    i64::MAX as u64 - 1,
    i64::MAX as u64,
    i64::MAX as u64 + 1,
    i64::MAX as u64 + 2,
    u64::MAX - 1,
    u64::MAX,
];

fn ledger(n: u64) -> UsageLedger {
    UsageLedger {
        requests: n,
        billable_requests: n,
        models: vec![ModelTokens {
            model: "model".into(),
            usage_units: BTreeMap::from([(UNIT_INPUT.into(), n), ("audio_seconds".into(), n)]),
        }],
    }
}

fn meter(bucket: u64, n: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: "key".into(),
        bucket,
        model: "model".into(),
        provider: "provider".into(),
        tokens_input: n,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: n,
        billable_requests: n,
        key_group_at_use: "group".into(),
        pricing_version: "version".into(),
        priced_from_ms: 0,
        usage_units: BTreeMap::from([("audio_seconds".into(), n)]),
    }
}

#[test]
fn usage_keys_remain_distinct_across_put_batch_replay_and_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_usage_unsigned");
    let store = TestStore::open(&db.url()).unwrap();
    for (index, key) in KEYS.into_iter().enumerate() {
        store
            .put_usage("bucket", key, &ledger(index as u64 + 1))
            .unwrap();
    }
    for (index, key) in KEYS.into_iter().enumerate() {
        assert_eq!(
            store.get_usage("bucket", key).unwrap(),
            ledger(index as u64 + 1)
        );
    }
    let delta = UsageDelta {
        requests: 2,
        billable_requests: 2,
        models: vec![ModelTokensDelta {
            model: "model".into(),
            usage_units: BTreeMap::from([(UNIT_INPUT.into(), 2), ("audio_seconds".into(), 2)]),
        }],
    };
    let cells: Vec<_> = KEYS
        .into_iter()
        .rev()
        .map(|key| ("bucket", key, delta.clone()))
        .collect();
    let op = OpId::from_parts(17, 1);
    store.add_usage_batch_op(op, &cells).unwrap();
    store.add_usage_batch_op(op, &cells).unwrap();
    let mut changed = cells.clone();
    changed[0].1 -= 1;
    assert_eq!(
        store.add_usage_batch_op(op, &changed),
        Err(OpRefused::Conflict)
    );
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    for (index, key) in KEYS.into_iter().enumerate() {
        assert_eq!(
            reopened.get_usage("bucket", key).unwrap(),
            ledger(index as u64 + 3)
        );
    }
    reopened.put_usage("bucket", u64::MAX, &ledger(31)).unwrap();
    assert_eq!(reopened.get_usage("bucket", u64::MAX).unwrap(), ledger(31));
    assert_eq!(
        reopened.get_usage("bucket", i64::MAX as u64).unwrap(),
        ledger(6)
    );
    assert_eq!(
        reopened.get_usage("bucket", u64::MAX - 1).unwrap(),
        ledger(9)
    );
}

#[test]
fn metering_buckets_remain_distinct_across_add_batch_replay_and_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_meter_unsigned");
    let store = TestStore::open(&db.url()).unwrap();
    let deltas: Vec<_> = KEYS
        .into_iter()
        .enumerate()
        .map(|(i, key)| meter(key, i as u64 + 1))
        .collect();
    let op = OpId::from_parts(17, 2);
    store.add_metering_batch_op(op, &deltas).unwrap();
    store.add_metering_batch_op(op, &deltas).unwrap();
    let mut changed = deltas.clone();
    changed[7].bucket -= 1;
    assert_eq!(
        store.add_metering_batch_op(op, &changed),
        Err(OpRefused::Conflict)
    );
    for d in &deltas {
        store.add_metering(d).unwrap();
    }
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    for (index, key) in KEYS.into_iter().enumerate() {
        let rows = reopened.list_metering(key).unwrap();
        assert_eq!(rows.len(), 1, "bucket {key}");
        let n = 2 * (index as u64 + 1);
        assert_eq!(rows[0].requests, n);
        assert_eq!(rows[0].billable_requests, n);
        assert_eq!(rows[0].tokens_input, n);
        assert_eq!(rows[0].usage_units.get("audio_seconds"), Some(&n));
    }
}

#[test]
fn unsigned_usage_purge_preserves_zero_equal_cutoffs_and_metering() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_usage_unsigned_purge");
    let store = TestStore::open(&db.url()).unwrap();
    for key in KEYS {
        store.add_metering(&meter(key, 7)).unwrap();
    }
    for cutoff in KEYS {
        for key in KEYS {
            store.put_usage("bucket", key, &ledger(5)).unwrap();
        }
        let removed = KEYS
            .into_iter()
            .filter(|key| *key != 0 && *key < cutoff)
            .count();
        assert_eq!(
            harness::block_on(
                busbar_contract::store_calls::StoreCalls::purge_usage_before(&*store, cutoff)
            )
            .unwrap(),
            removed as u64
        );
        for key in KEYS {
            let want = if key != 0 && key < cutoff {
                UsageLedger::default()
            } else {
                ledger(5)
            };
            assert_eq!(
                store.get_usage("bucket", key).unwrap(),
                want,
                "key {key}, cutoff {cutoff}"
            );
            let billed = store.list_metering(key).unwrap();
            assert_eq!(billed.len(), 1);
            assert_eq!(billed[0].requests, 7);
            assert_eq!(billed[0].usage_units.get("audio_seconds"), Some(&7));
        }
        let counts = store
            .lock()
            .query_one(
                "SELECT (SELECT count(*) FROM usage_windows),
                    (SELECT count(*) FROM usage_ledger),
                    (SELECT count(*) FROM usage_ledger_units)",
                &[],
            )
            .unwrap();
        for field in 0..3 {
            assert_eq!(counts.get::<_, i64>(field), (KEYS.len() - removed) as i64);
        }
    }
    for key in KEYS {
        store.put_usage("bucket", key, &ledger(5)).unwrap();
    }
    store
        .lock()
        .batch_execute(
            "CREATE FUNCTION reject_unsigned_purge() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'unsigned purge rollback'; END $$;
         CREATE TRIGGER reject_unsigned_purge BEFORE DELETE ON usage_ledger_units
         FOR EACH ROW EXECUTE FUNCTION reject_unsigned_purge();",
        )
        .unwrap();
    assert!(harness::block_on(
        busbar_contract::store_calls::StoreCalls::purge_usage_before(&*store, u64::MAX)
    )
    .is_err());
    for key in KEYS {
        assert_eq!(store.get_usage("bucket", key).unwrap(), ledger(5));
    }
}

#[test]
fn released_v6_usage_keys_migrate_without_reinterpreting_existing_maximum_rows() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_usage_v16");
    let store = TestStore::open(&db.url()).unwrap();
    for key in [0, 1, i64::MAX as u64] {
        store.put_usage("bucket", key, &ledger(7)).unwrap();
        store.add_metering(&meter(key, 9)).unwrap();
    }
    store
        .lock()
        .batch_execute(&format!("DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES ({FIRST_RELEASED_SCHEMA})"))
        .unwrap();
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    for key in [0, 1, i64::MAX as u64] {
        assert_eq!(reopened.get_usage("bucket", key).unwrap(), ledger(7));
        let rows = reopened.list_metering(key).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requests, 9);
        assert_eq!(rows[0].usage_units.get("audio_seconds"), Some(&9));
    }
    assert_eq!(
        reopened.get_usage("bucket", u64::MAX).unwrap(),
        UsageLedger::default()
    );
    assert!(reopened.list_metering(u64::MAX).unwrap().is_empty());
    reopened.put_usage("bucket", u64::MAX, &ledger(11)).unwrap();
    reopened.add_metering(&meter(u64::MAX, 13)).unwrap();
    assert_eq!(
        reopened.get_usage("bucket", i64::MAX as u64).unwrap(),
        ledger(7)
    );
    assert_eq!(reopened.get_usage("bucket", u64::MAX).unwrap(), ledger(11));
    assert_eq!(
        reopened.list_metering(i64::MAX as u64).unwrap()[0].requests,
        9
    );
    assert_eq!(reopened.list_metering(u64::MAX).unwrap()[0].requests, 13);
}

#[test]
fn released_v6_negative_usage_key_provenance_is_not_silently_reinterpreted() {
    let Some(url) = live_url() else { return };
    for (table, column) in [
        ("usage_windows", "window_start"),
        ("usage_ledger", "window_start"),
        ("usage_ledger_units", "window_start"),
        ("usage_metering", "bucket"),
        ("usage_metering_units", "bucket"),
    ] {
        let db = TempDb::create(&url, "spg_usage_negative");
        let store = TestStore::open(&db.url()).unwrap();
        store.put_usage("bucket", 1, &ledger(7)).unwrap();
        store.add_metering(&meter(1, 9)).unwrap();
        store
            .lock()
            .batch_execute(&format!(
                "UPDATE {table} SET {column}=-1;
             DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES (6)"
            ))
            .unwrap();
        drop(store);
        let error = TestStore::open(&db.url())
            .err()
            .expect("unknown old key encoding");
        assert!(error.contains("negative usage key"), "{error}");
        let mut raw = connect_client_with_retry(&db.url());
        let row = raw
            .query_one(
                &format!("SELECT {column}, (SELECT max(version) FROM busbar_schema) FROM {table}"),
                &[],
            )
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), -1);
        assert_eq!(row.get::<_, i64>(1), FIRST_RELEASED_SCHEMA);
    }
}
