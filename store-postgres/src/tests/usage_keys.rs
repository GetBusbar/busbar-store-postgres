// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::StoreCalls;

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
            harness::block_on(StoreCalls::purge_usage_before(&*store, cutoff)).unwrap(),
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
    assert!(harness::block_on(StoreCalls::purge_usage_before(&*store, u64::MAX)).is_err());
    for key in KEYS {
        assert_eq!(store.get_usage("bucket", key).unwrap(), ledger(5));
    }
}
