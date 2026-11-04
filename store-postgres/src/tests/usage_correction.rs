// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::correction::{
    self, Decision, Request, UsageAddress, UsageChange,
};
use busbar_contract::abi::sdk::store::dedupe::Dedupe;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::StoreFailure;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const KEY: &str = "correction-key";
const BUCKET: &str = "correction-bucket";
const MODEL: &str = "correction-model";
const OPEN_UNIT: &str = "audio_seconds";
const DAY: u64 = 86_400;
const WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(5);
const NODE: u64 = 0x5047_434f_5252;

fn ledger(n: u64) -> UsageLedger {
    UsageLedger {
        requests: n,
        billable_requests: n,
        models: vec![ModelTokens {
            model: MODEL.into(),
            usage_units: BTreeMap::from([(UNIT_INPUT.into(), n), (OPEN_UNIT.into(), n)]),
        }],
    }
}
fn request(expected: UsageLedger, replacement: UsageLedger) -> Request {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Request {
        version: correction::VERSION,
        op_id: OpId::from_parts(NODE, NEXT.fetch_add(1, Ordering::Relaxed)),
        key_id: KEY.into(),
        day_start: DAY,
        metering: vec![],
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: BUCKET.into(),
                window_start: DAY,
            },
            expected,
            replacement,
        }],
    }
}
fn apply(store: &TestStore, request: &Request) -> Result<Decision, StoreFailure> {
    harness::block_on(
        busbar_contract::store_calls::StoreCalls::apply_usage_correction(&**store, request),
    )
}
fn receipts(store: &TestStore) -> i64 {
    store
        .lock()
        .query_one("SELECT COUNT(*) FROM store_ops", &[])
        .unwrap()
        .get(0)
}
fn revision(store: &TestStore) -> i64 {
    store
        .lock()
        .query_one("SELECT revision FROM store_revision WHERE only_row", &[])
        .unwrap()
        .get(0)
}
fn until(mut predicate: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + WAIT;
    while Instant::now() < end {
        if predicate() {
            return true;
        }
        std::thread::sleep(POLL);
    }
    false
}
fn seed(db: &TempDb) -> TestStore {
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key(KEY)).unwrap();
    store
}
fn meter() -> MeteringDelta {
    MeteringDelta {
        key_id: KEY.into(),
        bucket: DAY,
        model: MODEL.into(),
        provider: "provider".into(),
        tokens_input: 7,
        tokens_output: 11,
        tokens_cache_read: 13,
        tokens_cache_write: 17,
        requests: 19,
        billable_requests: 23,
        key_group_at_use: "historical-group".into(),
        pricing_version: "historical-version".into(),
        priced_from_ms: 29,
        usage_units: BTreeMap::from([(OPEN_UNIT.into(), 31)]),
    }
}

#[test]
fn exact_rows_receipts_conflicts_and_full_unsigned_values_survive_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_exact");
    let store = seed(&db);
    assert!(busbar_contract::store_calls::StoreCalls::supports_usage_correction(&*store));
    let before = revision(&store);
    let r = request(UsageLedger::default(), ledger(u64::MAX));
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert_eq!(store.get_usage(BUCKET, DAY).unwrap(), ledger(u64::MAX));
    assert_eq!(receipts(&store), 1);
    assert_eq!(revision(&store), before);
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert_eq!(apply(&reopened, &r).unwrap(), Decision::Applied);
    let mut changed = r.clone();
    changed.usage[0].replacement = ledger(u64::MAX - 1);
    assert!(matches!(
        apply(&reopened, &changed),
        Err(StoreFailure::Conflict)
    ));
    let losing = request(UsageLedger::default(), ledger(40));
    assert_eq!(
        apply(&reopened, &losing).unwrap(),
        Decision::ConditionConflict
    );
    assert_eq!(receipts(&reopened), 1);
    assert_eq!(store_value(&reopened), ledger(u64::MAX));
    reopened.put_usage(BUCKET, DAY, &ledger(u64::MAX)).unwrap();
    assert_eq!(
        store_value(&reopened),
        ledger(u64::MAX),
        "ordinary absolute writes share the exact codec"
    );

    reopened
        .add_usage(
            BUCKET,
            DAY,
            &UsageDelta {
                requests: -1,
                billable_requests: -1,
                models: vec![ModelTokensDelta {
                    model: MODEL.into(),
                    usage_units: BTreeMap::from([(UNIT_INPUT.into(), -1), (OPEN_UNIT.into(), -1)]),
                }],
            },
        )
        .unwrap();
    assert_eq!(store_value(&reopened), ledger(u64::MAX - 1));
    reopened.delete_key(KEY).unwrap();
    assert_eq!(
        apply(&reopened, &r).unwrap(),
        Decision::Applied,
        "receipt precedes live-key predicate"
    );
    let mut fresh = request(ledger(u64::MAX - 1), ledger(40));
    assert_eq!(
        apply(&reopened, &fresh).unwrap(),
        Decision::ConditionConflict
    );
    assert_eq!(
        receipts(&reopened),
        2,
        "only the correction and ordinary accrual applied"
    );
    fresh.version += 1;
    assert!(matches!(
        apply(&reopened, &fresh),
        Err(StoreFailure::Refused(_))
    ));
    assert_eq!(store_value(&reopened), ledger(u64::MAX - 1));
    assert_eq!(receipts(&reopened), 2);
}
fn store_value(store: &TestStore) -> UsageLedger {
    store.get_usage(BUCKET, DAY).unwrap()
}

#[test]
fn full_metering_selection_compares_counts_c4_and_missing_or_added_identities() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_meter");
    let store = seed(&db);
    store.add_metering(&meter()).unwrap();
    let mut valid = request(UsageLedger::default(), ledger(40));
    valid.metering = store.list_metering(DAY).unwrap();
    correction::canonical_metering(&mut valid.metering);
    let original = valid.metering[0].clone();
    let mut alternatives = Vec::new();
    let mut r = valid.clone();
    r.metering.clear();
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].requests += 1;
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].billable_requests += 1;
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].tokens_input += 1;
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].tokens_output += 1;
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].tokens_cache_read += 1;
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].tokens_cache_write += 1;
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].usage_units.insert(OPEN_UNIT.into(), 37);
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].model.push('x');
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].provider.push('x');
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].key_group_at_use.push('x');
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].pricing_version.push('x');
    alternatives.push(r);
    let mut r = valid.clone();
    r.metering[0].priced_from_ms += 1;
    alternatives.push(r);
    let before = receipts(&store);
    for r in alternatives {
        assert_eq!(apply(&store, &r).unwrap(), Decision::ConditionConflict);
        assert_eq!(store_value(&store), UsageLedger::default());
        assert_eq!(receipts(&store), before);
    }
    let mut other = meter();
    other.key_group_at_use.push('x');
    store.add_metering(&other).unwrap();
    assert_eq!(apply(&store, &valid).unwrap(), Decision::ConditionConflict);
    valid.metering = store.list_metering(DAY).unwrap();
    correction::canonical_metering(&mut valid.metering);
    assert!(valid.metering.contains(&original));
    assert_eq!(apply(&store, &valid).unwrap(), Decision::Applied);
}

#[test]
fn every_replacement_and_receipt_roll_back_together_and_legacy_adjustments_are_closed() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_rollback");
    let store = seed(&db);
    let mut r = request(UsageLedger::default(), ledger(40));
    let mut second = r.usage[0].clone();
    second.address.bucket_id = correction::ADJUST_UP_BUCKET.into();
    second.address.window_start = DAY;
    r.usage.push(second);
    r.usage.sort_by(|a, b| a.address.cmp(&b.address));
    store
        .lock()
        .batch_execute(
            "CREATE FUNCTION reject_correction() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
         IF NEW.bucket_id='correction-bucket' THEN RAISE EXCEPTION 'correction rollback'; END IF;
         RETURN NEW; END $$;
         CREATE TRIGGER reject_correction BEFORE INSERT ON usage_ledger_units
         FOR EACH ROW EXECUTE FUNCTION reject_correction()",
        )
        .unwrap();
    assert!(apply(&store, &r).is_err());
    assert_eq!(receipts(&store), 0);
    assert_eq!(store_value(&store), UsageLedger::default());
    assert_eq!(
        store.get_usage(correction::ADJUST_UP_BUCKET, DAY).unwrap(),
        UsageLedger::default()
    );
    store.lock().batch_execute("DROP TRIGGER reject_correction ON usage_ledger_units; DROP FUNCTION reject_correction()").unwrap();
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert_eq!(store_value(&store), ledger(40));
    assert_eq!(
        store.get_usage(correction::ADJUST_UP_BUCKET, DAY).unwrap(),
        ledger(40)
    );
    assert!(store
        .put_usage(correction::ADJUST_UP_BUCKET, DAY, &ledger(41))
        .is_err());
    let delta = UsageDelta {
        requests: 1,
        ..Default::default()
    };
    let cells = [(correction::ADJUST_DOWN_BUCKET, DAY, delta)];
    let legacy = OpId::from_parts(NODE, u64::MAX);
    assert!(matches!(
        store.add_usage_batch_op(legacy, &cells),
        Err(OpRefused::Refused(_))
    ));
    assert_eq!(receipts(&store), 1);

    let body = Dedupe::usage(&cells).body_hex();
    store
        .lock()
        .execute(
            "INSERT INTO store_ops(op_id,body,answer,recorded_at) VALUES($1,$2,'',$3)",
            &[&legacy.0.as_slice(), &body, &(now_secs() as i64)],
        )
        .unwrap();
    store.add_usage_batch_op(legacy, &cells).unwrap();
    assert_eq!(
        store
            .get_usage(correction::ADJUST_DOWN_BUCKET, DAY)
            .unwrap(),
        UsageLedger::default()
    );
    let mut different = cells.clone();
    different[0].2.requests += 1;
    assert_eq!(
        store.add_usage_batch_op(legacy, &different),
        Err(OpRefused::Conflict)
    );
}

/// Queue an ordinary API writer ahead of correction at their shared first authority lock.
fn writer_before_correction(
    db: &TempDb,
    r: Request,
    write: impl FnOnce(TestStore) -> Result<(), String> + Send + 'static,
) -> Decision {
    let writer = TestStore::open(&db.url()).unwrap();
    let correction = TestStore::open(&db.url()).unwrap();

    let mut observer = connect_client_with_retry(&db.url());
    let mut blocker = connect_client_with_retry(&db.url());
    blocker
        .batch_execute("BEGIN; SELECT revision FROM store_revision WHERE only_row FOR UPDATE")
        .unwrap();
    let waiting = |raw: &mut postgres::Client| -> i64 {
        raw.query_one(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database()
            AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%store_revision%'",
            &[],
        )
        .unwrap()
        .get(0)
    };
    let writer = std::thread::spawn(move || write(writer));
    let writer_waited = until(|| waiting(&mut observer) == 1);
    let (tx, rx) = std::sync::mpsc::channel();
    let correction = std::thread::spawn(move || {
        let _ = tx.send(apply(&correction, &r));
    });
    let both_waited = until(|| waiting(&mut observer) == 2);
    blocker.batch_execute("COMMIT").unwrap();
    let written = writer.join().unwrap();
    let answer = rx.recv_timeout(WAIT).unwrap();
    correction.join().unwrap();
    assert!(
        writer_waited && both_waited,
        "both real calls must reach the authority before release"
    );
    written.unwrap();
    answer.unwrap()
}

#[test]
fn absent_insert_metering_phantom_purge_and_key_delete_are_serialized_with_correction() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_absent_insert");
    let store = seed(&db);
    let r = request(UsageLedger::default(), ledger(40));
    assert_eq!(
        writer_before_correction(&db, r, |s| s
            .add_usage(
                BUCKET,
                DAY,
                &UsageDelta {
                    requests: 1,
                    ..Default::default()
                }
            )
            .map_err(|e| e.0)),
        Decision::ConditionConflict
    );
    assert_eq!(store_value(&store).requests, 1);
    assert_eq!(receipts(&store), 1);

    let db = TempDb::create(&url, "spg_correction_absolute");
    let store = seed(&db);
    assert_eq!(
        writer_before_correction(&db, request(UsageLedger::default(), ledger(40)), |s| s
            .put_usage(BUCKET, DAY, &ledger(100))
            .map_err(|e| e.0)),
        Decision::ConditionConflict
    );
    assert_eq!(store_value(&store), ledger(100));
    assert_eq!(receipts(&store), 0);

    let db = TempDb::create(&url, "spg_correction_meter_phantom");
    let store = seed(&db);
    assert_eq!(
        writer_before_correction(&db, request(UsageLedger::default(), ledger(40)), |s| s
            .add_metering(&meter())
            .map_err(|e| e.0)),
        Decision::ConditionConflict
    );
    assert_eq!(store_value(&store), UsageLedger::default());
    assert_eq!(receipts(&store), 1);

    let db = TempDb::create(&url, "spg_correction_purge");
    let store = seed(&db);
    store.put_usage(BUCKET, DAY, &ledger(100)).unwrap();
    assert_eq!(
        writer_before_correction(&db, request(ledger(100), ledger(40)), |s| {
            harness::block_on(
                busbar_contract::store_calls::StoreCalls::purge_usage_before(&*s, DAY + 1),
            )
            .map(drop)
            .map_err(|e| e.to_string())
        }),
        Decision::ConditionConflict
    );
    assert_eq!(store_value(&store), UsageLedger::default());
    assert_eq!(receipts(&store), 0);

    let db = TempDb::create(&url, "spg_correction_key_delete");
    let store = seed(&db);
    assert_eq!(
        writer_before_correction(&db, request(UsageLedger::default(), ledger(40)), |s| s
            .delete_key(KEY)
            .map_err(|e| e.0)),
        Decision::ConditionConflict
    );
    assert_eq!(store_value(&store), UsageLedger::default());
    assert_eq!(receipts(&store), 0);
}

#[test]
fn two_corrections_cannot_both_spend_the_same_prestate() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_race");
    let store = seed(&db);
    store.put_usage(BUCKET, DAY, &ledger(100)).unwrap();
    let first = request(ledger(100), ledger(40));
    let second = request(ledger(100), ledger(40));
    assert_eq!(
        writer_before_correction(&db, second, move |s| {
            assert_eq!(
                apply(&s, &first).map_err(|e| e.to_string())?,
                Decision::Applied
            );
            Ok(())
        }),
        Decision::ConditionConflict
    );
    assert_eq!(store_value(&store), ledger(40));
    assert_eq!(receipts(&store), 1);
}

#[test]
fn a_lost_commit_reply_retains_exact_replay_custody_after_the_loaded_future_is_destroyed() {
    use super::conditional_records::faults::WithheldCommit;
    struct Release(Arc<WithheldCommit>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.lose_reply();
        }
    }
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_lost");
    let store = seed(&db);
    let mut gate = None;
    let settings = serde_json::json!({"url": db.url()}).to_string();
    let loaded = harness::open_loaded_over(&settings, |d| {
        let table = Arc::new(WithheldCommit::new(d.conn_waker()));
        gate = Some(table.clone());
        table
    })
    .unwrap();
    let gate = gate.unwrap();
    gate.arm();
    let _release = Release(gate.clone());
    let r = request(UsageLedger::default(), ledger(u64::MAX));
    let sent = r.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(harness::block_on(
            busbar_contract::store_calls::StoreCalls::apply_usage_correction(&loaded, &sent),
        ));
    });
    let witnessed = until(|| {
        gate.is_held()
            && store
                .lock()
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM store_ops WHERE op_id=$1) AND EXISTS(
         SELECT 1 FROM usage_windows WHERE bucket_id=$2 AND window_start=$3 AND requests::text=$4)",
                    &[
                        &r.op_id.0.as_slice(),
                        &BUCKET,
                        &(DAY as i64),
                        &u64::MAX.to_string(),
                    ],
                )
                .unwrap()
                .get::<_, bool>(0)
    });
    let premature = rx.try_recv();
    let pending = matches!(premature, Err(std::sync::mpsc::TryRecvError::Empty));
    gate.lose_reply();
    let unknown = premature.unwrap_or_else(|_| rx.recv_timeout(WAIT).unwrap());
    worker.join().unwrap();
    assert!(
        witnessed && pending,
        "actual commit and withheld Pending response must both be observed"
    );
    assert!(unknown.is_err());
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert_eq!(apply(&reopened, &r).unwrap(), Decision::Applied);
    assert_eq!(store_value(&reopened), ledger(u64::MAX));
    assert_eq!(receipts(&reopened), 1);
}

#[test]
fn cancelling_a_pending_authority_wait_drops_the_uncommitted_transaction_without_a_receipt() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_cancel");
    let store = seed(&db);
    let settings = serde_json::json!({"url": db.url()}).to_string();
    let loaded = harness::open_loaded(&settings).unwrap();

    let mut observer = connect_client_with_retry(&db.url());
    let mut blocker = connect_client_with_retry(&db.url());
    blocker
        .batch_execute("BEGIN; SELECT revision FROM store_revision WHERE only_row FOR UPDATE")
        .unwrap();
    let r = request(UsageLedger::default(), ledger(40));
    let mut pending =
        Box::pin(busbar_contract::store_calls::StoreCalls::apply_usage_correction(&loaded, &r));
    let mut cx = Context::from_waker(Waker::noop());
    let reached_wait = until(|| {
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
        observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
            AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%store_revision%FOR UPDATE%')", &[])
            .unwrap().get::<_,bool>(0)
    });
    drop(pending);
    drop(loaded);
    blocker.batch_execute("COMMIT").unwrap();
    assert!(
        reached_wait,
        "the actual loaded operation must own an in-flight database transaction"
    );
    assert_eq!(receipts(&store), 0);
    assert_eq!(store_value(&store), UsageLedger::default());
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert_eq!(receipts(&store), 1);
}

#[test]
fn v18_usage_counters_migrate_in_place_before_exact_corrections_are_accepted() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_v18");
    let store = seed(&db);
    let old = ledger(i64::MAX as u64);
    store.put_usage(BUCKET, DAY, &old).unwrap();
    store
        .lock()
        .batch_execute(
            "ALTER TABLE usage_windows ALTER COLUMN requests TYPE BIGINT,
            ALTER COLUMN billable_requests TYPE BIGINT;
         ALTER TABLE usage_ledger ALTER COLUMN tokens_input TYPE BIGINT,
            ALTER COLUMN tokens_output TYPE BIGINT, ALTER COLUMN tokens_cache_read TYPE BIGINT,
            ALTER COLUMN tokens_cache_write TYPE BIGINT;
         ALTER TABLE usage_ledger_units ALTER COLUMN count TYPE BIGINT;",
        )
        .unwrap();

    const PRECISE_METERING_SCHEMA: i64 = FIRST_RELEASED_SCHEMA;
    store
        .lock()
        .execute(
            "DELETE FROM busbar_schema WHERE version>$1",
            &[&PRECISE_METERING_SCHEMA],
        )
        .unwrap();
    store
        .lock()
        .execute(
            "INSERT INTO busbar_schema(version) VALUES($1) ON CONFLICT DO NOTHING",
            &[&PRECISE_METERING_SCHEMA],
        )
        .unwrap();
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert_eq!(store_value(&reopened), old);
    assert_eq!(
        apply(&reopened, &request(old, ledger(u64::MAX))).unwrap(),
        Decision::Applied
    );
    drop(reopened);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert_eq!(store_value(&reopened), ledger(u64::MAX));
    assert_eq!(
        apply(&reopened, &request(ledger(u64::MAX), ledger(u64::MAX - 1))).unwrap(),
        Decision::Applied
    );
    assert_eq!(store_value(&reopened), ledger(u64::MAX - 1));
}

#[test]
fn sparse_empty_stored_models_compare_as_an_absent_ledger() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_empty");
    let store = seed(&db);
    store
        .put_usage(
            BUCKET,
            DAY,
            &UsageLedger {
                models: vec![ModelTokens {
                    model: MODEL.into(),
                    usage_units: BTreeMap::new(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        apply(&store, &request(UsageLedger::default(), ledger(40))).unwrap(),
        Decision::Applied
    );
    assert_eq!(store_value(&store), ledger(40));
}

#[test]
fn empty_model_identity_keeps_its_units_separate_from_request_totals() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_empty_model");
    let store = seed(&db);
    let mut old = ledger(5);
    old.requests = 2;
    old.billable_requests = 3;
    old.models[0].model.clear();
    store.put_usage(BUCKET, DAY, &old).unwrap();
    assert_eq!(store_value(&store), old);
    let mut new = ledger(11);
    new.requests = 7;
    new.billable_requests = 13;
    new.models[0].model.clear();
    assert_eq!(
        apply(&store, &request(old, new.clone())).unwrap(),
        Decision::Applied
    );
    assert_eq!(store_value(&store), new);
    let delta = UsageDelta {
        requests: 17,
        billable_requests: 19,
        models: vec![ModelTokensDelta {
            model: String::new(),
            usage_units: BTreeMap::from([(UNIT_INPUT.into(), 23)]),
        }],
    };
    store.add_usage(BUCKET, DAY, &delta).unwrap();
    new.apply_delta(&delta);
    assert_eq!(store_value(&store), new);
}

#[test]
fn malformed_rows_are_rejected_before_any_replacement_or_receipt() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_correction_invalid");
    let store = seed(&db);
    let valid = request(UsageLedger::default(), ledger(40));
    let mut invalid = vec![];
    let mut r = valid.clone();
    r.usage.push(r.usage[0].clone());
    invalid.push(r);
    let mut r = valid.clone();
    let duplicate = r.usage[0].replacement.models[0].clone();
    r.usage[0].replacement.models.push(duplicate);
    invalid.push(r);
    let mut r = valid.clone();
    r.usage.clear();
    invalid.push(r);
    let mut r = valid;
    r.version += 1;
    invalid.push(r);
    let before = revision(&store);
    for r in invalid {
        assert!(matches!(apply(&store, &r), Err(StoreFailure::Refused(_))));
        assert_eq!(store_value(&store), UsageLedger::default());
        assert_eq!(receipts(&store), 0);
        assert_eq!(revision(&store), before);
    }
}
